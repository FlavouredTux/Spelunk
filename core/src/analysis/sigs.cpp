#include <ember/analysis/sigs.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <format>
#include <fstream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

#include <ember/analysis/pipeline.hpp>  // DiscoveredFunction
#include <ember/binary/symbol.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember::sigs {

// ============================================================================
// CRC16 — FLIRT polynomial 0x8408 (reversed CCITT). Public so a future
// `.o`-file sig generator can use the same implementation.
// ============================================================================

u16 crc16(std::span<const std::byte> bytes) noexcept {
    u16 crc = 0xFFFF;
    for (const auto byte : bytes) {
        crc ^= static_cast<u16>(static_cast<u8>(byte));
        for (int i = 0; i < 8; ++i) {
            const u16 lsb = crc & 1u;
            crc >>= 1;
            if (lsb) crc ^= 0x8408;
        }
    }
    // FLIRT's documented variant: byteswap the final value.
    return static_cast<u16>(((crc & 0xFFu) << 8) | (crc >> 8));
}

// ============================================================================
// .pat line parser
//
// Format (one signature per line):
//
//   <masked-prefix> <crc-len> <crc16> <total-len> [:offs name]+ [@offs name]* [^offs name]*
//
// `masked-prefix` is up to 64 hex chars (32 bytes) with `..` marking
// wildcards. `crc-len` is 2 hex chars, `crc16` is 4, `total-len` is 4.
// We accept lower- or upper-case hex throughout.
// ============================================================================

namespace {

[[nodiscard]] bool is_hex_digit(char c) noexcept {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

[[nodiscard]] u8 hex_nibble(char c) noexcept {
    if (c >= '0' && c <= '9') return static_cast<u8>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<u8>(c - 'a' + 10);
    return static_cast<u8>(c - 'A' + 10);
}

// Parse a fixed-width hex token. Advances `pos` past the token on success.
template <class T>
[[nodiscard]] bool parse_hex_token(std::string_view s, std::size_t& pos,
                                    std::size_t width, T& out) noexcept {
    if (pos + width > s.size()) return false;
    out = 0;
    for (std::size_t i = 0; i < width; ++i) {
        const char c = s[pos + i];
        if (!is_hex_digit(c)) return false;
        out = static_cast<T>((out << 4) | hex_nibble(c));
    }
    pos += width;
    return true;
}

void skip_spaces(std::string_view s, std::size_t& pos) noexcept {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t')) ++pos;
}

// One name token: read until whitespace.
[[nodiscard]] std::string_view read_name(std::string_view s, std::size_t& pos) noexcept {
    const std::size_t start = pos;
    while (pos < s.size() && s[pos] != ' ' && s[pos] != '\t' &&
           s[pos] != '\r' && s[pos] != '\n') ++pos;
    return s.substr(start, pos - start);
}

[[nodiscard]] std::optional<Sig> parse_pat_line(std::string_view line) {
    // Trim trailing CR (Windows-style line endings).
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n' ||
                              line.back() == ' '  || line.back() == '\t')) {
        line.remove_suffix(1);
    }
    // Skip blanks, comments, and the FLIRT module-end marker.
    {
        std::size_t i = 0;
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        if (i == line.size()) return std::nullopt;
        if (line[i] == ';' || line[i] == '#') return std::nullopt;
        if (line.substr(i).starts_with("---")) return std::nullopt;
    }

    std::size_t pos = 0;
    skip_spaces(line, pos);

    // Prefix: hex chars and `..` pairs, terminated by whitespace.
    Sig sig;
    {
        const std::size_t start = pos;
        while (pos < line.size() && line[pos] != ' ' && line[pos] != '\t') ++pos;
        const std::string_view prefix = line.substr(start, pos - start);
        if (prefix.size() % 2 != 0) return std::nullopt;
        const std::size_t pairs = std::min(prefix.size() / 2, kPrefixLen);
        for (std::size_t i = 0; i < pairs; ++i) {
            const char c0 = prefix[2 * i];
            const char c1 = prefix[2 * i + 1];
            if (c0 == '.' && c1 == '.') {
                sig.mask[i]   = false;
                sig.prefix[i] = 0;
            } else if (is_hex_digit(c0) && is_hex_digit(c1)) {
                sig.mask[i]   = true;
                sig.prefix[i] = static_cast<u8>((hex_nibble(c0) << 4) |
                                                  hex_nibble(c1));
            } else {
                return std::nullopt;
            }
        }
        sig.prefix_len = static_cast<u16>(pairs);
    }

    skip_spaces(line, pos);
    if (!parse_hex_token(line, pos, 2, sig.crc_length)) return std::nullopt;
    skip_spaces(line, pos);
    if (!parse_hex_token(line, pos, 4, sig.crc16))      return std::nullopt;
    skip_spaces(line, pos);
    if (!parse_hex_token(line, pos, 4, sig.total_length)) return std::nullopt;

    // Tokens: `:offset name`, `@offset name`, `^offset name`. We keep the
    // first `:0000`-offset name as the canonical public name; refs land
    // in `sig.refs`. Local refs (`^`) are recorded as refs too — the
    // matcher just consumes both types interchangeably for now.
    bool got_name = false;
    while (pos < line.size()) {
        skip_spaces(line, pos);
        if (pos >= line.size()) break;
        const char tag = line[pos];
        if (tag != ':' && tag != '@' && tag != '^') {
            // Unknown token kind — abort parsing this line gracefully.
            return std::nullopt;
        }
        ++pos;
        u16 offset = 0;
        if (!parse_hex_token(line, pos, 4, offset)) return std::nullopt;
        skip_spaces(line, pos);
        const auto name = read_name(line, pos);
        if (name.empty()) return std::nullopt;

        if (tag == ':') {
            // Take the first public name at offset 0 as the function's name.
            // Later `:offset` entries on the same line are aliases (often a
            // mangled variant) — ignore for the rename target.
            if (!got_name && offset == 0) {
                sig.name = std::string(name);
                got_name = true;
            }
        } else {
            // Record as a reference for collision-breaking.
            sig.refs.push_back({offset, std::string(name)});
        }
    }

    if (!got_name) return std::nullopt;

    // Pre-compute specificity = number of non-wildcard prefix bytes.
    u16 spec = 0;
    for (u16 i = 0; i < sig.prefix_len; ++i) if (sig.mask[i]) ++spec;
    sig.specificity = spec;

    return sig;
}

}  // namespace

// ============================================================================
// File loaders
// ============================================================================

Result<SigDb> load_pat(const std::filesystem::path& path) {
    std::ifstream in(path);
    if (!in) {
        return std::unexpected(Error::io(
            std::format("cannot read sig file '{}'", path.string())));
    }
    SigDb db;
    std::string line;
    std::size_t skipped = 0;
    while (std::getline(in, line)) {
        auto parsed = parse_pat_line(line);
        if (!parsed) {
            // Distinguish blank/comment/--- (legitimately silent) from a
            // structurally-broken line (worth a warning). We don't have
            // separate return values from parse_pat_line; the heuristic
            // is: a line whose first non-space char is hex, but failed
            // to parse, was probably a malformed sig.
            std::size_t i = 0;
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
            if (i < line.size() && is_hex_digit(line[i])) {
                ++skipped;
            }
            continue;
        }
        db.sigs.push_back(std::move(*parsed));
    }
    if (skipped > 0) {
        std::fprintf(stderr,
            "ember: --pat: %s: skipped %zu malformed line(s)\n",
            path.string().c_str(), skipped);
    }
    return db;
}

Result<SigDb> load_pats(std::span<const std::filesystem::path> paths) {
    SigDb out;
    for (const auto& p : paths) {
        auto rv = load_pat(p);
        if (!rv) return std::unexpected(rv.error());
        for (auto& s : rv->sigs) out.sigs.push_back(std::move(s));
    }
    // Dedupe identical (name, prefix) entries — common when two source
    // collections cover the same library.
    auto key = [](const Sig& s) {
        std::string k = s.name;
        k.append(reinterpret_cast<const char*>(s.prefix.data()), kPrefixLen);
        k.append(reinterpret_cast<const char*>(s.mask.data()),   kPrefixLen);
        return k;
    };
    std::unordered_set<std::string> seen;
    seen.reserve(out.sigs.size());
    std::vector<Sig> deduped;
    deduped.reserve(out.sigs.size());
    for (auto& s : out.sigs) {
        if (seen.insert(key(s)).second) deduped.push_back(std::move(s));
    }
    out.sigs = std::move(deduped);
    return out;
}

// ============================================================================
// Matcher
// ============================================================================

namespace {

[[nodiscard]] bool prefix_matches(const Sig& sig,
                                   std::span<const std::byte> bytes) noexcept {
    if (bytes.size() < sig.prefix_len) return false;
    for (u16 i = 0; i < sig.prefix_len; ++i) {
        if (!sig.mask[i]) continue;
        if (static_cast<u8>(bytes[i]) != sig.prefix[i]) return false;
    }
    return true;
}

[[nodiscard]] bool crc_matches(const Sig& sig, const Binary& b, addr_t addr) noexcept {
    if (sig.crc_length == 0) return true;
    auto span = b.bytes_at(addr + sig.prefix_len);
    if (span.size() < sig.crc_length) return false;
    return crc16(span.subspan(0, sig.crc_length)) == sig.crc16;
}

// Linear-decode the function from its entry, collecting direct call/jmp
// targets. Bounded by `byte_budget` (typically the sig's reported total
// length) and a hard step cap so a runaway misdecode can't loop. This is
// the same pattern arity.cpp's per-path walker uses, minus the BFS over
// branches — for sig refs we only care about calls discovered on the
// fall-through walk, which is what FLIRT itself indexes from the .o.
[[nodiscard]] std::vector<addr_t>
linear_calls(const Binary& b, addr_t entry, u32 byte_budget) {
    std::vector<addr_t> out;
    if (b.arch() != Arch::X86_64) return out;
    X64Decoder dec;
    addr_t ip       = entry;
    const addr_t end = entry + (byte_budget ? byte_budget : 4096u);
    for (int step = 0; step < 512 && ip < end; ++step) {
        auto span = b.bytes_at(ip);
        if (span.empty()) break;
        auto decoded = dec.decode(span, ip);
        if (!decoded) break;
        const Instruction& insn = *decoded;
        if (insn.mnemonic == Mnemonic::Call || insn.mnemonic == Mnemonic::Jmp) {
            if (insn.num_operands == 1 &&
                insn.operands[0].kind == Operand::Kind::Relative) {
                out.push_back(insn.operands[0].rel.target);
            }
        }
        if (insn.mnemonic == Mnemonic::Ret ||
            insn.mnemonic == Mnemonic::Ud2 ||
            insn.mnemonic == Mnemonic::Hlt) break;
        ip += insn.length;
    }
    return out;
}

// Resolve a call target to a public name we can compare against a sig
// reference: PLT import → bare import name (no @GLIBC_*), defined
// symbol → its name. Returns empty when the target is anonymous (an
// internal `sub_*` we haven't already renamed via some prior sig pass).
[[nodiscard]] std::string_view resolve_target_name(const Binary& b, addr_t tgt) noexcept {
    if (const Symbol* s = b.import_at_plt(tgt); s) {
        std::string_view name = s->name;
        if (auto at = name.find('@'); at != std::string_view::npos) {
            name = name.substr(0, at);
        }
        if (name.starts_with("__imp_")) name.remove_prefix(6);
        return name;
    }
    if (const Symbol* s = b.defined_object_at(tgt); s) {
        if (s->kind == SymbolKind::Function && s->addr == tgt) {
            return s->name;
        }
    }
    return {};
}

// All of `sig.refs` are reachable from this function's call set. Order
// and offset alignment are not enforced — too brittle when the
// candidate binary uses a different compiler or optimisation level
// than the reference. The presence test is enough to break the common
// "two functions share a prefix but call different libc helpers"
// collision.
[[nodiscard]] bool refs_match(const Sig& sig,
                                const std::vector<addr_t>& targets,
                                const Binary& b) {
    if (sig.refs.empty()) return true;
    for (const auto& ref : sig.refs) {
        bool found = false;
        for (const auto t : targets) {
            if (resolve_target_name(b, t) == ref.name) { found = true; break; }
        }
        if (!found) return false;
    }
    return true;
}

}  // namespace

std::vector<MatchResult>
apply_signatures(const Binary& b,
                 const SigDb& db,
                 std::span<const DiscoveredFunction> candidates,
                 std::span<const addr_t> existing_renames) {
    std::vector<MatchResult> out;
    if (db.empty()) return out;

    std::unordered_set<addr_t> skip;
    skip.reserve(existing_renames.size());
    for (auto a : existing_renames) skip.insert(a);

    for (const auto& fn : candidates) {
        // Symbol-named functions already have a real name — sigs only
        // exist to resolve `sub_*`/`vt_*` placeholders.
        if (fn.kind == DiscoveredFunction::Kind::Symbol) continue;
        if (skip.contains(fn.addr)) continue;

        auto bytes = b.bytes_at(fn.addr);
        if (bytes.empty()) continue;
        if (bytes.size() > kPrefixLen) bytes = bytes.subspan(0, kPrefixLen);

        // Two-stage collection: first all sigs that pass prefix + CRC,
        // then refs verification. We harvest call targets lazily — only
        // when the sig actually has refs to check, and only once per
        // candidate function.
        struct Hit { const Sig* sig; u16 ref_matches; };
        std::vector<Hit> hits;
        std::vector<addr_t> targets;
        bool targets_done = false;

        for (const auto& sig : db.sigs) {
            if (!prefix_matches(sig, bytes))   continue;
            if (!crc_matches(sig, b, fn.addr)) continue;
            if (!sig.refs.empty()) {
                if (!targets_done) {
                    targets = linear_calls(b, fn.addr, sig.total_length);
                    targets_done = true;
                }
                if (!refs_match(sig, targets, b)) continue;
            }
            hits.push_back({&sig, static_cast<u16>(sig.refs.size())});
        }

        if (hits.empty()) continue;

        // Pick the most specific sig, with ref-match count as the
        // tiebreaker. Refuse to rename only when a true tie remains.
        std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& c) {
            if (a.sig->specificity != c.sig->specificity)
                return a.sig->specificity > c.sig->specificity;
            return a.ref_matches > c.ref_matches;
        });
        if (hits.size() >= 2 &&
            hits[0].sig->specificity == hits[1].sig->specificity &&
            hits[0].ref_matches      == hits[1].ref_matches      &&
            hits[0].sig->name        != hits[1].sig->name) {
            continue;
        }
        out.push_back({fn.addr, hits[0].sig->name});
    }
    return out;
}

}  // namespace ember::sigs
