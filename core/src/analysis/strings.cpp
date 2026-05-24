#include <ember/analysis/strings.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <format>
#include <limits>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/demangle.hpp>
#include <ember/common/timing.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

constexpr std::size_t kMinStringLen = 4;
constexpr std::size_t kMaxStringLen = 1024;

[[nodiscard]] bool is_string_byte(unsigned char c) noexcept {
    if (c == '\t' || c == '\n' || c == '\r') return true;
    return c >= 0x20 && c <= 0x7e;
}

struct AddrRange {
    addr_t begin = 0;
    addr_t end   = 0;  // exclusive
};

[[nodiscard]] bool string_matches_scan_filter(
    std::string_view text, const StringScanOptions& options) {
    if (options.any_substrings.empty()) return true;
    return std::ranges::any_of(options.any_substrings, [&](const std::string& needle) {
        return !needle.empty() && text.find(needle) != std::string_view::npos;
    });
}

// Attempts to extract printable strings from a single section. Each NUL
// terminator ends the current run; overlapping/adjacent runs are independent
// entries (one per start offset).
void scan_section(const Section& sec, std::vector<StringEntry>& out,
                  const StringScanOptions& options) {
    if (sec.data.empty()) return;
    if (!sec.flags.readable) return;
    // Mach-O puts `__cstring` (and `__const`, `__ustring`, etc.) inside the
    // executable `__TEXT` segment - so filtering by the segment's X bit
    // means we miss the overwhelming majority of string literals on Mach-O.
    // The printable-run + NUL-terminated checks below filter out code bytes
    // perfectly well; trust them instead of a permissions heuristic.
    // Still skip obviously-code sections (__text itself, __stubs, ...) to
    // keep the scan fast and avoid occasional ASCII-looking instruction
    // sequences. We treat any section named `__text*` / `__stubs*` /
    // `__stub_helper` / `__init` / `__unwind*` / `__eh_frame` as code.
    const std::string_view sn = sec.name;
    auto is_code_section = [&]() {
        for (const std::string_view skip : {
            std::string_view{"__text"},
            std::string_view{"__stubs"},
            std::string_view{"__stub_helper"},
            std::string_view{"__unwind_info"},
            std::string_view{"__eh_frame"},
            std::string_view{"__init"},
            std::string_view{"__mod_init_func"},
            std::string_view{"__mod_term_func"},
            std::string_view{".text"},
            std::string_view{".plt"},
            std::string_view{".init"},
            std::string_view{".fini"},
        }) {
            if (sn == skip) return true;
            if (sn.ends_with(std::string{","} + std::string{skip})) return true;
        }
        return false;
    };
    if (is_code_section()) return;

    const auto* data = reinterpret_cast<const unsigned char*>(sec.data.data());
    const std::size_t n = sec.data.size();

    std::size_t i = 0;
    while (i < n) {
        // Skip past non-string bytes until we find a printable one.
        while (i < n && !is_string_byte(data[i])) ++i;
        if (i >= n) break;

        const std::size_t start = i;
        std::string s;
        while (i < n && is_string_byte(data[i]) && s.size() < kMaxStringLen) {
            s.push_back(static_cast<char>(data[i]));
            ++i;
        }
        // A valid C string is NUL-terminated in place. Require that to avoid
        // mistaking arbitrary ASCII stretches in code/data for string pools.
        const bool terminated = (i < n && data[i] == 0);
        if (terminated && s.size() >= kMinStringLen &&
            string_matches_scan_filter(s, options)) {
            StringEntry e;
            e.addr = sec.vaddr + static_cast<addr_t>(start);
            e.text = std::move(s);
            out.push_back(std::move(e));
        }
        if (i < n) ++i;  // skip the NUL / bad byte
    }
}

std::vector<StringEntry>
scan_strings_impl(const Binary &b, const StringScanOptions &options,
                  std::span<const DiscoveredFunction> discovered_functions,
                  bool have_discovered_functions) {
    ScopedTimer timer("strings.scan_strings");
    std::vector<StringEntry> results;
    for (const auto &sec : b.sections()) {
        scan_section(sec, results, options);
    }
    if (results.empty())
        return results;
    if (!options.collect_xrefs)
        return results;

    // Build a lookup: address → index in results.
    std::unordered_map<addr_t, std::size_t> by_addr;
    by_addr.reserve(results.size());
    for (std::size_t i = 0; i < results.size(); ++i) {
        by_addr.emplace(results[i].addr, i);
    }

    // For an operand-derived absolute address, find the string whose range
    // *contains* the address - since lea/mov/call immediates always target the
    // string start, we only match exact starts (simpler and avoids false hits
    // into the middle of a string).
    auto match = [&](addr_t a) -> StringEntry * {
        auto it = by_addr.find(a);
        if (it == by_addr.end())
            return nullptr;
        return &results[it->second];
    };

    // String discovery itself (scan_section above) is arch-agnostic, so
    // the results vector still contains every string in the binary on
    // any arch. Xref collection requires decoding instructions, which
    // currently only the X64Decoder does in this file. Bail before the
    // xref walk on non-x86 - strings still surface, the xrefs column
    // is just empty (the same as a stripped binary with no decodable
    // callers). Better than the prior silent miscount where each
    // discovered fn's bytes failed to decode and advanced one byte at a
    // time forever.
    if (b.arch() != Arch::X86_64)
        return results;

    // Walk every defined function + every discovered function (deduped
    // by address), decode linearly, collect xrefs. Earlier this walked
    // named symbols only, which on a partially-stripped binary missed
    // 95%+ of code and produced an empty xrefs column for strings only
    // referenced from anonymous fns. Same union-with-discovered fix as
    // compute_call_graph and compute_data_xrefs.
    struct WorkItem {
        addr_t addr;
        u64 size;
    };
    std::vector<WorkItem> work;
    std::unordered_set<addr_t> seen;
    auto add_discovered_function = [&](const DiscoveredFunction &fn) {
        if (b.import_at_plt(fn.addr) != nullptr)
            return;
        if (fn.size == 0)
            return;
        if (!seen.insert(fn.addr).second)
            return;
        work.push_back({fn.addr, fn.size});
    };
    if (have_discovered_functions) {
        seen.reserve(discovered_functions.size());
        work.reserve(discovered_functions.size());
        for (const auto &fn : discovered_functions) {
            add_discovered_function(fn);
        }
    } else {
        seen.reserve(b.symbols().size());
        work.reserve(b.symbols().size());
        for (const auto &sym : b.symbols()) {
            if (sym.is_import)
                continue;
            if (sym.kind != SymbolKind::Function)
                continue;
            if (sym.size == 0)
                continue;
            if (!seen.insert(sym.addr).second)
                continue;
            work.push_back({sym.addr, sym.size});
        }
        for (const auto &fn : enumerate_functions(b, EnumerateMode::Cheap)) {
            add_discovered_function(fn);
        }
    }

    X64Decoder dec;
    {
        ScopedTimer xref_timer("strings.scan_xrefs");
        for (const auto &w : work) {
            auto span = b.bytes_at(w.addr);
            if (span.empty())
                continue;
            const std::size_t limit =
                std::min<std::size_t>(span.size(), static_cast<std::size_t>(w.size));

            addr_t ip = w.addr;
            std::size_t off = 0;
            while (off < limit) {
                auto remaining = span.subspan(off, limit - off);
                auto decoded = dec.decode(remaining, ip);
                if (!decoded) {
                    ip += 1;
                    off += 1;
                    continue;
                }
                const auto &insn = *decoded;

                for (u8 j = 0; j < insn.num_operands; ++j) {
                    const Operand &op = insn.operands[j];
                    addr_t candidate = 0;
                    bool have = false;
                    if (op.kind == Operand::Kind::Relative) {
                        candidate = op.rel.target;
                        have = true;
                    } else if (op.kind == Operand::Kind::Memory && op.mem.has_disp) {
                        // rip-relative: disp is offset from next instruction.
                        if (op.mem.base == Reg::Rip && op.mem.index == Reg::None) {
                            candidate = ip + insn.length + static_cast<addr_t>(op.mem.disp);
                            have = true;
                        } else if (op.mem.base == Reg::None && op.mem.index == Reg::None) {
                            candidate = static_cast<addr_t>(op.mem.disp);
                            have = true;
                        }
                    } else if (op.kind == Operand::Kind::Immediate && op.imm.size >= 4) {
                        candidate = static_cast<addr_t>(op.imm.value);
                        have = true;
                    }
                    if (!have)
                        continue;
                    if (auto *e = match(candidate)) {
                        if (e->xrefs.empty() || e->xrefs.back() != ip) {
                            e->xrefs.push_back(ip);
                        }
                    }
                }

                ip += insn.length;
                off += insn.length;
            }
        }
    }

    // Dedupe xrefs.
    for (auto &e : results) {
        std::sort(e.xrefs.begin(), e.xrefs.end());
        e.xrefs.erase(std::unique(e.xrefs.begin(), e.xrefs.end()), e.xrefs.end());
    }

    return results;
}

}  // namespace

std::vector<StringEntry> scan_strings(const Binary& b) {
    return scan_strings(b, {});
}

std::vector<StringEntry> scan_strings(const Binary &b, const StringScanOptions &options) {
    return scan_strings_impl(b, options, {}, false);
}

namespace {

[[nodiscard]] bool is_ident_char(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return std::isalnum(u) || c == '_';
}

[[nodiscard]] bool good_name(std::string_view s) noexcept {
    if (s.size() < 4 || s.size() > 192) return false;
    if (s.starts_with("sub_")) return false;
    bool has_alpha = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) has_alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '[' || c == ']' ||
              c == '-' || c == '+' || c == ' ')) {
            return false;
        }
    }
    return has_alpha;
}

[[nodiscard]] std::string sanitize_name(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && i + 1 < s.size() && s[i + 1] == ':') {
            out += "::";
            ++i;
        } else if (c == '-' || c == '+' || c == '[' || c == ']' || c == ' ') {
            if (out.empty() || out.back() != '_') out.push_back('_');
        }
    }
    while (!out.empty() && out.front() == '_' &&
           !out.starts_with("_GLOBAL__N_")) {
        out.erase(out.begin());
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return good_name(out) ? out : std::string{};
}

[[nodiscard]] bool
demangled_name_needs_itanium_special_fallback(std::string_view name) noexcept {
    if (name.find("::~") != std::string_view::npos) return true;
    const auto last = name.rfind("::");
    if (last == std::string_view::npos || last + 2 >= name.size()) return false;
    const auto prev = name.rfind("::", last == 0 ? 0 : last - 1);
    const auto owner_start = prev == std::string_view::npos ? 0 : prev + 2;
    const auto owner = name.substr(owner_start, last - owner_start);
    const auto leaf = name.substr(last + 2);
    return !owner.empty() && owner == leaf;
}

[[nodiscard]] std::string_view trim_ascii(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) {
        s.remove_prefix(1);
    }
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) {
        s.remove_suffix(1);
    }
    return s;
}

[[nodiscard]] bool is_known_c_type_token(std::string_view tok) noexcept {
    return tok == "void" || tok == "bool" || tok == "char" ||
           tok == "short" || tok == "int" || tok == "long" ||
           tok == "float" || tok == "double" || tok == "size_t" ||
           tok == "ssize_t" || tok == "auto" || tok == "static" ||
           tok == "const" || tok == "volatile" || tok == "signed" ||
           tok == "unsigned" || tok == "struct" || tok == "class" ||
           tok == "enum" || tok == "BOOL" || tok == "id" ||
           tok.starts_with("uint") || tok.starts_with("int");
}

[[nodiscard]] bool has_c_signature_type_cue(std::string_view prefix) noexcept {
    prefix = trim_ascii(prefix);
    if (prefix.empty()) return false;
    if (prefix.find('*') != std::string_view::npos ||
        prefix.find('&') != std::string_view::npos) {
        return true;
    }
    for (std::size_t i = 0; i < prefix.size();) {
        while (i < prefix.size() && !is_ident_char(prefix[i])) ++i;
        const std::size_t start = i;
        while (i < prefix.size() && is_ident_char(prefix[i])) ++i;
        if (start != i && is_known_c_type_token(prefix.substr(start, i - start))) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] bool is_bad_plain_function_name(std::string_view name) noexcept {
    return name == "if" || name == "for" || name == "while" ||
           name == "switch" || name == "return" || name == "sizeof" ||
           name == "alignof" || name == "static_cast" ||
           name == "reinterpret_cast" || name == "const_cast" ||
           name == "dynamic_cast";
}

struct OperatorSuffixMatch {
    std::string_view token;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<OperatorSuffixMatch>
operator_suffix_match(std::string_view text, std::size_t pos) {
    struct OpName {
        std::string_view spelling;
        std::string_view token;
    };
    for (const auto& op : {
        OpName{"()", "call"},
        OpName{"[]", "index"},
        OpName{"<=>", "cmp"},
        OpName{"==", "eq"},
        OpName{"!=", "ne"},
        OpName{"<=", "le"},
        OpName{">=", "ge"},
        OpName{"->*", "ptr_member"},
        OpName{"->", "arrow"},
        OpName{"&&", "logical_and"},
        OpName{"||", "logical_or"},
        OpName{"++", "inc"},
        OpName{"--", "dec"},
        OpName{"+=", "plus_assign"},
        OpName{"-=", "minus_assign"},
        OpName{"*=", "mul_assign"},
        OpName{"/=", "div_assign"},
        OpName{"%=", "mod_assign"},
        OpName{"&=", "and_assign"},
        OpName{"|=", "or_assign"},
        OpName{"^=", "xor_assign"},
        OpName{"<<=", "shl_assign"},
        OpName{">>=", "shr_assign"},
        OpName{"<<", "shl"},
        OpName{">>", "shr"},
        OpName{"+", "plus"},
        OpName{"-", "minus"},
        OpName{"*", "mul"},
        OpName{"/", "div"},
        OpName{"%", "mod"},
        OpName{"&", "and"},
        OpName{"|", "or"},
        OpName{"^", "xor"},
        OpName{"~", "bit_not"},
        OpName{"!", "not"},
        OpName{"=", "assign"},
        OpName{"<", "lt"},
        OpName{">", "gt"},
        OpName{",", "comma"},
    }) {
        if (text.substr(pos).starts_with(op.spelling)) {
            return OperatorSuffixMatch{op.token, op.spelling.size()};
        }
    }
    if (text.substr(pos).starts_with(" new[]")) {
        return OperatorSuffixMatch{"new_array", 6};
    }
    if (text.substr(pos).starts_with(" delete[]")) {
        return OperatorSuffixMatch{"delete_array", 9};
    }
    if (text.substr(pos).starts_with(" new")) {
        return OperatorSuffixMatch{"new", 4};
    }
    if (text.substr(pos).starts_with(" delete")) {
        return OperatorSuffixMatch{"delete", 7};
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> operator_suffix_token(std::string_view text,
                                                               std::size_t pos) {
    auto match = operator_suffix_match(text, pos);
    if (!match)
        return std::nullopt;
    return std::string(match->token);
}

[[nodiscard]] std::string flat_demangled_type_token(std::string_view type) {
    type = trim_ascii(type);
    std::string out;
    out.reserve(type.size() + 8);
    auto underscore = [&] {
        if (!out.empty() && out.back() != '_')
            out.push_back('_');
    };
    auto append_word = [&](std::string_view word) {
        if (word.empty())
            return;
        if (!out.empty() && out.back() != '_')
            out.push_back('_');
        out.append(word);
    };
    for (std::size_t i = 0; i < type.size(); ++i) {
        const char c = type[i];
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
            out.push_back(c);
        } else if (c == ':' && i + 1 < type.size() && type[i + 1] == ':') {
            underscore();
            ++i;
        } else if (c == '*') {
            append_word("ptr");
        } else if (c == '&') {
            if (i + 1 < type.size() && type[i + 1] == '&') {
                append_word("rref");
                ++i;
            } else {
                append_word("ref");
            }
        } else if (c == '[') {
            append_word("array");
            while (i + 1 < type.size() && type[i + 1] != ']')
                ++i;
        } else {
            underscore();
        }
    }
    while (!out.empty() && out.front() == '_')
        out.erase(out.begin());
    while (!out.empty() && out.back() == '_')
        out.pop_back();
    return out;
}

[[nodiscard]] std::string normalize_operator_name(std::string_view name) {
    constexpr std::string_view needle = "operator";
    for (std::size_t pos = name.find(needle); pos != std::string_view::npos;
         pos = name.find(needle, pos + needle.size())) {
        const bool boundary_before =
            pos == 0 || (pos >= 2 && name[pos - 1] == ':' && name[pos - 2] == ':');
        if (!boundary_before)
            continue;
        auto match = operator_suffix_match(name, pos + needle.size());
        std::string out{name.substr(0, pos)};
        out += "operator_";
        if (match) {
            out += match->token;
            out += name.substr(pos + needle.size() + match->length);
            return out;
        }
        const auto target = trim_ascii(name.substr(pos + needle.size()));
        if (target.empty())
            continue;
        auto token = flat_demangled_type_token(target);
        if (token.empty())
            continue;
        out += token;
        return out;
    }
    return std::string{name};
}

struct ItaniumNameComponent {
    std::string token;
    std::size_t length = 0;
};

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_type_token(std::string_view text);

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_source_name_token(std::string_view text) {
    std::size_t pos = 0;
    if (pos >= text.size() || !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256)
            return std::nullopt;
    }
    if (len == 0 || pos + len > text.size())
        return std::nullopt;
    auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c))
            return std::nullopt;
    }
    return ItaniumNameComponent{std::string{name}, pos + len};
}

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_nested_type_token(std::string_view text) {
    if (text.empty() || text.front() != 'N')
        return std::nullopt;
    std::size_t pos = 1;
    while (pos < text.size() && (text[pos] == 'K' || text[pos] == 'V' || text[pos] == 'r' ||
                                 text[pos] == 'R' || text[pos] == 'O')) {
        ++pos;
    }
    std::vector<std::string> parts;
    while (pos < text.size() && text[pos] != 'E') {
        auto part = itanium_source_name_token(text.substr(pos));
        if (!part)
            return std::nullopt;
        parts.push_back(std::move(part->token));
        pos += part->length;
        if (pos < text.size() && text[pos] == 'I') {
            int depth = 1;
            ++pos;
            while (pos < text.size() && depth > 0) {
                if (text[pos] == 'I')
                    ++depth;
                else if (text[pos] == 'E')
                    --depth;
                ++pos;
            }
            if (depth != 0)
                return std::nullopt;
        }
    }
    if (pos >= text.size() || text[pos] != 'E' || parts.empty()) {
        return std::nullopt;
    }
    std::string token;
    for (const auto &part : parts) {
        if (!token.empty())
            token += '_';
        token += part;
    }
    return ItaniumNameComponent{std::move(token), pos + 1};
}

[[nodiscard]] std::optional<ItaniumNameComponent> itanium_type_token(std::string_view text) {
    if (text.empty())
        return std::nullopt;
    const char c = text.front();
    if (c == 'K' || c == 'V' || c == 'r') {
        auto inner = itanium_type_token(text.substr(1));
        if (!inner)
            return std::nullopt;
        if (c == 'K')
            inner->token = "const_" + inner->token;
        else if (c == 'V')
            inner->token = "volatile_" + inner->token;
        else
            inner->token = "restrict_" + inner->token;
        ++inner->length;
        return inner;
    }
    if (c == 'P' || c == 'R' || c == 'O') {
        auto inner = itanium_type_token(text.substr(1));
        if (!inner)
            return std::nullopt;
        inner->token += c == 'P' ? "_ptr" : c == 'R' ? "_ref" : "_rref";
        ++inner->length;
        return inner;
    }
    if (c == 'N')
        return itanium_nested_type_token(text);
    if (std::isdigit(static_cast<unsigned char>(c))) {
        return itanium_source_name_token(text);
    }
    struct Builtin {
        char code;
        std::string_view token;
    };
    for (const auto &b : {
             Builtin{'v', "void"},
             Builtin{'b', "bool"},
             Builtin{'c', "char"},
             Builtin{'a', "schar"},
             Builtin{'h', "uchar"},
             Builtin{'s', "short"},
             Builtin{'t', "ushort"},
             Builtin{'i', "int"},
             Builtin{'j', "uint"},
             Builtin{'l', "long"},
             Builtin{'m', "ulong"},
             Builtin{'x', "long_long"},
             Builtin{'y', "ulong_long"},
             Builtin{'f', "float"},
             Builtin{'d', "double"},
             Builtin{'e', "long_double"},
             Builtin{'g', "float128"},
             Builtin{'z', "ellipsis"},
         }) {
        if (c == b.code)
            return ItaniumNameComponent{std::string{b.token}, 1};
    }
    if (text.starts_with("S_"))
        return ItaniumNameComponent{"subst", 2};
    return std::nullopt;
}

[[nodiscard]] std::optional<ItaniumNameComponent>
itanium_operator_component(std::string_view text) {
    struct OpCode {
        std::string_view code;
        std::string_view token;
    };
    if (text.starts_with("cv")) {
        auto target = itanium_type_token(text.substr(2));
        if (!target)
            return std::nullopt;
        return ItaniumNameComponent{"operator_" + std::move(target->token), target->length + 2};
    }
    for (const auto &op : {
             OpCode{"nw", "operator_new"},         OpCode{"na", "operator_new_array"},
             OpCode{"dl", "operator_delete"},      OpCode{"da", "operator_delete_array"},
             OpCode{"ps", "operator_plus"},        OpCode{"ng", "operator_minus"},
             OpCode{"ad", "operator_and"},         OpCode{"de", "operator_mul"},
             OpCode{"co", "operator_bit_not"},     OpCode{"pl", "operator_plus"},
             OpCode{"mi", "operator_minus"},       OpCode{"ml", "operator_mul"},
             OpCode{"dv", "operator_div"},         OpCode{"rm", "operator_mod"},
             OpCode{"an", "operator_and"},         OpCode{"or", "operator_or"},
             OpCode{"eo", "operator_xor"},         OpCode{"aS", "operator_assign"},
             OpCode{"pL", "operator_plus_assign"}, OpCode{"mI", "operator_minus_assign"},
             OpCode{"mL", "operator_mul_assign"},  OpCode{"dV", "operator_div_assign"},
             OpCode{"rM", "operator_mod_assign"},  OpCode{"aN", "operator_and_assign"},
             OpCode{"oR", "operator_or_assign"},   OpCode{"eO", "operator_xor_assign"},
             OpCode{"ls", "operator_shl"},         OpCode{"rs", "operator_shr"},
             OpCode{"lS", "operator_shl_assign"},  OpCode{"rS", "operator_shr_assign"},
             OpCode{"eq", "operator_eq"},          OpCode{"ne", "operator_ne"},
             OpCode{"lt", "operator_lt"},          OpCode{"gt", "operator_gt"},
             OpCode{"le", "operator_le"},          OpCode{"ge", "operator_ge"},
             OpCode{"nt", "operator_not"},         OpCode{"aa", "operator_logical_and"},
             OpCode{"oo", "operator_logical_or"},  OpCode{"pp", "operator_inc"},
             OpCode{"mm", "operator_dec"},         OpCode{"cm", "operator_comma"},
             OpCode{"pm", "operator_ptr_member"},  OpCode{"pt", "operator_arrow"},
             OpCode{"cl", "operator_call"},        OpCode{"ix", "operator_index"},
         }) {
        if (text.starts_with(op.code)) {
            return ItaniumNameComponent{std::string(op.token), op.code.size()};
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
c_pretty_function_name(std::string_view text) {
    for (std::size_t paren = text.find('(');
         paren != std::string_view::npos;
         paren = text.find('(', paren + 1)) {
        auto head = trim_ascii(text.substr(0, paren));
        if (head.empty()) continue;

        std::size_t end = head.size();
        while (end > 0 &&
               std::isspace(static_cast<unsigned char>(head[end - 1]))) {
            --end;
        }
        std::size_t start = end;
        while (start > 0 && is_ident_char(head[start - 1])) --start;
        if (start == end) continue;

        const auto raw_name = head.substr(start, end - start);
        if (is_bad_plain_function_name(raw_name)) continue;
        if (!has_c_signature_type_cue(head.substr(0, start))) continue;
        if (auto n = sanitize_name(raw_name); !n.empty()) return n;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
itanium_nested_name_prefix(std::string_view text) {
    std::size_t start = 0;
    if (text.starts_with("ZZN") || text.starts_with("ZZNK")) start = 1;
    if (!text.substr(start).starts_with("ZN")) return std::nullopt;
    std::size_t pos = start + 2;
    while (pos < text.size() &&
           (text[pos] == 'K' || text[pos] == 'V' ||
            text[pos] == 'r' || text[pos] == 'R' || text[pos] == 'O')) {
        ++pos;
    }
    std::vector<std::string> parts;
    while (pos < text.size() && text[pos] != 'E') {
        if (pos + 1 < text.size() && text[pos] == 'C' &&
            (text[pos + 1] == '1' || text[pos + 1] == '2' ||
             text[pos + 1] == '3')) {
            if (!parts.empty()) parts.push_back("ctor_" + parts.back());
            pos += 2;
            continue;
        }
        if (pos + 1 < text.size() && text[pos] == 'D' &&
            (text[pos + 1] == '0' || text[pos + 1] == '1' ||
             text[pos + 1] == '2')) {
            if (!parts.empty()) parts.push_back("dtor_" + parts.back());
            pos += 2;
            continue;
        }
            if (auto op = itanium_operator_component(text.substr(pos))) {
                parts.push_back(std::move(op->token));
                pos += op->length;
                continue;
            }
        if (!std::isdigit(static_cast<unsigned char>(text[pos]))) return std::nullopt;
        std::size_t len = 0;
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
            len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > text.size()) return std::nullopt;
        auto comp = text.substr(pos, len);
        pos += len;
        if (comp.empty() || comp.front() == '$') continue;
        bool ok = true;
        for (char c : comp) {
            if (!(is_ident_char(c) || c == '$')) {
                ok = false;
                break;
            }
        }
        if (!ok) return std::nullopt;
        parts.emplace_back(comp);
    }
    if (pos >= text.size() || text[pos] != 'E') return std::nullopt;
    if (parts.size() < 2) return std::nullopt;
    if (parts.front() == "std" || parts.front() == "__cxxabiv1") return std::nullopt;

    std::string out;
    for (const auto& p : parts) {
        if (out.empty()) out = p;
        else out += "::" + p;
    }
    if (auto n = sanitize_name(out); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
itanium_local_function_name_prefix(std::string_view text) {
    std::size_t pos = 0;
    if (text.starts_with("ZZL")) pos = 1;
    if (!text.substr(pos).starts_with("ZL")) return std::nullopt;
    pos += 2;
    if (pos >= text.size() ||
        !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256) return std::nullopt;
    }
    if (len == 0 || pos + len > text.size()) return std::nullopt;
    const auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c)) return std::nullopt;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] bool is_itanium_type_start(char c) noexcept {
    switch (c) {
    case 'v': case 'w': case 'b': case 'c': case 'a': case 'h':
    case 's': case 't': case 'i': case 'j': case 'l': case 'm':
    case 'x': case 'y': case 'n': case 'o': case 'f': case 'd':
    case 'e': case 'g': case 'z': case 'P': case 'R': case 'O':
    case 'C': case 'G': case 'U': case 'N': case 'S': case 'I':
    case 'K': case 'V': case 'r': case 'E':
        return true;
    default:
        return false;
    }
}

[[nodiscard]] std::optional<std::string>
itanium_free_function_name_prefix(std::string_view text) {
    std::size_t pos = 0;
    if (text.starts_with("ZZ") && text.size() > 2 &&
        std::isdigit(static_cast<unsigned char>(text[2]))) {
        pos = 1;
    }
    if (pos >= text.size() || text[pos] != 'Z') return std::nullopt;
    ++pos;
    if (pos >= text.size() ||
        !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        return std::nullopt;
    }
    std::size_t len = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        len = len * 10 + static_cast<std::size_t>(text[pos] - '0');
        ++pos;
        if (len > 256) return std::nullopt;
    }
    if (len == 0 || pos + len > text.size()) return std::nullopt;
    const auto name = text.substr(pos, len);
    for (char c : name) {
        if (!is_ident_char(c)) return std::nullopt;
    }
    pos += len;
    if (pos < text.size() && !is_itanium_type_start(text[pos])) {
        return std::nullopt;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
itanium_embedded_function_name_prefix(std::string_view text) {
    if (auto n = itanium_nested_name_prefix(text)) return n;
    if (auto n = itanium_local_function_name_prefix(text)) return n;
    if (auto n = itanium_free_function_name_prefix(text)) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
reflection_owner_component(std::string_view enc) {
    std::vector<std::string> parts;
    if (!enc.empty() && enc.front() == 'N') {
        std::size_t pos = 1;
        while (pos < enc.size() && enc[pos] != 'E') {
            if (enc.substr(pos).starts_with("S_")) {
                pos += 2;
                continue;
            }
            if (!std::isdigit(static_cast<unsigned char>(enc[pos]))) break;
            std::size_t len = 0;
            while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
                len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
                ++pos;
                if (len > 256) return std::nullopt;
            }
            if (len == 0 || pos + len > enc.size()) return std::nullopt;
            parts.emplace_back(enc.substr(pos, len));
            pos += len;
        }
    } else if (!enc.empty() &&
               std::isdigit(static_cast<unsigned char>(enc.front()))) {
        std::size_t pos = 0;
        std::size_t len = 0;
        while (pos < enc.size() && std::isdigit(static_cast<unsigned char>(enc[pos]))) {
            len = len * 10 + static_cast<std::size_t>(enc[pos] - '0');
            ++pos;
            if (len > 256) return std::nullopt;
        }
        if (len == 0 || pos + len > enc.size()) return std::nullopt;
        parts.emplace_back(enc.substr(pos, len));
    }
    if (parts.empty()) return std::nullopt;
    auto owner = sanitize_name(parts.back());
    if (owner.empty()) return std::nullopt;
    return owner;
}

struct ReflectionDescriptorNameParts {
    std::string owner;
    std::string_view marker;
    std::string_view tag;
    std::string arity;
    bool include_arity = false;
};

[[nodiscard]] std::string reflection_descriptor_arity(std::string_view text) {
    if (const auto a = text.rfind("ELi"); a != std::string_view::npos) {
        std::size_t pos = a + 3;
        std::size_t end = pos;
        while (end < text.size() &&
               std::isdigit(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
        if (end > pos && end < text.size() && text[end] == 'E') {
            return std::string{text.substr(pos, end - pos)};
        }
    }
    return "n";
}

[[nodiscard]] std::optional<ReflectionDescriptorNameParts>
parse_reflection_descriptor_name_parts(std::string_view text) {
    struct Marker {
        std::string_view token;
        std::string_view tag;
        bool include_arity;
    };
    for (const auto& marker : {
        Marker{"BoundYieldFuncDescI", "yield_func", true},
        Marker{"CustomBoundFuncDescI", "bound_func", true},
        Marker{"BoundFuncDescI", "bound_func", true},
        Marker{"RemoteEventDescI", "remote_event", false},
        Marker{"EventDescI", "event", false},
        Marker{"EnumPropDescriptorI", "enum_property", false},
        Marker{"RefPropDescriptorI", "ref_property", false},
        Marker{"PropDescriptorI", "property", false},
        Marker{"TypedPropertyDescriptorI", "typed_property", false},
        Marker{"EnumDescI", "enum", false},
        Marker{"TTypeI", "type", false},
    }) {
        const auto p = text.find(marker.token);
        if (p == std::string_view::npos) continue;
        auto owner = reflection_owner_component(text.substr(p + marker.token.size()));
        if (!owner) continue;
        return ReflectionDescriptorNameParts{
            .owner = std::move(*owner),
            .marker = marker.token,
            .tag = marker.tag,
            .arity = marker.include_arity ? reflection_descriptor_arity(text) : "",
            .include_arity = marker.include_arity,
        };
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
reflection_descriptor_candidate_name(const ReflectionDescriptorNameParts& parts,
                                     std::optional<std::string_view> member) {
    std::string name = "reflection_" + parts.owner + "_";
    if (member && !member->empty()) {
        name += std::string{*member} + "_";
    }
    name += std::string{parts.tag};
    if (parts.include_arity) {
        name += "_argc_" + parts.arity;
    }
    if (auto n = sanitize_name(name); !n.empty()) return n;
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
reflection_bound_descriptor_name(std::string_view text) {
    auto parts = parse_reflection_descriptor_name_parts(text);
    if (!parts) return std::nullopt;
    if (!parts->include_arity) return std::nullopt;
    return reflection_descriptor_candidate_name(*parts, std::nullopt);
}

[[nodiscard]] bool looks_like_reflection_member_name(std::string_view text) noexcept {
    if (text.size() < 2 || text.size() > 96) return false;
    if (!(std::isalpha(static_cast<unsigned char>(text.front())) ||
          text.front() == '_')) {
        return false;
    }
    if (text.starts_with("__")) return false;
    if (text.find("DescI") != std::string_view::npos ||
        text.find("Reflection") != std::string_view::npos ||
        text.find("::") != std::string_view::npos) {
        return false;
    }

    bool alpha = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) alpha = true;
        if (!(std::isalnum(u) || c == '_')) return false;
    }
    return alpha;
}

[[nodiscard]] bool has_uppercase_transition(std::string_view text) noexcept {
    bool lower = false;
    bool upper = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        lower |= std::islower(u);
        upper |= std::isupper(u);
    }
    return lower && upper;
}

[[nodiscard]] bool has_role_identifier_suffix(std::string_view text) noexcept {
    for (const std::string_view suffix : {
             std::string_view{"Callback"},
             std::string_view{"Callbacks"},
             std::string_view{"Job"},
             std::string_view{"Jobs"},
             std::string_view{"Telemetry"},
             std::string_view{"Report"},
             std::string_view{"Reporter"},
             std::string_view{"Event"},
             std::string_view{"Events"},
             std::string_view{"Protocol"},
         }) {
        if (text.ends_with(suffix)) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_role_identifier_anchor(std::string_view text) noexcept {
    if (text.size() < 8 || text.size() > 80) return false;
    if (!std::isupper(static_cast<unsigned char>(text.front()))) return false;
    if (!has_uppercase_transition(text)) return false;
    if (!has_role_identifier_suffix(text)) return false;
    if (text.starts_with("NSt") || text.starts_with("ZN") ||
        text.starts_with("ZZ") || text.starts_with("T_")) {
        return false;
    }
    for (char c : text) {
        if (!is_ident_char(c)) return false;
    }
    return true;
}

[[nodiscard]] std::optional<std::string>
role_identifier_anchor_name(std::string_view text) {
    if (!looks_like_role_identifier_anchor(text)) return std::nullopt;
    auto name = sanitize_name(std::string{"string_anchor_"} + std::string{text});
    if (name.empty()) return std::nullopt;
    return name;
}

[[nodiscard]] std::string camel_tail_to_snake(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (std::isupper(static_cast<unsigned char>(c))) {
            const bool prev_lower_or_digit =
                i > 0 && (std::islower(static_cast<unsigned char>(text[i - 1])) ||
                          std::isdigit(static_cast<unsigned char>(text[i - 1])));
            const bool acronym_boundary =
                i > 0 && i + 1 < text.size() &&
                std::isupper(static_cast<unsigned char>(text[i - 1])) &&
                std::islower(static_cast<unsigned char>(text[i + 1]));
            if (!out.empty() && out.back() != '_' &&
                (prev_lower_or_digit || acronym_boundary)) {
                out.push_back('_');
            }
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else if (std::isalnum(static_cast<unsigned char>(c))) {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        } else if (!out.empty() && out.back() != '_') {
            out.push_back('_');
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    return out;
}

[[nodiscard]] bool is_graphics_api_ident(std::string_view tok) noexcept {
    if (tok.size() < 4 || tok.size() > 80) return false;
    if (!(tok.starts_with("gl") || tok.starts_with("vk"))) return false;
    if (!std::isupper(static_cast<unsigned char>(tok[2]))) return false;
    for (char c : tok) {
        if (!std::isalnum(static_cast<unsigned char>(c))) return false;
    }
    return true;
}

[[nodiscard]] std::optional<std::string>
graphics_api_name_from_string(std::string_view text) {
    for (std::size_t i = 0; i + 4 < text.size(); ++i) {
        if (i > 0 && is_ident_char(text[i - 1])) continue;
        if (!(text.substr(i).starts_with("gl") ||
              text.substr(i).starts_with("vk"))) {
            continue;
        }
        std::size_t j = i;
        while (j < text.size() &&
               std::isalnum(static_cast<unsigned char>(text[j]))) {
            ++j;
        }
        const auto tok = text.substr(i, j - i);
        if (!is_graphics_api_ident(tok)) continue;
        const bool call_expr = j < text.size() && text[j] == '(';
        const bool exact_name = i == 0 && j == text.size();
        if (!call_expr && !exact_name) continue;

        const auto api = tok.substr(0, 2);
        const auto tail = tok.substr(2);
        auto snake = camel_tail_to_snake(tail);
        if (snake.empty()) continue;
        auto name = std::string{"graphics_"} + std::string{api} + "_" + snake;
        if (exact_name) name += "_proc";
        if (auto n = sanitize_name(name); !n.empty()) return n;
    }

    if (text.find("#version") != std::string_view::npos &&
        (text.find("gl_Position") != std::string_view::npos ||
         text.find("layout(") != std::string_view::npos ||
         text.find("void main") != std::string_view::npos)) {
        if (auto n = sanitize_name("graphics_glsl_shader_source"); !n.empty()) return n;
    }
    if (text.find("SPIR-V") != std::string_view::npos ||
        text.find("SPIRV") != std::string_view::npos) {
        if (auto n = sanitize_name("graphics_spirv_shader_source"); !n.empty()) return n;
    }
    return std::nullopt;
}

[[nodiscard]] std::string lower_ascii_copy(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

[[nodiscard]] std::string remove_camel_word_copy(std::string_view text,
                                                 std::string_view word) {
    std::string out{text};
    std::size_t pos = 0;
    while ((pos = out.find(word, pos)) != std::string::npos) {
        out.erase(pos, word.size());
    }
    return out;
}

[[nodiscard]] std::optional<std::string>
sanitize_luau_anchor(std::string_view prefix, std::string_view tail) {
    auto snake = camel_tail_to_snake(tail);
    while (!snake.empty() && snake.front() == '_') snake.erase(snake.begin());
    while (!snake.empty() && snake.back() == '_') snake.pop_back();
    if (snake.empty()) return std::nullopt;
    auto name = sanitize_name(std::string{prefix} + snake);
    if (name.empty()) return std::nullopt;
    return name;
}

[[nodiscard]] bool looks_like_luau_opcode_token(std::string_view text) noexcept {
    if (text.empty() || text.size() > 40) return false;
    bool alpha = false;
    bool upper = false;
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) {
            alpha = true;
            if (!std::isupper(u)) return false;
            upper = true;
        } else if (!(std::isdigit(u) || c == '_')) {
            return false;
        }
    }
    if (!alpha || !upper) return false;
    for (const std::string_view needle : {
             std::string_view{"FASTCALL"},
             std::string_view{"NAMECALL"},
             std::string_view{"DUPCLOSURE"},
             std::string_view{"FORGPREP"},
             std::string_view{"FORGLOOP"},
             std::string_view{"JUMPIF"},
             std::string_view{"GETIMPORT"},
             std::string_view{"BYTECODE"},
         }) {
        if (text.find(needle) != std::string_view::npos) return true;
    }
    return false;
}

[[nodiscard]] std::optional<std::string>
luau_anchor_name_from_string(std::string_view text) {
    if (text.starts_with("luau-telemetry.")) {
        const auto tail = text.substr(std::string_view{"luau-telemetry."}.size());
        if (tail.size() < 3 || tail.size() > 96) return std::nullopt;
        for (char c : tail) {
            const auto u = static_cast<unsigned char>(c);
            if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_')) {
                return std::nullopt;
            }
        }
        return sanitize_luau_anchor("luau_telemetry_", tail);
    }

    if (looks_like_luau_opcode_token(text)) {
        return sanitize_luau_anchor("luau_opcode_", text);
    }

    const auto lower = lower_ascii_copy(text);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    if (has("unexpected opcode in short circuit")) {
        return sanitize_name("luau_unexpected_opcode_short_circuit");
    }
    if (has("unexpected opcode")) {
        return sanitize_name("luau_unexpected_opcode");
    }
    if (has("unhandled opcode")) {
        return sanitize_name("luau_unhandled_opcode");
    }
    if (has("bytecode auth check")) {
        return sanitize_name("luau_bytecode_auth_check");
    }
    if (lower == "invalid bytecode.") {
        return sanitize_name("luau_invalid_bytecode");
    }
    if (has("additional luau stack reservation has failed")) {
        return sanitize_name("luau_stack_reservation_failed");
    }
    if (text.starts_with("Debugger is out of Luau stack space in ")) {
        auto tail = text.substr(std::string_view{"Debugger is out of Luau stack space in "}.size());
        if (tail.starts_with("a ")) tail.remove_prefix(2);
        if (tail.starts_with("an ")) tail.remove_prefix(3);
        return sanitize_luau_anchor("luau_debugger_stack_", tail);
    }

    if (text == "LuauTelemetry") {
        return sanitize_name("luau_telemetry");
    }
    if (text.starts_with("Luau") && text.find("Telemetry") != std::string_view::npos) {
        auto tail = std::string_view{text}.substr(4);
        const auto stripped = remove_camel_word_copy(tail, "Telemetry");
        return sanitize_luau_anchor("luau_telemetry_", stripped);
    }
    if (text.starts_with("LuaApps") || text.starts_with("LuaShell") ||
        text.starts_with("LuaErrors")) {
        return sanitize_luau_anchor("luau_telemetry_", text);
    }
    if (text.find("LuauHeap") != std::string_view::npos) {
        return sanitize_luau_anchor("luau_heap_", text);
    }
    if (text.find("LuaBytecode") != std::string_view::npos ||
        text.find("Bytecode") != std::string_view::npos) {
        return sanitize_luau_anchor("luau_bytecode_", text);
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
graphics_phrase_name_from_string(std::string_view text) {
    const auto lower = lower_ascii_copy(text);
    auto has = [&](std::string_view needle) {
        return lower.find(needle) != std::string::npos;
    };

    if (has("vulkanbuggyrenderpass") || has("vulkan: error")) {
        if (auto n = sanitize_name("graphics_vulkan_backend_guard"); !n.empty()) return n;
    }
    if (has("opengl.framework")) {
        if (auto n = sanitize_name("graphics_gl_dlsym_resolver"); !n.empty()) return n;
    }
    if (has("failed to link shader program")) {
        if (auto n = sanitize_name("graphics_shader_program_link"); !n.empty()) return n;
    }
    if (has("failed to create shader")) {
        if (auto n = sanitize_name("graphics_shader_create"); !n.empty()) return n;
    }
    if (has("successfully compiled shader") || has("compiled {} shaders") ||
        has("compiled %d shaders")) {
        if (auto n = sanitize_name("graphics_shader_compile"); !n.empty()) return n;
    }
    if ((has("shader pack") || has("shaders from pack")) &&
        (has("opening") || has("loaded") || has("corrupted") ||
         has("outdated") || has("variant"))) {
        if (auto n = sanitize_name("graphics_shader_pack_load"); !n.empty()) return n;
    }
    if (has("deferred shader loading")) {
        if (auto n = sanitize_name("graphics_shader_deferred_loading"); !n.empty()) return n;
    }
    if (has("unknown shader type")) {
        if (auto n = sanitize_name("graphics_shader_type_dispatch"); !n.empty()) return n;
    }
    if (has("global instancing")) {
        if (auto n = sanitize_name("graphics_global_instancing"); !n.empty()) return n;
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string>
candidate_name_from_string(std::string_view text) {
    // Source-level block names often survive as strings even when the invoke
    // function itself is anonymous, e.g. "-[Cls doIt:]_block_invoke" or
    // "void Ns::Type::method(...)_block_invoke". Keep the suffix so these do
    // not collapse onto the enclosing method's name.
    if (const auto block_pos = text.find("_block_invoke");
        block_pos != std::string_view::npos) {
        std::string_view head = text.substr(0, block_pos);
        if (const auto objc_start = head.rfind("-[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto objc_start = head.rfind("+[");
            objc_start != std::string_view::npos) {
            if (auto n = sanitize_name(head.substr(objc_start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
        if (const auto scope = head.rfind("::");
            scope != std::string_view::npos) {
            std::size_t start = scope;
            while (start > 0) {
                const char c = head[start - 1];
                if (!(is_ident_char(c) || c == ':')) break;
                --start;
            }
            if (auto n = sanitize_name(head.substr(start)); !n.empty()) {
                n += "_block_invoke";
                return n;
            }
        }
    }

    // ObjC bracket form inside logs: "-[Class selector:]" or "+[Class sel]".
    for (std::size_t i = 0; i + 3 < text.size(); ++i) {
        if ((text[i] != '-' && text[i] != '+') || text[i + 1] != '[') continue;
        const auto end = text.find(']', i + 2);
        if (end == std::string_view::npos || end <= i + 3) continue;
        if (auto n = sanitize_name(text.substr(i, end - i + 1)); !n.empty()) return n;
    }

    if (auto n = reflection_bound_descriptor_name(text)) return n;
    if (auto n = graphics_api_name_from_string(text)) return n;
    if (auto n = graphics_phrase_name_from_string(text)) return n;

    // Itanium encodings embedded inside RTTI / std::function / lambda
    // metadata strings often carry a source function name even after the
    // symbol table is stripped. The common shape is a larger type encoding
    // containing `Z<function-encoding>`, for example
    // `...IZN7Example6Worker3runEvE...`.
    for (std::size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != 'Z') continue;
        if (text[i + 1] != 'N' &&
            text[i + 1] != 'L' &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'N') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' && text[i + 2] == 'L') &&
            !(i + 2 < text.size() && text[i + 1] == 'Z' &&
              std::isdigit(static_cast<unsigned char>(text[i + 2]))) &&
            !std::isdigit(static_cast<unsigned char>(text[i + 1]))) {
            continue;
        }
        std::string mangled = "_";
        mangled += text.substr(i);
        auto demangled = demangle_itanium(mangled);
        if (!demangled) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        auto base = strip_signature_suffix(*demangled);
        if (!base.contains("::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        if (base.starts_with("std::") || base.starts_with("__cxxabiv1::")) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
            continue;
        }
        base = normalize_operator_name(base);
        if (demangled_name_needs_itanium_special_fallback(base)) {
            if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
        }
        if (auto n = sanitize_name(base); !n.empty()) return n;
        if (auto n = itanium_embedded_function_name_prefix(text.substr(i))) return n;
    }

    // C++/namespace-ish tokens from logs: "Core::Player::step failed".
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (!is_ident_char(text[i])) continue;
        std::size_t j = i;
        while (j < text.size() &&
               (is_ident_char(text[j]) || (j + 1 < text.size() && text[j] == ':' && text[j + 1] == ':'))) {
            if (text[j] == ':') j += 2;
            else ++j;
        }
        const auto tok = text.substr(i, j - i);
        if (tok.find("::") != std::string_view::npos) {
            if (i > 0 && text[i - 1] == '[' &&
                j < text.size() && text[j] == ']') {
                i = j;
                continue;
            }
            if (tok.ends_with("::operator")) {
                if (auto suffix = operator_suffix_token(text, j)) {
                    if (auto n = sanitize_name(std::string(tok) + "_" + *suffix);
                        !n.empty()) {
                        return n;
                    }
                }
            }
            if (tok.ends_with("::") && j < text.size() && text[j] == '~') {
                const std::size_t name_start = j + 1;
                std::size_t name_end = name_start;
                while (name_end < text.size() && is_ident_char(text[name_end])) {
                    ++name_end;
                }
                if (name_end > name_start) {
                    std::string dtor = std::string(tok) + "dtor_" +
                                       std::string(text.substr(name_start,
                                                              name_end - name_start));
                    if (auto n = sanitize_name(dtor); !n.empty()) return n;
                }
            }
            if (auto n = sanitize_name(tok); !n.empty()) return n;
        }
        i = j;
    }

    // C/C++ compiler-provided function strings: `__PRETTY_FUNCTION__`,
    // assertion runtimes, and some logging macros preserve signatures such as
    // "static int recoverCachedValue(int)" even after symbols are stripped.
    if (auto n = c_pretty_function_name(text)) return n;

    // Prefix form: "recover_player_name: bad state" / "recover_player_name failed".
    const auto stop = text.find_first_of(":(");
    if (stop != std::string_view::npos && stop >= 4 && stop <= 80) {
        const auto prefix = text.substr(0, stop);
        bool all_ident = true;
        for (char c : prefix) {
            if (!is_ident_char(c)) { all_ident = false; break; }
        }
        if (all_ident) {
            if (auto n = sanitize_name(prefix); !n.empty()) return n;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::string clean_import_name_local(std::string_view name) {
    auto at = name.find('@');
    std::string bare(at == std::string_view::npos ? name : name.substr(0, at));
    if (bare.starts_with("__imp_")) bare.erase(0, 6);
    if (bare.starts_with('_') && !bare.starts_with("__")) bare.erase(0, 1);
    return bare;
}

[[nodiscard]] std::optional<std::size_t>
function_name_arg_index(std::string_view callee) noexcept {
    // glibc: __assert_fail(assertion, file, line, function)
    if (callee == "__assert_fail") return 3;
    // Darwin libc: __assert_rtn(function, file, line, expression)
    if (callee == "__assert_rtn") return 0;
    return std::nullopt;
}

[[nodiscard]] bool has_function_name_assert_import(const Binary& b) {
    for (const auto& sym : b.symbols()) {
        if (!sym.is_import) continue;
        if (function_name_arg_index(clean_import_name_local(sym.name))) return true;
    }
    return false;
}

[[nodiscard]] std::string read_cstring_local(const Binary& b, addr_t va) {
    auto bytes = b.bytes_at(va);
    std::string s;
    for (auto by : bytes) {
        const auto c = static_cast<unsigned char>(by);
        if (c == 0) break;
        if (!is_string_byte(c)) return {};
        s.push_back(static_cast<char>(c));
        if (s.size() > kMaxStringLen) return {};
    }
    return s.size() >= kMinStringLen ? s : std::string{};
}

[[nodiscard]] std::optional<u64>
read_u64_from_section(const Section& sec, std::size_t off) noexcept {
    if (off + 8 > sec.data.size()) return std::nullopt;
    const auto* p = reinterpret_cast<const unsigned char*>(sec.data.data() + off);
    u64 v = 0;
    for (unsigned i = 0; i < 8; ++i) v |= static_cast<u64>(p[i]) << (i * 8);
    return v;
}

[[nodiscard]] bool contains_executable_byte(const Binary& b, addr_t va) noexcept {
    for (const auto& sec : b.sections()) {
        if (!sec.flags.executable || sec.data.empty()) continue;
        if (va >= sec.vaddr && va < sec.vaddr + sec.data.size()) return true;
    }
    return false;
}

[[nodiscard]] bool looks_like_lua_reg_key(std::string_view s) noexcept {
    if (s.empty() || s.size() > 80) return false;
    bool useful = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u) || c == '_') useful = true;
        if (!(std::isalnum(u) || c == '_' || c == '.' || c == ':')) {
            return false;
        }
    }
    return useful;
}

[[nodiscard]] std::string lua_cfunc_name(std::string_view key) {
    return sanitize_name(std::string{"lua_cfunc_"} + std::string{key});
}

void infer_lua_registration_names(const Binary& b,
                                  std::span<const StringEntry> strings,
                                  std::vector<StringNameCandidate>& out,
                                  std::set<std::pair<addr_t, std::string>>& seen) {
    if (strings.empty()) return;

    std::map<addr_t, std::string_view> strings_by_addr;
    for (const auto& s : strings) {
        if (looks_like_lua_reg_key(s.text)) {
            strings_by_addr.emplace(s.addr, std::string_view{s.text});
        }
    }
    if (strings_by_addr.empty()) return;

    struct RegEntry {
        std::string_view key;
        addr_t           fn = 0;
    };

    for (const auto& sec : b.sections()) {
        if (sec.data.size() < 32) continue;
        if (!sec.flags.readable || sec.flags.executable) continue;

        const std::size_t align_skip =
            static_cast<std::size_t>((8 - (sec.vaddr & 7)) & 7);
        for (std::size_t off = align_skip; off + 16 <= sec.data.size(); off += 8) {
            std::vector<RegEntry> entries;
            bool terminated = false;
            std::size_t pos = off;
            for (; pos + 16 <= sec.data.size() && entries.size() < 256; pos += 16) {
                const auto name_va = read_u64_from_section(sec, pos);
                const auto fn_va = read_u64_from_section(sec, pos + 8);
                if (!name_va || !fn_va) break;
                if (*name_va == 0 && *fn_va == 0) {
                    terminated = true;
                    break;
                }
                if (*name_va == 0 || *fn_va == 0) break;
                const auto str_it = strings_by_addr.find(static_cast<addr_t>(*name_va));
                if (str_it == strings_by_addr.end()) break;
                const addr_t fn = static_cast<addr_t>(*fn_va);
                if (!contains_executable_byte(b, fn)) break;
                if (b.import_at_plt(fn) != nullptr) break;
                entries.push_back({str_it->second, fn});
            }
            if (!terminated || entries.empty()) continue;

            for (const auto& e : entries) {
                auto name = lua_cfunc_name(e.key);
                if (name.empty()) continue;
                if (seen.emplace(e.fn, name).second) {
                    out.push_back({e.fn, std::move(name),
                                   std::string{"luaL_Reg:"} + std::string{e.key}});
                }
            }
            off = pos;
        }
    }
}

template <class EnclosingFunction>
void infer_reflection_member_names(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct DescriptorRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
        ReflectionDescriptorNameParts parts;
    };
    struct MemberRef {
        const StringEntry* entry = nullptr;
        addr_t             xref = 0;
    };
    struct FunctionRefs {
        std::vector<DescriptorRef> descriptors;
        std::vector<MemberRef>     members;
    };

    std::map<addr_t, FunctionRefs> by_function;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        const auto parts = parse_reflection_descriptor_name_parts(s.text);
        const bool member = !parts && looks_like_reflection_member_name(s.text);
        if (!parts && !member) continue;

        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) {
                auto& refs = by_function[*fn];
                if (parts) {
                    refs.descriptors.push_back({&s, xr, *parts});
                } else {
                    refs.members.push_back({&s, xr});
                }
            }
        }
    }

    for (auto& [fn, refs] : by_function) {
        if (refs.descriptors.empty() || refs.members.empty()) continue;
        std::sort(refs.members.begin(), refs.members.end(),
                  [](const MemberRef& a, const MemberRef& b) {
                      if (a.xref != b.xref) return a.xref < b.xref;
                      return a.entry->text.size() < b.entry->text.size();
                  });

        for (const auto& desc_ref : refs.descriptors) {
            if (!desc_ref.entry) continue;

            const StringEntry* best = nullptr;
            addr_t best_dist = std::numeric_limits<addr_t>::max();
            bool best_precedes_descriptor = false;
            const addr_t lo = desc_ref.xref > 256 ? desc_ref.xref - 256 : 0;
            const addr_t hi = desc_ref.xref + 256;
            auto it = std::lower_bound(
                refs.members.begin(), refs.members.end(), lo,
                [](const MemberRef& ref, addr_t needle) { return ref.xref < needle; });
            for (; it != refs.members.end() && it->xref <= hi; ++it) {
                const auto& candidate_ref = *it;
                if (!candidate_ref.entry) continue;
                const addr_t dist = candidate_ref.xref > desc_ref.xref
                    ? candidate_ref.xref - desc_ref.xref
                    : desc_ref.xref - candidate_ref.xref;
                const bool precedes_descriptor = candidate_ref.xref <= desc_ref.xref;
                if (best && precedes_descriptor != best_precedes_descriptor) {
                    if (!precedes_descriptor) continue;
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = true;
                    continue;
                }
                if (dist < best_dist ||
                    (dist == best_dist && best &&
                     candidate_ref.entry->text.size() < best->text.size())) {
                    best = candidate_ref.entry;
                    best_dist = dist;
                    best_precedes_descriptor = precedes_descriptor;
                } else if (dist == best_dist && !best) {
                    best = candidate_ref.entry;
                    best_precedes_descriptor = precedes_descriptor;
                }
            }

            if (!best) continue;
            auto name = reflection_descriptor_candidate_name(
                desc_ref.parts, std::string_view{best->text});
            if (!name || name->empty()) continue;
            if (seen.emplace(fn, *name).second) {
                out.push_back({
                    fn,
                    std::move(*name),
                    std::format("reflection member {} near {}",
                                best->text, desc_ref.entry->text),
                });
            }
        }
    }
}

template <class EnclosingFunction>
void infer_role_identifier_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    std::map<std::string, std::set<addr_t>> functions_by_anchor;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = role_identifier_anchor_name(s.text);
        if (!name) continue;
        auto& functions = functions_by_anchor[*name];
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) functions.insert(*fn);
        }
    }

    std::map<addr_t, std::string> anchor_by_function;
    std::set<addr_t> ambiguous_functions;
    for (const auto& [name, functions] : functions_by_anchor) {
        if (functions.size() != 1) continue;
        const addr_t fn = *functions.begin();
        if (ambiguous_functions.contains(fn)) continue;
        auto [it, inserted] = anchor_by_function.emplace(fn, name);
        if (!inserted && it->second != name) {
            anchor_by_function.erase(it);
            ambiguous_functions.insert(fn);
        }
    }

    for (const auto& [fn, name] : anchor_by_function) {
        if (ambiguous_functions.contains(fn)) continue;
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, name, name.substr(std::string_view{"string_anchor_"}.size())});
        }
    }
}

[[nodiscard]] std::optional<std::string>
collapse_luau_anchor_family(const std::set<std::string>& names) {
    if (names.empty()) return std::nullopt;

    bool all_lua_apps = true;
    bool all_heap_profiler = true;
    bool all_bytecode = true;
    bool all_caps = true;
    for (const auto& name : names) {
        all_lua_apps &= name.starts_with("luau_telemetry_lua_apps_") ||
                        name == "luau_telemetry_lua_shell_errors";
        all_heap_profiler &= name.find("heap_profiler") != std::string::npos;
        all_bytecode &= name.starts_with("luau_bytecode_");
        all_caps &= name.starts_with("luau_telemetry_caps_");
    }

    if (all_lua_apps) return std::string{"luau_telemetry_lua_apps_metrics"};
    if (all_heap_profiler) return std::string{"luau_telemetry_heap_profiler"};
    if (all_bytecode) return std::string{"luau_bytecode_metrics"};
    if (all_caps) return std::string{"luau_telemetry_caps_use"};
    return std::nullopt;
}

template <class EnclosingFunction>
void infer_luau_metadata_anchors(
    std::span<const StringEntry> strings,
    EnclosingFunction enclosing_function,
    std::vector<StringNameCandidate>& out,
    std::set<std::pair<addr_t, std::string>>& seen) {
    struct AnchorRefs {
        std::set<addr_t> functions;
        std::string      source;
    };

    std::map<std::string, AnchorRefs> refs_by_name;
    for (const auto& s : strings) {
        if (s.xrefs.empty()) continue;
        auto name = luau_anchor_name_from_string(s.text);
        if (!name) continue;
        auto& refs = refs_by_name[*name];
        if (refs.source.empty()) refs.source = s.text;
        for (addr_t xr : s.xrefs) {
            if (auto fn = enclosing_function(xr)) refs.functions.insert(*fn);
        }
    }

    std::map<addr_t, std::set<std::string>> names_by_function;
    std::map<std::string, std::string> source_by_name;
    for (const auto& [name, refs] : refs_by_name) {
        if (refs.functions.size() != 1) continue;
        const addr_t fn = *refs.functions.begin();
        names_by_function[fn].insert(name);
        source_by_name.emplace(name, refs.source);
    }

    for (const auto& [fn, names] : names_by_function) {
        std::string name;
        std::string source;
        if (names.size() == 1) {
            name = *names.begin();
            source = source_by_name[name];
        } else if (auto collapsed = collapse_luau_anchor_family(names)) {
            name = *collapsed;
            source = std::format("{} Luau anchors", names.size());
        } else {
            continue;
        }
        if (seen.emplace(fn, name).second) {
            out.push_back({fn, std::move(name), std::move(source)});
        }
    }
}

[[nodiscard]] std::map<SsaKey, const IrInst*>
index_defs(const IrFunction& fn) {
    std::map<SsaKey, const IrInst*> out;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst)) out.emplace(*k, &inst);
        }
    }
    return out;
}

[[nodiscard]] std::optional<std::string>
resolve_string_value(const Binary& b,
                     const std::map<SsaKey, const IrInst*>& defs,
                     IrValue v,
                     int depth = 0) {
    if (depth > 10) return std::nullopt;
    for (int hop = 0; hop < 10; ++hop) {
        if (v.kind == IrValueKind::Imm) {
            auto s = read_cstring_local(b, static_cast<addr_t>(v.imm));
            if (!s.empty()) return s;
            return std::nullopt;
        }
        auto k = ssa_key(v);
        if (!k) return std::nullopt;
        auto it = defs.find(*k);
        if (it == defs.end()) return std::nullopt;
        const IrInst* d = it->second;
        if ((d->op == IrOp::Assign || d->op == IrOp::ZExt ||
             d->op == IrOp::SExt || d->op == IrOp::Trunc) &&
            d->src_count == 1) {
            v = d->srcs[0];
            continue;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

void infer_assertion_function_names(const Binary& b,
                                    std::span<const DiscoveredFunction> fns,
                                    std::vector<StringNameCandidate>& out,
                                    std::set<std::pair<addr_t, std::string>>& seen) {
    if (!has_function_name_assert_import(b)) return;

    auto dec_r = make_decoder(b);
    if (!dec_r) return;
    auto lifter_r = make_lifter(b);
    if (!lifter_r) return;

    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    const SsaBuilder ssa;

    for (const auto& fn : fns) {
        if (fn.size == 0 || b.import_at_plt(fn.addr) != nullptr) continue;
        auto cfg_r = builder.build(fn.addr, fn.name);
        if (!cfg_r) continue;
        auto ir_r = (*lifter_r)->lift(*cfg_r);
        if (!ir_r) continue;
        if (auto rv = ssa.convert(*ir_r); !rv) continue;
        if (auto rv = run_cleanup(*ir_r); !rv) continue;

        const auto defs = index_defs(*ir_r);
        for (const auto& bb : ir_r->blocks) {
            std::vector<IrValue> args;
            args.reserve(kMaxAbiIntArgs);
            for (const auto& inst : bb.insts) {
                if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                    args.clear();
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op == IrOp::Intrinsic &&
                    (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                        args.push_back(inst.srcs[i]);
                    }
                    continue;
                }
                if (inst.op != IrOp::Call) continue;
                const Symbol* s = b.import_at_plt(inst.target1);
                if (!s) {
                    args.clear();
                    continue;
                }
                auto idx = function_name_arg_index(clean_import_name_local(s->name));
                if (!idx || *idx >= args.size()) {
                    args.clear();
                    continue;
                }
                auto raw = resolve_string_value(b, defs, args[*idx]);
                if (!raw) {
                    args.clear();
                    continue;
                }
                auto name = sanitize_name(*raw);
                if (!name.empty() && seen.emplace(fn.addr, name).second) {
                    out.push_back({fn.addr, std::move(name), *raw});
                }
                args.clear();
            }
        }
    }
}

}  // namespace

std::vector<StringNameCandidate>
infer_function_names_from_strings(const Binary &b, StringNameInferenceOptions options) {
    ScopedTimer timer("strings.infer_names");
    std::vector<StringNameCandidate> out;
    std::set<std::pair<addr_t, std::string>> seen;
    std::vector<DiscoveredFunction> fns;
    {
        ScopedTimer phase("strings.enumerate_functions");
        fns = enumerate_functions(b, EnumerateMode::Cheap);
    }
    std::map<addr_t, std::size_t> function_sizes;
    for (const auto& fn : fns) function_sizes.emplace(fn.addr, fn.size);
    auto enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        auto it =
            std::upper_bound(fns.begin(), fns.end(), addr,
                             [](addr_t a, const DiscoveredFunction &d) { return a < d.addr; });
        if (it == fns.begin())
            return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size)
            return std::nullopt;
        if (it->size == 0) {
            auto next = it;
            ++next;
            if (next != fns.end() && addr >= next->addr)
                return std::nullopt;
        }
        if (b.bytes_at(it->addr).empty())
            return std::nullopt;
        return it->addr;
    };
    auto luau_enclosing_function = [&](addr_t addr) -> std::optional<addr_t> {
        auto fn = enclosing_function(addr);
        if (!fn) return std::nullopt;
        const auto it = function_sizes.find(*fn);
        if (it != function_sizes.end() && it->second > 1024 * 1024) return std::nullopt;
        return fn;
    };
    std::vector<StringEntry> strings;
    {
        ScopedTimer phase("strings.scan");
        strings = scan_strings_impl(b, {}, fns, true);
    }
    {
        ScopedTimer phase("strings.graphics_proc_loader");
        struct ProcVotes {
            std::set<std::string> gl;
            std::set<std::string> vk;
        };
        std::map<addr_t, ProcVotes> proc_votes;
        for (const auto &s : strings) {
            if (!s.xrefs.empty() && is_graphics_api_ident(s.text)) {
                for (addr_t xr : s.xrefs) {
                    if (auto fn = enclosing_function(xr)) {
                        auto &votes = proc_votes[*fn];
                        if (s.text.starts_with("gl"))
                            votes.gl.insert(s.text);
                        else if (s.text.starts_with("vk"))
                            votes.vk.insert(s.text);
                    }
                }
            }
        }
        for (const auto &[fn, votes] : proc_votes) {
            if (votes.gl.size() >= 12 && seen.emplace(fn, "graphics_gl_proc_loader").second) {
                out.push_back({fn, "graphics_gl_proc_loader",
                               std::format("{} OpenGL proc names", votes.gl.size())});
            } else if (votes.vk.size() >= 8 && seen.emplace(fn, "graphics_vk_proc_loader").second) {
                out.push_back({fn, "graphics_vk_proc_loader",
                               std::format("{} Vulkan proc names", votes.vk.size())});
            }
        }
    }
    {
        ScopedTimer phase("strings.lua_registration");
        infer_lua_registration_names(b, strings, out, seen);
    }
    {
        ScopedTimer phase("strings.reflection_members");
        infer_reflection_member_names(strings, enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.generic_candidates");
        for (const auto &s : strings) {
            if (s.xrefs.empty())
                continue;
            auto name = candidate_name_from_string(s.text);
            if (!name || name->empty())
                continue;
            std::set<addr_t> referencing_fns;
            for (addr_t xr : s.xrefs) {
                if (auto fn = enclosing_function(xr))
                    referencing_fns.insert(*fn);
            }
            for (addr_t fn : referencing_fns) {
                if (seen.emplace(fn, *name).second) {
                    out.push_back({fn, *name, s.text});
                }
            }
        }
    }
    if (options.assertion_names &&
        (options.max_assertion_functions == 0 || fns.size() <= options.max_assertion_functions)) {
        ScopedTimer phase("strings.assertion_names");
        infer_assertion_function_names(b, fns, out, seen);
    }
    {
        ScopedTimer phase("strings.luau_metadata_anchors");
        infer_luau_metadata_anchors(strings, luau_enclosing_function, out, seen);
    }
    {
        ScopedTimer phase("strings.role_identifier_anchors");
        infer_role_identifier_anchors(strings, enclosing_function, out, seen);
    }
    return out;
}

namespace {

[[nodiscard]] bool looks_like_log_category(std::string_view s) noexcept {
    if (s.size() < 4 || s.size() > 96) return false;
    if (s.find("::") == std::string_view::npos) return false;
    bool alpha = false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalpha(u)) alpha = true;
        if (!(std::isalnum(u) || c == '_' || c == ':' || c == '.' || c == '-')) {
            return false;
        }
    }
    return alpha;
}

[[nodiscard]] std::vector<std::string>
extract_log_categories(std::string_view text) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while ((pos = text.find('[', pos)) != std::string_view::npos) {
        const std::size_t end = text.find(']', pos + 1);
        if (end == std::string_view::npos) break;
        const std::string_view inside = text.substr(pos + 1, end - pos - 1);
        if (looks_like_log_category(inside)) {
            out.emplace_back(inside);
        }
        pos = end + 1;
    }
    return out;
}

}  // namespace

std::vector<LogCategoryCluster>
mine_log_categories(const Binary& b) {
    struct Accum {
        std::set<addr_t> functions;
        std::vector<std::string> examples;
        std::set<std::string> seen_examples;
    };
    std::map<std::string, Accum> by_category;
    struct CategoryString {
        std::string text;
        std::vector<std::string> categories;
    };
    std::map<addr_t, CategoryString> category_strings;

    std::vector<StringEntry> strings;
    for (const auto& sec : b.sections()) {
        scan_section(sec, strings, {});
    }
    for (auto& s : strings) {
        auto categories = extract_log_categories(s.text);
        if (categories.empty()) continue;
        category_strings.emplace(s.addr, CategoryString{
            .text = std::move(s.text),
            .categories = std::move(categories),
        });
    }
    if (category_strings.empty()) return {};

    if (b.arch() == Arch::X86_64) {
        struct WorkItem { addr_t addr; u64 size; };
        std::vector<WorkItem> work;
        std::unordered_set<addr_t> seen;
        for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
            if (b.import_at_plt(fn.addr) != nullptr) continue;
            if (fn.size == 0) continue;
            if (!seen.insert(fn.addr).second) continue;
            work.push_back({fn.addr, fn.size});
        }

        X64Decoder dec;
        for (const auto& w : work) {
            auto span = b.bytes_at(w.addr);
            if (span.empty()) continue;
            const std::size_t limit = std::min<std::size_t>(
                span.size(), static_cast<std::size_t>(w.size));

            addr_t ip = w.addr;
            std::size_t off = 0;
            while (off < limit) {
                auto remaining = span.subspan(off, limit - off);
                auto decoded = dec.decode(remaining, ip);
                if (!decoded) { ip += 1; off += 1; continue; }
                const auto& insn = *decoded;

                for (u8 j = 0; j < insn.num_operands; ++j) {
                    const Operand& op = insn.operands[j];
                    addr_t candidate = 0;
                    bool have = false;
                    if (op.kind == Operand::Kind::Relative) {
                        candidate = op.rel.target;
                        have = true;
                    } else if (op.kind == Operand::Kind::Memory && op.mem.has_disp) {
                        if (op.mem.base == Reg::Rip && op.mem.index == Reg::None) {
                            candidate = ip + insn.length +
                                        static_cast<addr_t>(op.mem.disp);
                            have = true;
                        } else if (op.mem.base == Reg::None &&
                                   op.mem.index == Reg::None) {
                            candidate = static_cast<addr_t>(op.mem.disp);
                            have = true;
                        }
                    } else if (op.kind == Operand::Kind::Immediate &&
                               op.imm.size >= 4) {
                        candidate = static_cast<addr_t>(op.imm.value);
                        have = true;
                    }
                    if (!have) continue;
                    auto it = category_strings.find(candidate);
                    if (it == category_strings.end()) continue;
                    for (const auto& cat : it->second.categories) {
                        auto& acc = by_category[cat];
                        acc.functions.insert(w.addr);
                        if (acc.examples.size() < 3 &&
                            acc.seen_examples.insert(it->second.text).second) {
                            acc.examples.push_back(it->second.text);
                        }
                    }
                }

                ip  += insn.length;
                off += insn.length;
            }
        }
    } else {
        for (const auto& [_, s] : category_strings) {
            for (const auto& cat : s.categories) {
                auto& acc = by_category[cat];
                if (acc.examples.size() < 3 &&
                    acc.seen_examples.insert(s.text).second) {
                    acc.examples.push_back(s.text);
                }
            }
        }
    }

    std::vector<LogCategoryCluster> out;
    out.reserve(by_category.size());
    for (auto& [cat, acc] : by_category) {
        LogCategoryCluster c;
        c.category = std::move(cat);
        c.functions.assign(acc.functions.begin(), acc.functions.end());
        c.examples = std::move(acc.examples);
        out.push_back(std::move(c));
    }
    std::ranges::sort(out, [](const auto& lhs, const auto& rhs) {
        if (lhs.functions.size() != rhs.functions.size()) {
            return lhs.functions.size() > rhs.functions.size();
        }
        return lhs.category < rhs.category;
    });
    return out;
}

}  // namespace ember
