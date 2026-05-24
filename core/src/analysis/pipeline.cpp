#include <ember/analysis/pipeline.hpp>
#include <ember/common/threads.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <format>
#include <mutex>
#include <optional>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ember/analysis/discovery.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/name_resolver.hpp>
#include <ember/analysis/objc.hpp>
#include <ember/analysis/packed.hpp>
#include <ember/analysis/rtti.hpp>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/import_sigs.hpp>
#include <ember/analysis/type_infer_local.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/progress.hpp>
#include <ember/common/timing.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/disasm/register.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

namespace ember {

namespace {

// Stops the linear-walk fallback at unconditional flow exits - the
// shape we need is "control doesn't fall through past this insn".
// Conditional branches stay out of this set: the next byte after a
// `je rel32` is a real instruction. Multi-arch coverage piggybacks on
// the public classifiers so a Mnemonic added there (A64Ret, etc.) is
// automatically picked up here without a duplicate switch to keep in
// sync. Without this, ARM64 functions whose size we don't know walked
// straight past `ret` and emitted whatever followed in the section.
bool is_terminator(Mnemonic m) noexcept {
    return is_unconditional_jmp(m) || is_return_like(m);
}

std::string hex_bytes(std::span<const std::byte> b) {
    std::string s;
    s.reserve(b.size() * 3);
    for (const auto byte : b) {
        s += std::format("{:02x} ", static_cast<u8>(byte));
    }
    if (!s.empty()) s.pop_back();
    return s;
}

// How far to advance after a decode failure. The old behaviour was
// always 1, which routinely misdecoded the ModR/M byte of a failed
// 0x0F-escaped opcode as a fresh one-byte instruction (`0f 57 c0`
// became "decode error + push rdi"). Prefixes and the two-byte escape
// aren't themselves a valid instruction start - skipping them avoids
// seeing them twice. VEX/EVEX take a wider swath because their payload
// bytes are drawn from a very different opcode space; one cautious
// forward jump is better than a multi-instruction cascade.
std::size_t decode_failure_advance(Arch arch, std::span<const std::byte> bytes) noexcept {
    if (arch == Arch::Ppc32 || arch == Arch::Ppc64) return std::min<std::size_t>(4, bytes.size());
    std::size_t i = 0;
    // Walk legacy prefixes. There are at most ~4 in practice; cap at 15
    // to match the architecture's maximum instruction length.
    while (i < bytes.size() && i < 15) {
        const u8 b = static_cast<u8>(bytes[i]);
        const bool is_prefix =
            b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 ||
            b == 0xF0 || b == 0xF2 || b == 0xF3;
        if (!is_prefix) break;
        ++i;
    }
    if (i >= bytes.size()) return std::max<std::size_t>(i, 1);
    u8 lead = static_cast<u8>(bytes[i]);
    // REX byte (0x40–0x4F). Transparent to opcode dispatch.
    if ((lead & 0xF0) == 0x40) {
        ++i;
        if (i >= bytes.size()) return std::max<std::size_t>(i, 1);
        lead = static_cast<u8>(bytes[i]);
    }
    // 0x0F two-byte escape: skip escape + next opcode byte.
    if (lead == 0x0F) {
        i += std::min<std::size_t>(2, bytes.size() - i);
        return std::max<std::size_t>(i, 1);
    }
    // VEX (0xC5: 2-byte, 0xC4: 3-byte) and EVEX (0x62: 4-byte). In
    // 64-bit code these always carry a full opcode payload after the
    // prefix. Advance past the whole prefix body + one opcode byte.
    if (lead == 0xC5) {
        i += std::min<std::size_t>(3, bytes.size() - i);  // C5 + payload + opcode
        return std::max<std::size_t>(i, 1);
    }
    if (lead == 0xC4) {
        i += std::min<std::size_t>(4, bytes.size() - i);  // C4 + 2 payload + opcode
        return std::max<std::size_t>(i, 1);
    }
    if (lead == 0x62) {
        i += std::min<std::size_t>(5, bytes.size() - i);  // 62 + 3 payload + opcode
        return std::max<std::size_t>(i, 1);
    }
    // Plain one-byte opcode: skip it.
    return std::max<std::size_t>(i + 1, 1);
}

std::optional<addr_t> rip_relative_target(const Instruction& insn) noexcept {
    const addr_t end = insn.address + insn.length;
    for (std::size_t i = 0; i < insn.num_operands; ++i) {
        const Operand& op = insn.operands[i];
        if (op.kind != Operand::Kind::Memory) continue;
        const Mem& m = op.mem;
        if (m.base == Reg::Rip && m.index == Reg::None) {
            return end + static_cast<u64>(m.disp);
        }
    }
    return std::nullopt;
}

// String literal at `addr` if the bytes there are NUL-terminated printable
// ASCII (≥ kMin chars). Result is escaped for inline-comment safety and
// truncated at kMax chars with an ellipsis. Conservative on purpose - a
// false positive shows up as junk in the comment column, so we require
// strict printable-only and a hard min length.
[[nodiscard]] std::optional<std::string>
disasm_string_at(const Binary& b, addr_t addr) {
    auto span = b.bytes_at(addr);
    if (span.empty()) return std::nullopt;
    constexpr std::size_t kMin = 4;
    constexpr std::size_t kMax = 48;
    const std::size_t lim = std::min(span.size(), kMax + 1);
    std::string s;
    s.reserve(kMax);
    bool terminated = false;
    std::size_t i = 0;
    for (; i < lim; ++i) {
        const auto c = static_cast<unsigned char>(span[i]);
        if (c == 0) { terminated = true; break; }
        if (i >= kMax) break;
        if (c == '\t') { s += "\\t"; continue; }
        if (c == '\n') { s += "\\n"; continue; }
        if (c == '\r') { s += "\\r"; continue; }
        if (c == '\\') { s += "\\\\"; continue; }
        if (c == '"')  { s += "\\\""; continue; }
        if (c < 0x20 || c > 0x7e) return std::nullopt;
        s.push_back(static_cast<char>(c));
    }
    if (!terminated && i < kMax) return std::nullopt;
    if (s.size() < kMin) return std::nullopt;
    if (!terminated) s += "...";
    return s;
}

std::string format_instruction_annotated(const Binary& b, const Instruction& insn) {
    std::string text = format_instruction(insn);
    std::optional<addr_t> target;
    if (is_call(insn.mnemonic) || is_unconditional_jmp(insn.mnemonic) ||
        is_conditional_branch(insn.mnemonic)) {
        target = branch_target(insn);
    }
    if (!target) target = rip_relative_target(insn);
    if (!target) return text;
    if (auto label = resolve_address_name(b, *target); label) {
        text += std::format("  ; {}", format_address_comment(*label));
        return text;
    }
    // No symbol at the target - see if it's a string literal. RIP-relative
    // loads of `.rodata` strings are extremely common; surfacing them
    // turns `lea rdi, [rip+0x1234]` into an actually-readable line.
    if (auto s = disasm_string_at(b, *target); s) {
        text += std::format("  ; \"{}\"", *s);
    }
    return text;
}

void append_function_text(std::string& out, const Binary& b, const Function& fn) {
    out += std::format("function {}\n", fn.name.empty() ? "<unknown>" : fn.name);
    out += std::format("  entry    {:#018x}\n", fn.start);
    out += std::format("  extent   {:#018x} - {:#018x}  ({} bytes)\n",
                       fn.start, fn.end, fn.end - fn.start);
    out += std::format("  blocks   {}\n", fn.blocks.size());
    out += std::format("  edges    {}\n", fn.edge_count());
    out += std::format("  calls    {}\n", fn.call_targets.size());
    out += "\n";

    for (const auto& bb : fn.blocks) {
        std::string header = std::format("bb_{:x}", bb.start);
        if (bb.start == fn.start) header += "  (entry)";
        if (!bb.predecessors.empty()) {
            header += "  <-";
            for (addr_t p : bb.predecessors) header += std::format(" bb_{:x}", p);
        }
        out += header + ":\n";

        for (const auto& insn : bb.instructions) {
            const auto bytes = std::span<const std::byte>(
                insn.raw_bytes.data(), insn.length);
            out += std::format("  {:#018x}  {:<30}  {}\n",
                               insn.address, hex_bytes(bytes),
                               format_instruction_annotated(b, insn));
        }

        switch (bb.kind) {
            case BlockKind::Return:
                out += "  -> <return>\n";
                break;
            case BlockKind::TailCall:
                if (!bb.successors.empty())
                    out += std::format("  -> {:#x}  (tail-call)\n", bb.successors[0]);
                break;
            case BlockKind::Conditional:
                if (bb.successors.size() >= 2) {
                    out += std::format("  -> bb_{:x}  (taken)\n", bb.successors[0]);
                    out += std::format("  -> bb_{:x}  (fallthrough)\n", bb.successors[1]);
                } else if (bb.successors.size() == 1) {
                    out += std::format("  -> bb_{:x}  (fallthrough; taken out-of-range)\n",
                                       bb.successors[0]);
                }
                break;
            case BlockKind::Unconditional:
            case BlockKind::Fallthrough:
                if (!bb.successors.empty())
                    out += std::format("  -> bb_{:x}\n", bb.successors[0]);
                break;
            case BlockKind::IndirectJmp:
                out += "  -> <indirect>\n";
                break;
            case BlockKind::Switch: {
                const std::size_t ncases = bb.case_values.size();
                for (std::size_t i = 0; i < ncases; ++i) {
                    out += std::format("  -> bb_{:x}  (case {})\n",
                                       bb.successors[i], bb.case_values[i]);
                }
                if (bb.has_default && !bb.successors.empty())
                    out += std::format("  -> bb_{:x}  (default)\n", bb.successors.back());
                break;
            }
        }
        out += "\n";
    }

    if (!fn.call_targets.empty()) {
        out += "calls:\n";
        for (auto t : fn.call_targets) out += std::format("  -> {:#x}\n", t);
    }
}

FuncWindow window_from_addr(addr_t start, u64 size_hint, std::string label) {
    FuncWindow w;
    w.start = start;
    w.size  = size_hint;
    w.label = std::move(label);
    return w;
}

std::span<const std::byte>
clamp_bytes(std::span<const std::byte> avail, u64 size) {
    if (avail.empty()) return avail;
    const u64 take = size > 0 ? std::min<u64>(size, avail.size())
                              : std::min<u64>(1024, avail.size());
    return avail.first(static_cast<std::size_t>(take));
}

}  // namespace

namespace {

// Try to parse `s` as a hex VA. Accepts `0x...`, `0X...`, or `sub_...`
// only - bare hex strings collide with legitimate symbol names like
// `add32`, so we require an explicit prefix.
[[nodiscard]] std::optional<addr_t> try_parse_va(std::string_view s) {
    if (s.starts_with("sub_"))          s.remove_prefix(4);
    else if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
    else return std::nullopt;
    if (s.empty() || s.size() > 16) return std::nullopt;
    u64 v = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) return std::nullopt;
    return static_cast<addr_t>(v);
}

// Find the Obj-C IMP matching a `-[Class sel]` / `+[Class sel]` string.
[[nodiscard]] std::optional<addr_t>
try_parse_objc_bracket(const Binary& b, std::string_view s) {
    if (s.size() < 4) return std::nullopt;
    const char sign = s.front();
    if (sign != '-' && sign != '+') return std::nullopt;
    if (s[1] != '[' || s.back() != ']') return std::nullopt;
    const auto inner = s.substr(2, s.size() - 3);
    const auto sp = inner.find(' ');
    if (sp == std::string_view::npos) return std::nullopt;
    const auto cls_name = inner.substr(0, sp);
    const auto sel      = inner.substr(sp + 1);
    const bool want_class = (sign == '+');
    for (const auto& m : parse_objc_methods(b)) {
        if (m.cls == cls_name && m.selector == sel &&
            m.is_class == want_class && m.imp != 0) {
            return m.imp;
        }
    }
    return std::nullopt;
}

// True when EMBER_QUIET=1 - the CLI sets this for --quiet, and we honour
// it for one-shot diagnostics too so a `--quiet` invocation produces no
// stderr noise even when -s lands mid-function.
[[nodiscard]] bool diagnostics_silenced() noexcept {
    const char* q = std::getenv("EMBER_QUIET");
    return q && q[0] == '1';
}

void note_mid_function(addr_t addr, std::string_view name, u64 off) {
    if (diagnostics_silenced()) return;
    std::fprintf(stderr,
        "ember: note: %#llx is inside %.*s at +%#llx\n",
        static_cast<unsigned long long>(addr),
        static_cast<int>(name.size()), name.data(),
        static_cast<unsigned long long>(off));
}

[[nodiscard]] std::optional<FuncWindow>
exact_discovered_function(const Binary& b, addr_t addr, EnumerateMode mode) {
    for (const auto& fn : enumerate_functions(b, mode)) {
        if (fn.addr != addr) continue;
        if (b.bytes_at(addr).empty()) return std::nullopt;
        return window_from_addr(fn.addr, fn.size, fn.name);
    }
    return std::nullopt;
}

// Resolve `addr` to the nearest containing function entry. Uses the
// defined-objects cache for an O(log n) lookup. Returns a FuncWindow
// whose `start` is the function entry (NOT `addr` itself) when `addr`
// lies inside a known function's extent; the label carries the offset
// so the caller can annotate the output. Nullopt when nothing contains
// `addr` and `addr` itself has no bytes mapped.
[[nodiscard]] std::optional<FuncWindow>
resolve_containing_function(const Binary& b, addr_t addr) {
    // Exact-addr Function symbol wins outright before the containing-
    // function logic kicks in. Covers two cases that defined_object_at
    // misses because it filters size==0 entries:
    //   - synthesized sub_<hex> stubs (no size known)
    //   - --force-fn-start overrides (user says "this VA is a function
    //     entry" so don't rebind to the closest-below symbol)
    for (const auto& s : b.symbols()) {
        if (s.addr == addr && s.kind == SymbolKind::Function && !s.is_import) {
            if (b.bytes_at(addr).empty()) return std::nullopt;
            return window_from_addr(addr, s.size, s.name);
        }
    }
    if (auto exact = exact_discovered_function(b, addr, EnumerateMode::Cheap); exact) {
        return exact;
    }
    const Symbol* c = b.defined_object_at(addr);
    if (c && c->kind == SymbolKind::Function && c->addr != 0) {
        if (b.bytes_at(c->addr).empty()) return std::nullopt;
        if (c->addr == addr) {
            return window_from_addr(c->addr, c->size, c->name);
        }
        const u64 off = addr - c->addr;
        if (c->size == 0 || off < c->size) {
            note_mid_function(addr, c->name, off);
            return window_from_addr(c->addr, c->size,
                                    std::format("{}+{:#x}", c->name, off));
        }
    }
    if (b.bytes_at(addr).empty()) return std::nullopt;
    // Fall back to the broader function index (CFG-discovered `sub_*`
    // entries that aren't in the symbol table). When the literal VA
    // lands mid-`sub_*` we still want the same offset note + entry-
    // anchored window the named branch produces - otherwise `-s 0xVA`
    // on a hex literal in the middle of a discovered function silently
    // disasms from the wrong instruction boundary.
    if (auto exact = exact_discovered_function(b, addr, EnumerateMode::Auto); exact) {
        return exact;
    }
    if (auto cf = containing_function(b, addr); cf && cf->entry != addr) {
        note_mid_function(addr, cf->name, cf->offset_within);
        return window_from_addr(cf->entry, cf->size,
            std::format("{}+{:#x}", cf->name, cf->offset_within));
    }
    if (!addr_in_code_section(b, addr)) return std::nullopt;
    return window_from_addr(addr, 0, std::format("sub_{:x}", addr));
}

}  // namespace

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol,
                 const Annotations* ann) {
    // Obj-C bracket form: -[Class sel] / +[Class sel] - look up the IMP
    // in the classlist, then resolve by VA.
    if (!symbol.empty() && (symbol.front() == '-' || symbol.front() == '+') &&
        symbol.size() > 1 && symbol[1] == '[') {
        if (auto addr = try_parse_objc_bracket(b, symbol); addr) {
            return resolve_containing_function(b, *addr);
        }
    }
    // Hex VA / sub_<hex> form: jump straight to VA-driven resolution so a
    // mid-function address gets resolved to its container rather than
    // silently failing.
    if (auto va = try_parse_va(symbol); va) {
        // `sub_<hex>` is the canonical name for a discovered function
        // entry. When the user types it explicitly, treat the address
        // as its own entry - even if a separate `sub_*` candidate's
        // closest-below container also covers it. Without this guard,
        // call targets that the prologue scan misses (because they
        // sit inside a larger prologue-detected blob) get rebound to
        // the container and rendered at offset +N, when the user
        // clearly meant the call target itself.
        const bool explicit_entry = symbol.starts_with("sub_");
        if (explicit_entry) {
            if (b.bytes_at(*va).empty() || !addr_in_code_section(b, *va)) {
                std::fprintf(stderr,
                    "ember: address %#llx is not in any code section "
                    "(or the bytes there are not mapped)\n",
                    static_cast<unsigned long long>(*va));
                return std::nullopt;
            }
            if (auto cf = containing_function(b, *va); cf && cf->entry == *va) {
                return window_from_addr(cf->entry, cf->size, cf->name);
            }
            return window_from_addr(*va, 0, std::format("sub_{:x}", *va));
        }
        auto win = resolve_containing_function(b, *va);
        if (!win) {
            // Common when --functions / call-graph discovery surfaces a
            // garbage indirect-jmp target on obfuscated binaries; the
            // address isn't in any mapped section so nothing decodes.
            std::fprintf(stderr,
                "ember: address %#llx is not in any mapped section "
                "(or the bytes there don't decode as code)\n",
                static_cast<unsigned long long>(*va));
        }
        return win;
    }

    const std::string_view lookup = symbol.empty() ? "main" : symbol;
    const Symbol* chosen = b.find_by_name(lookup);
    if (chosen && chosen->is_import) chosen = nullptr;
    if (!symbol.empty() && chosen && chosen->is_import) chosen = nullptr;

    if (chosen) {
        // Fingerprint import and user renames can silently bind the same
        // name to multiple addresses. Refuse the lookup rather than
        // picking the first - a wrong-address answer presents as phantom
        // bugs downstream.
        const auto all = b.find_all_by_name(lookup);
        if (all.size() > 1) {
            std::fprintf(stderr,
                "ember: name '%.*s' is ambiguous - matches %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), all.size());
            const std::size_t shown = std::min<std::size_t>(all.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(all[i]->addr));
            }
            if (all.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    all.size() - shown);
            }
            std::fprintf(stderr,
                "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (b.bytes_at(chosen->addr).empty()) {
            std::fprintf(stderr,
                "ember: symbol '%.*s' at %#llx has no mapped bytes\n",
                static_cast<int>(lookup.size()), lookup.data(),
                static_cast<unsigned long long>(chosen->addr));
            return std::nullopt;
        }
        return window_from_addr(chosen->addr, chosen->size, chosen->name);
    }

    // Annotation-rename fallback: a name typed by the user that doesn't
    // match the binary symbol table may match a `rename` record in the
    // resolved annotations file. Without this, freshly-named functions
    // (`ember annotate ADDR --set-name X`) wouldn't be reachable via
    // `-s X` until the user remembered the original `sub_<hex>` form.
    if (ann && !symbol.empty()) {
        std::vector<addr_t> hits;
        hits.reserve(2);
        for (const auto& [addr, name] : ann->renames) {
            if (name == lookup) hits.push_back(addr);
        }
        if (hits.size() > 1) {
            std::fprintf(stderr,
                "ember: rename '%.*s' is ambiguous - bound to %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), hits.size());
            const std::size_t shown = std::min<std::size_t>(hits.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(hits[i]));
            }
            if (hits.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    hits.size() - shown);
            }
            std::fprintf(stderr,
                "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (hits.size() == 1) {
            const addr_t a = hits.front();
            if (b.bytes_at(a).empty()) {
                std::fprintf(stderr,
                    "ember: rename '%.*s' resolves to %#llx but no bytes are mapped there\n",
                    static_cast<int>(lookup.size()), lookup.data(),
                    static_cast<unsigned long long>(a));
                return std::nullopt;
            }
            // Width unknown without lifting; window_from_addr's 0-size
            // fallback uses the terminator scan, same shape as the
            // sub_<hex> case.
            return window_from_addr(a, 0, std::string(lookup));
        }
    }

    if (!symbol.empty()) {
        std::vector<DiscoveredFunction> hits;
        for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
            if (fn.name == lookup) hits.push_back(fn);
            if (hits.size() > 5) break;
        }
        if (hits.size() > 1) {
            std::fprintf(stderr,
                "ember: discovered name '%.*s' is ambiguous - matches %zu addresses:",
                static_cast<int>(lookup.size()), lookup.data(), hits.size());
            const std::size_t shown = std::min<std::size_t>(hits.size(), 5);
            for (std::size_t i = 0; i < shown; ++i) {
                std::fprintf(stderr, " %#llx",
                    static_cast<unsigned long long>(hits[i].addr));
            }
            if (hits.size() > shown) {
                std::fprintf(stderr, " ... (+%zu more)",
                    hits.size() - shown);
            }
            std::fprintf(stderr, "; pass the VA (0x…) to pick one\n");
            return std::nullopt;
        }
        if (hits.size() == 1) {
            return window_from_addr(hits.front().addr, hits.front().size,
                                    hits.front().name);
        }
    }

    if (!symbol.empty()) {
        std::fprintf(stderr,
            "ember: no symbol named '%.*s'\n",
            static_cast<int>(lookup.size()), lookup.data());
        return std::nullopt;
    }

    const addr_t entry = b.entry_point();
    if (b.bytes_at(entry).empty()) return std::nullopt;
    return window_from_addr(entry, 0, "<entry>");
}

std::optional<FuncWindow>
resolve_function_at(const Binary& b, addr_t addr) {
    return resolve_containing_function(b, addr);
}

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w) {
    auto avail = b.bytes_at(w.start);
    if (avail.empty()) {
        return std::unexpected(Error::invalid_format(
            std::format("no bytes mapped at {:#x}", w.start)));
    }
    auto bytes = clamp_bytes(avail, w.size);

    std::string out = std::format(
        "; disassembly of {} at {:#018x} ({} bytes)\n",
        w.label, w.start, bytes.size());

    // Xref summary: who calls this function. Costs one call-graph walk on
    // first invocation (~1s on a 12k-fn binary), but the result reads as a
    // jump-off point - `; xrefs from: foo, bar, baz (+12 more)` saves the
    // common "open disasm, then go grep callers separately" round trip.
    if (const auto callers = compute_callers(b, w.start); !callers.empty()) {
        constexpr std::size_t kMaxShown = 8;
        const std::size_t shown = std::min(callers.size(), kMaxShown);
        std::string line = ";   xrefs from: ";
        for (std::size_t i = 0; i < shown; ++i) {
            if (i > 0) line += ", ";
            if (auto r = resolve_address_name(b, callers[i]); r) {
                line += r->name;
            } else {
                line += std::format("sub_{:x}", callers[i]);
            }
        }
        if (callers.size() > kMaxShown) {
            line += std::format(" (+{} more)", callers.size() - kMaxShown);
        }
        line += '\n';
        out += line;
    }

    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    addr_t ip = w.start;
    std::size_t off = 0;
    // FuncWindow contract: size != 0 means the caller has a reliable
    // extent (real symbol or CFG-built range), so walk all of it. Earlier
    // this also gated on `size < 1024`, which had the perverse effect of
    // truncating large functions at their first jmp/ret - e.g. `main`
    // in /usr/bin/git stopping after 13% of its 5435 bytes.
    const bool size_known = w.size != 0;

    // Padding-run collapse. MSVC/clang frequently align function exits and
    // sled gaps with runs of `cc` (Int3) or `90` (Nop). One line per byte
    // makes a 32-byte gap fill a screen; collapse runs of ≥ kPadCollapse
    // identical pad bytes into a single line.
    constexpr std::size_t kPadCollapse = 3;
    addr_t pad_start = 0;
    std::size_t pad_count = 0;
    Mnemonic pad_kind = Mnemonic::Nop;  // unused while pad_count == 0
    auto flush_padding = [&] {
        if (pad_count == 0) return;
        const char* name = (pad_kind == Mnemonic::Int3) ? "int3" : "nop";
        if (pad_count >= kPadCollapse) {
            out += std::format("{:#018x}  {:<30}  ; padding ({} {} bytes)\n",
                               pad_start,
                               std::format("{0:02x} {0:02x} ... x{1}",
                                           static_cast<unsigned>(
                                               pad_kind == Mnemonic::Int3 ? 0xcc : 0x90),
                                           pad_count),
                               pad_count, name);
        } else {
            // Sub-threshold: flush as individual lines so we don't lose info.
            const u8 byte = (pad_kind == Mnemonic::Int3) ? 0xcc : 0x90;
            for (std::size_t k = 0; k < pad_count; ++k) {
                out += std::format("{:#018x}  {:<30}  {}\n",
                                   pad_start + k,
                                   std::format("{:02x}", static_cast<unsigned>(byte)),
                                   name);
            }
        }
        pad_count = 0;
    };

    while (off < bytes.size()) {
        const auto remaining = bytes.subspan(off);
        auto decoded = dec.decode(remaining, ip);
        if (!decoded) {
            flush_padding();
            const std::size_t skip = decode_failure_advance(b.arch(), remaining);
            out += std::format("{:#018x}  {:<30}  ; decode error: {}\n",
                               ip, hex_bytes(remaining.first(std::min(skip, remaining.size()))),
                               decoded.error().message);
            ip  += skip;
            off += skip;
            continue;
        }
        const auto& insn = *decoded;
        const bool is_pad = insn.length == 1 &&
            (insn.mnemonic == Mnemonic::Int3 || insn.mnemonic == Mnemonic::Nop);
        if (is_pad) {
            if (pad_count > 0 && pad_kind == insn.mnemonic) {
                ++pad_count;
            } else {
                flush_padding();
                pad_start = ip;
                pad_kind  = insn.mnemonic;
                pad_count = 1;
            }
        } else {
            flush_padding();
            const auto bv = remaining.first(insn.length);
            out += std::format("{:#018x}  {:<30}  {}\n",
                               ip, hex_bytes(bv), format_instruction_annotated(b, insn));
        }
        ip  += insn.length;
        off += insn.length;
        if (!size_known && is_terminator(insn.mnemonic)) break;
    }
    flush_padding();
    return out;
}

Result<std::string>
format_disasm_range(const Binary& b, addr_t start, addr_t end) {
    if (end <= start) {
        return std::unexpected(Error::invalid_format(
            std::format("disasm range end {:#x} <= start {:#x}", end, start)));
    }
    auto avail = b.bytes_at(start);
    if (avail.empty()) {
        return std::unexpected(Error::invalid_format(
            std::format("no bytes mapped at {:#x}", start)));
    }
    auto bytes = clamp_bytes(avail, end - start);

    std::string out;
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    addr_t ip = start;
    std::size_t off = 0;
    while (off < bytes.size()) {
        const auto remaining = bytes.subspan(off);
        auto decoded = dec.decode(remaining, ip);
        if (!decoded) {
            const std::size_t skip = decode_failure_advance(b.arch(), remaining);
            out += std::format("{:#018x}  {:<30}  ; decode error: {}\n",
                               ip, hex_bytes(remaining.first(std::min(skip, remaining.size()))),
                               decoded.error().message);
            ip  += skip;
            off += skip;
            continue;
        }
        const auto& insn = *decoded;
        const auto bv = remaining.first(insn.length);
        out += std::format("{:#018x}  {:<30}  {}\n",
                           ip, hex_bytes(bv), format_instruction_annotated(b, insn));
        ip  += insn.length;
        off += insn.length;
    }
    return out;
}

Result<std::string>
format_cfg(const Binary& b, const FuncWindow& w) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    auto fn_r = builder.build(w.start, w.label);
    if (!fn_r) return std::unexpected(fn_r.error());
    std::string out;
    append_function_text(out, b, *fn_r);
    return out;
}

Result<std::string>
format_cfg_pseudo(const Binary& b, const FuncWindow& w,
                  const Annotations* ann, EmitOptions options) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    auto fn_r = builder.build(w.start, w.label);
    if (!fn_r) return std::unexpected(fn_r.error());

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return std::unexpected(lifter_r.error());
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return std::unexpected(ir_r.error());

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return std::unexpected(rv.error());
    if (auto rv = run_cleanup(*ir_r); !rv) return std::unexpected(rv.error());
    seed_call_return_types(b, *ir_r);
    infer_local_types(*ir_r);

    // Bypass the structurer entirely. Per-block emission needs the SSA-
    // cleaned IR but explicitly does NOT want regions collapsing block
    // boundaries - that's the whole point of the per-bb view.
    // StructuredFunction holds a non-owning raw IR pointer; the IR
    // itself stays in the local `ir` value for the lifetime of the
    // emit call.
    IrFunction ir = std::move(*ir_r);
    StructuredFunction sf;
    sf.ir   = &ir;
    sf.body = nullptr;

    const PseudoCEmitter emitter;
    auto c_r = emitter.emit_per_block(sf, &b, ann, options);
    if (!c_r) return std::unexpected(c_r.error());
    return std::move(*c_r);
}

Result<std::string>
format_struct(const Binary& b, const FuncWindow& w,
              bool pseudo, const Annotations* ann,
              EmitOptions options) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    if (options.known_function_entries) {
        builder.seed_known_entries(*options.known_function_entries);
    }

    auto fn_r = [&] {
        ScopedTimer t("  cfg_build");
        return builder.build(w.start, w.label);
    }();
    if (!fn_r) return std::unexpected(fn_r.error());

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return std::unexpected(lifter_r.error());
    auto ir_r = [&] {
        ScopedTimer t("  ir_lift");
        return (*lifter_r)->lift(*fn_r);
    }();
    if (!ir_r) return std::unexpected(ir_r.error());

    {
        ScopedTimer t("  ssa_convert");
        const SsaBuilder ssa;
        if (auto rv = ssa.convert(*ir_r); !rv) return std::unexpected(rv.error());
    }

    {
        ScopedTimer t("  cleanup");
        if (auto rv = run_cleanup(*ir_r); !rv) return std::unexpected(rv.error());
    }

    {
        ScopedTimer t("  type_inference");
        seed_call_return_types(b, *ir_r);
        infer_local_types(*ir_r);
    }

    const Structurer structurer;
    auto s_r = [&] {
        ScopedTimer t("  structurer");
        return structurer.structure(*ir_r);
    }();
    if (!s_r) return std::unexpected(s_r.error());

    if (pseudo) {
        ScopedTimer t("  emit");
        const PseudoCEmitter emitter;
        auto c_r = emitter.emit(*s_r, &b, ann, options);
        if (!c_r) return std::unexpected(c_r.error());
        return std::move(*c_r);
    }
    return format_structured(*s_r);
}

std::vector<CallEdge> compute_call_graph(const Binary& b,
                                         std::span<const addr_t> scope,
                                         CallGraphMode mode) {
    ScopedTimer total_timer("call_graph.total");
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;

    // Pre-collect work items so worker threads can binary-walk an
    // index instead of skipping over imports / data symbols.
    struct WorkItem {
        addr_t      addr;
        u64         size;
        std::string name;
    };
    // Always union named symbols with discovered functions. Earlier this
    // gated the discovery walk on `work.empty()`, which only fires on a
    // *fully* stripped binary - anything keeping even one named function
    // (partial strips are common: GNU `strip` leaves dynsym entries; some
    // distros retain a single anchor symbol) would skip discovery and the
    // call graph would contain edges from that handful of named functions
    // only. Symbols are pushed first so the symbol name wins on address
    // collisions with the `sub_<hex>` discovery name. Cheap mode avoids
    // recursing back into compute_call_graph.
    std::vector<WorkItem> work;
    work.reserve(b.symbols().size());
    std::unordered_set<addr_t> seen;
    const std::unordered_set<addr_t> scope_set(scope.begin(), scope.end());
    auto in_scope = [&](addr_t a) noexcept {
        return scope_set.empty() || scope_set.contains(a);
    };
    std::size_t raw_function_symbols = 0;
    std::size_t raw_sized_function_symbols = 0;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        ++raw_function_symbols;
        if (s.size != 0) ++raw_sized_function_symbols;
    }
    const bool distrust_huge_symbol_table =
        mode == CallGraphMode::Fast &&
        raw_function_symbols >= 100000;
    {
        ScopedTimer t("call_graph.worklist");
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.size == 0 || s.name.empty()) continue;
            if (distrust_huge_symbol_table) continue;
            if (!in_scope(s.addr)) continue;
            if (!seen.insert(s.addr).second) continue;
            work.push_back({s.addr, s.size, s.name});
        }
        if (distrust_huge_symbol_table && scope.empty()) {
            for (addr_t a : discover_from_prologues(b)) {
                if (b.import_at_plt(a)) continue;
                if (!seen.insert(a).second) continue;
                work.push_back({a, 0, std::format("sub_{:x}", a)});
            }
        } else {
            for (const auto& fn : enumerate_functions(b, EnumerateMode::Cheap)) {
                if (b.import_at_plt(fn.addr)) continue;
                if (!in_scope(fn.addr)) continue;
                if (!seen.insert(fn.addr).second) continue;
                work.push_back({fn.addr, fn.size, fn.name});
            }
        }
        std::ranges::sort(work, {}, [](const WorkItem& w) { return w.addr; });
        for (std::size_t i = 0; i < work.size(); ++i) {
            auto& w = work[i];
            addr_t section_end = 0;
            for (const auto& s : b.sections()) {
                if (!s.flags.executable) continue;
                if (w.addr < s.vaddr) continue;
                if (w.addr - s.vaddr < s.size) {
                    section_end = s.vaddr + s.size;
                    break;
                }
            }
            addr_t next_entry = section_end;
            for (std::size_t j = i + 1; j < work.size(); ++j) {
                if (section_end != 0 && work[j].addr >= section_end) break;
                if (work[j].addr > w.addr) {
                    next_entry = work[j].addr;
                    break;
                }
            }
            if (next_entry > w.addr) {
                const u64 gap = next_entry - w.addr;
                if (w.size == 0 || w.size > gap) w.size = gap;
            }
        }
    }
    if (work.empty()) return {};

    // CfgBuilder caches per-function unwind ranges in a mutable map
    // and isn't thread-safe; give each worker its own. The Binary +
    // Decoder are read-only and shared.
    const std::size_t total = work.size();
    // Cap at 8: local timings on a 104MB Blender binary showed no win
    // from 16 workers (the CFG walk stayed ~4.35s), while higher caps
    // risk oversubscribing cascades with many ember processes. EMBER_THREADS
    // can still lower this when many passes run concurrently.
    const std::size_t worker_count =
        std::min<std::size_t>(static_cast<std::size_t>(thread_pool_size(8)), total);
    if (timing_enabled()) {
        std::fprintf(stderr, "[timing] call_graph.functions: %zu\n", total);
        std::fprintf(stderr, "[timing] call_graph.threads: %zu\n", worker_count);
    }
    std::unordered_set<addr_t> known_entries;
    known_entries.reserve(work.size());
    for (const auto& w : work) known_entries.insert(w.addr);

    const bool force_cfg_call_graph = mode == CallGraphMode::FullCfg ||
        b.arch() != Arch::X86_64 || [] {
        const char* s = std::getenv("EMBER_CFG_CALL_GRAPH");
        return s != nullptr && *s != '\0' && *s != '0';
    }();

    auto scan_fast = [&](const WorkItem& w, std::vector<CallEdge>& sink) {
        auto span = b.bytes_at(w.addr);
        if (span.empty()) return;
        const std::size_t limit = w.size != 0
            ? std::min<std::size_t>(span.size(), static_cast<std::size_t>(w.size))
            : span.size();
        addr_t ip = w.addr;
        std::size_t off = 0;
        std::unordered_set<addr_t> seen_targets;
        while (off < limit) {
            if (b.is_data_in_code(ip)) {
                ++ip;
                ++off;
                continue;
            }
            auto remaining = span.subspan(off, limit - off);
            auto decoded = dec.decode(remaining, ip);
            if (!decoded) {
                const std::size_t skip = decode_failure_advance(b.arch(), remaining);
                ip += skip;
                off += skip;
                continue;
            }
            const Instruction& insn = *decoded;
            if (is_call(insn.mnemonic)) {
                if (auto target = branch_target(insn); target) {
                    if (seen_targets.insert(*target).second) {
                        sink.push_back({w.addr, *target});
                    }
                }
            } else if (is_unconditional_jmp(insn.mnemonic)) {
                if (auto target = branch_target(insn); target) {
                    if (known_entries.contains(*target) ||
                        b.import_at_plt(*target) != nullptr) {
                        if (seen_targets.insert(*target).second) {
                            sink.push_back({w.addr, *target});
                        }
                    }
                }
            }
            ip  += insn.length;
            off += insn.length;
        }
    };

    if (worker_count <= 1) {
        // Fall back to the simple serial loop. Avoids the thread-spawn
        // overhead on small binaries where it dominates.
        std::vector<CallEdge> out;
        const CfgBuilder builder(b, dec);
        const bool show = total >= 500 && progress_enabled();
        const auto tick = std::max<std::size_t>(1, total / 20);
        std::size_t done = 0;
        {
            ScopedTimer walk_timer(force_cfg_call_graph
                ? "call_graph.cfg_walk"
                : "call_graph.fast_scan");
            for (const auto& w : work) {
                if (force_cfg_call_graph) {
                    auto fn_r = builder.build(w.addr, w.name);
                    if (fn_r) {
                        for (auto target : fn_r->call_targets) out.push_back({w.addr, target});
                    }
                } else {
                    scan_fast(w, out);
                }
                ++done;
                if (show && (done % tick == 0 || done == total)) {
                    std::fprintf(stderr, "\r  call graph: [%zu/%zu]", done, total);
                    std::fflush(stderr);
                }
            }
        }
        if (show) std::fputc('\n', stderr);
        return out;
    }

    // Parallel worker pool - each worker pops indices from a shared
    // atomic counter and accumulates edges into its own buffer. The
    // CfgBuilder is per-thread because it lazily caches unwind ranges
    // in a map that isn't safe to populate concurrently.
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> done{0};
    std::vector<std::vector<CallEdge>> per_thread(worker_count);

    const bool show = total >= 500 && progress_enabled();
    std::mutex log_mu;     // serialize the carriage-return progress line
    const auto tick = std::max<std::size_t>(1, total / 20);

    auto worker = [&](std::size_t idx) {
        CfgBuilder builder(b, dec);
        auto& sink = per_thread[idx];
        sink.reserve(total / worker_count + 16);
        while (true) {
            const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= total) break;
            const auto& w = work[i];
            if (force_cfg_call_graph) {
                auto fn_r = builder.build(w.addr, w.name);
                if (fn_r) {
                    for (auto t : fn_r->call_targets) sink.push_back({w.addr, t});
                }
            } else {
                scan_fast(w, sink);
            }
            const std::size_t d = done.fetch_add(1, std::memory_order_relaxed) + 1;
            if (show && (d % tick == 0 || d == total)) {
                std::lock_guard lk(log_mu);
                std::fprintf(stderr, "\r  call graph: [%zu/%zu]", d, total);
                std::fflush(stderr);
            }
        }
    };

    {
        ScopedTimer walk_timer(force_cfg_call_graph
            ? "call_graph.cfg_walk"
            : "call_graph.fast_scan");
        std::vector<std::thread> threads;
        threads.reserve(worker_count);
        for (std::size_t i = 0; i < worker_count; ++i) {
            threads.emplace_back(worker, i);
        }
        for (auto& thread : threads) thread.join();
    }
    if (show) std::fputc('\n', stderr);

    // Merge per-thread buffers into the output. Order isn't observable
    // by callers - every consumer sorts/dedupes - so a simple
    // concatenation works.
    std::vector<CallEdge> out;
    {
        ScopedTimer t("call_graph.merge");
        std::size_t total_edges = 0;
        for (const auto& v : per_thread) total_edges += v.size();
        out.reserve(total_edges);
        for (auto& v : per_thread) {
            out.insert(out.end(),
                       std::make_move_iterator(v.begin()),
                       std::make_move_iterator(v.end()));
        }
    }
    return out;
}

std::vector<addr_t> compute_callees(const Binary& b, addr_t fn) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    std::string name;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == fn && !s.name.empty()) { name = s.name; break; }
    }
    auto fn_r = builder.build(fn, name);
    if (!fn_r) return {};
    std::vector<addr_t> out = fn_r->call_targets;
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

std::vector<addr_t> compute_callers(const Binary& b, addr_t fn) {
    std::vector<addr_t> out;
    for (const auto& edge : compute_call_graph(b)) {
        if (edge.callee == fn) out.push_back(edge.caller);
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

namespace {

// Drop discovered `sub_*` entries that fall inside the first decoded
// instruction of an earlier entry. The prologue sweep iterates byte by
// byte and accepts every offset whose first 1–4 bytes match a prologue
// shape AND whose first two instructions decode validly - at offsets
// 1 byte after a real prologue, the bytes are usually still a valid
// (different) instruction sequence, so both pass and the discovery
// list ends up with phantom 1-byte entries adjacent to real ones.
// Real symbols are authoritative and survive unconditionally.
//
// This runs before fill_unknown_sizes so the gap-to-next-entry size
// computation isn't poisoned by the phantoms either (a real fn
// followed by a phantom 1-byte fn would otherwise be reported as
// size 1 instead of its true extent).
void filter_shadowed_entries(std::vector<DiscoveredFunction>& fns,
                             const Binary& b) {
    if (fns.size() < 2) return;
    std::sort(fns.begin(), fns.end(),
              [](const auto& x, const auto& y) { return x.addr < y.addr; });
    auto dec_r = make_decoder(b);
    if (!dec_r) return;
    const Decoder& dec = **dec_r;

    std::vector<DiscoveredFunction> out;
    out.reserve(fns.size());
    addr_t shadow_until = 0;       // exclusive upper bound of the
                                   // last-emitted entry's first insn
    for (auto& fn : fns) {
        if (fn.kind != DiscoveredFunction::Kind::Sub ||
            fn.addr >= shadow_until) {
            // Not shadowed by a prior entry. Push it, then advance the
            // shadow window using its first instruction's length so the
            // *next* iteration can detect overlap.
            const auto bytes = b.bytes_at(fn.addr);
            if (!bytes.empty()) {
                if (auto insn = dec.decode(bytes, fn.addr); insn && insn->length > 0) {
                    shadow_until = fn.addr + static_cast<addr_t>(insn->length);
                } else {
                    shadow_until = fn.addr + 1;
                }
            } else {
                shadow_until = fn.addr + 1;
            }
            out.push_back(std::move(fn));
        }
        // else: fn.addr falls inside out.back()'s first decoded
        // instruction - drop silently. Symbols never reach this
        // branch because they bypass the shadow check above.
    }
    fns = std::move(out);
}

void filter_entries_inside_unwind_extents(std::vector<DiscoveredFunction>& fns,
                                          std::vector<FdeExtent> extents) {
    if (fns.empty() || extents.empty()) return;
    std::erase_if(extents, [](const FdeExtent& e) {
        return e.pc_begin == 0 || e.pc_range == 0;
    });
    if (extents.empty()) return;
    std::ranges::sort(extents, {}, &FdeExtent::pc_begin);

    std::vector<FdeExtent> merged;
    merged.reserve(extents.size());
    for (const auto& e : extents) {
        if (!merged.empty() && merged.back().pc_begin == e.pc_begin) {
            merged.back().pc_range = std::max(merged.back().pc_range, e.pc_range);
        } else {
            merged.push_back(e);
        }
    }

    auto covered_by_other_start = [&](addr_t a) {
        auto it = std::ranges::upper_bound(
            merged, a, {}, [](const FdeExtent& e) { return e.pc_begin; });
        if (it == merged.begin()) return false;
        --it;
        if (a == it->pc_begin) return false;
        const u64 off = static_cast<u64>(a - it->pc_begin);
        return off < it->pc_range;
    };

    std::erase_if(fns, [&](const DiscoveredFunction& fn) {
        return fn.kind == DiscoveredFunction::Kind::Sub &&
               covered_by_other_start(fn.addr);
    });
}

// Some defined symbols and all CFG-discovered `sub_*` entries have no reliable
// extent in the loader metadata. Downstream tools (fingerprints, xrefs, size
// filters) still need a usable estimate. Derive an upper-bound size from the
// gap to the next discovered function entry (or the end of the containing
// executable section). Over-counts when there's padding / jump tables in
// between, but that's the safe direction for filtering both ends.
void fill_unknown_sizes(std::vector<DiscoveredFunction>& fns, const Binary& b) {
    if (fns.empty()) return;

    auto is_code_section = [](const Section& s) noexcept {
        return s.flags.executable
            || s.name == ".text" || s.name == "__text" || s.name == "CODE"
            || s.name == ".byfron";
    };
    auto containing_code_section = [&](addr_t a) -> const Section* {
        for (const auto& s : b.sections()) {
            if (!is_code_section(s)) continue;
            if (a >= s.vaddr && a < s.vaddr + s.size) return &s;
        }
        return nullptr;
    };

    for (std::size_t i = 0; i < fns.size(); ++i) {
        if (fns[i].size != 0) continue;
        if (fns[i].kind == DiscoveredFunction::Kind::Sub) {
            bool inside_sized_symbol = false;
            for (std::size_t j = i; j-- > 0;) {
                if (fns[j].size == 0) continue;
                if (fns[j].addr + fns[j].size <= fns[i].addr) break;
                if (fns[j].kind == DiscoveredFunction::Kind::Symbol) {
                    inside_sized_symbol = true;
                    break;
                }
            }
            if (inside_sized_symbol) continue;
        }

        u64 upper = 0;
        const Section* sec = containing_code_section(fns[i].addr);
        if (sec != nullptr) {
            upper = sec->vaddr + sec->size;
        }
        if (i + 1 < fns.size() && fns[i + 1].addr > fns[i].addr) {
            const Section* next_sec = containing_code_section(fns[i + 1].addr);
            if (sec == nullptr || next_sec == sec) {
                upper = (upper == 0)
                    ? fns[i + 1].addr
                    : std::min<u64>(upper, fns[i + 1].addr);
            }
        }
        if (upper > fns[i].addr) {
            fns[i].size = upper - fns[i].addr;
        }
    }
}

[[nodiscard]] std::vector<addr_t> discover_code_pointers(const Binary& b) {
    const u8 width = (b.arch() == Arch::Ppc64 || b.arch() == Arch::X86_64) ? 8 : 4;
    std::vector<addr_t> out;
    auto in_code = [&](addr_t a) noexcept { return addr_in_code_section(b, a); };
    for (const auto& s : b.sections()) {
        if (!s.flags.allocated || s.flags.executable || s.data.size() < width) continue;
        for (std::size_t off = 0; off + width <= s.data.size(); off += width) {
            const std::byte* p = s.data.data() + off;
            addr_t target = 0;
            if (width == 4) {
                target = b.endian() == Endian::Big ? read_be_at<u32>(p) : read_le_at<u32>(p);
            } else {
                target = b.endian() == Endian::Big ? read_be_at<u64>(p) : read_le_at<u64>(p);
            }
            if (target == 0 || !in_code(target)) continue;
            out.push_back(target);
        }
    }
    std::ranges::sort(out);
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

[[nodiscard]] std::string objc_name_token(std::string_view s,
                                          std::string_view fallback) {
    std::string out;
    out.reserve(s.size());
    bool last_us = false;
    for (char ch : s) {
        const unsigned char c = static_cast<unsigned char>(ch);
        if (std::isalnum(c)) {
            out.push_back(ch);
            last_us = false;
        } else if (!last_us && !out.empty()) {
            out.push_back('_');
            last_us = true;
        }
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) out = std::string(fallback);
    if (!std::isalpha(static_cast<unsigned char>(out.front())) &&
        out.front() != '_') {
        out.insert(out.begin(), '_');
    }
    return out;
}

[[nodiscard]] std::string objc_method_context_name(const ObjcMethod& m) {
    std::string cls = objc_name_token(m.cls, "ObjC");
    std::string sel = objc_name_token(m.selector, "method");
    return std::format("{}_{}", cls, sel);
}

[[nodiscard]] std::string lower_first_ascii(std::string s) {
    if (!s.empty()) {
        s.front() = static_cast<char>(
            std::tolower(static_cast<unsigned char>(s.front())));
    }
    return s;
}

[[nodiscard]] std::vector<std::string>
objc_selector_arg_names_local(std::string_view selector) {
    std::vector<std::string> names;
    std::size_t start = 0;
    while (start < selector.size()) {
        const std::size_t colon = selector.find(':', start);
        if (colon == std::string_view::npos) break;
        std::string piece(selector.substr(start, colon - start));
        if (names.empty()) {
            if (piece.starts_with("set") && piece.size() > 3) {
                piece = lower_first_ascii(piece.substr(3));
            } else if (piece.starts_with("with") && piece.size() > 4) {
                piece = lower_first_ascii(piece.substr(4));
            } else if (auto with = piece.rfind("With");
                       with != std::string::npos && with + 4 < piece.size()) {
                piece = lower_first_ascii(piece.substr(with + 4));
            }
        }
        names.push_back(objc_name_token(piece, std::format("arg{}", names.size())));
        start = colon + 1;
    }
    return names;
}

[[nodiscard]] std::optional<std::string>
objc_method_capture_name_for_reg(Reg r, const ObjcMethod& m) {
    switch (canonical_reg(r)) {
        case Reg::Rdi:
            return "self";
        case Reg::Rdx: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (!names.empty()) return names[0];
            break;
        }
        case Reg::Rcx: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 1) return names[1];
            break;
        }
        case Reg::R8: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 2) return names[2];
            break;
        }
        case Reg::R9: {
            const auto names = objc_selector_arg_names_local(m.selector);
            if (names.size() > 3) return names[3];
            break;
        }
        default:
            break;
    }
    return std::nullopt;
}

[[nodiscard]] std::string objc_selector_result_name(std::string_view selector) {
    const std::size_t colon = selector.find(':');
    if (colon != std::string_view::npos) selector = selector.substr(0, colon);
    return objc_name_token(selector, "result");
}

[[nodiscard]] std::optional<std::string>
call_target_name(const Binary& b, const Instruction& insn) {
    std::optional<addr_t> target = branch_target(insn);
    if (!target) {
        if (auto slot = rip_relative_target(insn); slot) {
            auto bytes = b.bytes_at(*slot);
            if (bytes.size() >= 8) {
                u64 ptr = 0;
                std::memcpy(&ptr, bytes.data(), 8);
                if (ptr != 0) target = static_cast<addr_t>(ptr);
            }
        }
    }
    if (!target) return std::nullopt;
    auto resolved = resolve_address_name(b, *target);
    if (!resolved) return std::nullopt;
    return resolved->name;
}

[[nodiscard]] std::vector<ObjcStackBlockInvoke>
discover_objc_stack_block_invokes_impl(const Binary& b) {
    if (b.format() != Format::MachO || b.arch() != Arch::X86_64) return {};

    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;

    const auto methods = parse_objc_methods(b);
    if (methods.empty()) return {};
    const auto selrefs = parse_objc_selrefs(b);

    std::vector<addr_t> method_starts;
    method_starts.reserve(methods.size());
    for (const auto& m : methods) {
        if (m.imp != 0 && addr_in_code_section(b, m.imp)) {
            method_starts.push_back(m.imp);
        }
    }
    std::ranges::sort(method_starts);
    method_starts.erase(std::unique(method_starts.begin(), method_starts.end()),
                        method_starts.end());

    struct Found {
        addr_t invoke = 0;
        std::string selector;
        std::size_t insn_index = 0;
        Reg base = Reg::None;
        Reg index = Reg::None;
        i64 block_disp = 0;
        std::map<u64, std::string> captures;
        std::string self_class;
    };

    std::vector<ObjcStackBlockInvoke> out;
    std::unordered_set<addr_t> seen;
    for (const auto& m : methods) {
        if (m.imp == 0 || !addr_in_code_section(b, m.imp)) continue;
        auto bytes = b.bytes_at(m.imp);
        if (bytes.empty()) continue;

        const std::string method_ctx = objc_method_context_name(m);
        std::map<Reg, addr_t> code_ptr_reg;
        std::map<Reg, std::string> selector_reg;
        std::map<Reg, std::string> value_reg;
        std::vector<Found> found;
        std::string last_selector;
        std::size_t last_selector_index = 0;
        std::size_t insn_index = 0;
        std::size_t off = 0;
        std::size_t method_limit = 4096;
        auto next = std::ranges::upper_bound(method_starts, m.imp);
        if (next != method_starts.end() && *next > m.imp) {
            method_limit = static_cast<std::size_t>(*next - m.imp);
        }
        const std::size_t limit = std::min<std::size_t>(bytes.size(), method_limit);

        auto set_selector = [&](std::string selector) {
            if (selector.empty()) return;
            last_selector = std::move(selector);
            last_selector_index = insn_index;
            for (auto& f : found) {
                if (insn_index > f.insn_index + 96) continue;
                f.selector = last_selector;
            }
        };

        while (off < limit) {
            auto insn_r = dec.decode(bytes.subspan(off, limit - off),
                                     m.imp + static_cast<addr_t>(off));
            if (!insn_r || insn_r->length == 0) {
                off += decode_failure_advance(b.arch(), bytes.subspan(off, limit - off));
                ++insn_index;
                continue;
            }
            const Instruction& insn = *insn_r;

            if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const auto& src = insn.operands[1];
                bool selector_armed = false;
                if (src.kind == Operand::Kind::Memory &&
                    src.mem.base == Reg::Rip && src.mem.index == Reg::None &&
                    src.mem.has_disp) {
                    const addr_t slot = insn.address + insn.length +
                                        static_cast<addr_t>(src.mem.disp);
                    if (auto it = selrefs.find(slot); it != selrefs.end()) {
                        selector_reg[dst] = it->second;
                        if (dst == Reg::Rsi) set_selector(it->second);
                        selector_armed = true;
                    }
                } else if (src.kind == Operand::Kind::Register) {
                    const Reg src_r = canonical_reg(src.reg);
                    if (auto it = selector_reg.find(src_r); it != selector_reg.end()) {
                        selector_reg[dst] = it->second;
                        if (dst == Reg::Rsi) set_selector(it->second);
                        selector_armed = true;
                    }
                }
                if (!selector_armed) selector_reg.erase(dst);
            }

            if (insn.mnemonic == Mnemonic::Lea && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register &&
                insn.operands[1].kind == Operand::Kind::Memory) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const Mem& mem = insn.operands[1].mem;
                if (mem.base == Reg::Rip && mem.index == Reg::None && mem.has_disp) {
                    const addr_t target = insn.address + insn.length +
                                          static_cast<addr_t>(mem.disp);
                    if (target != m.imp && addr_in_code_section(b, target)) {
                        code_ptr_reg[dst] = target;
                    } else {
                        code_ptr_reg.erase(dst);
                    }
                } else {
                    code_ptr_reg.erase(dst);
                }
            } else if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                       insn.operands[0].kind == Operand::Kind::Memory &&
                       insn.operands[1].kind == Operand::Kind::Register) {
                const Mem& dst = insn.operands[0].mem;
                const Reg src = canonical_reg(insn.operands[1].reg);
                if (dst.base != Reg::Rip && dst.index == Reg::None &&
                    dst.has_disp && dst.disp == 0x10) {
                    if (auto it = code_ptr_reg.find(src); it != code_ptr_reg.end()) {
                        Found f;
                        f.invoke = it->second;
                        f.selector = last_selector;
                        f.insn_index = insn_index;
                        f.base = canonical_reg(dst.base);
                        f.index = canonical_reg(dst.index);
                        f.block_disp = dst.disp - 0x10;
                        f.self_class = m.cls;
                        found.push_back(std::move(f));
                    }
                } else if (dst.base != Reg::Rip && dst.has_disp && dst.disp >= 0x20 &&
                           ((dst.disp - 0x20) % 8) == 0 &&
                           !code_ptr_reg.contains(src)) {
                    const Reg dst_base = canonical_reg(dst.base);
                    const Reg dst_index = canonical_reg(dst.index);
                    for (auto it = found.rbegin(); it != found.rend(); ++it) {
                        if (insn_index > it->insn_index + 96) continue;
                        if (it->base != dst_base || it->index != dst_index) continue;
                        const i64 field_off = dst.disp - it->block_disp;
                        if (field_off < 0x20 || (field_off % 8) != 0) continue;
                        if (auto name = objc_method_capture_name_for_reg(src, m); name) {
                            const u64 capture_idx =
                                static_cast<u64>((field_off - 0x20) / 8);
                            it->captures.emplace(capture_idx, *name);
                        } else if (auto name_it = value_reg.find(src);
                                   name_it != value_reg.end() &&
                                   !name_it->second.empty()) {
                            const u64 capture_idx =
                                static_cast<u64>((field_off - 0x20) / 8);
                            it->captures.emplace(capture_idx, name_it->second);
                        }
                        break;
                    }
                }
            } else if (insn.mnemonic == Mnemonic::Mov && insn.num_operands == 2 &&
                       insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst = canonical_reg(insn.operands[0].reg);
                const auto& src = insn.operands[1];
                if (src.kind == Operand::Kind::Register) {
                    const Reg src_r = canonical_reg(src.reg);
                    if (auto it = code_ptr_reg.find(src_r); it != code_ptr_reg.end()) {
                        code_ptr_reg[dst] = it->second;
                    } else {
                        code_ptr_reg.erase(dst);
                    }
                    if (auto it = value_reg.find(src_r); it != value_reg.end()) {
                        value_reg[dst] = it->second;
                    } else {
                        value_reg.erase(dst);
                    }
                } else {
                    code_ptr_reg.erase(dst);
                    value_reg.erase(dst);
                }
            }

            if (is_call(insn.mnemonic)) {
                const auto name = call_target_name(b, insn);
                const bool retain_autoreleased =
                    name && name->find("objc_retainAutoreleasedReturnValue") !=
                                std::string::npos;
                if (retain_autoreleased) {
                    if (auto it = value_reg.find(Reg::Rdi); it != value_reg.end()) {
                        value_reg[Reg::Rax] = it->second;
                    } else {
                        value_reg.erase(Reg::Rax);
                    }
                } else if (!last_selector.empty() &&
                           insn_index <= last_selector_index + 8) {
                    value_reg[Reg::Rax] = objc_selector_result_name(last_selector);
                } else {
                    value_reg.erase(Reg::Rax);
                }
                value_reg.erase(Reg::Rcx);
                value_reg.erase(Reg::Rdx);
                value_reg.erase(Reg::Rsi);
                value_reg.erase(Reg::R8);
                value_reg.erase(Reg::R9);
            }

            off += insn.length;
            ++insn_index;
            if (is_return_like(insn.mnemonic)) break;
        }

        for (const auto& f : found) {
            if (f.invoke == 0 || !seen.insert(f.invoke).second) continue;
            const std::string callback =
                f.selector.empty() ? std::string{} :
                    "_" + objc_name_token(f.selector, "callback");
            out.push_back({
                f.invoke,
                std::format("{}{}__block_invoke", method_ctx, callback),
                f.captures,
                f.self_class
            });
        }
    }

    std::ranges::sort(out, {}, &ObjcStackBlockInvoke::invoke);
    return out;
}

}  // namespace

std::vector<ObjcStackBlockInvoke>
discover_objc_stack_block_invokes(const Binary& b) {
    return discover_objc_stack_block_invokes_impl(b);
}

std::vector<DiscoveredFunction>
enumerate_functions(const Binary& b, EnumerateMode mode, addr_t lo, addr_t hi) {
    const bool scoped = hi > lo;
    auto in_scope = [&](addr_t a) noexcept { return !scoped || (a >= lo && a < hi); };

    std::vector<DiscoveredFunction> out;

    // Pass 1: defined function symbols. These carry real sizes, so prefer
    // them when a later CFG-discovered entry lands on the same address.
    std::unordered_map<addr_t, std::size_t> index;
    std::size_t symbol_added = 0;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (!in_scope(s.addr)) continue;
        if (index.count(s.addr)) continue;
        index.emplace(s.addr, out.size());
        out.push_back({s.addr, s.size, s.name,
                       DiscoveredFunction::Kind::Symbol});
        ++symbol_added;
    }

    constexpr std::size_t kDenseFdeThreshold = 4096;

    // Pass 1.1: unwind metadata. On stripped ELF/Mach-O binaries this is
    // much stronger evidence than bytewise prologue sweeping: an FDE gives
    // both the exact entry and an extent, while a prologue-shaped byte
    // sequence inside a function body is only a guess. Large Android C++
    // libraries in particular can have hundreds of thousands of FDEs; once
    // that metadata is dense, the prologue sweep mostly adds false positives.
    std::size_t unwind_added = 0;
    auto unwind_extents = enumerate_fde_extents(b);
    std::vector<FdeExtent> compact_unwind_extents;
    {
        compact_unwind_extents = enumerate_compact_unwind_extents(b);
        unwind_extents.insert(unwind_extents.end(),
                              compact_unwind_extents.begin(),
                              compact_unwind_extents.end());
    }
    auto add_unwind_extent = [&](const FdeExtent& fde) {
        if (fde.pc_begin == 0 || fde.pc_range == 0) return;
        if (!in_scope(fde.pc_begin)) return;
        if (b.import_at_plt(fde.pc_begin) != nullptr) return;
        if (index.count(fde.pc_begin)) return;
        index.emplace(fde.pc_begin, out.size());
        out.push_back({fde.pc_begin, fde.pc_range,
                       std::format("sub_{:x}", fde.pc_begin),
                       DiscoveredFunction::Kind::Sub});
        ++unwind_added;
    };
    if (unwind_extents.size() >= kDenseFdeThreshold) {
        for (const auto& fde : unwind_extents) {
            add_unwind_extent(fde);
        }
    } else {
        // Compact-unwind entries are linker-authored function starts, not
        // byte-pattern guesses. Even small Mach-O binaries can rely on them
        // when LC_FUNCTION_STARTS is stripped or sparse.
        for (const auto& fde : compact_unwind_extents) {
            add_unwind_extent(fde);
        }
    }

    // Two address-level gates filter the noise from later passes:
    //   1. Target must land in some executable section.
    //   2. That section must not be encrypted (high entropy).
    //
    // Even on a binary that doesn't trip `binary_looks_packed`, a
    // single high-entropy executable section will usually produce
    // garbage targets. Section-level filtering catches that case
    // without needing the binary-level heuristic to fire.
    //
    // Cache the encrypted-section verdict by Section pointer - without
    // this cache, `section_looks_encrypted(*sec)` runs the O(n) entropy
    // sweep over the whole section once per discovered prologue
    // (~24 k hits on a 14 MB Roblox-shaped DLL = ~336 GB of byte
    // processing). Dominates cold open by two orders of magnitude.
    const auto& sections = b.sections();
    std::unordered_map<const Section*, bool> encrypted_cache;
    auto is_encrypted_cached = [&](const Section* s) -> bool {
        if (auto it = encrypted_cache.find(s); it != encrypted_cache.end()) {
            return it->second;
        }
        const bool v = section_looks_encrypted(*s);
        encrypted_cache.emplace(s, v);
        return v;
    };
    auto section_for = [&](addr_t a) -> const Section* {
        for (const auto& s : sections) {
            // "Code-shaped" - either flagged exec or named .text /
            // __text / CODE. Byfron / VMProtect strip the exec bit
            // on disk and flip it at runtime; pretending those
            // bytes aren't code drops every discovered function on
            // the floor.
            const bool is_code = s.flags.executable
                || s.name == ".text" || s.name == "__text" || s.name == "CODE"
                || s.name == ".byfron";
            if (!is_code) continue;
            if (a >= s.vaddr && a < s.vaddr + s.size) return &s;
        }
        return nullptr;
    };
    auto ppc_candidate_decodes = [&](addr_t a) -> bool {
        if (b.arch() != Arch::Ppc32 && b.arch() != Arch::Ppc64) return true;
        if ((a & 3u) != 0) return false;
        auto bytes = b.bytes_at(a);
        if (bytes.size() < 4) return false;
        auto dec_r = make_decoder(b);
        if (!dec_r) return false;
        auto insn = (*dec_r)->decode(bytes, a);
        return insn && insn->length == 4;
    };
    auto add_candidate = [&](addr_t a, std::string_view label,
                             bool trusted = false,
                             const std::string* explicit_name = nullptr) {
        if (!in_scope(a)) return;
        if (b.import_at_plt(a) != nullptr) return;
        if (auto existing = index.find(a); existing != index.end()) {
            if (explicit_name && !explicit_name->empty()) {
                auto& fn = out[existing->second];
                if (fn.name.starts_with("sub_")) fn.name = *explicit_name;
            }
            return;
        }
        const Section* sec = section_for(a);
        if (!sec) return;
        if (!ppc_candidate_decodes(a)) return;
        // Trusted entries (vtable pointers from RTTI) bypass the
        // encrypted-section filter - they come from structural
        // metadata in .rdata, not heuristic pattern matching in
        // encrypted code. Even on a packed binary, these are real
        // class methods that will exist after unpacking.
        if (!trusted && mode == EnumerateMode::Auto && is_encrypted_cached(sec)) return;
        index.emplace(a, out.size());
        out.push_back({a, 0,
                       explicit_name ? *explicit_name
                                     : std::format("{}_{:x}", label, a),
                       DiscoveredFunction::Kind::Sub});
    };

    // Pass 1.5: cheap structural discovery. Vtables come from RTTI
    // (already parsed for naming) - every slot is a guaranteed
    // function pointer. Prologue sweep linear-scans executable
    // bytes for x64 prologue patterns and validates each candidate
    // by decoding two instructions. Both run on packed binaries
    // too - RTTI lives in unencrypted .rdata, and the prologue
    // sweep itself skips encrypted sections.
    if (b.format() == Format::Pe) {
        auto msvc_classes = parse_msvc_rtti(b);
        auto rtti_names   = rtti_method_names(msvc_classes);
        for (const auto& cls : msvc_classes) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!in_scope(m)) continue;
                if (!addr_in_code_section(b, m)) continue;
                auto it = rtti_names.find(m);
                add_candidate(m, "sub", true,
                              it != rtti_names.end() ? &it->second : nullptr);
            }
        }
    }
    if (b.format() != Format::Pe) {
        auto itanium_classes = parse_itanium_rtti(b);
        auto rtti_names      = rtti_method_names(itanium_classes);
        for (const auto& cls : itanium_classes) {
            for (addr_t m : cls.methods) {
                if (m == 0) continue;
                if (!in_scope(m)) continue;
                if (!addr_in_code_section(b, m)) continue;
                auto it = rtti_names.find(m);
                add_candidate(m, "sub", true,
                              it != rtti_names.end() ? &it->second : nullptr);
            }
        }
    }
    if (b.format() == Format::MachO) {
        for (const auto& blk : parse_objc_blocks(b)) {
            if (blk.invoke == 0) continue;
            if (!in_scope(blk.invoke)) continue;
            if (!addr_in_code_section(b, blk.invoke)) continue;
            const std::string name = std::format("__block_invoke_{:x}",
                                                 static_cast<u64>(blk.invoke));
            add_candidate(blk.invoke, "sub", true, &name);
        }
        for (const auto& blk : discover_objc_stack_block_invokes(b)) {
            if (blk.invoke == 0) continue;
            if (!in_scope(blk.invoke)) continue;
            if (!addr_in_code_section(b, blk.invoke)) continue;
            add_candidate(blk.invoke, "sub", true, &blk.name);
        }
    }
    const std::size_t before_prologues = out.size();
    if (unwind_extents.size() < kDenseFdeThreshold) {
        for (addr_t a : discover_from_prologues(b, lo, hi)) add_candidate(a, "sub");
    }
    const std::size_t prologue_added = out.size() - before_prologues;
    if (b.format() == Format::Dol || b.arch() == Arch::Ppc32 || b.arch() == Arch::Ppc64) {
        for (addr_t a : discover_code_pointers(b)) add_candidate(a, "sub", true);
    }
    if (timing_enabled()) {
        std::fprintf(stderr,
            "[timing] enumerate_functions.seed: symbols=%zu unwind_extents=%zu unwind_added=%zu prologue=%zu total=%zu\n",
            symbol_added, unwind_extents.size(), unwind_added, prologue_added, out.size());
    }

    // Loader-only mode: on a packed binary the call-graph walker chases
    // garbage targets through encrypted stub code, blocks the UI for
    // ~30s, and pollutes the function list with `sub_…` entries that
    // never decompile. Skip pass 2 - the user can pass --full-analysis
    // if they want it anyway. Pass 1.5 above already gave us anything
    // recoverable from the unencrypted parts of the image.
    //
    // `Cheap` callers (resolve_containing_function on per-function CLI
    // invocations) bail here unconditionally - they only need a
    // best-effort "is this a function entry?" answer, and the call-
    // graph walk costs minutes on big DLLs. Auto mode also bails when
    // symbols/unwind already provide a dense authoritative function map:
    // on modern Mach-O/C++ apps this avoids decoding hundreds of
    // thousands of CFGs just to rediscover call targets for `--functions`.
    const bool dense_authoritative_starts =
        mode == EnumerateMode::Auto &&
        (symbol_added >= kDenseFdeThreshold ||
         unwind_extents.size() >= kDenseFdeThreshold);
    if (mode == EnumerateMode::Cheap ||
        dense_authoritative_starts ||
        (mode == EnumerateMode::Auto && binary_looks_packed(b))) {
        if (unwind_extents.size() >= kDenseFdeThreshold) {
            filter_entries_inside_unwind_extents(out, unwind_extents);
        }
        filter_shadowed_entries(out, b);
        fill_unknown_sizes(out, b);
        return out;
    }

    // Pass 2: CFG-walked call targets. Skip PLT stubs (import thunks).
    // Sizes for these are filled in later by fill_unknown_sizes() using the
    // gap to the next discovered function (or section boundary).
    for (const auto& e : compute_call_graph(b)) {
        add_candidate(e.callee, "sub");
    }

    if (unwind_extents.size() >= kDenseFdeThreshold) {
        filter_entries_inside_unwind_extents(out, unwind_extents);
    }
    filter_shadowed_entries(out, b);
    fill_unknown_sizes(out, b);
    return out;
}

namespace {

// True when `target` is the entry of a defined function or a PLT stub -
// the same predicate the CFG builder uses to convert a `jmp` into a
// TailCall block. Duplicated here so the pipeline doesn't need to expose
// CFG-builder internals.
[[nodiscard]] bool callee_is_function_entry(const Binary& b, addr_t target) noexcept {
    if (const Symbol* s = b.defined_object_at(target);
        s && s->kind == SymbolKind::Function && s->addr == target) {
        return true;
    }
    if (b.import_at_plt(target) != nullptr) return true;
    return false;
}

[[nodiscard]] bool addr_in_executable_section(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (a >= s.vaddr && a < s.vaddr + s.size) return true;
    }
    return false;
}

[[nodiscard]] std::optional<u64> read_u64_le(const Binary& b, addr_t a) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < 8) return std::nullopt;
    u64 v = 0;
    std::memcpy(&v, span.data(), 8);
    return v;
}

}  // namespace

std::vector<ClassifiedCallee>
compute_classified_callees(const Binary& b, addr_t fn,
                           const std::unordered_set<addr_t>* known_entries) {
    auto dec_r = make_decoder(b);
    if (!dec_r) return {};
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);
    if (known_entries) {
        builder.seed_known_entries(*known_entries);
    }

    std::string name;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == fn && !s.name.empty()) { name = s.name; break; }
    }
    auto fn_r = builder.build(fn, name);
    if (!fn_r) return {};

    // Vtable index for the back-trace. Itanium ABI covers both Mach-O
    // and ELF C++ binaries; `parse_itanium_rtti` already walks
    // `__const`, `.data.rel.ro`, and `.rodata`. PE is MSVC-RTTI shaped
    // differently - handled elsewhere, not yet wired here.
    //
    // Key subtlety: `RttiClass::vtable` is the *typeinfo slot* (offset
    // 8 inside the vtable struct). The ABI-defined vptr - the value
    // stored in every object's head and the value the compiler loads
    // when emitting `lea reg, [rip + K]` - points at `methods[0]`,
    // which sits at `vtable + 8`. We index by the vptr value the code
    // actually sees, so `call [reg + slot*8]` resolves directly with
    // no adjustment at the call site.
    std::map<addr_t, const RttiClass*> vtable_index;
    std::vector<RttiClass> rtti;
    if (b.format() == Format::MachO || b.format() == Format::Elf) {
        rtti = parse_itanium_rtti(b);
        for (const auto& c : rtti) {
            if (c.vtable != 0 && !c.methods.empty()) {
                vtable_index.emplace(c.vtable + 8, &c);
            }
        }
    }

    std::vector<ClassifiedCallee> out;
    out.reserve(fn_r->call_targets.size());

    // Resolve a `mov dst, [base_reg + disp]` vtable slot load. If
    // `base_reg` currently holds a known vptr, the loaded value is
    // the IMP at that slot.
    auto resolve_vptr_slot =
        [&](addr_t vptr, i64 disp) -> std::optional<addr_t> {
        auto it = vtable_index.find(vptr);
        if (it == vtable_index.end()) return std::nullopt;
        if (disp < 0 || (disp & 7) != 0) return std::nullopt;
        const std::size_t slot = static_cast<std::size_t>(disp) / 8;
        if (slot >= it->second->methods.size()) return std::nullopt;
        const addr_t imp = it->second->methods[slot];
        if (imp == 0 || !addr_in_executable_section(b, imp)) return std::nullopt;
        return imp;
    };

    for (const auto& bb : fn_r->blocks) {
        // Per-block register state for the vtable back-trace. Two
        // strata:
        //   vptr: register holds a vptr value (points to methods[0]
        //         of a known vtable). Reached by `lea r, [rip+K]`,
        //         `mov r, [rip+K]` where *K is a vptr, or reg-copy.
        //   imp:  register holds the resolved IMP of some slot, e.g.
        //         after `mov r, [vptr_reg + slot*8]`.
        // Keyed by canonical 64-bit reg so sub-register writes to the
        // same family correctly invalidate.
        std::map<Reg, addr_t> reg_vptr;
        std::map<Reg, addr_t> reg_imp;
        auto disarm = [&](Reg canon) {
            reg_vptr.erase(canon);
            reg_imp.erase(canon);
        };

        for (const auto& insn : bb.instructions) {
            const Mnemonic mn = insn.mnemonic;

            // `lea dst, [rip + K]` - arm dst as carrying a vptr when
            // K is exactly a known vptr address.
            if (mn == Mnemonic::Lea && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst   = insn.operands[0].reg;
                const Reg dst_c = canonical_reg(dst);
                const auto& src = insn.operands[1];
                bool armed = false;
                if (reg_size(dst) == 8 &&
                    src.kind == Operand::Kind::Memory &&
                    src.mem.base == Reg::Rip &&
                    src.mem.index == Reg::None &&
                    src.mem.has_disp) {
                    const addr_t k = insn.address + insn.length +
                                     static_cast<addr_t>(src.mem.disp);
                    if (vtable_index.count(k)) {
                        disarm(dst_c);
                        reg_vptr[dst_c] = k;
                        armed = true;
                    }
                }
                if (!armed) disarm(dst_c);
                continue;
            }

            // `mov dst, <src>` - multiple cases. See disarm() fallback
            // at the bottom.
            if (mn == Mnemonic::Mov && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst   = insn.operands[0].reg;
                const Reg dst_c = canonical_reg(dst);
                const auto& src = insn.operands[1];
                bool armed = false;
                if (reg_size(dst) == 8) {
                    // mov dst, [rip + K] - *K might be a stored vptr.
                    if (src.kind == Operand::Kind::Memory &&
                        src.mem.base == Reg::Rip &&
                        src.mem.index == Reg::None &&
                        src.mem.has_disp) {
                        const addr_t k = insn.address + insn.length +
                                         static_cast<addr_t>(src.mem.disp);
                        if (auto v = read_u64_le(b, k); v) {
                            const auto stored = static_cast<addr_t>(*v);
                            if (vtable_index.count(stored)) {
                                disarm(dst_c);
                                reg_vptr[dst_c] = stored;
                                armed = true;
                            }
                        }
                    }
                    // mov dst, [reg + disp] - slot load from an armed
                    // vptr-carrying register. Resolves to an IMP.
                    else if (src.kind == Operand::Kind::Memory &&
                             src.mem.base != Reg::None &&
                             src.mem.base != Reg::Rip &&
                             src.mem.index == Reg::None &&
                             src.mem.has_disp) {
                        const Reg base_c = canonical_reg(src.mem.base);
                        if (auto it = reg_vptr.find(base_c);
                            it != reg_vptr.end()) {
                            if (auto imp = resolve_vptr_slot(it->second, src.mem.disp)) {
                                disarm(dst_c);
                                reg_imp[dst_c] = *imp;
                                armed = true;
                            }
                        }
                    }
                    // mov dst, src_reg - one-hop reg→reg copy of any
                    // currently-armed state.
                    else if (src.kind == Operand::Kind::Register) {
                        const Reg src_c = canonical_reg(src.reg);
                        if (auto it = reg_vptr.find(src_c); it != reg_vptr.end()) {
                            disarm(dst_c);
                            reg_vptr[dst_c] = it->second;
                            armed = true;
                        } else if (auto it2 = reg_imp.find(src_c); it2 != reg_imp.end()) {
                            disarm(dst_c);
                            reg_imp[dst_c] = it2->second;
                            armed = true;
                        }
                    }
                }
                if (!armed) disarm(dst_c);
                continue;
            }

            if (is_call(mn)) {
                if (insn.num_operands == 0) {
                    reg_vptr.clear();
                    reg_imp.clear();
                    continue;
                }
                const auto& op = insn.operands[0];
                if (op.kind == Operand::Kind::Relative) {
                    out.push_back({op.rel.target, CalleeKind::Direct, insn.address});
                } else if (op.kind == Operand::Kind::Memory &&
                           op.mem.base == Reg::Rip &&
                           op.mem.has_disp &&
                           op.mem.index == Reg::None) {
                    // call qword ptr [rip + disp]: dereference the slot
                    // and emit indirect_const if it points into code.
                    const addr_t slot = insn.address + insn.length +
                                        static_cast<addr_t>(op.mem.disp);
                    if (auto v = read_u64_le(b, slot); v) {
                        const auto target = static_cast<addr_t>(*v);
                        if (target != 0 && addr_in_executable_section(b, target)) {
                            out.push_back({target, CalleeKind::IndirectConst,
                                           insn.address});
                        }
                    }
                } else if (op.kind == Operand::Kind::Memory &&
                           op.mem.base != Reg::None &&
                           op.mem.base != Reg::Rip &&
                           op.mem.index == Reg::None &&
                           op.mem.has_disp) {
                    // call [reg + disp]: resolve through the most
                    // recent vtable-pointer load into the same canon
                    // register.
                    const Reg base_c = canonical_reg(op.mem.base);
                    if (auto it = reg_vptr.find(base_c); it != reg_vptr.end()) {
                        if (auto imp = resolve_vptr_slot(it->second, op.mem.disp)) {
                            out.push_back({*imp, CalleeKind::IndirectConst,
                                           insn.address});
                        }
                    }
                } else if (op.kind == Operand::Kind::Register) {
                    // call reg: if the register already carries a
                    // resolved IMP (from a prior `mov rax, [vptr+slot]`),
                    // emit the edge directly.
                    const Reg r_c = canonical_reg(op.reg);
                    if (auto it = reg_imp.find(r_c); it != reg_imp.end()) {
                        out.push_back({it->second, CalleeKind::IndirectConst,
                                       insn.address});
                    }
                }
                // Any call clobbers the SysV caller-save set. Clearing
                // everything is cheaper than enumerating that set and
                // costs nothing in precision.
                reg_vptr.clear();
                reg_imp.clear();
                continue;
            }

            if (is_unconditional_jmp(mn)) {
                if (auto t = branch_target(insn); t && callee_is_function_entry(b, *t)) {
                    out.push_back({*t, CalleeKind::Tail, insn.address});
                    continue;
                }
                // Tail-call through a resolved IMP: `jmp *rax` where
                // rax carries a known slot IMP. Same edge kind as a
                // tail-call to a known symbol entry.
                if (insn.num_operands == 1) {
                    const auto& jop = insn.operands[0];
                    if (jop.kind == Operand::Kind::Register) {
                        const Reg r_c = canonical_reg(jop.reg);
                        if (auto it = reg_imp.find(r_c); it != reg_imp.end()) {
                            out.push_back({it->second, CalleeKind::Tail,
                                           insn.address});
                        }
                    } else if (jop.kind == Operand::Kind::Memory &&
                               jop.mem.base != Reg::None &&
                               jop.mem.base != Reg::Rip &&
                               jop.mem.index == Reg::None &&
                               jop.mem.has_disp) {
                        const Reg base_c = canonical_reg(jop.mem.base);
                        if (auto it = reg_vptr.find(base_c); it != reg_vptr.end()) {
                            if (auto imp = resolve_vptr_slot(it->second, jop.mem.disp)) {
                                out.push_back({*imp, CalleeKind::Tail,
                                               insn.address});
                            }
                        }
                    }
                }
                continue;
            }

            // Any other instruction that writes a register first-
            // operand invalidates our tracked state for that canon reg.
            // Conservative: arithmetic, lea-without-vtable, pop, etc.
            // Memory-dst instructions leave register state untouched.
            if (insn.num_operands >= 1 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                disarm(canonical_reg(insn.operands[0].reg));
            }
        }
    }

    std::sort(out.begin(), out.end(),
              [](const ClassifiedCallee& a, const ClassifiedCallee& bb) {
                  if (a.target != bb.target) return a.target < bb.target;
                  if (a.kind != bb.kind)
                      return static_cast<u8>(a.kind) < static_cast<u8>(bb.kind);
                  return a.site < bb.site;
              });
    out.erase(std::unique(out.begin(), out.end(),
                          [](const ClassifiedCallee& a, const ClassifiedCallee& bb) {
                              return a.target == bb.target && a.kind == bb.kind;
                          }),
              out.end());
    return out;
}

std::optional<ContainingFn>
containing_function(const Binary& b, addr_t addr) {
    // Cheap mode: Pass 1 (defined symbols) + Pass 1.5 (vtable + x64
    // prologue sweep). On a non-packed 16 MB DLL with ~27 k entries
    // the full call-graph walk is ~2 minutes; the cheap subset takes
    // milliseconds and covers every entry that ships in PE .pdata
    // (already absorbed into the symbol table) plus every prologue-
    // shaped function start. The CLI's `--functions` pass still
    // populates the UI sidebar with the full call-graph result;
    // resolving a click back through here doesn't need to redo it.
    const auto fns = enumerate_functions(b, EnumerateMode::Cheap);
    if (fns.empty()) return std::nullopt;

    // `fns` is already sorted by addr ascending. upper_bound finds the
    // first entry strictly greater than `addr`; the one before it is
    // the candidate.
    auto it = std::upper_bound(fns.begin(), fns.end(), addr,
        [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
    if (it == fns.begin()) return std::nullopt;
    --it;

    // Respect the known extent when the symbol gives us one. A symbol
    // with size=0 (stripped `sub_*` entries) is bounded implicitly by
    // the next function's start - without that, an addr that lands far
    // outside any real function would still be claimed by the
    // largest-start ≤ addr entry, surfacing absurd offsets like
    // `sub_53290+0x29586126579c` on backtrace frames pointing into
    // libc that the primary binary has no business labelling.
    if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
    if (it->size == 0) {
        addr_t implied_end = 0;
        auto nxt = it; ++nxt;
        if (nxt != fns.end()) implied_end = nxt->addr;
        if (implied_end != 0 && addr >= implied_end) return std::nullopt;
        // Last function in the sorted set with size==0: cap by section
        // extent so a PC past the .text mapping doesn't get mislabelled.
        if (implied_end == 0) {
            for (const auto& s : b.sections()) {
                if (it->addr >= s.vaddr && it->addr < s.vaddr + s.size) {
                    if (addr >= s.vaddr + s.size) return std::nullopt;
                    break;
                }
            }
        }
    }
    if (b.bytes_at(it->addr).empty()) return std::nullopt;

    ContainingFn out;
    out.entry         = it->addr;
    out.size          = it->size;
    out.name          = it->name;
    out.offset_within = addr - it->addr;
    return out;
}

std::map<addr_t, addr_t>
compute_call_resolutions(const Binary& b, addr_t fn,
                         const std::unordered_set<addr_t>* known_entries) {
    std::map<addr_t, addr_t> out;
    for (const auto& e : compute_classified_callees(b, fn, known_entries)) {
        // First writer wins when two edges share a site - the
        // classifier already sorts by (target, kind, site), but a given
        // `call` instruction is only classified once in practice.
        out.emplace(e.site, e.target);
    }
    return out;
}

NameValidation
validate_name(const Binary& b, std::string_view name,
              std::span<const FingerprintRow> precomputed) {
    NameValidation out;
    if (name.empty()) return out;

    const auto matches = b.find_all_by_name(name);

    // The bound-address path always needs an "enclosing function entry"
    // lookup - a wrong rename can pin a name mid-function, and the
    // fingerprint we report has to be the enclosing fn's, not 0. That
    // table comes from enumerate_functions regardless of caching.
    const auto fns = enumerate_functions(b);
    std::vector<addr_t> bound_addrs;
    bound_addrs.reserve(matches.size() + 1);
    for (const Symbol* s : matches) bound_addrs.push_back(s->addr);
    for (const auto& fn : fns) {
        if (fn.name == name &&
            std::find(bound_addrs.begin(), bound_addrs.end(), fn.addr) == bound_addrs.end()) {
            bound_addrs.push_back(fn.addr);
        }
    }
    out.bound.reserve(bound_addrs.size());
    out.fps.reserve(bound_addrs.size());
    out.offsets.reserve(bound_addrs.size());

    auto enclosing_entry = [&](addr_t addr) -> std::optional<addr_t> {
        auto it = std::upper_bound(fns.begin(), fns.end(), addr,
            [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
        if (it == fns.begin()) return std::nullopt;
        --it;
        if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
        return it->addr;
    };

    // Index the precomputed table by addr for O(1) fingerprint lookup.
    // When empty, `fingerprint_at` falls through to the slow path so the
    // function still works on a fresh binary with no cache.
    std::unordered_map<addr_t, std::size_t> fp_by_addr;
    if (!precomputed.empty()) {
        fp_by_addr.reserve(precomputed.size());
        for (std::size_t i = 0; i < precomputed.size(); ++i) {
            fp_by_addr.emplace(precomputed[i].addr, i);
        }
    }
    auto fingerprint_at = [&](addr_t a) -> FunctionFingerprint {
        if (auto it = fp_by_addr.find(a); it != fp_by_addr.end()) {
            return precomputed[it->second].fp;
        }
        if (!precomputed.empty()) return {};
        return compute_fingerprint(b, a);
    };

    FunctionFingerprint anchor{};
    bool anchor_set = false;
    for (addr_t bound_addr : bound_addrs) {
        out.bound.push_back(bound_addr);
        u64 off = 0;
        FunctionFingerprint fp{};
        if (auto entry = enclosing_entry(bound_addr); entry) {
            off = bound_addr - *entry;
            fp = fingerprint_at(*entry);
        }
        out.fps.push_back(fp);
        out.offsets.push_back(off);
        if (!anchor_set && fp.hash != 0) {
            anchor = fp;
            anchor_set = true;
        }
    }

    // Near-match scan: every other function whose (blocks, insts, calls)
    // tuple matches the anchor. Hash equality is *kept* (same content,
    // different addr is the strongest name-DB confusion signal); callers
    // grep for hash=<anchor> when they want to single out exact twins.
    if (anchor_set) {
        std::unordered_set<addr_t> bound_entries;
        for (addr_t a : out.bound) {
            if (auto e = enclosing_entry(a); e) bound_entries.insert(*e);
        }

        auto consider = [&](addr_t addr, const FunctionFingerprint& fp,
                            std::string_view fname) {
            if (bound_entries.contains(addr)) return;
            if (fp.hash == 0) return;
            if (fp.blocks != anchor.blocks) return;
            if (fp.insts  != anchor.insts)  return;
            if (fp.calls  != anchor.calls)  return;
            NameValidation::NearMatch nm;
            nm.addr = addr;
            nm.fp   = fp;
            nm.name = std::string{fname};
            out.near_matches.push_back(std::move(nm));
        };

        if (!precomputed.empty()) {
            for (const auto& row : precomputed) {
                consider(row.addr, row.fp, row.name);
            }
        } else {
            for (const auto& d : fns) {
                const auto fp = compute_fingerprint(b, d.addr);
                consider(d.addr, fp, d.name);
            }
        }
        std::sort(out.near_matches.begin(), out.near_matches.end(),
            [](const auto& a, const auto& bb) { return a.addr < bb.addr; });
    }

    if (out.bound.empty())          out.verdict = NameValidation::Verdict::Unknown;
    else if (out.bound.size() > 1)  out.verdict = NameValidation::Verdict::Ambiguous;
    else if (out.near_matches.empty()) out.verdict = NameValidation::Verdict::Strong;
    else                            out.verdict = NameValidation::Verdict::Weak;
    return out;
}

Collisions
collect_collisions(const Binary& b,
                   std::span<const FingerprintRow> precomputed) {
    Collisions out;

    // Name collisions come straight from the symbol table - find_all_by_name
    // already does the per-name filter, but here we want every duplicate
    // in one pass. Skip imports (PLT stubs share names with their defined
    // counterparts and that's not a collision worth flagging).
    {
        std::unordered_map<std::string_view, std::vector<addr_t>> by_name;
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.name.empty()) continue;
            by_name[s.name].push_back(s.addr);
        }
        for (auto& [name, addrs] : by_name) {
            if (addrs.size() < 2) continue;
            std::sort(addrs.begin(), addrs.end());
            addrs.erase(std::unique(addrs.begin(), addrs.end()), addrs.end());
            if (addrs.size() < 2) continue;
            NameCollision nc;
            nc.name  = std::string{name};
            nc.addrs = std::move(addrs);
            out.by_name.push_back(std::move(nc));
        }
        std::sort(out.by_name.begin(), out.by_name.end(),
            [](const NameCollision& a, const NameCollision& bb) {
                return a.name < bb.name;
            });
    }

    // Fingerprint collisions: bucket every function's hash, emit groups
    // with size > 1. The fingerprint source is `precomputed` when
    // supplied (the cache-fed fast path) or compute-on-the-fly otherwise.
    {
        std::unordered_map<u64, std::vector<addr_t>> by_fp;
        if (!precomputed.empty()) {
            by_fp.reserve(precomputed.size());
            for (const auto& row : precomputed) {
                if (row.fp.hash == 0) continue;
                by_fp[row.fp.hash].push_back(row.addr);
            }
        } else {
            for (const auto& d : enumerate_functions(b)) {
                const auto fp = compute_fingerprint(b, d.addr);
                if (fp.hash == 0) continue;
                by_fp[fp.hash].push_back(d.addr);
            }
        }
        out.by_fingerprint.reserve(by_fp.size());
        for (auto& [hash, addrs] : by_fp) {
            if (addrs.size() < 2) continue;
            std::sort(addrs.begin(), addrs.end());
            FingerprintCollision fc;
            fc.hash  = hash;
            fc.addrs = std::move(addrs);
            out.by_fingerprint.push_back(std::move(fc));
        }
        std::sort(out.by_fingerprint.begin(), out.by_fingerprint.end(),
            [](const FingerprintCollision& a, const FingerprintCollision& bb) {
                return a.addrs.front() < bb.addrs.front();
            });
    }

    return out;
}

}  // namespace ember
