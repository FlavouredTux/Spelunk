#include <ember/analysis/pipeline.hpp>

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <format>
#include <optional>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

#include <ember/analysis/objc.hpp>
#include <ember/analysis/rtti.hpp>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/common/progress.hpp>
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

bool is_terminator(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Ret:
        case Mnemonic::Jmp:
        case Mnemonic::Ud2:
        case Mnemonic::Hlt:
            return true;
        default:
            return false;
    }
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
// aren't themselves a valid instruction start — skipping them avoids
// seeing them twice. VEX/EVEX take a wider swath because their payload
// bytes are drawn from a very different opcode space; one cautious
// forward jump is better than a multi-instruction cascade.
std::size_t decode_failure_advance(std::span<const std::byte> bytes) noexcept {
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

void append_function_text(std::string& out, const Function& fn) {
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
                               format_instruction(insn));
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
// only — bare hex strings collide with legitimate symbol names like
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

// Resolve `addr` to the nearest containing function entry. Uses the
// defined-objects cache for an O(log n) lookup. Returns a FuncWindow
// whose `start` is the function entry (NOT `addr` itself) when `addr`
// lies inside a known function's extent; the label carries the offset
// so the caller can annotate the output. Nullopt when nothing contains
// `addr` and `addr` itself has no bytes mapped.
[[nodiscard]] std::optional<FuncWindow>
resolve_containing_function(const Binary& b, addr_t addr) {
    const Symbol* c = b.defined_object_at(addr);
    if (c && c->kind == SymbolKind::Function && c->addr != 0) {
        if (b.bytes_at(c->addr).empty()) return std::nullopt;
        if (c->addr == addr) {
            return window_from_addr(c->addr, c->size, c->name);
        }
        const u64 off = addr - c->addr;
        if (c->size == 0 || off < c->size) {
            std::fprintf(stderr,
                "ember: note: %#llx is inside %s at +%#llx\n",
                static_cast<unsigned long long>(addr),
                c->name.c_str(),
                static_cast<unsigned long long>(off));
            return window_from_addr(c->addr, c->size,
                                    std::format("{}+{:#x}", c->name, off));
        }
    }
    if (b.bytes_at(addr).empty()) return std::nullopt;
    return window_from_addr(addr, 0, std::format("sub_{:x}", addr));
}

}  // namespace

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol) {
    // Obj-C bracket form: -[Class sel] / +[Class sel] — look up the IMP
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
        return resolve_containing_function(b, *va);
    }

    const std::string_view lookup = symbol.empty() ? "main" : symbol;
    const Symbol* chosen = b.find_by_name(lookup);
    if (chosen && chosen->is_import) chosen = nullptr;
    if (!symbol.empty() && chosen && chosen->is_import) chosen = nullptr;

    if (chosen) {
        // Fingerprint import and user renames can silently bind the same
        // name to multiple addresses. Refuse the lookup rather than
        // picking the first — a wrong-address answer presents as phantom
        // bugs downstream.
        const auto all = b.find_all_by_name(lookup);
        if (all.size() > 1) {
            std::fprintf(stderr,
                "ember: name '%.*s' is ambiguous — matches %zu addresses:",
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
        if (b.bytes_at(chosen->addr).empty()) return std::nullopt;
        return window_from_addr(chosen->addr, chosen->size, chosen->name);
    }
    if (!symbol.empty()) return std::nullopt;

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

    auto dec_r = make_decoder(b);
    if (!dec_r) return std::unexpected(dec_r.error());
    const Decoder& dec = **dec_r;
    addr_t ip = w.start;
    std::size_t off = 0;
    const bool size_known = bytes.size() < 1024 && w.size != 0;

    while (off < bytes.size()) {
        const auto remaining = bytes.subspan(off);
        auto decoded = dec.decode(remaining, ip);
        if (!decoded) {
            const std::size_t skip = decode_failure_advance(remaining);
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
                           ip, hex_bytes(bv), format_instruction(insn));
        ip  += insn.length;
        off += insn.length;
        if (!size_known && is_terminator(insn.mnemonic)) break;
    }
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
            const std::size_t skip = decode_failure_advance(remaining);
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
                           ip, hex_bytes(bv), format_instruction(insn));
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
    append_function_text(out, *fn_r);
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

    // Bypass the structurer entirely. Per-block emission needs the SSA-
    // cleaned IR but explicitly does NOT want regions collapsing block
    // boundaries — that's the whole point of the per-bb view.
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
    auto fn_r = builder.build(w.start, w.label);
    if (!fn_r) return std::unexpected(fn_r.error());

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return std::unexpected(lifter_r.error());
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return std::unexpected(ir_r.error());

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return std::unexpected(rv.error());

    if (auto rv = run_cleanup(*ir_r); !rv) return std::unexpected(rv.error());

    const Structurer structurer;
    auto s_r = structurer.structure(*ir_r);
    if (!s_r) return std::unexpected(s_r.error());

    if (pseudo) {
        const PseudoCEmitter emitter;
        auto c_r = emitter.emit(*s_r, &b, ann, options);
        if (!c_r) return std::unexpected(c_r.error());
        return std::move(*c_r);
    }
    return format_structured(*s_r);
}

std::vector<CallEdge> compute_call_graph(const Binary& b) {
    std::vector<CallEdge> out;
    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const Decoder& dec = **dec_r;
    const CfgBuilder builder(b, dec);

    std::size_t candidates = 0;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.size == 0 || s.name.empty()) continue;
        ++candidates;
    }
    const auto tick = std::max<std::size_t>(1, candidates / 20);
    std::size_t done = 0;
    const bool show = candidates >= 500 && progress_enabled();

    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.size == 0 || s.name.empty()) continue;
        auto fn_r = builder.build(s.addr, s.name);
        ++done;
        if (show && (done % tick == 0 || done == candidates)) {
            std::fprintf(stderr, "\r  call graph: [%zu/%zu]", done, candidates);
            std::fflush(stderr);
        }
        if (!fn_r) continue;
        for (auto t : fn_r->call_targets) out.push_back({s.addr, t});
    }
    if (show) std::fputc('\n', stderr);
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

std::vector<DiscoveredFunction> enumerate_functions(const Binary& b) {
    std::vector<DiscoveredFunction> out;

    // Pass 1: defined function symbols. These carry real sizes, so prefer
    // them when a later CFG-discovered entry lands on the same address.
    std::unordered_map<addr_t, std::size_t> index;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (index.count(s.addr)) continue;
        index.emplace(s.addr, out.size());
        out.push_back({s.addr, s.size, s.name,
                       DiscoveredFunction::Kind::Symbol});
    }

    // Pass 2: CFG-walked call targets. Skip PLT stubs (import thunks).
    // Unknown size for these — stripped binaries don't tell us where they
    // end without a CFG build we don't want to run on every enumerate.
    for (const auto& e : compute_call_graph(b)) {
        if (b.import_at_plt(e.callee) != nullptr) continue;
        if (index.count(e.callee)) continue;
        index.emplace(e.callee, out.size());
        out.push_back({e.callee, 0, std::format("sub_{:x}", e.callee),
                       DiscoveredFunction::Kind::Sub});
    }

    std::sort(out.begin(), out.end(),
              [](const auto& x, const auto& y) { return x.addr < y.addr; });
    return out;
}

namespace {

// True when `target` is the entry of a defined function or a PLT stub —
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
compute_classified_callees(const Binary& b, addr_t fn) {
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

    // Vtable index for the back-trace. Itanium ABI covers both Mach-O
    // and ELF C++ binaries; `parse_itanium_rtti` already walks
    // `__const`, `.data.rel.ro`, and `.rodata`. PE is MSVC-RTTI shaped
    // differently — handled elsewhere, not yet wired here.
    //
    // Key subtlety: `RttiClass::vtable` is the *typeinfo slot* (offset
    // 8 inside the vtable struct). The ABI-defined vptr — the value
    // stored in every object's head and the value the compiler loads
    // when emitting `lea reg, [rip + K]` — points at `methods[0]`,
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

            // `lea dst, [rip + K]` — arm dst as carrying a vptr when
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

            // `mov dst, <src>` — multiple cases. See disarm() fallback
            // at the bottom.
            if (mn == Mnemonic::Mov && insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register) {
                const Reg dst   = insn.operands[0].reg;
                const Reg dst_c = canonical_reg(dst);
                const auto& src = insn.operands[1];
                bool armed = false;
                if (reg_size(dst) == 8) {
                    // mov dst, [rip + K] — *K might be a stored vptr.
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
                    // mov dst, [reg + disp] — slot load from an armed
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
                    // mov dst, src_reg — one-hop reg→reg copy of any
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
    // Build a sorted (start → DiscoveredFunction) index once per call.
    // enumerate_functions already dedupes and sorts; copy into a pair
    // vector so we can binary-search by start.
    const auto fns = enumerate_functions(b);
    if (fns.empty()) return std::nullopt;

    // `fns` is already sorted by addr ascending. upper_bound finds the
    // first entry strictly greater than `addr`; the one before it is
    // the candidate.
    auto it = std::upper_bound(fns.begin(), fns.end(), addr,
        [](addr_t a, const DiscoveredFunction& d) { return a < d.addr; });
    if (it == fns.begin()) return std::nullopt;
    --it;

    // Respect the known extent when the symbol gives us one. A symbol
    // with size=0 (stripped `sub_*` entries) is treated as open-ended:
    // we still return it because the decompiler will walk it via the
    // terminator. Caller sees offset_within = addr - entry regardless.
    if (it->size != 0 && addr >= it->addr + it->size) return std::nullopt;
    if (b.bytes_at(it->addr).empty()) return std::nullopt;

    ContainingFn out;
    out.entry         = it->addr;
    out.size          = it->size;
    out.name          = it->name;
    out.offset_within = addr - it->addr;
    return out;
}

std::map<addr_t, addr_t>
compute_call_resolutions(const Binary& b, addr_t fn) {
    std::map<addr_t, addr_t> out;
    for (const auto& e : compute_classified_callees(b, fn)) {
        // First writer wins when two edges share a site — the
        // classifier already sorts by (target, kind, site), but a given
        // `call` instruction is only classified once in practice.
        out.emplace(e.site, e.target);
    }
    return out;
}

}  // namespace ember
