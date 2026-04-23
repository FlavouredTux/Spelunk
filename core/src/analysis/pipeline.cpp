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

    const Symbol* chosen = b.find_by_name(symbol.empty() ? "main" : symbol);
    if (chosen && chosen->is_import) chosen = nullptr;
    if (!symbol.empty() && chosen && chosen->is_import) chosen = nullptr;

    if (chosen) {
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
            out += std::format("{:#018x}  {:<30}  ; decode error: {}\n",
                               ip, hex_bytes(remaining.first(1)),
                               decoded.error().message);
            ip  += 1;
            off += 1;
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
            out += std::format("{:#018x}  {:<30}  ; decode error: {}\n",
                               ip, hex_bytes(remaining.first(1)),
                               decoded.error().message);
            ip  += 1;
            off += 1;
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

    std::vector<ClassifiedCallee> out;
    out.reserve(fn_r->call_targets.size());

    for (const auto& bb : fn_r->blocks) {
        for (const auto& insn : bb.instructions) {
            const Mnemonic mn = insn.mnemonic;

            if (is_call(mn)) {
                if (insn.num_operands == 0) continue;
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
                }
                continue;
            }

            if (is_unconditional_jmp(mn)) {
                if (auto t = branch_target(insn); t && callee_is_function_entry(b, *t)) {
                    out.push_back({*t, CalleeKind::Tail, insn.address});
                }
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

}  // namespace ember
