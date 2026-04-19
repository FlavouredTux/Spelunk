#include <ember/analysis/pipeline.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <format>
#include <span>
#include <string>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/decompile/emitter.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/ir/x64_lifter.hpp>
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

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol) {
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
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.addr == addr && !s.name.empty()) {
            if (b.bytes_at(addr).empty()) return std::nullopt;
            return window_from_addr(addr, s.size, s.name);
        }
    }
    if (b.bytes_at(addr).empty()) return std::nullopt;
    return window_from_addr(addr, 0, std::format("sub_{:x}", addr));
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

    const X64Decoder dec;
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
    const X64Decoder dec;
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
    const X64Decoder dec;
    const CfgBuilder builder(b, dec);
    auto fn_r = builder.build(w.start, w.label);
    if (!fn_r) return std::unexpected(fn_r.error());
    std::string out;
    append_function_text(out, *fn_r);
    return out;
}

Result<std::string>
format_struct(const Binary& b, const FuncWindow& w,
              bool pseudo, const Annotations* ann,
              EmitOptions options) {
    const X64Decoder dec;
    const CfgBuilder builder(b, dec);
    auto fn_r = builder.build(w.start, w.label);
    if (!fn_r) return std::unexpected(fn_r.error());

    const X64Lifter lifter;
    auto ir_r = lifter.lift(*fn_r);
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
    const X64Decoder dec;
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
    const bool show = candidates >= 500;  // skip chatter on tiny fixtures

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
    const X64Decoder dec;
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

}  // namespace ember
