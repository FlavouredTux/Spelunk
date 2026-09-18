// Text views: disassembly, CFG and structured regions.

#include <spelunk/analysis/pipeline.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <expected>
#include <format>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/cfg_builder.hpp>
#include <spelunk/analysis/function.hpp>
#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/analysis/name_resolver.hpp>
#include <spelunk/analysis/type_infer_local.hpp>
#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/decompile/emit_options.hpp>
#include <spelunk/decompile/emitter.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/passes.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/structure/region.hpp>
#include <spelunk/structure/structurer.hpp>

#include "pipeline_internal.hpp"

namespace spelunk::pipeline {

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

std::span<const std::byte>
clamp_bytes(std::span<const std::byte> avail, u64 size) {
    if (avail.empty()) return avail;
    const u64 take = size > 0 ? std::min<u64>(size, avail.size())
                              : std::min<u64>(1024, avail.size());
    return avail.first(static_cast<std::size_t>(take));
}

}  // namespace

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

FuncWindow window_from_addr(addr_t start, u64 size_hint, std::string label) {
    FuncWindow w;
    w.start = start;
    w.size  = size_hint;
    w.label = std::move(label);
    return w;
}

}  // namespace spelunk::pipeline

namespace spelunk {

using namespace pipeline;

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w) {
    return format_disasm(b, w, DisasmOptions{});
}

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w, const DisasmOptions& opts) {
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
    std::vector<addr_t>     computed;
    std::span<const addr_t> callers;
    if (opts.callers) {
        callers = *opts.callers;
    } else {
        computed = compute_callers(b, w.start);
        callers  = computed;
    }
    if (!callers.empty()) {
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

    if (options.c_source) {
        for (const auto& block : fn_r->blocks) {
            if (block.kind == BlockKind::TailCall) continue;
            for (addr_t target : block.successors) {
                if (!fn_r->block_at.contains(target)) {
                    return std::unexpected(Error::not_implemented(std::format(
                        "C export for {} is incomplete: undecoded control-flow target {:#x}; use -d to inspect it",
                        w.label, target)));
                }
            }
        }
    }

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

}  // namespace spelunk
