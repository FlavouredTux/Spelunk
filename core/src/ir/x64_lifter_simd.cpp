// Scalar floating point and packed SIMD.

#include <array>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {

void lift_cmpss(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3 ||
        insn.operands[2].kind != Operand::Kind::Immediate) return;
    static constexpr std::array names{
        "_mm_cmpeq_ss", "_mm_cmplt_ss", "_mm_cmple_ss", "_mm_cmpunord_ss",
        "_mm_cmpneq_ss", "_mm_cmpnlt_ss", "_mm_cmpnle_ss", "_mm_cmpord_ss",
    };
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = names[static_cast<u64>(insn.operands[2].imm.value) & 7u];
    i.dst = ctx.temp(IrType::I128);
    // The destination contributes all 128 bits; the source contributes only
    // its low float, including a four-byte load for the memory form.
    i.srcs[0] = read_xmm(ctx, insn.operands[0], IrType::I128);
    i.srcs[1] = materialize_fp_rvalue(insn.operands[1], ctx, IrType::F32);
    i.src_count = 2;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

// Read an operand as a scalar floating-point value at the requested type
// (F32 or F64). Xmm registers come back as `IrValue::make_reg(r, t)`;
// memory operands lift to a Load typed at `t`.
IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        return IrValue::make_reg(op.reg, t);
    }
    if (op.kind == Operand::Kind::Memory) {
        IrValue ea = compute_ea(op.mem, ctx);
        return ctx.emit_load(ea, t, op.mem.segment);
    }
    return IrValue{};
}

// Store a scalar FP value back to an xmm destination or memory operand.
void store_fp_lvalue(const Operand& op, IrValue value, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        if (ctx.preserve_scalar_lanes && is_xmm(op.reg)) {
            const auto& insn = *ctx.insn;
            const bool memory_load = (insn.mnemonic == Mnemonic::MovssLoad ||
                                      insn.mnemonic == Mnemonic::MovsdXmm) &&
                                     insn.operands[1].kind == Operand::Kind::Memory;
            const bool vex = (insn.x86_vex || insn.x86_evex) && insn.num_operands >= 3;
            IrInst lane;
            lane.op = IrOp::Intrinsic;
            lane.dst = ctx.temp(IrType::I128);
            lane.name = t == IrType::F32 ? "xmm.insert_f32" : "xmm.insert_f64";
            lane.srcs[0] = memory_load ? ctx.imm(0, IrType::I128)
                : IrValue::make_reg(vex ? insn.operands[1].reg : op.reg, IrType::I128);
            lane.srcs[1] = value;
            lane.src_count = 2;
            const auto result = lane.dst;
            ctx.emit(std::move(lane));
            ctx.emit_assign(IrValue::make_reg(op.reg, IrType::I128), result);
            return;
        }
        ctx.emit_assign(IrValue::make_reg(op.reg, t), value);
        return;
    }
    if (op.kind == Operand::Kind::Memory) {
        IrValue ea = compute_ea(op.mem, ctx);
        ctx.emit_store(ea, value, op.mem.segment);
    }
}

// Lift a scalar-FP binary op like `addsd xmm0, xmm1` or `addsd xmm0, [mem]`.
// Operand 0 is both source and destination (x86-two-operand form).
void lift_fp_binop(LiftCtx& ctx, IrOp op, IrType t) {
    const auto& insn = *ctx.insn;
    const bool nondestructive = (insn.x86_vex || insn.x86_evex) &&
                                insn.num_operands >= 3;
    if ((!nondestructive && insn.num_operands != 2) ||
        (nondestructive && insn.num_operands < 3)) return;
    IrValue a = materialize_fp_rvalue(
        insn.operands[nondestructive ? 1 : 0], ctx, t);
    IrValue b = materialize_fp_rvalue(
        insn.operands[nondestructive ? 2 : 1], ctx, t);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None) return;
    IrValue result = ctx.emit_binop(op, a, b);
    store_fp_lvalue(insn.operands[0], result, ctx, t);
}

// Scalar-FP move. `storing` selects the MovssStore / MovsdXmmStore variant,
// where operand 0 is the destination r/m (and may be memory).
void lift_fp_mov(LiftCtx& ctx, IrType t, bool storing) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    const Operand& dst = insn.operands[0];
    const Operand& src = insn.operands[1];
    (void)storing;  // operand order already encodes it
    IrValue v = materialize_fp_rvalue(src, ctx, t);
    if (v.kind == IrValueKind::None) return;
    store_fp_lvalue(dst, v, ctx, t);
}

// ----- Packed SIMD intrinsics --------------------------------------------
//
// XMM dataflow at the register-width level uses IrType::I128 - the actual
// 128-bit width - so the upper 64 bits aren't silently truncated by the
// loads/stores that used to flow through F64. The reader still gets named
// intrinsics (`_mm_xor_ps`, `_mm_add_pd`, …) that carry the lane-width
// interpretation; the IR-level type is just an honest "16-byte
// register-shaped value".
//
// `read_xmm`/`write_xmm` honour the caller's `t` because half-XMM moves
// like `movhps` / `movlps` deliberately transfer 64 bits into one half of
// the register and need that narrower type to round-trip. Full-XMM ops
// (lift_simd_binop, lift_simd_shift_imm, the 128-bit lift_simd_mov path)
// pin t = I128 at the call site below.
IrValue read_xmm(LiftCtx& ctx, const Operand& op, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        if (!is_x86_vector(op.reg)) {
            return ctx.match_size(ctx.read_reg(op.reg), t, /*sign_ext=*/false);
        }
        return IrValue::make_reg(op.reg, t);
    }
    if (op.kind == Operand::Kind::Memory) {
        IrValue ea = compute_ea(op.mem, ctx);
        return ctx.emit_load(ea, t, op.mem.segment);
    }
    return IrValue{};
}

void write_xmm(LiftCtx& ctx, const Operand& op, IrValue v, IrType t) {
    if (ctx.preserve_scalar_lanes && is_float_type(t)) {
        store_fp_lvalue(op, v, ctx, t);
        return;
    }
    if (op.kind == Operand::Kind::Register) {
        if (!is_x86_vector(op.reg)) {
            v = ctx.match_size(v, operand_type(op), /*sign_ext=*/false);
            store_lvalue(op, v, ctx);
            return;
        }
        ctx.emit_assign(IrValue::make_reg(op.reg, t), v);
        return;
    }
    if (op.kind == Operand::Kind::Memory) {
        IrValue ea = compute_ea(op.mem, ctx);
        ctx.emit_store(ea, v, op.mem.segment);
    }
}

// Two-operand packed intrinsic: `op xmm_dst, xmm/m`. Reads both as `t`,
// emits a named Intrinsic, writes the result back to operand 0. Used for
// every commutative-or-not SSE binary op that lacks a clean infix form
// (xor/and/or/andnot, packed integer arithmetic, packed compares,
// unpacks, shuffles).
// `t` is the IR-level type of the produced value:
//   - I128 for any full-XMM op (every `_mm_*_ps`, `_mm_*_pd`, `_mm_*_si128`,
//     `_mm_*_epi*`, shuffle/unpack, etc.). Carries the full 128-bit width so
//     SSA / cleanup / emit don't truncate the upper 64 bits.
//   - F32 / F64 for scalar-low-lane ops (`_mm_min_ss`, `_mm_max_sd`, etc.) -
//     architecturally these only modify the low lane and the compiler treats
//     the result as scalar. Keeping them at scalar width lets the surrounding
//     scalar-FP code (Movss/Movsd loads, return values) flow naturally.
void lift_simd_binop(LiftCtx& ctx, std::string_view name, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    if ((insn.x86_vex || insn.x86_evex) && t == IrType::I128) {
        t = insn.x86_vector_bits == 3 ? IrType::I512
            : (insn.x86_vector_bits == 2 ? IrType::I256 : IrType::I128);
    }
    const bool unary_shuffle = insn.mnemonic == Mnemonic::Pshufd ||
        insn.mnemonic == Mnemonic::Pshuflw || insn.mnemonic == Mnemonic::Pshufhw;
    const bool nondestructive = !unary_shuffle && (insn.x86_vex || insn.x86_evex) &&
                                insn.num_operands >= 3;
    IrValue a = read_xmm(ctx, insn.operands[unary_shuffle || nondestructive ? 1 : 0], t);
    IrValue b = unary_shuffle ? IrValue{} : read_xmm(ctx, insn.operands[nondestructive ? 2 : 1], t);
    if (a.kind == IrValueKind::None || (!unary_shuffle && b.kind == IrValueKind::None)) return;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    if (t == IrType::I256 && i.name.starts_with("_mm_")) {
        i.name.replace(0, 4, "_mm256_");
    } else if (t == IrType::I512 && i.name.starts_with("_mm_")) {
        i.name.replace(0, 4, "_mm512_");
    }
    if (insn.x86_evex && insn.x86_mask != 0) {
        i.name = std::format("avx512.{}.{}",
            insn.x86_zeroing ? "maskz" : "mask", i.name);
    }
    i.dst  = ctx.temp(t);
    i.srcs[0]   = a;
    i.src_count = 1;
    if (!unary_shuffle) i.srcs[i.src_count++] = b;
    // Shuffle controls are unsigned encoding bytes, not signed constants.
    const std::size_t immediate_index = nondestructive ? 3u : 2u;
    if (insn.num_operands > immediate_index &&
        insn.operands[immediate_index].kind == Operand::Kind::Immediate) {
        const Imm& im = insn.operands[immediate_index].imm;
        i.srcs[i.src_count++] = ctx.imm(static_cast<u8>(im.value), IrType::I32);
    }
    if (insn.x86_evex && insn.x86_mask != 0 &&
        i.src_count < i.srcs.size()) {
        i.srcs[i.src_count++] = IrValue::make_reg(
            static_cast<Reg>(static_cast<unsigned>(Reg::K0) + insn.x86_mask),
            IrType::I64);
    }
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, t);
}

// SSE2 immediate-shift shape: `psllw xmm, imm8` and friends. The
// regular lift_simd_binop path tries to `read_xmm(operands[1])`,
// which fails for immediates - so the shift would silently emit
// nothing. Here we pin operand[0] as the xmm to shift, operand[1]
// as the imm, and emit a named intrinsic with both. Result writes
// back to operand[0].
void lift_simd_shift_imm(LiftCtx& ctx, std::string_view name, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    if (insn.operands[1].kind != Operand::Kind::Immediate) return;
    IrValue a = read_xmm(ctx, insn.operands[0], t);
    if (a.kind == IrValueKind::None) return;
    const Imm& im = insn.operands[1].imm;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(t);
    i.srcs[0]   = a;
    i.srcs[1]   = ctx.imm(im.value, type_for_bits(im.size * 8));
    i.src_count = 2;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, t);
}

// `pinsrw xmm, r/m16, imm8`: vector in/out, scalar lane source.
// The generic XMM binop helper reads every operand as vector-shaped, which is
// wrong for this GPR/memory source and pollutes the intrinsic arguments.
void lift_pinsrw(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3 ||
        insn.operands[2].kind != Operand::Kind::Immediate) {
        return;
    }

    IrValue vec = read_xmm(ctx, insn.operands[0], IrType::I128);
    IrValue lane = materialize_rvalue(insn.operands[1], ctx);
    if (vec.kind == IrValueKind::None || lane.kind == IrValueKind::None) return;
    lane = ctx.match_size(lane, IrType::I16, /*sign_ext=*/false);

    const Imm& im = insn.operands[2].imm;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = "_mm_insert_epi16";
    i.dst  = ctx.temp(IrType::I128);
    i.srcs[0]   = vec;
    i.srcs[1]   = lane;
    i.srcs[2]   = ctx.imm(im.value, type_for_bits(im.size * 8));
    i.src_count = 3;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

// `pextrw r32/m16, xmm, imm8`: scalar result, vector source. Legacy SSE2
// zero-extends the selected 16-bit lane into a 32-bit register destination;
// the SSE4.1 memory form stores only the selected word. Lifting this as
// vector out made return types become `__m128i`.
void lift_pextrw(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3 ||
        insn.operands[2].kind != Operand::Kind::Immediate) {
        return;
    }

    IrValue src = read_xmm(ctx, insn.operands[1], IrType::I128);
    if (src.kind == IrValueKind::None) return;

    const Imm& im = insn.operands[2].imm;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = "_mm_extract_epi16";
    i.dst  = ctx.temp(IrType::I32);
    i.srcs[0]   = src;
    i.srcs[1]   = ctx.imm(im.value, type_for_bits(im.size * 8));
    i.src_count = 2;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, operand_type(insn.operands[0]), /*sign_ext=*/false);
    store_lvalue(insn.operands[0], result, ctx);
}

// `movdqa xmm, xmm/m128` (and unaligned `movdqu`). Treated as a typed
// load+store at the chosen SIMD width - the IR carries the dataflow, the
// emitter prints `xmm0 = *(__m128i*)(rsi);` style.
void lift_simd_mov(LiftCtx& ctx, IrType t, bool storing) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    (void)storing;  // operand order already encodes it
    if ((insn.x86_vex || insn.x86_evex) && t == IrType::I128) {
        t = insn.x86_vector_bits == 3 ? IrType::I512
            : (insn.x86_vector_bits == 2 ? IrType::I256 : IrType::I128);
    }
    IrValue v = read_xmm(ctx, insn.operands[1], t);
    if (v.kind == IrValueKind::None) return;
    write_xmm(ctx, insn.operands[0], v, t);
}

// `movd/movq xmm, r/m32|64`: copy a scalar into the low lane and zero the
// rest of the XMM register. A plain scalar assignment leaves later lane
// consumers thinking they are extracting from an integer, not a vector-shaped
// value.
void lift_gpr_scalar_to_xmm(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    if (src.kind == IrValueKind::None) return;
    const IrType scalar_t = operand_type(insn.operands[1]) == IrType::I64
        ? IrType::I64
        : IrType::I32;
    src = ctx.match_size(src, scalar_t, /*sign_ext=*/false);

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = scalar_t == IrType::I64 ? "_mm_cvtsi64_si128"
                                     : "_mm_cvtsi32_si128";
    i.dst  = ctx.temp(IrType::I128);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

// `movd/movq r/m32|64, xmm`: extract the low scalar from an XMM value. This
// must pass through normal GPR store semantics so `eax` writes zero-extend
// into `rax`.
void lift_gpr_scalar_from_xmm(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = read_xmm(ctx, insn.operands[1], IrType::I128);
    if (src.kind == IrValueKind::None) return;
    const IrType scalar_t = operand_type(insn.operands[0]) == IrType::I64
        ? IrType::I64
        : IrType::I32;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = scalar_t == IrType::I64 ? "_mm_cvtsi128_si64"
                                     : "_mm_cvtsi128_si32";
    i.dst  = ctx.temp(scalar_t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, operand_type(insn.operands[0]), /*sign_ext=*/false);
    store_lvalue(insn.operands[0], result, ctx);
}

// `ucomiss xmm0, xmm1` / `ucomisd xmm0, xmm1`: scalar FP compare that sets
// ZF / CF / PF. The architecturally faithful mapping is:
//   ordered:    ZF = (a == b)   CF = (a < b)   PF = 0
//   unordered:  ZF = 1          CF = 1         PF = 1     (one of a, b is NaN)
//
// Materialize unordered at the compare, so a later XMM write cannot change
// the parity predicate. SF and OF are cleared even if an integer operation
// left them set before the comparison.
void lift_ucomi(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue b = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None) return;
    IrInst unordered;
    unordered.op = IrOp::Intrinsic;
    unordered.name = "unordered_fp_compare";
    unordered.dst = ctx.temp(IrType::I1);
    unordered.srcs[0] = a;
    unordered.srcs[1] = b;
    unordered.src_count = 2;
    const auto pf = unordered.dst;
    ctx.emit(std::move(unordered));
    ctx.emit_set_flag(Flag::Zf, ctx.emit_binop_i1(IrOp::Or, pf, ctx.emit_cmp(IrOp::CmpEq, a, b)));
    ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(IrOp::Or, pf, ctx.emit_cmp(IrOp::CmpUlt, a, b)));
    ctx.emit_set_flag(Flag::Sf, ctx.imm(0, IrType::I1));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    ctx.last_pf_value = pf;
    ctx.last_fp_cmp_a = a;
    ctx.last_fp_cmp_b = b;
}

// Scalar-FP unary with no clean infix: sqrtss/sqrtsd. Models as a named
// intrinsic so the reader sees `sqrtf(x)` / `sqrt(x)` (the libm names),
// plus the usual two-operand x86 `dst, src` form where dst==operand[0].
void lift_fp_unop(LiftCtx& ctx, std::string_view name, IrType t) {
    const auto& insn = *ctx.insn;
    const bool vex_scalar = (insn.x86_vex || insn.x86_evex) &&
                            insn.num_operands >= 3;
    if ((!vex_scalar && insn.num_operands != 2) ||
        (vex_scalar && insn.num_operands < 3)) return;
    IrValue src = materialize_fp_rvalue(
        insn.operands[vex_scalar ? 2 : 1], ctx, t);
    if (src.kind == IrValueKind::None) return;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    store_fp_lvalue(insn.operands[0], result, ctx, t);
}

// Conversions: gpr/m -> xmm (cvtsi2ss/sd), xmm/m -> gpr (cvtt*2si),
// xmm -> xmm width change (cvtss2sd / cvtsd2ss). Kept as named intrinsics
// rather than introducing a dedicated IrOp::FpConv - the cast itself is
// the dataflow, and the emitter prints `xmm0 = cvtsi2ss(rax);` cleanly.
void lift_int_to_fp(LiftCtx& ctx, std::string_view name, IrType dst_t) {
    const auto& insn = *ctx.insn;
    const bool vex_form = (insn.x86_vex || insn.x86_evex) &&
                          insn.num_operands >= 3;
    if ((!vex_form && insn.num_operands != 2) ||
        (vex_form && insn.num_operands < 3)) return;
    IrValue src = materialize_rvalue(insn.operands[vex_form ? 2 : 1], ctx);
    if (src.kind == IrValueKind::None) return;
    // CVTSI2S* interprets the encoded integer width as signed, independently
    // of parameter types or the zero-extension caused by an earlier EAX write.
    src = ctx.match_size(src, IrType::I64, /*sign_ext=*/true);
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(dst_t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    store_fp_lvalue(insn.operands[0], result, ctx, dst_t);
}

void lift_fp_to_int(LiftCtx& ctx, std::string_view name, IrType src_t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, src_t);
    if (src.kind == IrValueKind::None) return;
    const IrType dst_t = operand_type(insn.operands[0]);
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(dst_t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(insn.operands[0], result, ctx);
}

void lift_fp_to_fp(LiftCtx& ctx, std::string_view name, IrType src_t,
                   IrType dst_t) {
    const auto& insn = *ctx.insn;
    const bool vex_form = (insn.x86_vex || insn.x86_evex) &&
                          insn.num_operands >= 3;
    if ((!vex_form && insn.num_operands != 2) ||
        (vex_form && insn.num_operands < 3)) return;
    IrValue src = materialize_fp_rvalue(
        insn.operands[vex_form ? 2 : 1], ctx, src_t);
    if (src.kind == IrValueKind::None) return;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(dst_t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    store_fp_lvalue(insn.operands[0], result, ctx, dst_t);
}

// SetCC: write 0 or 1 to a byte destination based on the flag predicate.
// Reuses jcc_predicate() so the flag logic is shared with conditional
// branches - i.e. `sete` and `je` compute the same i1.
void lift_setcc(LiftCtx& ctx, Mnemonic mn) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    Mnemonic jcc_equiv = Mnemonic::Invalid;
    switch (mn) {
        case Mnemonic::Seto:   jcc_equiv = Mnemonic::Jo;   break;
        case Mnemonic::Setno:  jcc_equiv = Mnemonic::Jno;  break;
        case Mnemonic::Setb:   jcc_equiv = Mnemonic::Jb;   break;
        case Mnemonic::Setae:  jcc_equiv = Mnemonic::Jae;  break;
        case Mnemonic::Sete:   jcc_equiv = Mnemonic::Je;   break;
        case Mnemonic::Setne:  jcc_equiv = Mnemonic::Jne;  break;
        case Mnemonic::Setbe:  jcc_equiv = Mnemonic::Jbe;  break;
        case Mnemonic::Seta:   jcc_equiv = Mnemonic::Ja;   break;
        case Mnemonic::Sets:   jcc_equiv = Mnemonic::Js;   break;
        case Mnemonic::Setns:  jcc_equiv = Mnemonic::Jns;  break;
        case Mnemonic::Setp:   jcc_equiv = Mnemonic::Jp;   break;
        case Mnemonic::Setnp:  jcc_equiv = Mnemonic::Jnp;  break;
        case Mnemonic::Setl:   jcc_equiv = Mnemonic::Jl;   break;
        case Mnemonic::Setge:  jcc_equiv = Mnemonic::Jge;  break;
        case Mnemonic::Setle:  jcc_equiv = Mnemonic::Jle;  break;
        case Mnemonic::Setg:   jcc_equiv = Mnemonic::Jg;   break;
        default: return;
    }
    IrValue cond = jcc_predicate(jcc_equiv, ctx);
    IrValue byte = ctx.emit_convert(IrOp::ZExt, cond, IrType::I8);
    store_lvalue(insn.operands[0], byte, ctx);
}

// String ops: implicit rdi/rsi/rcx/rax operands. Model as an intrinsic that
// reads those registers and then clobbers rdi/rsi/rcx (and rax for scas/lods).
// Keeps liveness honest without trying to model the exact `rep`-loop semantics.
void lift_string_op(LiftCtx& ctx, std::string_view name,
                    bool touches_rsi, bool touches_rax) {
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.srcs[0]   = ctx.read_reg(Reg::Rdi);
    i.srcs[1]   = touches_rsi ? ctx.read_reg(Reg::Rsi) : ctx.read_reg(Reg::Rax);
    i.srcs[2]   = ctx.read_reg(Reg::Rcx);
    i.src_count = 3;
    ctx.emit(std::move(i));

    auto clobber = [&](Reg r) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    };
    clobber(Reg::Rdi);
    if (touches_rsi) clobber(Reg::Rsi);
    if (touches_rax) clobber(Reg::Rax);
    clobber(Reg::Rcx);
}

}  // namespace spelunk::x64_lift
