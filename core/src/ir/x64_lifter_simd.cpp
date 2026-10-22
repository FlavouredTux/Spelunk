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
    // Same-register idioms do not read the register: `pxor x, x` and
    // `psub x, x` produce zero and `pcmpeq x, x` all ones. Lifting them as
    // constants keeps a stale entry value out of the dataflow.
    const Operand& left_op = insn.operands[unary_shuffle || nondestructive ? 1 : 0];
    const Operand& right_op = insn.operands[nondestructive ? 2 : 1];
    if (!unary_shuffle && (t == IrType::I128 || t == IrType::I256) &&
        !(insn.x86_evex && insn.x86_mask != 0) &&
        left_op.kind == Operand::Kind::Register && right_op.kind == Operand::Kind::Register &&
        left_op.reg == right_op.reg) {
        const bool zero = name == "_mm_xor_si128" || name == "_mm_xor_ps" || name == "_mm_xor_pd" ||
            name == "_mm_andnot_si128" || name == "_mm_andnot_ps" || name == "_mm_andnot_pd" ||
            name.starts_with("_mm_sub_epi") || name.starts_with("_mm_cmpgt_epi");
        const bool ones = name.starts_with("_mm_cmpeq_epi");
        if (zero || ones) {
            IrInst constant;
            constant.op = IrOp::Intrinsic;
            constant.name = vector_name(zero ? "_mm_setzero_si128" : "_mm_set1_epi32", t);
            constant.dst = ctx.temp(t);
            if (ones) constant.srcs[constant.src_count++] = ctx.imm(-1, IrType::I32);
            const IrValue result = constant.dst;
            ctx.emit(std::move(constant));
            write_xmm(ctx, insn.operands[0], result, t);
            return;
        }
    }
    IrValue a = read_xmm(ctx, left_op, t);
    // `_mm256_sll_epi32(v, count)` takes its count as an __m128i.
    const bool count_operand = name.starts_with("_mm_sll_") || name.starts_with("_mm_srl_") ||
                               name.starts_with("_mm_sra_");
    IrValue b = unary_shuffle ? IrValue{}
        : read_xmm(ctx, right_op, count_operand ? IrType::I128 : t);
    if (a.kind == IrValueKind::None || (!unary_shuffle && b.kind == IrValueKind::None)) return;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = vector_name(name, t);
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
    // Legacy `psllq xmm, imm`; VEX `vpsllq dst(vvvv), src, imm`.
    const std::size_t source = insn.num_operands == 3 ? 1 : 0;
    if (insn.num_operands < 2) return;
    if (insn.operands[source + 1].kind != Operand::Kind::Immediate) return;
    if (t == IrType::I128) t = vector_type(insn);
    IrValue a = read_xmm(ctx, insn.operands[source], t);
    if (a.kind == IrValueKind::None) return;
    const Imm& im = insn.operands[source + 1].imm;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = vector_name(name, t);
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

IrType vector_type(const Instruction& insn) noexcept {
    if (!insn.x86_vex && !insn.x86_evex) return IrType::I128;
    return insn.x86_vector_bits == 3 ? IrType::I512
        : (insn.x86_vector_bits == 2 ? IrType::I256 : IrType::I128);
}

std::string vector_name(std::string_view name, IrType type) {
    std::string result(name);
    if (!result.starts_with("_mm_") || (type != IrType::I256 && type != IrType::I512)) return result;
    const bool wide = type == IrType::I512;
    result.replace(0, 4, wide ? "_mm512_" : "_mm256_");
    // Whole-register integer ops name the register width: `_mm256_and_si256`.
    if (result.ends_with("_si128")) {
        result.replace(result.size() - 3, 3, wide ? "512" : "256");
    }
    return result;
}

void lift_simd_unop(LiftCtx& ctx, std::string_view name, VectorShape shape) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    const IrType width = vector_type(insn);
    const IrType source_type = shape == VectorShape::Widening ? IrType::I128 : width;
    const IrType result_type = shape == VectorShape::Narrowing ? IrType::I128 : width;
    const Operand& source = insn.operands[1];
    IrValue src;
    if (source.kind == Operand::Kind::Memory && source.mem.size != 0 && source.mem.size < 16 &&
        source.mem.size * 8u < type_bits(source_type)) {
        // Only the low lanes are read; widen them into a vector value.
        // A float broadcast loads the float itself, so a constant renders as
        // its value.
        const bool float_lane = (name.ends_with("broadcastss_ps") && source.mem.size == 4) ||
                                (name.ends_with("broadcastsd_pd") && source.mem.size == 8);
        const IrType narrow = float_lane ? (source.mem.size == 4 ? IrType::F32 : IrType::F64)
                                         : type_for_bits(source.mem.size * 8u);
        IrValue loaded = ctx.emit_load(compute_ea(source.mem, ctx), narrow, source.mem.segment);
        IrInst widen;
        widen.op = IrOp::Intrinsic;
        widen.name = narrow == IrType::F32 ? "_mm_set_ss"
            : (narrow == IrType::F64 ? "_mm_set_sd"
            : (narrow == IrType::I64 ? "_mm_cvtsi64_si128" : "_mm_cvtsi32_si128"));
        widen.dst = ctx.temp(IrType::I128);
        widen.srcs[0] = narrow == IrType::I64 || float_lane ? loaded
            : ctx.match_size(loaded, IrType::I32, /*sign_ext=*/false);
        widen.src_count = 1;
        src = widen.dst;
        ctx.emit(std::move(widen));
    } else {
        src = read_xmm(ctx, source, source_type);
    }
    if (src.kind == IrValueKind::None) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = vector_name(name, width);
    i.dst = ctx.temp(result_type);
    i.srcs[0] = src;
    i.src_count = 1;
    if (insn.num_operands > 2 && insn.operands[2].kind == Operand::Kind::Immediate) {
        i.srcs[i.src_count++] = ctx.imm(static_cast<u8>(insn.operands[2].imm.value), IrType::I32);
    }
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, result_type);
}

void lift_simd_to_gpr(LiftCtx& ctx, std::string_view name, IrType result_type) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    // movmsk reads the whole (VEX.256) register; lane extracts read an xmm.
    const IrType width = name.starts_with("_mm_movemask") ? vector_type(insn) : IrType::I128;
    IrValue src = read_xmm(ctx, insn.operands[1], width);
    if (src.kind == IrValueKind::None) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = vector_name(name, width);
    i.dst = ctx.temp(result_type);
    i.srcs[0] = src;
    i.src_count = 1;
    if (insn.num_operands > 2 && insn.operands[2].kind == Operand::Kind::Immediate) {
        i.srcs[i.src_count++] = ctx.imm(static_cast<u8>(insn.operands[2].imm.value), IrType::I32);
    }
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, operand_type(insn.operands[0]), /*sign_ext=*/false);
    store_lvalue(insn.operands[0], result, ctx);
}

void lift_simd_insert(LiftCtx& ctx, std::string_view name, IrType lane_type) {
    const auto& insn = *ctx.insn;
    // Legacy `pinsrd xmm, r/m, imm`; VEX `vpinsrd xmm, xmm(vvvv), r/m, imm`.
    const std::size_t base = insn.num_operands == 4 ? 1 : 0;
    if (insn.num_operands != 3 + base ||
        insn.operands[2 + base].kind != Operand::Kind::Immediate) return;
    IrValue vec = read_xmm(ctx, insn.operands[base], IrType::I128);
    IrValue lane = materialize_rvalue(insn.operands[1 + base], ctx);
    if (vec.kind == IrValueKind::None || lane.kind == IrValueKind::None) return;
    lane = ctx.match_size(lane, lane_type, /*sign_ext=*/false);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = ctx.temp(IrType::I128);
    i.srcs[0] = vec;
    i.srcs[1] = lane;
    i.srcs[2] = ctx.imm(static_cast<u8>(insn.operands[2 + base].imm.value), IrType::I32);
    i.src_count = 3;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

void lift_simd_cmp_predicate(LiftCtx& ctx, std::string_view suffix) {
    const auto& insn = *ctx.insn;
    if (insn.x86_vex || insn.x86_evex) {
        // AVX has 32 predicates and one intrinsic taking the immediate.
        if (insn.num_operands != 4 || insn.operands[3].kind != Operand::Kind::Immediate) return;
        const IrType width = suffix == "sd" || suffix == "ss" ? IrType::I128 : vector_type(insn);
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = vector_name(std::format("_mm_cmp_{}", suffix), width);
        i.dst = ctx.temp(width);
        i.srcs[0] = read_xmm(ctx, insn.operands[1], width);
        i.srcs[1] = read_xmm(ctx, insn.operands[2], width);
        i.srcs[2] = ctx.imm(static_cast<u8>(insn.operands[3].imm.value), IrType::I32);
        i.src_count = 3;
        if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
        const IrValue result = i.dst;
        ctx.emit(std::move(i));
        write_xmm(ctx, insn.operands[0], result, width);
        return;
    }
    if (insn.num_operands != 3 || insn.operands[2].kind != Operand::Kind::Immediate) return;
    static constexpr std::array predicates{
        "eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord"};
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("_mm_cmp{}_{}",
        predicates[static_cast<u64>(insn.operands[2].imm.value) & 7u], suffix);
    i.dst = ctx.temp(IrType::I128);
    i.srcs[0] = read_xmm(ctx, insn.operands[0], IrType::I128);
    // The scalar form reads only the source's low double.
    i.srcs[1] = suffix == "sd"
        ? materialize_fp_rvalue(insn.operands[1], ctx, IrType::F64)
        : read_xmm(ctx, insn.operands[1], IrType::I128);
    i.src_count = 2;
    if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

void lift_simd_blendv(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    // Legacy: xmm0 is the implicit selector. VEX: `dst, a, b, mask`.
    const bool vex = insn.num_operands == 4;
    const IrType width = vector_type(insn);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = vector_name(name, width);
    i.dst = ctx.temp(width);
    i.srcs[0] = read_xmm(ctx, insn.operands[vex ? 1 : 0], width);
    i.srcs[1] = read_xmm(ctx, insn.operands[vex ? 2 : 1], width);
    i.srcs[2] = vex ? read_xmm(ctx, insn.operands[3], width)
                    : IrValue::make_reg(Reg::Xmm0, IrType::I128);
    i.src_count = 3;
    if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, width);
}

// `ptest a, b`: ZF = (a & b) == 0, CF = (~a & b) == 0, the rest cleared.
void lift_ptest(LiftCtx& ctx, std::string_view suffix) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    const IrType width = vector_type(insn);
    const IrValue a = read_xmm(ctx, insn.operands[0], width);
    const IrValue b = read_xmm(ctx, insn.operands[1], width);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None) return;
    const auto test = [&](std::string_view name) {
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = std::string(name);
        i.dst = ctx.temp(IrType::I1);
        i.srcs[0] = a;
        i.srcs[1] = b;
        i.src_count = 2;
        const IrValue result = i.dst;
        ctx.emit(std::move(i));
        return result;
    };
    const std::string_view vector_suffix =
        suffix == "si128" && width == IrType::I256 ? "si256" : suffix;
    ctx.emit_set_flag(Flag::Zf, test(vector_name(std::format("_mm_testz_{}", vector_suffix), width)));
    ctx.emit_set_flag(Flag::Cf, test(vector_name(std::format("_mm_testc_{}", vector_suffix), width)));
    ctx.emit_set_flag(Flag::Sf, ctx.imm(0, IrType::I1));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
}

// `crc32 r32/64, r/m8|16|32|64`: CRC-32C accumulated over the source.
void lift_crc32(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue crc = materialize_rvalue(insn.operands[0], ctx);
    IrValue data = materialize_rvalue(insn.operands[1], ctx);
    if (crc.kind == IrValueKind::None || data.kind == IrValueKind::None) return;
    const unsigned bits = type_bits(data.type);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("_mm_crc32_u{}", bits);
    i.dst = ctx.temp(bits == 64 ? IrType::I64 : IrType::I32);
    i.srcs[0] = ctx.match_size(crc, i.dst.type, /*sign_ext=*/false);
    i.srcs[1] = data;
    i.src_count = 2;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, operand_type(insn.operands[0]), /*sign_ext=*/false);
    store_lvalue(insn.operands[0], result, ctx);
}

// `movbe`: a byte-swapping load or store.
void lift_movbe(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    if (src.kind == IrValueKind::None) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = "bswap";
    i.dst = ctx.temp(src.type);
    i.srcs[0] = src;
    i.src_count = 1;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(insn.operands[0], result, ctx);
}

// `stmxcsr m32` / `ldmxcsr m32`: the SSE control register round-trips
// through memory.
void lift_mxcsr(LiftCtx& ctx, bool store) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1 || insn.operands[0].kind != Operand::Kind::Memory) return;
    const IrValue ea = compute_ea(insn.operands[0].mem, ctx);
    IrInst i;
    i.op = IrOp::Intrinsic;
    if (store) {
        i.name = "_mm_getcsr";
        i.dst = ctx.temp(IrType::I32);
        const IrValue value = i.dst;
        ctx.emit(std::move(i));
        ctx.emit_store(ea, value, insn.operands[0].mem.segment);
        return;
    }
    i.name = "_mm_setcsr";
    i.srcs[0] = ctx.emit_load(ea, IrType::I32, insn.operands[0].mem.segment);
    i.src_count = 1;
    ctx.emit(std::move(i));
}

void lift_clflush(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1 || insn.operands[0].kind != Operand::Kind::Memory) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = "_mm_clflush";
    i.srcs[0] = compute_ea(insn.operands[0].mem, ctx);
    i.src_count = 1;
    ctx.emit(std::move(i));
}

void lift_half_move(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2 && insn.num_operands != 3) return;
    const auto intrinsic = [&](std::string_view name, IrType type,
                               std::initializer_list<IrValue> args) {
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = std::string(name);
        i.dst = ctx.temp(type);
        for (const IrValue& arg : args) i.srcs[i.src_count++] = arg;
        const IrValue result = i.dst;
        ctx.emit(std::move(i));
        return result;
    };
    const Mnemonic mnemonic = insn.mnemonic;
    if (mnemonic == Mnemonic::MovlpsStore || mnemonic == Mnemonic::MovhpsStore) {
        IrValue src = read_xmm(ctx, insn.operands[1], IrType::I128);
        if (src.kind == IrValueKind::None) return;
        if (mnemonic == Mnemonic::MovhpsStore) {
            src = intrinsic("_mm_unpackhi_epi64", IrType::I128, {src, src});
        }
        const IrValue half = intrinsic("_mm_cvtsi128_si64", IrType::I64, {src});
        if (insn.operands[0].kind == Operand::Kind::Memory) {
            ctx.emit_store(compute_ea(insn.operands[0].mem, ctx), half, insn.operands[0].mem.segment);
        }
        return;
    }
    const bool high = mnemonic == Mnemonic::Movhps;
    // VEX takes the untouched half from vvvv: `vmovhps xmm0, xmm1, [m]`.
    const std::size_t from = insn.num_operands == 3 ? 1 : 0;
    const IrValue dst = read_xmm(ctx, insn.operands[from], IrType::I128);
    if (dst.kind == IrValueKind::None) return;
    const Operand& source = insn.operands[from + 1];
    IrValue result;
    if (source.kind == Operand::Kind::Register) {
        // movlhps: dst.high = src.low. movhlps: dst.low = src.high.
        const IrValue src = read_xmm(ctx, source, IrType::I128);
        result = high ? intrinsic("_mm_unpacklo_epi64", IrType::I128, {dst, src})
                      : intrinsic("_mm_unpackhi_epi64", IrType::I128, {src, dst});
    } else if (source.kind == Operand::Kind::Memory) {
        const IrValue loaded = ctx.emit_load(compute_ea(source.mem, ctx), IrType::I64,
                                             source.mem.segment);
        const IrValue lane = intrinsic("_mm_cvtsi64_si128", IrType::I128, {loaded});
        result = high
            ? intrinsic("_mm_unpacklo_epi64", IrType::I128, {dst, lane})
            : intrinsic("_mm_unpacklo_epi64", IrType::I128,
                        {lane, intrinsic("_mm_unpackhi_epi64", IrType::I128, {dst, dst})});
    } else {
        return;
    }
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

// `vpermd ymm0, ymm1(idx), ymm2(src)`: the intrinsic takes (src, idx).
void lift_permutevar(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const IrType width = vector_type(insn);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = ctx.temp(width);
    i.srcs[0] = read_xmm(ctx, insn.operands[2], width);
    i.srcs[1] = read_xmm(ctx, insn.operands[1], width);
    i.src_count = 2;
    if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, width);
}

// vinserti128 / vinsertf128: a 256-bit source and a 128-bit lane.
void lift_insert128(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4 || insn.operands[3].kind != Operand::Kind::Immediate) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = ctx.temp(IrType::I256);
    i.srcs[0] = read_xmm(ctx, insn.operands[1], IrType::I256);
    i.srcs[1] = read_xmm(ctx, insn.operands[2], IrType::I128);
    i.srcs[2] = ctx.imm(insn.operands[3].imm.value & 1, IrType::I32);
    i.src_count = 3;
    if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I256);
}

// vextracti128 / vextractf128 / vcvtps2ph: a 128-bit (or narrower) result
// written to an xmm register or stored.
void lift_vector_narrow_out(LiftCtx& ctx, std::string_view name, bool keep_immediate) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3 || insn.operands[2].kind != Operand::Kind::Immediate) return;
    const IrType width = vector_type(insn);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = vector_name(name, width);
    i.dst = ctx.temp(IrType::I128);
    i.srcs[0] = read_xmm(ctx, insn.operands[1], width);
    i.srcs[1] = ctx.imm(insn.operands[2].imm.value & (keep_immediate ? 0xff : 1), IrType::I32);
    i.src_count = 2;
    if (i.srcs[0].kind == IrValueKind::None) return;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    const Operand& destination = insn.operands[0];
    if (destination.kind == Operand::Kind::Memory && destination.mem.size == 8) {
        IrInst low;
        low.op = IrOp::Intrinsic;
        low.name = "_mm_cvtsi128_si64";
        low.dst = ctx.temp(IrType::I64);
        low.srcs[0] = result;
        low.src_count = 1;
        result = low.dst;
        ctx.emit(std::move(low));
        ctx.emit_store(compute_ea(destination.mem, ctx), result, destination.mem.segment);
        return;
    }
    write_xmm(ctx, destination, result, IrType::I128);
}

// vmaskmov / vpmaskmov: masked loads produce a vector, masked stores write
// memory through the intrinsic.
void lift_masked_move(LiftCtx& ctx, std::string_view name, bool store) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const IrType width = vector_type(insn);
    const Operand& memory = insn.operands[store ? 0 : 2];
    if (memory.kind != Operand::Kind::Memory) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = vector_name(name, width);
    i.srcs[0] = compute_ea(memory.mem, ctx);
    i.srcs[1] = read_xmm(ctx, insn.operands[1], width);
    i.src_count = 2;
    if (store) {
        i.srcs[i.src_count++] = read_xmm(ctx, insn.operands[2], width);
        ctx.emit(std::move(i));
        return;
    }
    i.dst = ctx.temp(width);
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, width);
}

// VEX register-form vmovss / vmovsd: low lane from the source, the rest
// from vvvv.
void lift_vex_scalar_merge(LiftCtx& ctx, bool single) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = single ? "_mm_move_ss" : "_mm_move_sd";
    i.dst = ctx.temp(IrType::I128);
    i.srcs[0] = read_xmm(ctx, insn.operands[1], IrType::I128);
    i.srcs[1] = read_xmm(ctx, insn.operands[2], IrType::I128);
    i.src_count = 2;
    if (i.srcs[0].kind == IrValueKind::None || i.srcs[1].kind == IrValueKind::None) return;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, IrType::I128);
}

void lift_vzeroall(LiftCtx& ctx) {
    for (unsigned r = 0; r < 16; ++r) {
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = "_mm256_setzero_si256";
        i.dst = ctx.temp(IrType::I256);
        const IrValue zero = i.dst;
        ctx.emit(std::move(i));
        ctx.emit_assign(IrValue::make_reg(static_cast<Reg>(static_cast<unsigned>(Reg::Ymm0) + r),
                                          IrType::I256), zero);
    }
}

// FMA3: 132 = dst*src3 + src2, 213 = src2*dst + src3, 231 = src2*src3 + dst.
// Packed forms map to `_mm*_f*_p*`; scalar ones to C99 fma/fmaf, which round
// once exactly like the instruction.
void lift_fma(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const std::string_view name = mnemonic_name(insn.mnemonic);
    const std::size_t digits = name.find_first_of("0123456789");
    if (digits == std::string_view::npos || name.size() < digits + 5) return;
    const std::string_view operation = name.substr(0, digits);
    const std::string_view order = name.substr(digits, 3);
    const std::string_view suffix = name.substr(digits + 3);
    const bool scalar = suffix == "ss" || suffix == "sd";
    const IrType type = scalar ? (suffix == "ss" ? IrType::F32 : IrType::F64) : vector_type(insn);
    const IrValue destination = scalar ? materialize_fp_rvalue(insn.operands[0], ctx, type)
                                       : read_xmm(ctx, insn.operands[0], type);
    const IrValue second = scalar ? materialize_fp_rvalue(insn.operands[1], ctx, type)
                                  : read_xmm(ctx, insn.operands[1], type);
    const IrValue third = scalar ? materialize_fp_rvalue(insn.operands[2], ctx, type)
                                 : read_xmm(ctx, insn.operands[2], type);
    if (destination.kind == IrValueKind::None || second.kind == IrValueKind::None ||
        third.kind == IrValueKind::None) return;
    IrValue a = second, b = third, c = destination;
    if (order == "132") { a = destination; b = third; c = second; }
    else if (order == "213") { a = second; b = destination; c = third; }
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.dst = ctx.temp(type);
    if (scalar) {
        const auto negate = [&](IrValue value) {
            IrInst neg;
            neg.op = IrOp::Neg;
            neg.dst = ctx.temp(type);
            neg.srcs[0] = value;
            neg.src_count = 1;
            const IrValue negated = neg.dst;
            ctx.emit(std::move(neg));
            return negated;
        };
        if (operation == "fnmadd" || operation == "fnmsub") a = negate(a);
        if (operation == "fmsub" || operation == "fnmsub") c = negate(c);
        i.name = type == IrType::F32 ? "fmaf" : "fma";
    } else {
        i.name = vector_name(std::format("_mm_{}_{}", operation, suffix), type);
    }
    i.srcs[0] = a;
    i.srcs[1] = b;
    i.srcs[2] = c;
    i.src_count = 3;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    if (scalar) store_fp_lvalue(insn.operands[0], result, ctx, type);
    else write_xmm(ctx, insn.operands[0], result, type);
}

// AMD FMA4: dst = src1 * src2 +/- src3 with all four operands explicit.
void lift_fma4(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4) return;
    const std::string_view name = mnemonic_name(insn.mnemonic);
    const std::string_view operation = name.substr(0, name.size() - 2);
    const std::string_view suffix = name.substr(name.size() - 2);
    const bool scalar = suffix == "ss" || suffix == "sd";
    const IrType type = scalar ? (suffix == "ss" ? IrType::F32 : IrType::F64) : vector_type(insn);
    const auto read = [&](const Operand& operand) {
        return scalar ? materialize_fp_rvalue(operand, ctx, type) : read_xmm(ctx, operand, type);
    };
    IrValue a = read(insn.operands[1]);
    const IrValue b = read(insn.operands[2]);
    IrValue c = read(insn.operands[3]);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None || c.kind == IrValueKind::None) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.dst = ctx.temp(type);
    if (scalar) {
        const auto negate = [&](IrValue value) {
            IrInst neg;
            neg.op = IrOp::Neg;
            neg.dst = ctx.temp(type);
            neg.srcs[0] = value;
            neg.src_count = 1;
            const IrValue negated = neg.dst;
            ctx.emit(std::move(neg));
            return negated;
        };
        if (operation == "fnmadd" || operation == "fnmsub") a = negate(a);
        if (operation == "fmsub" || operation == "fnmsub") c = negate(c);
        i.name = type == IrType::F32 ? "fmaf" : "fma";
    } else {
        i.name = vector_name(std::format("_mm_{}_{}", operation, suffix), type);
    }
    i.srcs[0] = a;
    i.srcs[1] = b;
    i.srcs[2] = c;
    i.src_count = 3;
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    if (scalar) store_fp_lvalue(insn.operands[0], result, ctx, type);
    else write_xmm(ctx, insn.operands[0], result, type);
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

// String ops: implicit rdi/rsi/rcx/rax operands. Without REP, MOVS/STOS/LODS
// move one element. REP MOVS/STOS become an intrinsic that runs to
// completion: the pointers end past the block and the count is spent, which
// matters because MSVC's inline memcpy is `rep movsd` then `rep movsb`
// continuing from where the first stopped. REPE/REPNE CMPS/SCAS can stop
// early, so they clobber rdi/rsi/rcx (and rax) instead.
void lift_string_op(LiftCtx& ctx, std::string_view name,
                    bool touches_rsi, bool touches_rax) {
    const auto& insn = *ctx.insn;
    const i64 element = name.ends_with('b') ? 1 : name.ends_with('w') ? 2
        : name.ends_with('d') ? 4 : 8;
    const bool copy = name.find("movs") != std::string_view::npos;
    const bool fill = name.find("stos") != std::string_view::npos;
    const bool load = name.find("lods") != std::string_view::npos;
    const Reg accumulator = element == 1 ? Reg::Al : element == 2 ? Reg::Ax
        : element == 4 ? Reg::Eax : Reg::Rax;
    const IrType element_type = type_for_bits(static_cast<unsigned>(element) * 8);
    const auto advance = [&](Reg r, IrValue bytes) {
        ctx.write_reg(r, ctx.emit_binop(IrOp::Add, ctx.read_reg(r), bytes));
    };
    if (!insn.prefixes.rep && !insn.prefixes.repne && (copy || fill || load)) {
        const IrValue step = ctx.imm(element, ctx.word_type());
        if (copy) {
            const IrValue value = ctx.emit_load(ctx.read_reg(Reg::Rsi), element_type);
            ctx.emit_store(ctx.read_reg(Reg::Rdi), value);
        } else if (fill) {
            ctx.emit_store(ctx.read_reg(Reg::Rdi), ctx.read_reg(accumulator));
        } else {
            ctx.write_reg(accumulator, ctx.emit_load(ctx.read_reg(Reg::Rsi), element_type));
        }
        if (copy || fill) advance(Reg::Rdi, step);
        if (copy || load) advance(Reg::Rsi, step);
        return;
    }

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.srcs[0]   = ctx.read_reg(Reg::Rdi);
    i.srcs[1]   = touches_rsi ? ctx.read_reg(Reg::Rsi) : ctx.read_reg(Reg::Rax);
    i.srcs[2]   = ctx.read_reg(Reg::Rcx);
    i.src_count = 3;
    const IrValue count = i.srcs[2];
    ctx.emit(std::move(i));

    if (copy || fill) {
        const IrValue bytes = element == 1 ? count
            : ctx.emit_binop(IrOp::Mul, count, ctx.imm(element, ctx.word_type()));
        advance(Reg::Rdi, bytes);
        if (copy) advance(Reg::Rsi, bytes);
        ctx.write_reg(Reg::Rcx, ctx.imm(0, ctx.word_type()));
        return;
    }

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
