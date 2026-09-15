// Paired-single and Gekko intrinsics.

#include <array>
#include <format>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "ppc_lifter_internal.hpp"

namespace spelunk::ppc_lift {

IrValue materialize_ps_value(const Operand& operand, LiftCtx& ctx) {
    if (operand.kind == Operand::Kind::Register) {
        return IrValue::make_reg(operand.reg, IrType::V2F32);
    }
    return materialize_rvalue(operand, ctx);
}

void lift_ps_compare(LiftCtx& ctx, std::string_view base_name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const u8 field = static_cast<u8>(insn.operands[0].imm.value) & 7u;
    const IrValue lhs = materialize_ps_value(insn.operands[1], ctx);
    const IrValue rhs = materialize_ps_value(insn.operands[2], ctx);
    constexpr std::array<std::string_view, 3> suffixes = {".lt", ".gt", ".eq"};
    for (u8 bit = 0; bit < suffixes.size(); ++bit) {
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = std::string(base_name) + std::string(suffixes[bit]);
        i.dst = IrValue::make_flag(ppc_cr_flag(field, bit));
        i.srcs[0] = lhs;
        i.srcs[1] = rhs;
        i.src_count = 2;
        ctx.emit(std::move(i));
    }
    ctx.emit_set_flag(ppc_cr_flag(field, 3), ctx.imm(0, IrType::I1));
}

void set_record_result(LiftCtx& ctx, IrValue value) {
    value = ctx.match_size(value, ctx.ppc_reg_type(), true);
    const IrValue zero = ctx.imm(0, value.type);
    set_cr_field(ctx, 0,
                 ctx.emit_cmp(IrOp::CmpSlt, value, zero),
                 ctx.emit_cmp(IrOp::CmpSgt, value, zero),
                 ctx.emit_cmp(IrOp::CmpEq, value, zero),
                 ctx.imm(0, IrType::I1));
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    for (u8 j = 0; j < ctx.insn->num_operands && j < 3; ++j) {
        IrValue v = materialize_rvalue(ctx.insn->operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

void lift_dst_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 0 || insn.operands[0].kind != Operand::Kind::Register) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = ctx.reg(insn.operands[0].reg);
    for (u8 j = 1; j < insn.num_operands && j < 4; ++j) {
        IrValue v = materialize_rvalue(insn.operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
    if (insn.ppc_record) set_record_result(ctx, ctx.read_reg(insn.operands[0].reg));
}

void lift_ps_dst_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 0 || insn.operands[0].kind != Operand::Kind::Register) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    for (u8 j = 1; j < insn.num_operands && j < 4; ++j) {
        IrValue value = materialize_ps_value(insn.operands[j], ctx);
        if (value.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = value;
    }
    ctx.emit(std::move(i));
}

void lift_ps_binop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue lhs = materialize_ps_value(insn.operands[1], ctx);
    IrValue rhs = materialize_ps_value(insn.operands[2], ctx);
    IrValue result = ctx.emit_binop(op, lhs, rhs, IrType::V2F32);
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32), result);
}

void lift_ps_unop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue result = ctx.emit_unop(op, materialize_ps_value(insn.operands[1], ctx),
                                   IrType::V2F32);
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32), result);
}

void lift_ps_fused_op(LiftCtx& ctx, bool subtract, bool negate) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4) return;
    // Paired-single A-form source order matches the scalar fused family:
    // FRA, FRC, FRB. Preserve the two-lane vector type while exposing the
    // multiply/add/subtract dataflow to cleanup and pseudo-C.
    const IrValue lhs = materialize_ps_value(insn.operands[1], ctx);
    const IrValue rhs = materialize_ps_value(insn.operands[2], ctx);
    const IrValue addend = materialize_ps_value(insn.operands[3], ctx);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None ||
        addend.kind == IrValueKind::None) {
        return;
    }
    IrValue result = ctx.emit_binop(
        subtract ? IrOp::Sub : IrOp::Add,
        ctx.emit_binop(IrOp::Mul, lhs, rhs, IrType::V2F32),
        addend, IrType::V2F32);
    if (negate) result = ctx.emit_unop(IrOp::Neg, result, IrType::V2F32);
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32),
                    result);
}

void lift_psq_memory(LiftCtx& ctx, bool load, bool update) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4 ||
        insn.operands[0].kind != Operand::Kind::Register ||
        insn.operands[1].kind != Operand::Kind::Memory ||
        insn.operands[2].kind != Operand::Kind::Immediate ||
        insn.operands[3].kind != Operand::Kind::Immediate) {
        return;
    }

    const Mem& mem = insn.operands[1].mem;
    const IrValue ea = compute_ea(mem, ctx);
    const u8 w = static_cast<u8>(insn.operands[2].imm.value) & 1u;
    const u8 gqr = static_cast<u8>(insn.operands[3].imm.value) & 7u;

    // GQR0 is the SDK's unquantized float mode. W=0 transfers both lanes;
    // W=1 transfers lane 0 and constructs/discards lane 1 as specified by
    // Gekko (loads synthesize 1.0f). Keep the memory access typed even for
    // the single-lane form so alias and stack analysis can see it.
    if (ctx.is_ppc32() && gqr == 0) {
        if (w == 0 && load) {
            IrValue value = ctx.emit_load(ea, IrType::V2F32);
            ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg,
                                              IrType::V2F32), value);
        } else if (w == 0) {
            ctx.emit_store(ea, IrValue::make_reg(insn.operands[0].reg,
                                                 IrType::V2F32));
        } else if (load) {
            IrValue lane0 = ctx.emit_load(ea, IrType::F32);
            IrInst pack;
            pack.op = IrOp::Intrinsic;
            pack.name = "ppc.ps_build_pair_one";
            pack.dst = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
            pack.srcs[pack.src_count++] = lane0;
            ctx.emit(std::move(pack));
        } else {
            IrInst lane;
            lane.op = IrOp::Intrinsic;
            lane.name = "ppc.ps_lane0";
            lane.dst = ctx.temp(IrType::F32);
            lane.srcs[lane.src_count++] =
                IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
            const IrValue lane0 = lane.dst;
            ctx.emit(std::move(lane));
            ctx.emit_store(ea, lane0);
        }
        if (update && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
        return;
    }

    // GQR layout differs by direction:
    //   store type[2:0],  signed scale[13:8]
    //   load  type[18:16], signed scale[29:24]
    // Type selects float/u8/u16/s8/s16 and scale is the power-of-two
    // quantization exponent. Decode both fields into ordinary IR so later
    // passes see the real runtime configuration rather than an opaque GQR.
    const IrValue raw_gqr = ctx.read_reg(static_cast<Reg>(
        static_cast<unsigned>(Reg::PpcGqr0) + gqr));
    const i64 type_shift = load ? 16 : 0;
    const i64 scale_shift = load ? 24 : 8;
    IrValue type_bits = raw_gqr;
    if (type_shift != 0) {
        type_bits = ctx.emit_binop(IrOp::Lshr, type_bits,
                                   ctx.imm(type_shift, IrType::I32), IrType::I32);
    }
    type_bits = ctx.emit_binop(IrOp::And, type_bits,
                               ctx.imm(7, IrType::I32), IrType::I32);
    IrValue scale = ctx.emit_binop(IrOp::Lshr, raw_gqr,
                                   ctx.imm(scale_shift, IrType::I32), IrType::I32);
    scale = ctx.emit_binop(IrOp::And, scale,
                           ctx.imm(0x3f, IrType::I32), IrType::I32);
    scale = ctx.emit_binop(IrOp::Shl, scale,
                           ctx.imm(26, IrType::I32), IrType::I32);
    scale = ctx.emit_binop(IrOp::Ashr, scale,
                           ctx.imm(26, IrType::I32), IrType::I32);

    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("ppc.psq_{}_quantized_w{}",
                         load ? "load" : "store", w);
    if (load) {
        i.dst = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    } else {
        i.srcs[i.src_count++] = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    }
    i.srcs[i.src_count++] = ea;
    i.srcs[i.src_count++] = type_bits;
    i.srcs[i.src_count++] = scale;
    ctx.emit(std::move(i));

    if (update && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
}

}  // namespace spelunk::ppc_lift
