// Scalar floating point and CR field updates.

#include <array>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "ppc_lifter_internal.hpp"

namespace spelunk::ppc_lift {

namespace {

void set_fp_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field) {
    set_cr_field(ctx, field,
                 ctx.emit_cmp(IrOp::CmpSlt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpSgt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpEq, lhs, rhs),
                 ctx.imm(0, IrType::I1));
}

}  // namespace

void lift_fp_mov(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue v = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (v.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], v, ctx, t);
}

void lift_fp_store(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue v = materialize_fp_rvalue(insn.operands[0], ctx, t);
    if (v.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[1], v, ctx, t);
}

void lift_fp_binop(LiftCtx& ctx, IrOp op, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue lhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[2], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], ctx.emit_binop(op, lhs, rhs, t), ctx, t);
}

void lift_fp_unop(LiftCtx& ctx, IrOp op, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (src.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], ctx.emit_unop(op, src, t), ctx, t);
}

void lift_fp_fused_op(LiftCtx& ctx, IrType t, bool subtract, bool negate) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4) return;
    // The decoder keeps the ISA's source order: FRA, FRC, FRB. PPC fused
    // forms compute (FRA * FRC) +/- FRB, optionally negating the result.
    IrValue lhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[2], ctx, t);
    IrValue addend = materialize_fp_rvalue(insn.operands[3], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None ||
        addend.kind == IrValueKind::None) {
        return;
    }
    IrValue product = ctx.emit_binop(IrOp::Mul, lhs, rhs, t);
    IrValue result = ctx.emit_binop(subtract ? IrOp::Sub : IrOp::Add,
                                    product, addend, t);
    if (negate) result = ctx.emit_unop(IrOp::Neg, result, t);
    store_fp_lvalue(insn.operands[0], result, ctx, t);
}

void lift_frsp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, IrType::F64);
    if (src.kind == IrValueKind::None) return;
    // A C float cast communicates the architecturally visible round to
    // single precision much better than an opaque ppc.frsp(...) call.
    IrValue rounded = ctx.emit_unop(IrOp::Trunc, src, IrType::F32);
    store_fp_lvalue(insn.operands[0], rounded, ctx, IrType::F32);
}

IrValue lift_fctiwz_value(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2 ||
        insn.operands[0].kind != Operand::Kind::Register) {
        return {};
    }
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, IrType::F64);
    if (src.kind == IrValueKind::None) return {};
    IrValue converted = ctx.emit_unop(IrOp::FpToInt, src, IrType::I32);
    // fctiwz carries an integer payload in an FPR until the conventional
    // stfd/lwz spill extracts its low word. Keep that payload typed as I32 so
    // standalone IR is useful even when the spill idiom is absent.
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::I32), converted);
    return converted;
}

bool lift_fctiwz_spill(LiftCtx& ctx,
                                     const Instruction& store,
                                     const Instruction& load) {
    const auto& convert = *ctx.insn;
    if (convert.mnemonic != Mnemonic::Fctiwz || convert.num_operands != 2 ||
        convert.operands[0].kind != Operand::Kind::Register ||
        store.mnemonic != Mnemonic::Stfd || store.num_operands != 2 ||
        store.operands[0].kind != Operand::Kind::Register ||
        store.operands[0].reg != convert.operands[0].reg ||
        store.operands[1].kind != Operand::Kind::Memory ||
        load.mnemonic != Mnemonic::Lwz || load.num_operands != 2 ||
        load.operands[0].kind != Operand::Kind::Register ||
        load.operands[1].kind != Operand::Kind::Memory) {
        return false;
    }
    const Mem& stored = store.operands[1].mem;
    const Mem& loaded = load.operands[1].mem;
    // Metrowerks extracts the big-endian low integer word at spill+4. Limit
    // the fold to a plain r1-local slot so an observable memory store is never
    // removed from an arbitrary caller-provided address.
    if (stored.base != Reg::PpcR1 || loaded.base != Reg::PpcR1 ||
        stored.index != Reg::None || loaded.index != Reg::None ||
        !stored.has_disp || !loaded.has_disp || loaded.disp != stored.disp + 4) {
        return false;
    }
    IrValue converted = lift_fctiwz_value(ctx);
    if (converted.kind == IrValueKind::None) return false;
    store_lvalue(load.operands[0], converted, ctx);
    return true;
}

void set_cr_field(LiftCtx& ctx, u8 field, IrValue lt, IrValue gt,
                  IrValue eq, IrValue so) {
    ctx.emit_set_flag(ppc_cr_flag(field, 0), lt);
    ctx.emit_set_flag(ppc_cr_flag(field, 1), gt);
    ctx.emit_set_flag(ppc_cr_flag(field, 2), eq);
    ctx.emit_set_flag(ppc_cr_flag(field, 3), so);

    // Keep CR0 mirrored in the legacy generic flags. Other architectures use
    // these flags, and retaining the aliases avoids needless churn in existing
    // PPC32 output while CR1..CR7 remain fully independent.
    if (field == 0) {
        ctx.emit_set_flag(Flag::Sf, lt);
        ctx.emit_set_flag(Flag::Zf, eq);
        ctx.emit_set_flag(Flag::Cf, lt);
        ctx.emit_set_flag(Flag::Of, so);
    }
}

void lift_fp_cmp(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue lhs = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None) return;
    set_fp_compare_flags(ctx, lhs, rhs, insn.ppc_cr_field);
}

}  // namespace spelunk::ppc_lift
