// Operand access: effective addresses, rvalue reads and lvalue writes.

#include <algorithm>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>

#include "ppc_lifter_internal.hpp"

namespace ember::ppc_lift {

namespace {

[[nodiscard]] IrType operand_type(const Operand& op) noexcept {
    switch (op.kind) {
        case Operand::Kind::Register:
            return type_for_bits(reg_size(op.reg) * 8);
        case Operand::Kind::Memory:
            return type_for_bits(std::max<unsigned>(8, op.mem.size * 8));
        case Operand::Kind::Immediate:
            return type_for_bits(std::max<unsigned>(8, op.imm.size * 8));
        default:
            return IrType::I64;
    }
}

}  // namespace

IrType ppc_abi_reg_type(Abi abi) noexcept {
    return abi == Abi::Ppc32Sysv ? IrType::I32 : IrType::I64;
}

IrValue compute_ea(const Mem& mem, LiftCtx& ctx) {
    IrValue base = mem.base == Reg::None ? ctx.imm(0) : ctx.read_reg(mem.base);
    if (mem.index != Reg::None) {
        IrValue idx = ctx.read_reg(mem.index);
        if (mem.scale != 1) {
            idx = ctx.emit_binop(IrOp::Mul, idx, ctx.imm(mem.scale, idx.type), idx.type);
        }
        base = ctx.emit_binop(IrOp::Add, ctx.match_size(base, idx.type), idx, idx.type);
    }
    if (!mem.has_disp || mem.disp == 0) return base;
    return ctx.emit_binop(IrOp::Add, base, ctx.imm(mem.disp, base.type), base.type);
}

u32 ppc_mask32(u32 mb, u32 me) noexcept {
    u32 mask = 0;
    for (u32 i = 0; i < 32; ++i) {
        const bool in_range = mb <= me ? (i >= mb && i <= me) : (i >= mb || i <= me);
        if (in_range) mask |= 1u << (31u - i);
    }
    return mask;
}

IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx) {
    switch (op.kind) {
        case Operand::Kind::Register:
            return ctx.read_reg(op.reg);
        case Operand::Kind::Immediate:
            return ctx.imm(op.imm.value, operand_type(op));
        case Operand::Kind::Memory:
            return ctx.emit_load(compute_ea(op.mem, ctx), type_for_bits(op.mem.size * 8));
        case Operand::Kind::Relative:
            return ctx.imm(static_cast<i64>(op.rel.target));
        default:
            return {};
    }
}

void store_lvalue(const Operand& op, IrValue value, LiftCtx& ctx) {
    switch (op.kind) {
        case Operand::Kind::Register:
            ctx.write_reg(op.reg, value);
            return;
        case Operand::Kind::Memory:
            ctx.emit_store(compute_ea(op.mem, ctx),
                           ctx.match_size(value, type_for_bits(op.mem.size * 8)));
            return;
        default:
            return;
    }
}

IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) return IrValue::make_reg(op.reg, t);
    if (op.kind == Operand::Kind::Memory) return ctx.emit_load(compute_ea(op.mem, ctx), t);
    return {};
}

void store_fp_lvalue(const Operand& op, IrValue value, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        ctx.emit_assign(IrValue::make_reg(op.reg, t), value);
        return;
    }
    if (op.kind == Operand::Kind::Memory) ctx.emit_store(compute_ea(op.mem, ctx), value);
}

}  // namespace ember::ppc_lift
