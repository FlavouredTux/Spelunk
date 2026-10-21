// Operand access: effective addresses, rvalue reads and lvalue writes.

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {

// Effective address for a memory operand.
IrValue compute_ea(const Mem& m, LiftCtx& ctx) {
    if (m.base == Reg::Rip) {
        const addr_t end_addr = ctx.insn->address + ctx.insn->length;
        return ctx.imm(static_cast<i64>(end_addr + static_cast<u64>(m.disp)),
                       IrType::I64);
    }

    if (ctx.mode32()) {
        IrValue sum = ctx.imm(m.disp, IrType::I32);
        if (m.base != Reg::None) {
            IrValue base = ctx.match_size(ctx.read_reg(m.base), IrType::I32, false);
            sum = m.disp == 0 ? base : ctx.emit_binop(IrOp::Add, base, sum);
        }
        if (m.index != Reg::None) {
            IrValue index = ctx.match_size(ctx.read_reg(m.index), IrType::I32, false);
            if (m.scale > 1) index = ctx.emit_binop(IrOp::Mul, index, ctx.imm(m.scale, IrType::I32));
            sum = ctx.emit_binop(IrOp::Add, sum, index);
        }
        if (m.address_size == 2) {
            sum = ctx.emit_convert(IrOp::Trunc, sum, IrType::I16);
            sum = ctx.emit_convert(IrOp::ZExt, sum, IrType::I32);
        }
        return sum;
    }

    IrValue sum;
    bool    has = false;

    if (m.base != Reg::None) {
        IrValue b = ctx.read_reg(m.base);
        if (b.type != IrType::I64) {
            b = ctx.emit_convert(IrOp::ZExt, b, IrType::I64);
        }
        sum = b;
        has = true;
    }

    if (m.index != Reg::None) {
        IrValue idx = ctx.read_reg(m.index);
        if (idx.type != IrType::I64) {
            idx = ctx.emit_convert(IrOp::ZExt, idx, IrType::I64);
        }
        if (m.scale > 1) {
            idx = ctx.emit_binop(IrOp::Mul, idx, ctx.imm(m.scale, IrType::I64));
        }
        sum = has ? ctx.emit_binop(IrOp::Add, sum, idx) : idx;
        has = true;
    }

    if (m.disp != 0 || !has) {
        IrValue d = ctx.imm(m.disp, IrType::I64);
        sum = has ? ctx.emit_binop(IrOp::Add, sum, d) : d;
    }

    if (m.address_size == 4) {
        IrValue low = ctx.emit_convert(IrOp::Trunc, sum, IrType::I32);
        sum = ctx.emit_convert(IrOp::ZExt, low, IrType::I64);
    }

    return sum;
}

IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx) {
    switch (op.kind) {
        case Operand::Kind::Register:
            return ctx.read_reg(op.reg);
        case Operand::Kind::Immediate: {
            const IrType t = type_for_bits(op.imm.size * 8);
            return ctx.imm(op.imm.value, t);
        }
        case Operand::Kind::Memory: {
            IrValue ea = compute_ea(op.mem, ctx);
            const IrType t = type_for_bits(op.mem.size * 8);
            return ctx.emit_load(ea, t, op.mem.segment);
        }
        case Operand::Kind::Relative:
            return ctx.imm(static_cast<i64>(op.rel.target), IrType::I64);
        case Operand::Kind::None:
            return IrValue{};
    }
    return IrValue{};
}

void store_lvalue(const Operand& op, IrValue value, LiftCtx& ctx) {
    switch (op.kind) {
        case Operand::Kind::Register:
            ctx.write_reg(op.reg, value);
            break;
        case Operand::Kind::Memory: {
            IrValue ea = compute_ea(op.mem, ctx);
            ctx.emit_store(ea, value, op.mem.segment);
            break;
        }
        default:
            break;
    }
}

IrType operand_type(const Operand& op) noexcept {
    switch (op.kind) {
        case Operand::Kind::Register:  return type_for_bits(reg_size(op.reg) * 8);
        case Operand::Kind::Memory:    return type_for_bits(op.mem.size * 8);
        case Operand::Kind::Immediate: return type_for_bits(op.imm.size * 8);
        default:                       return IrType::I64;
    }
}

}  // namespace spelunk::x64_lift
