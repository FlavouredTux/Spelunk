#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {
namespace {
IrValue st(unsigned index) {
    return IrValue::make_reg(static_cast<Reg>(static_cast<unsigned>(Reg::St0) + index), IrType::F64);
}

IrValue fp_cast(LiftCtx& ctx, IrValue value, IrType type) {
    if (value.type == type) return value;
    IrInst inst;
    inst.op = IrOp::Intrinsic;
    inst.name = type == IrType::F64 ? "cvtss2sd" : "cvtsd2ss";
    inst.dst = ctx.temp(type);
    inst.srcs[0] = value;
    inst.src_count = 1;
    const IrValue result = inst.dst;
    ctx.emit(std::move(inst));
    return result;
}

IrValue fp_operand(LiftCtx& ctx, const Operand& operand) {
    if (operand.kind == Operand::Kind::Register) return st(operand.x87_stack);
    return fp_cast(ctx, ctx.emit_load(compute_ea(operand.mem, ctx),
        operand.mem.size == 4 ? IrType::F32 : IrType::F64, operand.mem.segment), IrType::F64);
}

void pop(LiftCtx& ctx) {
    for (unsigned i = 0; i < 7; ++i) ctx.emit_assign(st(i), st(i + 1));
    IrInst clobber;
    clobber.op = IrOp::Clobber;
    clobber.dst = st(7);
    ctx.emit(std::move(clobber));
}
} // namespace

// Scalar float/double x87 dataflow. Control/status, integer conversions and
// extended-precision operands remain explicit intrinsics in partial output.
bool lift_x86_fp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    const auto mnemonic = insn.mnemonic;
    if (mnemonic == Mnemonic::X87Fld && insn.num_operands) {
        IrValue value = ctx.snapshot(fp_operand(ctx, insn.operands[0]));
        for (unsigned i = 7; i > 0; --i) ctx.emit_assign(st(i), st(i - 1));
        ctx.emit_assign(st(0), value);
        return true;
    }
    if ((mnemonic == Mnemonic::X87Fst || mnemonic == Mnemonic::X87Fstp) && insn.num_operands) {
        const auto& operand = insn.operands[0];
        if (operand.kind == Operand::Kind::Register) ctx.emit_assign(st(operand.x87_stack), st(0));
        else ctx.emit_store(compute_ea(operand.mem, ctx),
            fp_cast(ctx, st(0), operand.mem.size == 4 ? IrType::F32 : IrType::F64), operand.mem.segment);
        if (mnemonic == Mnemonic::X87Fstp) pop(ctx);
        return true;
    }
    if (mnemonic == Mnemonic::X87Fxch && insn.num_operands) {
        IrValue value = ctx.snapshot(st(0));
        ctx.emit_assign(st(0), st(insn.operands[0].x87_stack));
        ctx.emit_assign(st(insn.operands[0].x87_stack), value);
        return true;
    }
    if (mnemonic == Mnemonic::X87Fchs) {
        ctx.emit_assign(st(0), ctx.emit_binop(IrOp::Sub, ctx.imm(0, IrType::F64), st(0)));
        return true;
    }
    IrOp op;
    switch (mnemonic) {
        case Mnemonic::X87Fadd: case Mnemonic::X87Faddp: op = IrOp::Add; break;
        case Mnemonic::X87Fsub: case Mnemonic::X87Fsubr:
        case Mnemonic::X87Fsubp: case Mnemonic::X87Fsubrp: op = IrOp::Sub; break;
        case Mnemonic::X87Fmul: case Mnemonic::X87Fmulp: op = IrOp::Mul; break;
        case Mnemonic::X87Fdiv: case Mnemonic::X87Fdivr:
        case Mnemonic::X87Fdivp: case Mnemonic::X87Fdivrp: op = IrOp::Div; break;
        default: return false;
    }
    if (!insn.num_operands) return false;
    bool popping = mnemonic == Mnemonic::X87Faddp || mnemonic == Mnemonic::X87Fmulp ||
        mnemonic == Mnemonic::X87Fsubp || mnemonic == Mnemonic::X87Fsubrp ||
        mnemonic == Mnemonic::X87Fdivp || mnemonic == Mnemonic::X87Fdivrp;
    unsigned escape = 0;
    for (u8 i = 0; i < insn.length; ++i) {
        const auto byte = static_cast<u8>(insn.raw_bytes[i]);
        if (byte >= 0xd8 && byte <= 0xdf) { escape = byte; break; }
    }
    const bool memory = insn.operands[0].kind == Operand::Kind::Memory;
    const unsigned index = memory ? 0 : (insn.operands[0].x87_stack | insn.operands[1].x87_stack);
    const unsigned destination = popping || escape == 0xdc ? index : 0;
    IrValue lhs = st(destination);
    IrValue rhs = memory ? fp_operand(ctx, insn.operands[0]) : st(destination == 0 ? index : 0);
    const bool reverse = mnemonic == Mnemonic::X87Fsubr || mnemonic == Mnemonic::X87Fdivr ||
        mnemonic == Mnemonic::X87Fsubrp || mnemonic == Mnemonic::X87Fdivrp;
    if (reverse) std::swap(lhs, rhs);
    ctx.emit_assign(st(destination), ctx.emit_binop(op, lhs, rhs));
    if (popping) pop(ctx);
    return true;
}
} // namespace spelunk::x64_lift
