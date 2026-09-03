#include <ember/ir/arm32_lifter.hpp>

#include <bit>
#include <cstddef>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <ember/analysis/function.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>

// ARM (A32) → IR lifter. Mirrors the AArch64 lifter's shape: register file
// is 32-bit (self-canonical, no sub-register views), NZCV maps onto the
// shared Zf/Sf/Cf/Of flags, and the condition encoding is identical to
// AArch64's so the predicate synthesis is the same table.
//
// Predication: conditional register and flag writes commit through Select.
// Side effects which the scalar IR cannot guard directly are preserved as
// explicit conditional intrinsics instead of being executed unconditionally.

namespace ember {

namespace {

constexpr IrType kWord = IrType::I32;

// ARM/AArch64 condition encoding (4-bit) → i1 predicate over NZCV.
[[nodiscard]] IrValue cond_to_pred(unsigned cond, IrValue zf, IrValue nf,
                                    IrValue cf, IrValue vf,
                                    auto& emit_unop, auto& emit_binop_i1) {
    switch (cond & 0xf) {
        case 0x0: return zf;                                   // EQ
        case 0x1: return emit_unop(IrOp::Not, zf);             // NE
        case 0x2: return cf;                                   // CS/HS
        case 0x3: return emit_unop(IrOp::Not, cf);             // CC/LO
        case 0x4: return nf;                                   // MI
        case 0x5: return emit_unop(IrOp::Not, nf);             // PL
        case 0x6: return vf;                                   // VS
        case 0x7: return emit_unop(IrOp::Not, vf);             // VC
        case 0x8: { IrValue nz = emit_unop(IrOp::Not, zf);     // HI = C && !Z
                    return emit_binop_i1(IrOp::And, cf, nz); }
        case 0x9: { IrValue ncf = emit_unop(IrOp::Not, cf);    // LS = !C || Z
                    return emit_binop_i1(IrOp::Or, ncf, zf); }
        case 0xa: { IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);  // GE = N==V
                    return emit_unop(IrOp::Not, ne); }
        case 0xb: return emit_binop_i1(IrOp::Xor, nf, vf);     // LT = N!=V
        case 0xc: { IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);  // GT
                    IrValue eq = emit_unop(IrOp::Not, ne);
                    IrValue nz = emit_unop(IrOp::Not, zf);
                    return emit_binop_i1(IrOp::And, nz, eq); }
        case 0xd: { IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);  // LE
                    return emit_binop_i1(IrOp::Or, zf, ne); }
        case 0xe: return IrValue::make_imm(1, IrType::I1);     // AL
        case 0xf: return IrValue::make_imm(1, IrType::I1);     // NV → AL
    }
    return IrValue::make_imm(0, IrType::I1);
}

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;
    Abi                abi  = Abi::AapcsArm32;
    std::optional<IrValue>  cached_predicate;

    [[nodiscard]] u32 new_temp_id() noexcept { return fn->next_temp_id++; }
    [[nodiscard]] IrValue temp(IrType t) noexcept {
        return IrValue::make_temp(new_temp_id(), t);
    }
    [[nodiscard]] IrValue imm(i64 v, IrType t = kWord) noexcept {
        return IrValue::make_imm(v, t);
    }
    [[nodiscard]] IrValue flag_val(Flag f) noexcept { return IrValue::make_flag(f); }

    void emit(IrInst i) {
        i.source_addr = insn->address;
        blk->insts.push_back(std::move(i));
    }
    void emit_assign(IrValue dst, IrValue src) {
        IrInst i; i.op = IrOp::Assign; i.dst = dst; i.srcs[0] = src;
        i.src_count = 1; emit(std::move(i));
    }
    IrValue emit_binop(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(a.type);
        IrInst i; i.op = op; i.dst = t; i.srcs[0] = a; i.srcs[1] = b;
        i.src_count = 2; emit(std::move(i)); return t;
    }
    IrValue emit_unop(IrOp op, IrValue a) {
        IrValue t = temp(a.type);
        IrInst i; i.op = op; i.dst = t; i.srcs[0] = a; i.src_count = 1;
        emit(std::move(i)); return t;
    }
    IrValue emit_convert(IrOp op, IrValue a, IrType rt) {
        IrValue t = temp(rt);
        IrInst i; i.op = op; i.dst = t; i.srcs[0] = a; i.src_count = 1;
        emit(std::move(i)); return t;
    }
    IrValue emit_cmp(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(IrType::I1);
        IrInst i; i.op = op; i.dst = t; i.srcs[0] = a; i.srcs[1] = b;
        i.src_count = 2; emit(std::move(i)); return t;
    }
    IrValue emit_binop_i1(IrOp op, IrValue a, IrValue b) { return emit_cmp(op, a, b); }
    void emit_set_flag(Flag f, IrValue v) { emit_assign(IrValue::make_flag(f), v); }

    IrValue emit_load(IrValue addr, IrType t) {
        IrValue dst = temp(t);
        IrInst i; i.op = IrOp::Load; i.dst = dst; i.srcs[0] = addr;
        i.src_count = 1; emit(std::move(i)); return dst;
    }
    IrValue emit_guarded_load(IrValue addr, IrValue old_value, IrType t,
                              bool sign_extend = false) {
        if (insn->arm_cond == kArmCondAL) return emit_load(addr, t);
        IrInst i; i.op = IrOp::Intrinsic;
        i.name = std::format("arm.load_if_{}{}",
                             sign_extend ? "s" : "u", type_bits(t));
        i.dst = temp(kWord);
        i.srcs[0] = cond_predicate(insn->arm_cond);
        i.srcs[1] = addr;
        i.srcs[2] = old_value;
        i.src_count = 3;
        IrValue result = i.dst;
        emit(std::move(i));
        return result;
    }
    void emit_store(IrValue addr, IrValue value) {
        IrInst i; i.op = IrOp::Store; i.srcs[0] = addr; i.srcs[1] = value;
        i.src_count = 2; emit(std::move(i));
    }
    void emit_guarded_store(IrValue addr, IrValue value) {
        if (insn->arm_cond == kArmCondAL) {
            emit_store(addr, value);
            return;
        }
        IrInst i; i.op = IrOp::Intrinsic; i.name = "arm.store_if";
        i.srcs[0] = cond_predicate(insn->arm_cond);
        i.srcs[1] = addr;
        i.srcs[2] = value;
        i.src_count = 3;
        emit(std::move(i));
    }

    // PC reads see the current instruction address + 8 (ARM pipeline offset).
    [[nodiscard]] IrValue read_reg(Reg r) {
        if (r == Reg::Apc) return imm(static_cast<i64>(insn->address + 8));
        return IrValue::make_reg(r, kWord);
    }
    void write_reg(Reg r, IrValue value) {
        if (value.type != kWord) {
            value = (type_bits(value.type) < 32)
                ? emit_convert(IrOp::ZExt, value, kWord)
                : emit_convert(IrOp::Trunc, value, kWord);
        }
        emit_assign(IrValue::make_reg(r, kWord), value);
    }

    IrValue cond_predicate(unsigned cond) {
        if (cached_predicate) return *cached_predicate;
        IrValue zf = flag_val(Flag::Zf), nf = flag_val(Flag::Sf);
        IrValue cf = flag_val(Flag::Cf), vf = flag_val(Flag::Of);
        auto u = [&](IrOp op, IrValue a) { return emit_unop(op, a); };
        auto b = [&](IrOp op, IrValue a, IrValue bb) { return emit_binop_i1(op, a, bb); };
        cached_predicate = cond_to_pred(cond, zf, nf, cf, vf, u, b);
        return *cached_predicate;
    }

    // Commit a register result, honouring predication.
    void commit(Reg r, IrValue value) {
        if (insn->arm_cond != kArmCondAL) {
            if (value.type != kWord) {
                value = (type_bits(value.type) < 32)
                    ? emit_convert(IrOp::ZExt, value, kWord)
                    : emit_convert(IrOp::Trunc, value, kWord);
            }
            IrValue old = read_reg(r);
            IrValue pred = cond_predicate(insn->arm_cond);
            IrInst i; i.op = IrOp::Select; i.dst = temp(kWord);
            i.srcs[0] = pred; i.srcs[1] = value; i.srcs[2] = old;
            i.src_count = 3;
            IrValue sel = i.dst;
            emit(std::move(i));
            write_reg(r, sel);
            return;
        }
        write_reg(r, value);
    }

    void commit_flag(Flag f, IrValue value) {
        if (insn->arm_cond == kArmCondAL) {
            emit_set_flag(f, value);
            return;
        }
        IrValue old = flag_val(f);
        IrValue pred = cond_predicate(insn->arm_cond);
        IrInst i; i.op = IrOp::Select; i.dst = temp(IrType::I1);
        i.srcs[0] = pred; i.srcs[1] = value; i.srcs[2] = old;
        i.src_count = 3;
        IrValue selected = i.dst;
        emit(std::move(i));
        emit_set_flag(f, selected);
    }

    // Apply an ARM barrel shift carried on a register operand.
    IrValue apply_shift(IrValue v, ArmShift type, u8 amt) {
        if (type == ArmShift::Lsl && amt == 0) return v;
        if (type == ArmShift::Ror && amt == 0) {  // RRX: (v >> 1) | (C << 31)
            IrValue lo = emit_binop(IrOp::Lshr, v, imm(1));
            IrValue c  = emit_convert(IrOp::ZExt, flag_val(Flag::Cf), kWord);
            IrValue hi = emit_binop(IrOp::Shl, c, imm(31));
            return emit_binop(IrOp::Or, lo, hi);
        }
        switch (type) {
            case ArmShift::Lsl: return emit_binop(IrOp::Shl,  v, imm(amt));
            case ArmShift::Lsr: return emit_binop(IrOp::Lshr, v, imm(amt));
            case ArmShift::Asr: return emit_binop(IrOp::Ashr, v, imm(amt));
            case ArmShift::Ror: {
                IrValue lo = emit_binop(IrOp::Lshr, v, imm(amt));
                IrValue hi = emit_binop(IrOp::Shl, v, imm(32 - amt));
                return emit_binop(IrOp::Or, lo, hi);
            }
        }
        return v;
    }

    IrValue apply_shift_reg(IrValue v, ArmShift type, Reg amount_reg) {
        IrValue amt = emit_binop(IrOp::And, read_reg(amount_reg), imm(0xff));
        switch (type) {
            case ArmShift::Lsl: return emit_binop(IrOp::Shl, v, amt);
            case ArmShift::Lsr: return emit_binop(IrOp::Lshr, v, amt);
            case ArmShift::Asr: return emit_binop(IrOp::Ashr, v, amt);
            case ArmShift::Ror: {
                IrValue lo = emit_binop(IrOp::Lshr, v, amt);
                IrValue k = emit_binop(IrOp::Sub, imm(32), amt);
                IrValue rotated = emit_binop(IrOp::Or, lo,
                                              emit_binop(IrOp::Shl, v, k));
                IrValue zero = emit_cmp(IrOp::CmpEq, amt, imm(0));
                IrInst i; i.op = IrOp::Select; i.dst = temp(kWord);
                i.srcs[0] = zero; i.srcs[1] = v; i.srcs[2] = rotated;
                i.src_count = 3;
                IrValue result = i.dst;
                emit(std::move(i));
                return result;
            }
        }
        return v;
    }

    IrValue materialize_op(const Operand& op) {
        switch (op.kind) {
            case Operand::Kind::Register: {
                IrValue v = read_reg(op.reg);
                if (op.arm_shift_reg != Reg::None)
                    return apply_shift_reg(v, op.arm_shift, op.arm_shift_reg);
                return apply_shift(v, op.arm_shift, op.arm_shift_amt);
            }
            case Operand::Kind::Immediate: return imm(op.imm.value, kWord);
            case Operand::Kind::Relative:  return imm(static_cast<i64>(op.rel.target), kWord);
            case Operand::Kind::Memory:    return emit_load(compute_ea(op.mem),
                                                            type_for_bits(op.mem.size * 8));
            case Operand::Kind::None:      return IrValue{};
        }
        return IrValue{};
    }

    IrValue compute_ea(const Mem& m) {
        IrValue base = (m.base != Reg::None) ? read_reg(m.base) : imm(0);
        if (m.index != Reg::None) {
            IrValue idx = read_reg(m.index);
            if (m.scale > 1) idx = emit_binop(IrOp::Mul, idx, imm(m.scale));
            base = emit_binop(m.subtract_index ? IrOp::Sub : IrOp::Add,
                              base, idx);
        }
        if (m.disp != 0 || m.base == Reg::None) {
            base = emit_binop(IrOp::Add, base, imm(m.disp));
        }
        return base;
    }
};

// NZCV after an integer op, matching the AArch64 model.
void set_nzcv(LiftCtx& ctx, IrValue a, IrValue b, IrValue result, bool subtract) {
    const IrType t = result.type;
    ctx.commit_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, result, ctx.imm(0, t)));
    ctx.commit_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, result, ctx.imm(0, t)));
    IrValue carry = subtract
        ? ctx.emit_unop(IrOp::Not, ctx.emit_binop_i1(IrOp::SubBorrow, a, b))
        : ctx.emit_binop_i1(IrOp::AddCarry, a, b);
    ctx.commit_flag(Flag::Cf, carry);
    ctx.commit_flag(Flag::Of,
        subtract ? ctx.emit_binop_i1(IrOp::SubOverflow, a, b)
                 : ctx.emit_binop_i1(IrOp::AddOverflow, a, b));
}

void set_nz_logical(LiftCtx& ctx, IrValue r) {
    ctx.commit_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, r, ctx.imm(0, r.type)));
    ctx.commit_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, r, ctx.imm(0, r.type)));
}

void lift_carry_arith(LiftCtx& ctx, bool subtract, bool reverse) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return;
    IrValue rn = ctx.materialize_op(in.operands[1]);
    IrValue op2 = ctx.materialize_op(in.operands[2]);
    IrValue a = reverse ? op2 : rn;
    IrValue b = reverse ? rn : op2;
    IrValue carry = ctx.emit_convert(IrOp::ZExt, ctx.flag_val(Flag::Cf), kWord);
    IrValue adjustment = subtract
        ? ctx.emit_binop(IrOp::Xor, carry, ctx.imm(1))
        : carry;
    IrValue first = ctx.emit_binop(subtract ? IrOp::Sub : IrOp::Add, a, b);
    IrValue result = ctx.emit_binop(subtract ? IrOp::Sub : IrOp::Add,
                                    first, adjustment);
    if (in.arm_setflags) {
        ctx.commit_flag(Flag::Zf,
            ctx.emit_cmp(IrOp::CmpEq, result, ctx.imm(0)));
        ctx.commit_flag(Flag::Sf,
            ctx.emit_cmp(IrOp::CmpSlt, result, ctx.imm(0)));
        IrValue c1 = ctx.emit_binop_i1(subtract ? IrOp::SubBorrow : IrOp::AddCarry,
                                      a, b);
        IrValue c2 = ctx.emit_binop_i1(subtract ? IrOp::SubBorrow : IrOp::AddCarry,
                                      first, adjustment);
        IrValue any = ctx.emit_binop_i1(IrOp::Or, c1, c2);
        ctx.commit_flag(Flag::Cf, subtract ? ctx.emit_unop(IrOp::Not, any) : any);
        IrValue o1 = ctx.emit_binop_i1(subtract ? IrOp::SubOverflow : IrOp::AddOverflow,
                                      a, b);
        IrValue o2 = ctx.emit_binop_i1(subtract ? IrOp::SubOverflow : IrOp::AddOverflow,
                                      first, adjustment);
        ctx.commit_flag(Flag::Of, ctx.emit_binop_i1(IrOp::Or, o1, o2));
    }
    ctx.commit(in.operands[0].reg, result);
}

// rd, rn, op2 arithmetic. `reverse` swaps operands (RSB/RSC).
void lift_arith(LiftCtx& ctx, IrOp op, bool subtract, bool reverse) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return;
    IrValue rn  = ctx.materialize_op(in.operands[1]);
    IrValue op2 = ctx.materialize_op(in.operands[2]);
    IrValue a = reverse ? op2 : rn;
    IrValue b = reverse ? rn  : op2;
    IrValue r = ctx.emit_binop(op, a, b);
    if (in.arm_setflags) set_nzcv(ctx, a, b, r, subtract);
    ctx.commit(in.operands[0].reg, r);
}

// CMP/CMN/TST/TEQ: set flags, no destination.
void lift_compare(LiftCtx& ctx, IrOp op, bool subtract) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2) return;
    IrValue a = ctx.materialize_op(in.operands[0]);
    IrValue b = ctx.materialize_op(in.operands[1]);
    IrValue r = ctx.emit_binop(op, a, b);
    if (subtract || op == IrOp::Add) set_nzcv(ctx, a, b, r, subtract);
    else set_nz_logical(ctx, r);
}

void lift_logical(LiftCtx& ctx, IrOp op, bool invert_rhs) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return;
    IrValue rn  = ctx.materialize_op(in.operands[1]);
    IrValue op2 = ctx.materialize_op(in.operands[2]);
    if (invert_rhs) op2 = ctx.emit_unop(IrOp::Not, op2);
    IrValue r = ctx.emit_binop(op, rn, op2);
    if (in.arm_setflags) set_nz_logical(ctx, r);
    ctx.commit(in.operands[0].reg, r);
}

void lift_mov(LiftCtx& ctx, bool invert) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2) return;
    IrValue v = ctx.materialize_op(in.operands[1]);
    if (invert) v = ctx.emit_unop(IrOp::Not, v);
    if (in.arm_setflags) set_nz_logical(ctx, v);
    ctx.commit(in.operands[0].reg, v);
}

// LSL/LSR/ASR/ROR rd, rm, #amt | rs
void lift_shift(LiftCtx& ctx, IrOp op) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return;
    IrValue rm  = ctx.materialize_op(in.operands[1]);
    IrValue amt = ctx.materialize_op(in.operands[2]);
    IrValue r;
    if (op == IrOp::Nop) {  // ROR
        IrValue lo = ctx.emit_binop(IrOp::Lshr, rm, amt);
        IrValue k  = ctx.emit_binop(IrOp::Sub, ctx.imm(32), amt);
        IrValue hi = ctx.emit_binop(IrOp::Shl, rm, k);
        r = ctx.emit_binop(IrOp::Or, lo, hi);
    } else {
        r = ctx.emit_binop(op, rm, amt);
    }
    if (in.arm_setflags) set_nz_logical(ctx, r);
    ctx.commit(in.operands[0].reg, r);
}

void lift_movw(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2) return;
    ctx.commit(in.operands[0].reg, ctx.imm(in.operands[1].imm.value & 0xffff));
}

void lift_movt(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2) return;
    IrValue cur = ctx.read_reg(in.operands[0].reg);
    IrValue lo  = ctx.emit_binop(IrOp::And, cur, ctx.imm(0xffff));
    IrValue hi  = ctx.imm((in.operands[1].imm.value & 0xffff) << 16);
    ctx.commit(in.operands[0].reg, ctx.emit_binop(IrOp::Or, lo, hi));
}

void lift_mul(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return;
    IrValue a = ctx.read_reg(in.operands[1].reg);
    IrValue b = ctx.read_reg(in.operands[2].reg);
    IrValue r = ctx.emit_binop(IrOp::Mul, a, b);
    if (in.arm_setflags) set_nz_logical(ctx, r);
    ctx.commit(in.operands[0].reg, r);
}

void lift_mla(LiftCtx& ctx, bool sub) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 4) return;
    IrValue p  = ctx.emit_binop(IrOp::Mul, ctx.read_reg(in.operands[1].reg),
                                ctx.read_reg(in.operands[2].reg));
    IrValue ra = ctx.read_reg(in.operands[3].reg);
    ctx.commit(in.operands[0].reg,
               ctx.emit_binop(sub ? IrOp::Sub : IrOp::Add, ra, p));
}

// UMULL/SMULL/UMLAL/SMLAL: rdlo, rdhi = rm * rs (+ {rdhi:rdlo}).
void lift_mull(LiftCtx& ctx, bool is_signed, bool accumulate) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 4) return;
    const IrOp ext = is_signed ? IrOp::SExt : IrOp::ZExt;
    IrValue m = ctx.emit_convert(ext, ctx.read_reg(in.operands[2].reg), IrType::I64);
    IrValue s = ctx.emit_convert(ext, ctx.read_reg(in.operands[3].reg), IrType::I64);
    IrValue prod = ctx.emit_binop(IrOp::Mul, m, s);
    if (accumulate) {
        IrValue lo = ctx.emit_convert(IrOp::ZExt, ctx.read_reg(in.operands[0].reg), IrType::I64);
        IrValue hi = ctx.emit_convert(IrOp::ZExt, ctx.read_reg(in.operands[1].reg), IrType::I64);
        IrValue acc = ctx.emit_binop(IrOp::Or, ctx.emit_binop(IrOp::Shl, hi, ctx.imm(32, IrType::I64)), lo);
        prod = ctx.emit_binop(IrOp::Add, prod, acc);
    }
    IrValue lo = ctx.emit_convert(IrOp::Trunc, prod, kWord);
    IrValue hi = ctx.emit_convert(IrOp::Trunc,
                     ctx.emit_binop(IrOp::Lshr, prod, ctx.imm(32, IrType::I64)), kWord);
    ctx.commit(in.operands[0].reg, lo);
    ctx.commit(in.operands[1].reg, hi);
}

void lift_extend(LiftCtx& ctx, unsigned bits, bool sign) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2) return;
    IrValue src = ctx.emit_convert(IrOp::Trunc, ctx.read_reg(in.operands[1].reg),
                                   type_for_bits(bits));
    ctx.commit(in.operands[0].reg,
               ctx.emit_convert(sign ? IrOp::SExt : IrOp::ZExt, src, kWord));
}

void lift_load(LiftCtx& ctx, unsigned bits, bool sign) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2 || in.operands[1].kind != Operand::Kind::Memory) return;
    IrValue ea  = ctx.compute_ea(in.operands[1].mem);
    const Reg dst = in.operands[0].reg;
    IrValue val = ctx.emit_guarded_load(ea, ctx.read_reg(dst),
                                        type_for_bits(bits), sign);
    if (in.arm_cond != kArmCondAL) {
        ctx.write_reg(dst, val);
        return;
    }
    if (val.type != kWord)
        val = ctx.emit_convert(sign ? IrOp::SExt : IrOp::ZExt, val, kWord);
    ctx.commit(dst, val);
}

void lift_store(LiftCtx& ctx, unsigned bits) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2 || in.operands[1].kind != Operand::Kind::Memory) return;
    IrValue val = ctx.read_reg(in.operands[0].reg);
    const IrType t = type_for_bits(bits);
    if (val.type != t) val = ctx.emit_convert(IrOp::Trunc, val, t);
    ctx.emit_guarded_store(ctx.compute_ea(in.operands[1].mem), val);
}

// LDRD/STRD: a register pair at [ea] and [ea+4].
void lift_dword(LiftCtx& ctx, bool load) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 2 || in.operands[1].kind != Operand::Kind::Memory) return;
    const Reg rd = in.operands[0].reg;
    const Reg rd2 = static_cast<Reg>(static_cast<unsigned>(rd) + 1);
    IrValue ea  = ctx.compute_ea(in.operands[1].mem);
    IrValue ea2 = ctx.emit_binop(IrOp::Add, ea, ctx.imm(4));
    if (load) {
        if (ctx.insn->arm_cond == kArmCondAL) {
            ctx.commit(rd,  ctx.emit_load(ea,  kWord));
            ctx.commit(rd2, ctx.emit_load(ea2, kWord));
        } else {
            ctx.write_reg(rd, ctx.emit_guarded_load(ea, ctx.read_reg(rd), kWord));
            ctx.write_reg(rd2, ctx.emit_guarded_load(ea2, ctx.read_reg(rd2), kWord));
        }
    } else {
        ctx.emit_guarded_store(ea,  ctx.read_reg(rd));
        ctx.emit_guarded_store(ea2, ctx.read_reg(rd2));
    }
}

Reg arm_gpr_n(unsigned n) {
    switch (n) {
        case 13: return Reg::Asp; case 14: return Reg::Alr; case 15: return Reg::Apc;
        default: return static_cast<Reg>(static_cast<unsigned>(Reg::ArmR0) + n);
    }
}

// Generic block transfer (LDM/STM/PUSH/POP). Registers occupy ascending
// addresses lowest-numbered first; the P/U/W/L flags select the mode.
std::optional<IrValue> lift_block(LiftCtx& ctx, bool push_pop_reversed) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 3) return std::nullopt;
    const Reg base = in.operands[0].reg;
    const u32 list = static_cast<u32>(in.operands[1].imm.value);
    const i64 flags = in.operands[2].imm.value;
    const bool p = (flags >> 3) & 1, u = (flags >> 2) & 1;
    const bool w = (flags >> 1) & 1, l = flags & 1;
    (void)push_pop_reversed;

    const unsigned count = static_cast<unsigned>(std::popcount(list));
    if (count == 0) return std::nullopt;

    IrValue baseval = ctx.read_reg(base);
    // Lowest address the transfer touches.
    IrValue start;
    if (u) start = p ? ctx.emit_binop(IrOp::Add, baseval, ctx.imm(4)) : baseval;
    else   start = ctx.emit_binop(IrOp::Sub, baseval,
                                  ctx.imm(static_cast<i64>(count * 4) - (p ? 0 : 4)));

    IrValue addr = start;
    std::optional<IrValue> loaded_pc;
    unsigned done = 0;
    for (unsigned r = 0; r < 16; ++r) {
        if (!(list & (1u << r))) continue;
        if (done > 0) addr = ctx.emit_binop(IrOp::Add, addr, ctx.imm(4));
        const Reg rr = arm_gpr_n(r);
        if (l) {
            IrValue value = ctx.emit_guarded_load(addr, ctx.read_reg(rr), kWord);
            if (rr == Reg::Apc) loaded_pc = value;
            else if (ctx.insn->arm_cond == kArmCondAL) ctx.commit(rr, value);
            else ctx.write_reg(rr, value);
        } else {
            ctx.emit_guarded_store(addr, ctx.read_reg(rr));
        }
        ++done;
    }
    if (w) {
        IrValue nb = u ? ctx.emit_binop(IrOp::Add, baseval, ctx.imm(static_cast<i64>(count * 4)))
                       : ctx.emit_binop(IrOp::Sub, baseval, ctx.imm(static_cast<i64>(count * 4)));
        ctx.commit(base, nb);
    }
    return loaded_pc;
}

void emit_arg_barriers(LiftCtx& ctx) {
    const auto args = int_arg_regs(ctx.abi);
    auto fill = [&](std::string_view name, std::size_t lo) {
        IrInst i; i.op = IrOp::Intrinsic; i.name = std::string(name);
        for (std::size_t n = 0; n < 3 && lo + n < args.size(); ++n)
            i.srcs[i.src_count++] = ctx.read_reg(args[lo + n]);
        if (i.src_count) ctx.emit(std::move(i));
    };
    fill("call.args.1", 0);
    fill("call.args.2", 3);
}

void emit_call_clobbers(LiftCtx& ctx) {
    for (Reg r : caller_saved_int_regs(ctx.abi)) {
        IrInst i; i.op = IrOp::Clobber;
        i.dst = IrValue::make_reg(r, kWord);
        ctx.emit(std::move(i));
    }
}

void lift_call(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    emit_arg_barriers(ctx);
    if (in.arm_cond != kArmCondAL) {
        IrInst guarded; guarded.op = IrOp::Intrinsic;
        guarded.name = "arm.call_if";
        guarded.srcs[guarded.src_count++] = ctx.cond_predicate(in.arm_cond);
        if (in.num_operands >= 1)
            guarded.srcs[guarded.src_count++] = ctx.materialize_op(in.operands[0]);
        ctx.emit(std::move(guarded));
        return;
    }
    IrInst i; i.op = IrOp::Call;
    if (in.num_operands >= 1 && in.operands[0].kind == Operand::Kind::Relative) {
        i.target1 = in.operands[0].rel.target;
    } else if (in.num_operands >= 1 && in.operands[0].kind == Operand::Kind::Register) {
        i.op = IrOp::CallIndirect;
        i.srcs[0] = ctx.read_reg(in.operands[0].reg);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));
    emit_call_clobbers(ctx);
}

void lift_branch(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    IrInst i;
    if (in.arm_cond != kArmCondAL) {
        i.op = IrOp::Intrinsic; i.name = "arm.branch_if";
        i.srcs[0] = ctx.cond_predicate(in.arm_cond);
        if (in.num_operands >= 1) i.srcs[1] = ctx.materialize_op(in.operands[0]);
        i.src_count = in.num_operands >= 1 ? 2 : 1;
        ctx.emit(std::move(i));
        return;
    }
    if (in.num_operands >= 1 && in.operands[0].kind == Operand::Kind::Relative) {
        i.op = IrOp::Branch; i.target1 = in.operands[0].rel.target;
    } else {
        i.op = IrOp::BranchIndirect;
        if (in.num_operands >= 1) {
            i.srcs[0] = ctx.materialize_op(in.operands[0]); i.src_count = 1;
        }
    }
    ctx.emit(std::move(i));
}

void lift_bcc(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    if (in.num_operands < 1 || in.operands[0].kind != Operand::Kind::Relative) return;
    IrValue pred = ctx.cond_predicate(in.arm_cond);
    IrInst i; i.op = IrOp::CondBranch; i.srcs[0] = pred; i.src_count = 1;
    i.target1 = in.operands[0].rel.target;
    ctx.emit(std::move(i));
}

void lift_ret(LiftCtx& ctx) {
    // pop/ldm-with-pc restores registers before returning; replay the loads
    // so callee-saved dataflow survives, then return r0.
    const auto& in = *ctx.insn;
    if (in.num_operands >= 3 && in.operands[1].kind == Operand::Kind::Immediate)
        (void)lift_block(ctx, false);
    IrInst i; i.op = IrOp::Return;
    i.srcs[0] = ctx.read_reg(Reg::ArmR0); i.src_count = 1;
    ctx.emit(std::move(i));
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& in = *ctx.insn;
    IrInst i; i.op = IrOp::Intrinsic; i.name = std::format("arm.{}", name);
    for (u8 j = 0; j < in.num_operands && j < 3; ++j) {
        IrValue v = ctx.materialize_op(in.operands[j]);
        if (v.kind != IrValueKind::None) i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

void lift_instruction(LiftCtx& ctx) {
    const auto& in = *ctx.insn;
    switch (in.mnemonic) {
        case Mnemonic::A32And: lift_logical(ctx, IrOp::And, false); break;
        case Mnemonic::A32Eor: lift_logical(ctx, IrOp::Xor, false); break;
        case Mnemonic::A32Orr: lift_logical(ctx, IrOp::Or,  false); break;
        case Mnemonic::A32Bic: lift_logical(ctx, IrOp::And, true);  break;
        case Mnemonic::A32Add: lift_arith(ctx, IrOp::Add, false, false); break;
        case Mnemonic::A32Adc: lift_carry_arith(ctx, false, false); break;
        case Mnemonic::A32Sub: lift_arith(ctx, IrOp::Sub, true,  false); break;
        case Mnemonic::A32Sbc: lift_carry_arith(ctx, true,  false); break;
        case Mnemonic::A32Rsb: lift_arith(ctx, IrOp::Sub, true,  true);  break;
        case Mnemonic::A32Rsc: lift_carry_arith(ctx, true,  true);  break;
        case Mnemonic::A32Cmp: lift_compare(ctx, IrOp::Sub, true);  break;
        case Mnemonic::A32Cmn: lift_compare(ctx, IrOp::Add, false); break;
        case Mnemonic::A32Tst: lift_compare(ctx, IrOp::And, false); break;
        case Mnemonic::A32Teq: lift_compare(ctx, IrOp::Xor, false); break;
        case Mnemonic::A32Mov: lift_mov(ctx, false); break;
        case Mnemonic::A32Mvn: lift_mov(ctx, true);  break;
        case Mnemonic::A32Lsl: lift_shift(ctx, IrOp::Shl);  break;
        case Mnemonic::A32Lsr: lift_shift(ctx, IrOp::Lshr); break;
        case Mnemonic::A32Asr: lift_shift(ctx, IrOp::Ashr); break;
        case Mnemonic::A32Ror: lift_shift(ctx, IrOp::Nop);  break;
        case Mnemonic::A32Rrx: {
            if (in.num_operands >= 2)
                ctx.commit(in.operands[0].reg,
                           ctx.apply_shift(ctx.read_reg(in.operands[1].reg),
                                           ArmShift::Ror, 0));
            break;
        }
        case Mnemonic::A32Movw: lift_movw(ctx); break;
        case Mnemonic::A32Movt: lift_movt(ctx); break;
        case Mnemonic::A32Mul:  lift_mul(ctx);  break;
        case Mnemonic::A32Mla:  lift_mla(ctx, false); break;
        case Mnemonic::A32Mls:  lift_mla(ctx, true);  break;
        case Mnemonic::A32Umull: lift_mull(ctx, false, false); break;
        case Mnemonic::A32Umlal: lift_mull(ctx, false, true);  break;
        case Mnemonic::A32Smull: lift_mull(ctx, true,  false); break;
        case Mnemonic::A32Smlal: lift_mull(ctx, true,  true);  break;
        case Mnemonic::A32Udiv:
        case Mnemonic::A32Sdiv: {
            if (in.num_operands < 3) break;
            IrValue r = ctx.emit_binop(IrOp::Div, ctx.read_reg(in.operands[1].reg),
                                       ctx.read_reg(in.operands[2].reg));
            ctx.commit(in.operands[0].reg, r);
            break;
        }
        case Mnemonic::A32Clz:   lift_intrinsic(ctx, "clz"); break;
        case Mnemonic::A32Rev:   lift_intrinsic(ctx, "rev"); break;
        case Mnemonic::A32Rev16: lift_intrinsic(ctx, "rev16"); break;
        case Mnemonic::A32Sxtb: lift_extend(ctx, 8,  true);  break;
        case Mnemonic::A32Sxth: lift_extend(ctx, 16, true);  break;
        case Mnemonic::A32Uxtb: lift_extend(ctx, 8,  false); break;
        case Mnemonic::A32Uxth: lift_extend(ctx, 16, false); break;

        case Mnemonic::A32Ldr:   lift_load(ctx, 32, false); break;
        case Mnemonic::A32Ldrb:  lift_load(ctx, 8,  false); break;
        case Mnemonic::A32Ldrh:  lift_load(ctx, 16, false); break;
        case Mnemonic::A32Ldrsb: lift_load(ctx, 8,  true);  break;
        case Mnemonic::A32Ldrsh: lift_load(ctx, 16, true);  break;
        case Mnemonic::A32Str:   lift_store(ctx, 32); break;
        case Mnemonic::A32Strb:  lift_store(ctx, 8);  break;
        case Mnemonic::A32Strh:  lift_store(ctx, 16); break;
        case Mnemonic::A32Ldrd:  lift_dword(ctx, true);  break;
        case Mnemonic::A32Strd:  lift_dword(ctx, false); break;

        case Mnemonic::A32Push: case Mnemonic::A32Stm:
        case Mnemonic::A32Pop:  case Mnemonic::A32Ldm:
            (void)lift_block(ctx, false); break;
        case Mnemonic::A32LdmPc: {
            auto target = lift_block(ctx, false);
            if (!target) break;
            if (in.arm_cond == kArmCondAL) {
                IrInst i; i.op = IrOp::BranchIndirect;
                i.srcs[0] = *target; i.src_count = 1; ctx.emit(std::move(i));
            } else {
                IrInst i; i.op = IrOp::Intrinsic; i.name = "arm.branch_if";
                i.srcs[0] = ctx.cond_predicate(in.arm_cond);
                i.srcs[1] = *target; i.src_count = 2; ctx.emit(std::move(i));
            }
            break;
        }

        case Mnemonic::A32B:   lift_branch(ctx); break;
        case Mnemonic::A32Bx:  lift_branch(ctx); break;
        case Mnemonic::A32Bcc: lift_bcc(ctx); break;
        case Mnemonic::A32Bl:  lift_call(ctx); break;
        case Mnemonic::A32Blx: lift_call(ctx); break;
        case Mnemonic::A32Ret: lift_ret(ctx); break;

        case Mnemonic::A32Nop: break;
        case Mnemonic::A32Svc: lift_intrinsic(ctx, "syscall"); break;
        case Mnemonic::A32Bkpt:
        case Mnemonic::A32Udf: {
            IrInst i; i.op = IrOp::Unreachable; ctx.emit(std::move(i)); break;
        }
        case Mnemonic::A32Undef:
            lift_intrinsic(ctx, std::format("word_{:#010x}",
                static_cast<u32>(in.operands[0].kind == Operand::Kind::Immediate
                                 ? in.operands[0].imm.value : 0)));
            break;
        default:
            lift_intrinsic(ctx, mnemonic_name(in.mnemonic));
            break;
    }
}

void ensure_terminator(IrBlock& bb) {
    if (!bb.insts.empty() && is_terminator(bb.insts.back().op)) return;
    switch (bb.kind) {
        case BlockKind::Return: {
            IrInst i; i.op = IrOp::Return; bb.insts.push_back(std::move(i)); break;
        }
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
            if (!bb.successors.empty()) {
                IrInst i; i.op = IrOp::Branch; i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            } else {
                IrInst i; i.op = IrOp::Unreachable; bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::IndirectJmp: {
            IrInst i; i.op = IrOp::Unreachable; bb.insts.push_back(std::move(i)); break;
        }
        case BlockKind::Switch: break;
        case BlockKind::TailCall: break;
        case BlockKind::Conditional:
            if (!bb.successors.empty()) {
                IrInst i; i.op = IrOp::Branch; i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            }
            break;
    }
}

}  // namespace

Result<IrFunction> Arm32Lifter::lift(const Function& fn) const {
    IrFunction ir;
    ir.start = fn.start;
    ir.end   = fn.end;
    ir.name  = fn.name;

    ir.blocks.reserve(fn.blocks.size());
    for (const auto& bb : fn.blocks) {
        IrBlock irb;
        irb.start        = bb.start;
        irb.end          = bb.end;
        irb.kind         = bb.kind;
        irb.successors   = bb.successors;
        irb.predecessors = bb.predecessors;
        irb.case_values  = bb.case_values;
        irb.has_default  = bb.has_default;
        irb.switch_index = bb.switch_index;
        ir.block_at[irb.start] = ir.blocks.size();
        ir.blocks.push_back(std::move(irb));
    }

    for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
        const auto& src_bb = fn.blocks[i];
        auto&       dst_bb = ir.blocks[i];
        LiftCtx ctx;
        ctx.fn = &ir; ctx.blk = &dst_bb; ctx.abi = abi_;
        for (const auto& insn : src_bb.instructions) {
            ctx.insn = &insn;
            ctx.cached_predicate.reset();
            lift_instruction(ctx);
        }
        ensure_terminator(dst_bb);
    }
    return ir;
}

}  // namespace ember
