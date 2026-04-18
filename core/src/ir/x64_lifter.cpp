#include <ember/ir/x64_lifter.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include <ember/disasm/register.hpp>
#include <ember/ir/ssa.hpp>  // canonical_reg

namespace ember {

namespace {

// ah/bh/ch/dh — the upper 8 bits of the low 16.
[[nodiscard]] constexpr bool is_high_byte(Reg r) noexcept {
    return r == Reg::Ah || r == Reg::Bh || r == Reg::Ch || r == Reg::Dh;
}

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;

    [[nodiscard]] u32 new_temp_id() noexcept { return fn->next_temp_id++; }

    [[nodiscard]] IrValue temp(IrType t) noexcept {
        return IrValue::make_temp(new_temp_id(), t);
    }
    // Low-level: IrValue naming a (possibly sub-) register at its natural width.
    // Used only for canonical 64-bit identities (direct Rax/Rdi/... references).
    // For sub-register I/O, use read_reg/write_reg so x64 partial-register
    // semantics and zero-extend semantics are modeled explicitly.
    [[nodiscard]] IrValue reg(Reg r) noexcept {
        return IrValue::make_reg(r, type_for_bits(reg_size(r) * 8));
    }
    [[nodiscard]] IrValue imm(i64 v, IrType t) noexcept {
        return IrValue::make_imm(v, t);
    }
    [[nodiscard]] IrValue flag_val(Flag f) noexcept {
        return IrValue::make_flag(f);
    }

    void emit(IrInst i) {
        i.source_addr = insn->address;
        blk->insts.push_back(std::move(i));
    }

    void emit_assign(IrValue dst, IrValue src) {
        IrInst i;
        i.op        = IrOp::Assign;
        i.dst       = dst;
        i.srcs[0]   = src;
        i.src_count = 1;
        emit(std::move(i));
    }

    IrValue emit_binop(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(a.type);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.srcs[1]   = b;
        i.src_count = 2;
        emit(std::move(i));
        return t;
    }

    IrValue emit_unop(IrOp op, IrValue a) {
        IrValue t = temp(a.type);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.src_count = 1;
        emit(std::move(i));
        return t;
    }

    IrValue emit_convert(IrOp op, IrValue a, IrType result_type) {
        IrValue t = temp(result_type);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.src_count = 1;
        emit(std::move(i));
        return t;
    }

    IrValue emit_cmp(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(IrType::I1);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.srcs[1]   = b;
        i.src_count = 2;
        emit(std::move(i));
        return t;
    }

    IrValue emit_binop_i1(IrOp op, IrValue a, IrValue b) {
        return emit_cmp(op, a, b);
    }

    void emit_set_flag(Flag f, IrValue v) {
        emit_assign(IrValue::make_flag(f), v);
    }

    IrValue emit_load(IrValue addr, IrType t, Reg seg = Reg::None) {
        IrValue dst = temp(t);
        IrInst i;
        i.op        = IrOp::Load;
        i.dst       = dst;
        i.srcs[0]   = addr;
        i.src_count = 1;
        i.segment   = seg;
        emit(std::move(i));
        return dst;
    }

    void emit_store(IrValue addr, IrValue value, Reg seg = Reg::None) {
        IrInst i;
        i.op        = IrOp::Store;
        i.srcs[0]   = addr;
        i.srcs[1]   = value;
        i.src_count = 2;
        i.segment   = seg;
        emit(std::move(i));
    }

    void set_zf_sf(IrValue result) {
        IrType t = result.type;
        emit_set_flag(Flag::Zf, emit_cmp(IrOp::CmpEq, result, imm(0, t)));
        emit_set_flag(Flag::Sf, emit_cmp(IrOp::CmpSlt, result, imm(0, t)));
    }

    void clear_cf_of() {
        emit_set_flag(Flag::Cf, imm(0, IrType::I1));
        emit_set_flag(Flag::Of, imm(0, IrType::I1));
    }

    IrValue match_size(IrValue v, IrType target, bool sign_ext) {
        if (v.type == target) return v;
        const unsigned vb = type_bits(v.type);
        const unsigned tb = type_bits(target);
        if (vb < tb) {
            return emit_convert(sign_ext ? IrOp::SExt : IrOp::ZExt, v, target);
        }
        return emit_convert(IrOp::Trunc, v, target);
    }

    // --- Partial-register semantics ------------------------------------------
    // Registers are canonicalized to their 64-bit form in SSA. Sub-register
    // reads are Trunc-views of the canonical Rax/Rbx/..., sub-register writes
    // rebuild the canonical value honoring x86-64 semantics:
    //   - 64-bit write:   rax = v
    //   - 32-bit write:   rax = zext64(v)                        // zero-extends
    //   - 16-bit write:   rax = (rax & ~0xFFFF) | zext64(v)
    //   - 8-bit low:      rax = (rax & ~0xFF) | zext64(v)
    //   - 8-bit high:     rax = (rax & ~0xFF00) | (zext64(v) << 8)
    //
    // This makes the SSA variable `rax` a single well-defined 64-bit thing,
    // instead of the old scheme where separate eax/rax writes silently shared
    // an SSA variable with conflicting widths.

    [[nodiscard]] IrValue read_reg(Reg r) {
        const Reg canon = canonical_reg(r);
        const unsigned bytes = reg_size(r);
        const IrType natural_t = type_for_bits(bytes * 8);

        if (canon == r) {
            // Own canonical — read at the register's natural width.
            // GPRs (rax/rdi/r8/...) → I64; segment regs (fs/gs/...) → I16;
            // Rip → I64. No trunc or partial-register logic applies.
            return IrValue::make_reg(r, natural_t);
        }

        // Sub-register of a 64-bit GPR family: trunc the canonical.
        IrValue full = IrValue::make_reg(canon, IrType::I64);

        if (is_high_byte(r)) {
            // ah: trunc8(lshr(rax, 8))
            IrValue shifted = emit_binop(IrOp::Lshr, full, imm(8, IrType::I64));
            return emit_convert(IrOp::Trunc, shifted, IrType::I8);
        }

        return emit_convert(IrOp::Trunc, full, natural_t);
    }

    void write_reg(Reg r, IrValue value) {
        const Reg canon = canonical_reg(r);
        const unsigned bytes = reg_size(r);
        const IrType natural_t = type_for_bits(bytes * 8);

        if (canon == r) {
            // Own canonical — direct assign at natural width. No partial-
            // register merge concept applies to segment regs, rip, etc.;
            // for GPRs this is simply the full 64-bit write.
            if (value.type != natural_t) {
                value = match_size(value, natural_t, /*sign_ext=*/false);
            }
            emit_assign(IrValue::make_reg(r, natural_t), value);
            return;
        }

        // Sub-register of a 64-bit GPR family: rebuild the canonical Rax.
        IrValue canon_lv = IrValue::make_reg(canon, IrType::I64);

        // Match incoming width to the sub-register width so the merge
        // patterns below operate on a value of known size.
        if (value.type != natural_t) {
            value = match_size(value, natural_t, /*sign_ext=*/false);
        }

        if (bytes == 4) {
            // x64: 32-bit writes zero-extend to 64 bits.
            IrValue zext = emit_convert(IrOp::ZExt, value, IrType::I64);
            emit_assign(canon_lv, zext);
            return;
        }

        IrValue full = IrValue::make_reg(canon, IrType::I64);
        IrValue zext = emit_convert(IrOp::ZExt, value, IrType::I64);

        if (is_high_byte(r)) {
            IrValue shifted = emit_binop(IrOp::Shl, zext, imm(8, IrType::I64));
            IrValue mask = imm(static_cast<i64>(~u64{0xFF00}), IrType::I64);
            IrValue preserved = emit_binop(IrOp::And, full, mask);
            IrValue merged = emit_binop(IrOp::Or, preserved, shifted);
            emit_assign(canon_lv, merged);
            return;
        }

        if (bytes == 2) {
            IrValue mask = imm(static_cast<i64>(~u64{0xFFFF}), IrType::I64);
            IrValue preserved = emit_binop(IrOp::And, full, mask);
            IrValue merged = emit_binop(IrOp::Or, preserved, zext);
            emit_assign(canon_lv, merged);
            return;
        }

        // bytes == 1, low byte (al/bl/cl/dl/sil/dil/bpl/spl/r8b..r15b)
        IrValue mask = imm(static_cast<i64>(~u64{0xFF}), IrType::I64);
        IrValue preserved = emit_binop(IrOp::And, full, mask);
        IrValue merged = emit_binop(IrOp::Or, preserved, zext);
        emit_assign(canon_lv, merged);
    }
};

// Effective address for a memory operand.
[[nodiscard]] IrValue compute_ea(const Mem& m, LiftCtx& ctx) {
    if (m.base == Reg::Rip) {
        const addr_t end_addr = ctx.insn->address + ctx.insn->length;
        return ctx.imm(static_cast<i64>(end_addr + static_cast<u64>(m.disp)),
                       IrType::I64);
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

    return sum;
}

[[nodiscard]] IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx) {
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

[[nodiscard]] IrType operand_type(const Operand& op) noexcept {
    switch (op.kind) {
        case Operand::Kind::Register:  return type_for_bits(reg_size(op.reg) * 8);
        case Operand::Kind::Memory:    return type_for_bits(op.mem.size * 8);
        case Operand::Kind::Immediate: return type_for_bits(op.imm.size * 8);
        default:                       return IrType::I64;
    }
}

// ========== Individual lifters ==========

void lift_mov(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    src = ctx.match_size(src, dst_t, /*sign_ext=*/true);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_movzx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    if (src.type != dst_t) src = ctx.emit_convert(IrOp::ZExt, src, dst_t);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_movsx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    if (src.type != dst_t) src = ctx.emit_convert(IrOp::SExt, src, dst_t);
    store_lvalue(insn.operands[0], src, ctx);
}

void lift_lea(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2 ||
        insn.operands[1].kind != Operand::Kind::Memory ||
        insn.operands[0].kind != Operand::Kind::Register) {
        return;
    }
    IrValue ea = compute_ea(insn.operands[1].mem, ctx);
    const IrType dst_t = operand_type(insn.operands[0]);
    ea = ctx.match_size(ea, dst_t, false);
    store_lvalue(insn.operands[0], ea, ctx);
}

void lift_arith(LiftCtx& ctx, IrOp op, IrOp carry_op, IrOp overflow_op,
                bool store_result, bool set_flags) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);

    if (set_flags) {
        ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(carry_op, a, b));
        ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(overflow_op, a, b));
    }

    IrValue result = ctx.emit_binop(op, a, b);

    if (set_flags) ctx.set_zf_sf(result);
    if (store_result) store_lvalue(insn.operands[0], result, ctx);
}

void lift_add(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Add, IrOp::AddCarry, IrOp::AddOverflow, true, true);
}
void lift_sub(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Sub, IrOp::SubBorrow, IrOp::SubOverflow, true, true);
}
void lift_cmp(LiftCtx& ctx) {
    lift_arith(ctx, IrOp::Sub, IrOp::SubBorrow, IrOp::SubOverflow, false, true);
}

void lift_bitwise(LiftCtx& ctx, IrOp op, bool store_result) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);
    IrValue r = ctx.emit_binop(op, a, b);
    ctx.set_zf_sf(r);
    ctx.clear_cf_of();
    if (store_result) store_lvalue(insn.operands[0], r, ctx);
}

void lift_and(LiftCtx& ctx)  { lift_bitwise(ctx, IrOp::And, true);  }
void lift_or (LiftCtx& ctx)  { lift_bitwise(ctx, IrOp::Or,  true);  }
void lift_xor(LiftCtx& ctx)  { lift_bitwise(ctx, IrOp::Xor, true);  }
void lift_test(LiftCtx& ctx) { lift_bitwise(ctx, IrOp::And, false); }

void lift_inc(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue one = ctx.imm(1, a.type);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::AddOverflow, a, one));
    IrValue r = ctx.emit_binop(IrOp::Add, a, one);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_dec(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue one = ctx.imm(1, a.type);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::SubOverflow, a, one));
    IrValue r = ctx.emit_binop(IrOp::Sub, a, one);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_neg(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpNe, a, ctx.imm(0, a.type)));
    const i64 sign_bit = static_cast<i64>(1ULL << (type_bits(a.type) - 1));
    ctx.emit_set_flag(Flag::Of, ctx.emit_cmp(IrOp::CmpEq, a,
                                              ctx.imm(sign_bit, a.type)));
    IrValue r = ctx.emit_unop(IrOp::Neg, a);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_not(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue r = ctx.emit_unop(IrOp::Not, a);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_shift(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[1], ctx);
    cnt = ctx.match_size(cnt, a.type, /*sign_ext=*/false);
    IrValue r = ctx.emit_binop(op, a, cnt);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_shl(LiftCtx& ctx) { lift_shift(ctx, IrOp::Shl);  }
void lift_shr(LiftCtx& ctx) { lift_shift(ctx, IrOp::Lshr); }
void lift_sar(LiftCtx& ctx) { lift_shift(ctx, IrOp::Ashr); }

void lift_imul(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 2) {
        IrValue a = materialize_rvalue(insn.operands[0], ctx);
        IrValue b = materialize_rvalue(insn.operands[1], ctx);
        b = ctx.match_size(b, a.type, /*sign_ext=*/true);
        IrValue r = ctx.emit_binop(IrOp::Mul, a, b);
        store_lvalue(insn.operands[0], r, ctx);
    } else if (insn.num_operands == 3) {
        IrValue a = materialize_rvalue(insn.operands[1], ctx);
        IrValue b = materialize_rvalue(insn.operands[2], ctx);
        b = ctx.match_size(b, a.type, /*sign_ext=*/true);
        IrValue r = ctx.emit_binop(IrOp::Mul, a, b);
        store_lvalue(insn.operands[0], r, ctx);
    } else {
        IrInst i;
        i.op   = IrOp::Intrinsic;
        i.name = "imul.1op";
        ctx.emit(std::move(i));
    }
}

void lift_push(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue val = materialize_rvalue(insn.operands[0], ctx);
    if (val.type != IrType::I64) {
        val = ctx.emit_convert(IrOp::SExt, val, IrType::I64);
    }
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue new_rsp = ctx.emit_binop(IrOp::Sub, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_store(new_rsp, val);
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
}

void lift_pop(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const IrType t = operand_type(insn.operands[0]);
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue val = ctx.emit_load(rsp, IrType::I64);
    IrValue new_rsp = ctx.emit_binop(IrOp::Add, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
    val = ctx.match_size(val, t, /*sign_ext=*/false);
    store_lvalue(insn.operands[0], val, ctx);
}

void lift_leave(LiftCtx& ctx) {
    IrValue rbp = ctx.reg(Reg::Rbp);
    ctx.emit_assign(ctx.reg(Reg::Rsp), rbp);
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue val = ctx.emit_load(rsp, IrType::I64);
    IrValue new_rsp = ctx.emit_binop(IrOp::Add, rsp, ctx.imm(8, IrType::I64));
    ctx.emit_assign(ctx.reg(Reg::Rbp), val);
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
}

// SysV x86-64 caller-saved registers — any call may destroy these.
static constexpr Reg kCallerSaved[] = {
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
};

void emit_call_clobbers(LiftCtx& ctx) {
    for (Reg r : kCallerSaved) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    }
}

void lift_call(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const auto& op = insn.operands[0];

    // Emit ABI barriers so DCE keeps argument-register setup code alive.
    // Calls don't textually reference arg regs in our IR, so without this,
    // the optimizer would delete code that sets them.
    {
        IrInst abc;
        abc.op        = IrOp::Intrinsic;
        abc.name      = "call.args.1";
        abc.srcs[0]   = ctx.reg(Reg::Rdi);
        abc.srcs[1]   = ctx.reg(Reg::Rsi);
        abc.srcs[2]   = ctx.reg(Reg::Rdx);
        abc.src_count = 3;
        ctx.emit(std::move(abc));
    }
    {
        IrInst def;
        def.op        = IrOp::Intrinsic;
        def.name      = "call.args.2";
        def.srcs[0]   = ctx.reg(Reg::Rcx);
        def.srcs[1]   = ctx.reg(Reg::R8);
        def.srcs[2]   = ctx.reg(Reg::R9);
        def.src_count = 3;
        ctx.emit(std::move(def));
    }

    IrInst i;
    if (op.kind == Operand::Kind::Relative) {
        i.op      = IrOp::Call;
        i.target1 = op.rel.target;
    } else {
        i.op      = IrOp::CallIndirect;
        i.srcs[0] = materialize_rvalue(op, ctx);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));

    // Model the call clobbering caller-saved registers. Any prior def of
    // a caller-saved reg that isn't read before the call becomes dead
    // (picked up by the existing DCE pass).
    emit_call_clobbers(ctx);
}

void lift_ret(LiftCtx& ctx) {
    // Model the SysV x86-64 return value. Integer/pointer results come back
    // in rax; floating-point results come back in xmm0. We record both as
    // sources of the Return so DCE keeps each computation alive. The
    // structurer later picks whichever source carries meaningful data when
    // rendering `return <expr>;`.
    IrInst i;
    i.op        = IrOp::Return;
    i.srcs[0]   = ctx.read_reg(Reg::Rax);
    i.srcs[1]   = IrValue::make_reg(Reg::Xmm0, IrType::F64);
    i.src_count = 2;
    ctx.emit(std::move(i));
}

void lift_jmp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const auto& op = insn.operands[0];

    // Tail call: the CFG builder marked this jmp's block as TailCall because
    // the target is a known function entry. Lift as `call target; return rax;`
    // — the same shape as a regular call, which gives us the call.args.*
    // argument barriers and natural pseudo-C output.
    if (ctx.blk->kind == BlockKind::TailCall &&
        op.kind == Operand::Kind::Relative) {
        lift_call(ctx);
        lift_ret(ctx);
        return;
    }

    IrInst i;
    if (op.kind == Operand::Kind::Relative) {
        i.op      = IrOp::Branch;
        i.target1 = op.rel.target;
    } else {
        i.op      = IrOp::BranchIndirect;
        i.srcs[0] = materialize_rvalue(op, ctx);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));
}

[[nodiscard]] IrValue jcc_predicate(Mnemonic mn, LiftCtx& ctx) {
    const IrValue zf = ctx.flag_val(Flag::Zf);
    const IrValue sf = ctx.flag_val(Flag::Sf);
    const IrValue cf = ctx.flag_val(Flag::Cf);
    const IrValue of = ctx.flag_val(Flag::Of);

    switch (mn) {
        case Mnemonic::Jo:  return of;
        case Mnemonic::Jno: return ctx.emit_unop(IrOp::Not, of);
        case Mnemonic::Jb:  return cf;
        case Mnemonic::Jae: return ctx.emit_unop(IrOp::Not, cf);
        case Mnemonic::Je:  return zf;
        case Mnemonic::Jne: return ctx.emit_unop(IrOp::Not, zf);
        case Mnemonic::Jbe: return ctx.emit_binop_i1(IrOp::Or, cf, zf);
        case Mnemonic::Ja: {
            IrValue nzf = ctx.emit_unop(IrOp::Not, zf);
            IrValue ncf = ctx.emit_unop(IrOp::Not, cf);
            return ctx.emit_binop_i1(IrOp::And, nzf, ncf);
        }
        case Mnemonic::Js:  return sf;
        case Mnemonic::Jns: return ctx.emit_unop(IrOp::Not, sf);
        case Mnemonic::Jl:  return ctx.emit_binop_i1(IrOp::Xor, sf, of);
        case Mnemonic::Jge: {
            IrValue x = ctx.emit_binop_i1(IrOp::Xor, sf, of);
            return ctx.emit_unop(IrOp::Not, x);
        }
        case Mnemonic::Jle: {
            IrValue x = ctx.emit_binop_i1(IrOp::Xor, sf, of);
            return ctx.emit_binop_i1(IrOp::Or, zf, x);
        }
        case Mnemonic::Jg: {
            IrValue x = ctx.emit_binop_i1(IrOp::Xor, sf, of);
            IrValue nxr = ctx.emit_unop(IrOp::Not, x);
            IrValue nzf = ctx.emit_unop(IrOp::Not, zf);
            return ctx.emit_binop_i1(IrOp::And, nzf, nxr);
        }
        case Mnemonic::Jp:
        case Mnemonic::Jnp: {
            IrValue t = ctx.temp(IrType::I1);
            IrInst inst;
            inst.op   = IrOp::Intrinsic;
            inst.dst  = t;
            inst.name = (mn == Mnemonic::Jp) ? "parity" : "not_parity";
            ctx.emit(std::move(inst));
            return t;
        }
        default:
            return ctx.imm(0, IrType::I1);
    }
}

void lift_jcc(LiftCtx& ctx, Mnemonic mn) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1 ||
        insn.operands[0].kind != Operand::Kind::Relative) return;
    IrValue cond = jcc_predicate(mn, ctx);
    IrInst i;
    i.op        = IrOp::CondBranch;
    i.srcs[0]   = cond;
    i.src_count = 1;
    i.target1   = insn.operands[0].rel.target;
    i.target2   = insn.address + insn.length;
    ctx.emit(std::move(i));
}

void lift_nop(LiftCtx& ctx) {
    IrInst i;
    i.op = IrOp::Nop;
    ctx.emit(std::move(i));
}

void lift_unreachable(LiftCtx& ctx) {
    IrInst i;
    i.op = IrOp::Unreachable;
    ctx.emit(std::move(i));
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    ctx.emit(std::move(i));
}

// Read an operand as a scalar floating-point value at the requested type
// (F32 or F64). Xmm registers come back as `IrValue::make_reg(r, t)`;
// memory operands lift to a Load typed at `t`.
[[nodiscard]] IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t) {
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
    if (insn.num_operands != 2) return;
    IrValue a = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue b = materialize_fp_rvalue(insn.operands[1], ctx, t);
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

// SetCC: write 0 or 1 to a byte destination based on the flag predicate.
// Reuses jcc_predicate() so the flag logic is shared with conditional
// branches — i.e. `sete` and `je` compute the same i1.
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

void lift_instruction(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
        case Mnemonic::Mov:     lift_mov(ctx);     break;
        case Mnemonic::Movzx:   lift_movzx(ctx);   break;
        case Mnemonic::Movsx:   lift_movsx(ctx);   break;
        case Mnemonic::Movsxd:  lift_movsx(ctx);   break;
        case Mnemonic::Lea:     lift_lea(ctx);     break;
        case Mnemonic::Add:     lift_add(ctx);     break;
        case Mnemonic::Sub:     lift_sub(ctx);     break;
        case Mnemonic::Cmp:     lift_cmp(ctx);     break;
        case Mnemonic::And:     lift_and(ctx);     break;
        case Mnemonic::Or:      lift_or(ctx);      break;
        case Mnemonic::Xor:     lift_xor(ctx);     break;
        case Mnemonic::Test:    lift_test(ctx);    break;
        case Mnemonic::Inc:     lift_inc(ctx);     break;
        case Mnemonic::Dec:     lift_dec(ctx);     break;
        case Mnemonic::Neg:     lift_neg(ctx);     break;
        case Mnemonic::Not:     lift_not(ctx);     break;
        case Mnemonic::Shl:     lift_shl(ctx);     break;
        case Mnemonic::Shr:     lift_shr(ctx);     break;
        case Mnemonic::Sar:     lift_sar(ctx);     break;
        case Mnemonic::Imul:    lift_imul(ctx);    break;
        case Mnemonic::Push:    lift_push(ctx);    break;
        case Mnemonic::Pop:     lift_pop(ctx);     break;
        case Mnemonic::Leave:   lift_leave(ctx);   break;
        case Mnemonic::Call:    lift_call(ctx);    break;
        case Mnemonic::Ret:     lift_ret(ctx);     break;
        case Mnemonic::Jmp:     lift_jmp(ctx);     break;
        case Mnemonic::Nop:     lift_nop(ctx);     break;
        case Mnemonic::Int3:
        case Mnemonic::Hlt:
        case Mnemonic::Ud2:
            lift_unreachable(ctx);
            break;
        case Mnemonic::Syscall:
            lift_intrinsic(ctx, "syscall");
            break;
        case Mnemonic::Endbr64: lift_intrinsic(ctx, "endbr64"); break;
        case Mnemonic::Endbr32: lift_intrinsic(ctx, "endbr32"); break;
        case Mnemonic::Cdqe: {
            // rax = sext64(eax)
            IrValue eax = ctx.read_reg(Reg::Eax);
            IrValue sx  = ctx.emit_convert(IrOp::SExt, eax, IrType::I64);
            ctx.write_reg(Reg::Rax, sx);
            break;
        }
        case Mnemonic::Cwde: {
            // eax = sext32(ax)   — 32-bit write then zero-extends per x64 rules.
            IrValue ax = ctx.read_reg(Reg::Ax);
            IrValue sx = ctx.emit_convert(IrOp::SExt, ax, IrType::I32);
            ctx.write_reg(Reg::Eax, sx);
            break;
        }
        case Mnemonic::Cdq:
        case Mnemonic::Cqo:
            lift_intrinsic(ctx, mnemonic_name(insn.mnemonic));
            break;

        // SetCC: nice lift reusing Jcc predicate logic.
        case Mnemonic::Seto: case Mnemonic::Setno:
        case Mnemonic::Setb: case Mnemonic::Setae:
        case Mnemonic::Sete: case Mnemonic::Setne:
        case Mnemonic::Setbe: case Mnemonic::Seta:
        case Mnemonic::Sets: case Mnemonic::Setns:
        case Mnemonic::Setp: case Mnemonic::Setnp:
        case Mnemonic::Setl: case Mnemonic::Setge:
        case Mnemonic::Setle: case Mnemonic::Setg:
            lift_setcc(ctx, insn.mnemonic);
            break;

        // ---- Scalar floating-point ---------------------------------------
        // Arithmetic: Add/Sub/Mul/Div at f32 or f64 type. The emitter
        // renders these as infix operators, so `addsd xmm0, xmm1` decompiles
        // to `xmm0 = (xmm0 + xmm1)`, and with a declared signature that
        // becomes `return (a + b);`.
        case Mnemonic::Addss: lift_fp_binop(ctx, IrOp::Add, IrType::F32); break;
        case Mnemonic::Subss: lift_fp_binop(ctx, IrOp::Sub, IrType::F32); break;
        case Mnemonic::Mulss: lift_fp_binop(ctx, IrOp::Mul, IrType::F32); break;
        case Mnemonic::Divss: lift_fp_binop(ctx, IrOp::Div, IrType::F32); break;
        case Mnemonic::Addsd: lift_fp_binop(ctx, IrOp::Add, IrType::F64); break;
        case Mnemonic::Subsd: lift_fp_binop(ctx, IrOp::Sub, IrType::F64); break;
        case Mnemonic::Mulsd: lift_fp_binop(ctx, IrOp::Mul, IrType::F64); break;
        case Mnemonic::Divsd: lift_fp_binop(ctx, IrOp::Div, IrType::F64); break;
        // Moves: xmm ← xmm/mem and xmm/mem ← xmm at scalar width.
        case Mnemonic::MovssLoad:     lift_fp_mov(ctx, IrType::F32, false); break;
        case Mnemonic::MovssStore:    lift_fp_mov(ctx, IrType::F32, true);  break;
        case Mnemonic::MovsdXmm:      lift_fp_mov(ctx, IrType::F64, false); break;
        case Mnemonic::MovsdXmmStore: lift_fp_mov(ctx, IrType::F64, true);  break;
        // Packed moves: compiler-emitted shortcuts for copying a whole
        // xmm register — we model as scalar F64 copies. This loses the
        // upper 64 bits of SIMD data (which we never reason about anyway)
        // but preserves the scalar dataflow that compiler output relies on.
        case Mnemonic::Movaps:       lift_fp_mov(ctx, IrType::F64, false); break;
        case Mnemonic::MovapsStore:  lift_fp_mov(ctx, IrType::F64, true);  break;
        case Mnemonic::Movups:       lift_fp_mov(ctx, IrType::F64, false); break;
        case Mnemonic::MovupsStore:  lift_fp_mov(ctx, IrType::F64, true);  break;
        // Conversions and compares stay as intrinsics for now — named, so
        // the reader sees "cvtsi2sd(...)" / "ucomisd(...)" clearly.
        case Mnemonic::Sqrtss: case Mnemonic::Sqrtsd:
        case Mnemonic::Cvtsi2ss: case Mnemonic::Cvtsi2sd:
        case Mnemonic::Cvttss2si: case Mnemonic::Cvttsd2si:
        case Mnemonic::Cvtss2sd: case Mnemonic::Cvtsd2ss:
        case Mnemonic::Ucomiss: case Mnemonic::Ucomisd:
            lift_intrinsic(ctx, mnemonic_name(insn.mnemonic));
            break;

        // String ops: intrinsic with explicit rdi/rsi/rcx effect.
        case Mnemonic::Movsb: lift_string_op(ctx, "rep.movsb", true,  false); break;
        case Mnemonic::Movsd: lift_string_op(ctx, "rep.movsd", true,  false); break;
        case Mnemonic::Movsq: lift_string_op(ctx, "rep.movsq", true,  false); break;
        case Mnemonic::Cmpsb: lift_string_op(ctx, "rep.cmpsb", true,  false); break;
        case Mnemonic::Cmpsd: lift_string_op(ctx, "rep.cmpsd", true,  false); break;
        case Mnemonic::Cmpsq: lift_string_op(ctx, "rep.cmpsq", true,  false); break;
        case Mnemonic::Stosb: lift_string_op(ctx, "rep.stosb", false, true);  break;
        case Mnemonic::Stosd: lift_string_op(ctx, "rep.stosd", false, true);  break;
        case Mnemonic::Stosq: lift_string_op(ctx, "rep.stosq", false, true);  break;
        case Mnemonic::Lodsb: lift_string_op(ctx, "rep.lodsb", false, true);  break;
        case Mnemonic::Lodsd: lift_string_op(ctx, "rep.lodsd", false, true);  break;
        case Mnemonic::Lodsq: lift_string_op(ctx, "rep.lodsq", false, true);  break;
        case Mnemonic::Scasb: lift_string_op(ctx, "rep.scasb", false, true);  break;
        case Mnemonic::Scasd: lift_string_op(ctx, "rep.scasd", false, true);  break;
        case Mnemonic::Scasq: lift_string_op(ctx, "rep.scasq", false, true);  break;

        default:
            if (is_conditional_branch(insn.mnemonic)) {
                lift_jcc(ctx, insn.mnemonic);
            } else {
                lift_intrinsic(ctx, mnemonic_name(insn.mnemonic));
            }
            break;
    }
}

void ensure_terminator(IrBlock& bb) {
    if (!bb.insts.empty() && is_terminator(bb.insts.back().op)) return;

    switch (bb.kind) {
        case BlockKind::Return: {
            IrInst i;
            i.op = IrOp::Return;
            bb.insts.push_back(std::move(i));
            break;
        }
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            } else {
                IrInst i;
                i.op = IrOp::Unreachable;
                bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::IndirectJmp: {
            IrInst i;
            i.op = IrOp::Unreachable;
            bb.insts.push_back(std::move(i));
            break;
        }
        case BlockKind::Switch:
            // The indirect jmp is the block's natural terminator; it lifts
            // to BranchIndirect so no synthetic instruction is needed.
            break;
        case BlockKind::TailCall:
            // The jmp was lifted as call+return; the Return is the terminator.
            break;
        case BlockKind::Conditional:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            }
            break;
    }
}

}  // anonymous namespace

Result<IrFunction> X64Lifter::lift(const Function& fn) const {
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
        ctx.fn  = &ir;
        ctx.blk = &dst_bb;

        for (const auto& insn : src_bb.instructions) {
            ctx.insn = &insn;
            lift_instruction(ctx);
        }

        ensure_terminator(dst_bb);
    }

    return ir;
}

}  // namespace ember
