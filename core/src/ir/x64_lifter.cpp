#include <ember/ir/x64_lifter.hpp>

#include <cstddef>
#include <format>
#include <string>
#include <string_view>
#include <utility>

#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
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
    Abi                abi  = Abi::SysVAmd64;

    // Last flag-setting computation in this block, if any. Used by Jp/Jnp/
    // Setp/Cmovp to compute PF from the actual result rather than emitting
    // an opaque `parity()` intrinsic. Reset per block via the constructor's
    // default (kind=None). Stays within-block: cross-block PF use falls back
    // to the intrinsic (the Flag enum has no Pf).
    IrValue last_flag_src = {};

    // When the last flag-setting op was a scalar-FP compare (ucomiss /
    // ucomisd / comiss / comisd), these hold its two operands. After such a
    // compare PF means "unordered (one operand is NaN)", NOT integer parity
    // of the result, so a subsequent Jp/Jnp/Setp/Cmovp must lower to an
    // `unordered_fp_compare(a, b)` intrinsic instead of the XOR-fold formula.
    // Cleared by `set_zf_sf` (and any other integer flag-setter) so a later
    // `add; jp` doesn't pick up a stale FP-cmp.
    IrValue last_fp_cmp_a = {};
    IrValue last_fp_cmp_b = {};

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
        last_flag_src = result;
        // Integer flag-setter happened — any prior FP-compare context is now
        // invalid for PF interpretation.
        last_fp_cmp_a = {};
        last_fp_cmp_b = {};
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

// Forward decl: cmov_predicate (defined alongside lift_cmov earlier in the
// dispatch order) reuses jcc_predicate's flag-combining logic, but
// jcc_predicate is naturally placed next to the jcc/setcc family further
// down. Decl up here lets us keep both groupings.
[[nodiscard]] IrValue jcc_predicate(Mnemonic mn, LiftCtx& ctx);

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

// CF/OF for shift instructions. CF holds the last bit shifted out:
//   shl: bit (W - count) of the original value
//   shr/sar: bit (count - 1) of the original value
// OF is only well-defined for 1-bit shifts; we compute it unconditionally
// because the common case is `shl/shr ..., 1` where the value is meaningful,
// and at higher counts OF is documented as undefined anyway.
//   shl OF = MSB(result) ^ CF
//   shr OF = MSB(original)
//   sar OF = 0
//
// We deliberately don't gate on count==0 (which per Intel leaves flags
// unchanged): that case is exceedingly rare in compiled code and adding a
// Select on every shift would clutter every byte-extraction sequence.
void lift_shift(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[1], ctx);
    cnt = ctx.match_size(cnt, a.type, /*sign_ext=*/false);

    const unsigned width = type_bits(a.type);
    IrValue width_imm = ctx.imm(static_cast<i64>(width), a.type);
    IrValue one_t     = ctx.imm(1, a.type);
    IrValue zero_t    = ctx.imm(0, a.type);

    IrValue cf_bit;
    if (op == IrOp::Shl) {
        IrValue shift = ctx.emit_binop(IrOp::Sub, width_imm, cnt);
        IrValue out_bit = ctx.emit_binop(IrOp::Lshr, a, shift);
        cf_bit = ctx.emit_binop(IrOp::And, out_bit, one_t);
    } else {
        IrValue shift = ctx.emit_binop(IrOp::Sub, cnt, one_t);
        IrValue out_bit = ctx.emit_binop(IrOp::Lshr, a, shift);
        cf_bit = ctx.emit_binop(IrOp::And, out_bit, one_t);
    }
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpNe, cf_bit, zero_t));

    IrValue r = ctx.emit_binop(op, a, cnt);

    if (op == IrOp::Shl) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb = ctx.emit_binop(IrOp::Lshr, r, msb_shift);
        IrValue msb_bit = ctx.emit_binop(IrOp::And, msb, one_t);
        IrValue msb_i1  = ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t);
        ctx.emit_set_flag(Flag::Of,
            ctx.emit_binop_i1(IrOp::Xor, msb_i1, ctx.flag_val(Flag::Cf)));
    } else if (op == IrOp::Lshr) {
        IrValue msb_shift = ctx.imm(static_cast<i64>(width - 1), a.type);
        IrValue msb = ctx.emit_binop(IrOp::Lshr, a, msb_shift);
        IrValue msb_bit = ctx.emit_binop(IrOp::And, msb, one_t);
        ctx.emit_set_flag(Flag::Of, ctx.emit_cmp(IrOp::CmpNe, msb_bit, zero_t));
    } else {
        ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    }

    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

void lift_shl(LiftCtx& ctx) { lift_shift(ctx, IrOp::Shl);  }
void lift_shr(LiftCtx& ctx) { lift_shift(ctx, IrOp::Lshr); }
void lift_sar(LiftCtx& ctx) { lift_shift(ctx, IrOp::Ashr); }

// SHLD dst, src, count: dst = (dst << count) | (src >> (W - count))
// SHRD dst, src, count: dst = (dst >> count) | (src << (W - count))
// Lift as the equivalent shift+or expression so the reader sees the actual
// bit-stitch rather than an opaque intrinsic. Flag handling is approximate:
// we set ZF/SF on the result and leave CF/OF as their pre-shift values
// (true Intel semantics: undefined for count >= W, otherwise CF = last bit
// shifted out — which adds another four ops per shift; the dataflow is the
// part that matters for decompiled output).
void lift_double_shift(LiftCtx& ctx, bool right) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue dst = materialize_rvalue(insn.operands[0], ctx);
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    IrValue cnt = materialize_rvalue(insn.operands[2], ctx);
    src = ctx.match_size(src, dst.type, /*sign_ext=*/false);
    cnt = ctx.match_size(cnt, dst.type, /*sign_ext=*/false);

    const unsigned width = type_bits(dst.type);
    IrValue width_imm = ctx.imm(static_cast<i64>(width), dst.type);
    IrValue cnt_compl = ctx.emit_binop(IrOp::Sub, width_imm, cnt);

    IrValue lo, hi;
    if (right) {
        lo = ctx.emit_binop(IrOp::Lshr, dst, cnt);
        hi = ctx.emit_binop(IrOp::Shl,  src, cnt_compl);
    } else {
        lo = ctx.emit_binop(IrOp::Shl,  dst, cnt);
        hi = ctx.emit_binop(IrOp::Lshr, src, cnt_compl);
    }
    IrValue r = ctx.emit_binop(IrOp::Or, lo, hi);
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

// 1-op MUL/IMUL: rax = rax * src, with the high half going into rdx (or
// AH for byte form). We model this by widening both operands to 2W and
// computing the full product, then assigning the low half back to rax/eax/...
// and the high half to rdx/edx/... For 64-bit we don't have I128, so the
// high half degrades to a named `mulh.{s,u}` intrinsic that still carries
// both source operands so the reader can see what's being multiplied.
//
// `signed_mul` selects IMUL (SExt) vs MUL (ZExt).
void lift_mul_one_op(LiftCtx& ctx, bool signed_mul) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue b = materialize_rvalue(insn.operands[0], ctx);
    const IrType t = b.type;
    const unsigned bits = type_bits(t);

    Reg lo_a, lo_dst, hi_dst;
    switch (bits) {
        case 8:  lo_a = Reg::Al;  lo_dst = Reg::Ax;  hi_dst = Reg::None; break;
        case 16: lo_a = Reg::Ax;  lo_dst = Reg::Ax;  hi_dst = Reg::Dx;   break;
        case 32: lo_a = Reg::Eax; lo_dst = Reg::Eax; hi_dst = Reg::Edx;  break;
        default: lo_a = Reg::Rax; lo_dst = Reg::Rax; hi_dst = Reg::Rdx;  break;
    }
    IrValue a = ctx.read_reg(lo_a);

    if (bits <= 32) {
        const IrType wide = type_for_bits(bits * 2);
        IrOp ext = signed_mul ? IrOp::SExt : IrOp::ZExt;
        IrValue aw = ctx.emit_convert(ext, a, wide);
        IrValue bw = ctx.emit_convert(ext, b, wide);
        IrValue prod = ctx.emit_binop(IrOp::Mul, aw, bw);
        if (bits == 8) {
            // mul al, r/m8 → ax = al * r/m. Whole AX is the product.
            ctx.write_reg(lo_dst, prod);
        } else {
            IrValue lo = ctx.emit_convert(IrOp::Trunc, prod, t);
            IrValue shift = ctx.emit_binop(IrOp::Lshr, prod,
                                            ctx.imm(static_cast<i64>(bits), wide));
            IrValue hi = ctx.emit_convert(IrOp::Trunc, shift, t);
            ctx.write_reg(lo_dst, lo);
            ctx.write_reg(hi_dst, hi);
        }
    } else {
        // 64-bit: low half is just rax * src; high half degrades to a named
        // intrinsic so the reader sees both operands. RAX is also clobbered
        // first by the low product before RDX takes the high — that ordering
        // matches Intel's atomicity (both updated together).
        IrValue lo = ctx.emit_binop(IrOp::Mul, a, b);
        ctx.write_reg(lo_dst, lo);

        IrInst high;
        high.op   = IrOp::Intrinsic;
        high.name = signed_mul ? "mulh.s.64" : "mulh.u.64";
        high.dst  = ctx.temp(t);
        high.srcs[0] = a;
        high.srcs[1] = b;
        high.src_count = 2;
        IrValue hi_v = high.dst;
        ctx.emit(std::move(high));
        ctx.write_reg(hi_dst, hi_v);
    }
}

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
        lift_mul_one_op(ctx, /*signed_mul=*/true);
    }
}

void lift_mul(LiftCtx& ctx) {
    lift_mul_one_op(ctx, /*signed_mul=*/false);
}

// DIV / IDIV r/m: divides (rdx:rax) by r/m, writes quotient to rax/al and
// remainder to rdx/ah. Dividend is built by combining the implicit register
// pair widened to 2W; for 64-bit we don't have I128 so we degrade to named
// `divq.{s,u}.64` / `divr.{s,u}.64` intrinsics that carry both halves of
// the dividend explicitly (same shape as the 64-bit MUL path's
// `mulh.{s,u}.64`).
void lift_div_one_op(LiftCtx& ctx, bool signed_div) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue divisor = materialize_rvalue(insn.operands[0], ctx);
    const IrType t = divisor.type;
    const unsigned bits = type_bits(t);

    Reg lo_a, hi_a, lo_dst, hi_dst;
    switch (bits) {
        case 8:  lo_a = Reg::Al;  hi_a = Reg::None; lo_dst = Reg::Al;  hi_dst = Reg::Ah;  break;
        case 16: lo_a = Reg::Ax;  hi_a = Reg::Dx;   lo_dst = Reg::Ax;  hi_dst = Reg::Dx;  break;
        case 32: lo_a = Reg::Eax; hi_a = Reg::Edx;  lo_dst = Reg::Eax; hi_dst = Reg::Edx; break;
        default: lo_a = Reg::Rax; hi_a = Reg::Rdx;  lo_dst = Reg::Rax; hi_dst = Reg::Rdx; break;
    }

    if (bits == 8) {
        // 8-bit divide: AX / r/m8 → AL=quot, AH=rem. AX is already a wider
        // version of the dividend register pair.
        IrValue ax = ctx.read_reg(Reg::Ax);
        IrOp ext = signed_div ? IrOp::SExt : IrOp::ZExt;
        IrValue dw = ctx.emit_convert(ext, divisor, IrType::I16);
        IrValue q  = ctx.emit_binop(IrOp::Div, ax, dw);
        IrValue r  = ctx.emit_binop(IrOp::Mod, ax, dw);
        IrValue ql = ctx.emit_convert(IrOp::Trunc, q, IrType::I8);
        IrValue rl = ctx.emit_convert(IrOp::Trunc, r, IrType::I8);
        ctx.write_reg(lo_dst, ql);
        ctx.write_reg(hi_dst, rl);
        return;
    }

    if (bits <= 32) {
        const IrType wide = type_for_bits(bits * 2);
        IrOp ext = signed_div ? IrOp::SExt : IrOp::ZExt;
        IrValue lo = ctx.read_reg(lo_a);
        IrValue hi = ctx.read_reg(hi_a);
        IrValue lo_w = ctx.emit_convert(IrOp::ZExt, lo, wide);
        IrValue hi_w = ctx.emit_convert(ext,        hi, wide);
        IrValue hi_shift = ctx.emit_binop(IrOp::Shl, hi_w,
                                           ctx.imm(static_cast<i64>(bits), wide));
        IrValue dividend = ctx.emit_binop(IrOp::Or, hi_shift, lo_w);
        IrValue dw = ctx.emit_convert(ext, divisor, wide);
        IrValue q  = ctx.emit_binop(IrOp::Div, dividend, dw);
        IrValue r  = ctx.emit_binop(IrOp::Mod, dividend, dw);
        IrValue ql = ctx.emit_convert(IrOp::Trunc, q, t);
        IrValue rl = ctx.emit_convert(IrOp::Trunc, r, t);
        ctx.write_reg(lo_dst, ql);
        ctx.write_reg(hi_dst, rl);
        return;
    }

    // 64-bit: no I128, so we degrade to named intrinsics that carry both
    // halves of the dividend explicitly — same shape as the 64-bit MUL
    // path's `mulh.{s,u}.64`. The reader sees `divq_u64(rdx, rax, b)` so
    // it's visible that RDX participates; the constant folder skips
    // intrinsics, so the wrong-arithmetic class of bug from folding
    // `Div(rax, b)` against a sign-extended i64 imm goes away too.
    //
    // `xor edx, edx; div r64` and `cdq; idiv r64` both still render
    // correctly — the reader sees the constant 0 (or the sign-extended
    // rax) flowing into the high arg.
    IrValue rax = ctx.read_reg(Reg::Rax);
    IrValue rdx = ctx.read_reg(Reg::Rdx);

    IrInst qi;
    qi.op   = IrOp::Intrinsic;
    qi.name = signed_div ? "divq.s.64" : "divq.u.64";
    qi.dst  = ctx.temp(t);
    qi.srcs[0] = rdx;
    qi.srcs[1] = rax;
    qi.srcs[2] = divisor;
    qi.src_count = 3;
    IrValue q = qi.dst;
    ctx.emit(std::move(qi));

    IrInst ri;
    ri.op   = IrOp::Intrinsic;
    ri.name = signed_div ? "divr.s.64" : "divr.u.64";
    ri.dst  = ctx.temp(t);
    ri.srcs[0] = rdx;
    ri.srcs[1] = rax;
    ri.srcs[2] = divisor;
    ri.src_count = 3;
    IrValue r = ri.dst;
    ctx.emit(std::move(ri));

    ctx.write_reg(lo_dst, q);
    ctx.write_reg(hi_dst, r);
}

// ADC dst, src: dst = dst + src + CF. Update CF/OF/ZF/SF.
// SBB dst, src: dst = dst - src - CF.
// We model carry by widening to I1 and adding into the result; CF/OF for the
// combined operation are computed against (a OP b) — the second-step carry
// from adding the cf bit is folded in via OR with the first-step carry.
// That's an approximation: in cases where (a+b) doesn't overflow but
// (a+b+1) does, OF will miss the second step. The dataflow side (the actual
// sum/difference) is exact.
void lift_adc_sbb(LiftCtx& ctx, bool subtract) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_rvalue(insn.operands[0], ctx);
    IrValue b = materialize_rvalue(insn.operands[1], ctx);
    b = ctx.match_size(b, a.type, /*sign_ext=*/true);
    IrValue cf  = ctx.flag_val(Flag::Cf);
    IrValue cf_w = ctx.emit_convert(IrOp::ZExt, cf, a.type);

    IrOp op_main   = subtract ? IrOp::Sub        : IrOp::Add;
    IrOp op_carry  = subtract ? IrOp::SubBorrow  : IrOp::AddCarry;
    IrOp op_over   = subtract ? IrOp::SubOverflow: IrOp::AddOverflow;

    IrValue mid = ctx.emit_binop(op_main, a, b);
    IrValue r   = ctx.emit_binop(op_main, mid, cf_w);

    IrValue cf1 = ctx.emit_binop_i1(op_carry, a, b);
    IrValue cf2 = ctx.emit_binop_i1(op_carry, mid, cf_w);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(IrOp::Or, cf1, cf2));
    IrValue of1 = ctx.emit_binop_i1(op_over, a, b);
    IrValue of2 = ctx.emit_binop_i1(op_over, mid, cf_w);
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::Or, of1, of2));
    ctx.set_zf_sf(r);
    store_lvalue(insn.operands[0], r, ctx);
}

// Build the same i1 condition that jcc would produce, given the CMOVcc
// mnemonic. Reuses jcc_predicate by mapping cmov→jcc.
[[nodiscard]] IrValue cmov_predicate(Mnemonic mn, LiftCtx& ctx) {
    Mnemonic jcc = Mnemonic::Invalid;
    switch (mn) {
        case Mnemonic::Cmovo:  jcc = Mnemonic::Jo;  break;
        case Mnemonic::Cmovno: jcc = Mnemonic::Jno; break;
        case Mnemonic::Cmovb:  jcc = Mnemonic::Jb;  break;
        case Mnemonic::Cmovae: jcc = Mnemonic::Jae; break;
        case Mnemonic::Cmove:  jcc = Mnemonic::Je;  break;
        case Mnemonic::Cmovne: jcc = Mnemonic::Jne; break;
        case Mnemonic::Cmovbe: jcc = Mnemonic::Jbe; break;
        case Mnemonic::Cmova:  jcc = Mnemonic::Ja;  break;
        case Mnemonic::Cmovs:  jcc = Mnemonic::Js;  break;
        case Mnemonic::Cmovns: jcc = Mnemonic::Jns; break;
        case Mnemonic::Cmovp:  jcc = Mnemonic::Jp;  break;
        case Mnemonic::Cmovnp: jcc = Mnemonic::Jnp; break;
        case Mnemonic::Cmovl:  jcc = Mnemonic::Jl;  break;
        case Mnemonic::Cmovge: jcc = Mnemonic::Jge; break;
        case Mnemonic::Cmovle: jcc = Mnemonic::Jle; break;
        case Mnemonic::Cmovg:  jcc = Mnemonic::Jg;  break;
        default: return ctx.imm(0, IrType::I1);
    }
    return jcc_predicate(jcc, ctx);
}

// CMOVcc dst, src: dst = cond ? src : dst. Lift as IrOp::Select so the
// emitter renders it as `dst = (cond ? src : dst);` — matches the source
// idiom `dst = cond ? src : dst;` rather than an opaque branch or intrinsic.
void lift_cmov(LiftCtx& ctx, Mnemonic mn) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue dst = materialize_rvalue(insn.operands[0], ctx);
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    src = ctx.match_size(src, dst.type, /*sign_ext=*/false);
    IrValue cond = cmov_predicate(mn, ctx);

    IrInst i;
    i.op        = IrOp::Select;
    i.dst       = ctx.temp(dst.type);
    i.srcs[0]   = cond;
    i.srcs[1]   = src;
    i.srcs[2]   = dst;
    i.src_count = 3;
    IrValue r = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(insn.operands[0], r, ctx);
}

// XCHG dst, src: swap. We materialize src first so the read isn't shadowed
// by the dst write. For memory operands this is still atomic at the SSA
// level (two assigns), which is enough for the decompiled-output reader.
void lift_xchg(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue dst_v = materialize_rvalue(insn.operands[0], ctx);
    IrValue src_v = materialize_rvalue(insn.operands[1], ctx);
    src_v = ctx.match_size(src_v, dst_v.type, /*sign_ext=*/false);
    store_lvalue(insn.operands[0], src_v, ctx);
    store_lvalue(insn.operands[1], dst_v, ctx);
}

// XADD dst, src: tmp = dst + src; src = dst; dst = tmp. Atomic in hardware;
// we model the dataflow without trying to express atomicity. Sets the
// add-style flags so subsequent jcc readouts are sensible.
void lift_xadd(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue dst_v = materialize_rvalue(insn.operands[0], ctx);
    IrValue src_v = materialize_rvalue(insn.operands[1], ctx);
    src_v = ctx.match_size(src_v, dst_v.type, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_binop_i1(IrOp::AddCarry, dst_v, src_v));
    ctx.emit_set_flag(Flag::Of, ctx.emit_binop_i1(IrOp::AddOverflow, dst_v, src_v));
    IrValue sum = ctx.emit_binop(IrOp::Add, dst_v, src_v);
    ctx.set_zf_sf(sum);
    store_lvalue(insn.operands[1], dst_v, ctx);
    store_lvalue(insn.operands[0], sum, ctx);
}

// CMPXCHG dst, src: if (rax == dst) { ZF=1; dst = src; } else { ZF=0; rax = dst; }
// We model the full conditional via two Selects so the dataflow stays explicit
// (no opaque intrinsic).
void lift_cmpxchg(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue dst_v = materialize_rvalue(insn.operands[0], ctx);
    IrValue src_v = materialize_rvalue(insn.operands[1], ctx);
    src_v = ctx.match_size(src_v, dst_v.type, /*sign_ext=*/false);

    Reg accum;
    switch (type_bits(dst_v.type)) {
        case 8:  accum = Reg::Al;  break;
        case 16: accum = Reg::Ax;  break;
        case 32: accum = Reg::Eax; break;
        default: accum = Reg::Rax; break;
    }
    IrValue acc = ctx.read_reg(accum);
    IrValue eq  = ctx.emit_cmp(IrOp::CmpEq, acc, dst_v);
    ctx.emit_set_flag(Flag::Zf, eq);
    // Integer flag-setter — invalidate any prior FP-compare context so a
    // later Jp/Jnp doesn't lower against stale ucomi operands.
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};

    // dst = eq ? src : dst (no-op, but lets later optimization see the cond)
    IrInst d;
    d.op = IrOp::Select;
    d.dst = ctx.temp(dst_v.type);
    d.srcs[0] = eq; d.srcs[1] = src_v; d.srcs[2] = dst_v;
    d.src_count = 3;
    IrValue d_new = d.dst;
    ctx.emit(std::move(d));
    store_lvalue(insn.operands[0], d_new, ctx);

    // rax = eq ? rax : dst
    IrInst r;
    r.op = IrOp::Select;
    r.dst = ctx.temp(dst_v.type);
    r.srcs[0] = eq; r.srcs[1] = acc; r.srcs[2] = dst_v;
    r.src_count = 3;
    IrValue r_new = r.dst;
    ctx.emit(std::move(r));
    ctx.write_reg(accum, r_new);
}

// BSF dst, src: dst = trailing-zero-count(src); ZF = (src == 0). The dst is
// undefined when src is 0 (Intel), but compiler-emitted code always guards on
// ZF first, so leaving the intrinsic value in dst is fine.
// BSR dst, src: dst = position of MSB.
void lift_bit_scan(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType t = operand_type(insn.operands[0]);
    src = ctx.match_size(src, t, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, src, ctx.imm(0, t)));
    // Integer flag-setter — clear any prior FP-compare context.
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(t);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue r = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(insn.operands[0], r, ctx);
}

// BT base, off: CF = (base >> (off mod W)) & 1. We don't model the mod
// because compilers emit immediate-form `bt base, imm` where the count is
// already in range; the symbolic shift is enough for the reader.
// BTS/BTR/BTC additionally write back base with bit `off` set/cleared/flipped.
void lift_bit_test(LiftCtx& ctx, char op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue base = materialize_rvalue(insn.operands[0], ctx);
    IrValue off  = materialize_rvalue(insn.operands[1], ctx);
    off = ctx.match_size(off, base.type, /*sign_ext=*/false);

    IrValue shifted = ctx.emit_binop(IrOp::Lshr, base, off);
    IrValue one_t   = ctx.imm(1, base.type);
    IrValue bit     = ctx.emit_binop(IrOp::And, shifted, one_t);
    ctx.emit_set_flag(Flag::Cf,
                      ctx.emit_cmp(IrOp::CmpNe, bit, ctx.imm(0, base.type)));

    if (op == 't') return;  // BT — read-only

    IrValue mask = ctx.emit_binop(IrOp::Shl, one_t, off);
    IrValue r;
    if (op == 's') {
        r = ctx.emit_binop(IrOp::Or, base, mask);
    } else if (op == 'r') {
        IrValue inv_mask = ctx.emit_unop(IrOp::Not, mask);
        r = ctx.emit_binop(IrOp::And, base, inv_mask);
    } else {  // 'c' — complement
        r = ctx.emit_binop(IrOp::Xor, base, mask);
    }
    store_lvalue(insn.operands[0], r, ctx);
}

// BSWAP r64: byte-reverse. There's no clean infix expression for this; emit a
// named intrinsic so the reader sees `dst = __bswap(src);`.
void lift_bswap(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    IrValue src = materialize_rvalue(insn.operands[0], ctx);
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = "bswap";
    i.dst  = ctx.temp(src.type);
    i.srcs[0]   = src;
    i.src_count = 1;
    IrValue r = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(insn.operands[0], r, ctx);
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

void emit_call_clobbers(LiftCtx& ctx) {
    for (Reg r : caller_saved_int_regs(ctx.abi)) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    }
}

// Emit the ABI barriers that keep argument-register setup code live
// through DCE. `call.args.1` carries slots 0-2 and `call.args.2` carries
// slots 3-5; Win64 only uses 4 slots so slots 4-5 are unset there. Every
// slot is looked up from the current ABI's int_arg_regs table so the
// same sig_inference logic that reads these can decode Win64 too.
void emit_arg_barriers(LiftCtx& ctx) {
    const auto args = int_arg_regs(ctx.abi);
    auto arg_value = [&](std::size_t slot) -> IrValue {
        if (slot < args.size()) return ctx.reg(args[slot]);
        if (ctx.abi == Abi::Win64 && slot < kMaxAbiIntArgs) {
            const i64 off = 0x20 + static_cast<i64>(slot - args.size()) * 8;
            IrValue rsp = ctx.reg(Reg::Rsp);
            IrValue addr = ctx.emit_binop(IrOp::Add, rsp, ctx.imm(off, IrType::I64));
            return ctx.emit_load(addr, IrType::I64);
        }
        return {};
    };
    auto fill = [&](std::string_view name, std::size_t lo) {
        IrInst in;
        in.op   = IrOp::Intrinsic;
        in.name = std::string(name);
        u8 cnt = 0;
        for (std::size_t i = 0; i < 3 && lo + i < kMaxAbiIntArgs; ++i) {
            IrValue v = arg_value(lo + i);
            if (v.kind == IrValueKind::None) break;
            in.srcs[cnt++] = v;
        }
        if (cnt == 0) return;
        in.src_count = cnt;
        ctx.emit(std::move(in));
    };
    fill("call.args.1", 0);
    fill("call.args.2", 3);
    fill("call.args.3", 6);
}

void lift_call(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const auto& op = insn.operands[0];

    emit_arg_barriers(ctx);

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

    // Indirect tail call: `jmp [mem]` / `jmp reg` is the canonical x86-64
    // form for indirect tail-calls (vtable dispatch, fn-ptr-table dispatch,
    // PLT thunks). The CFG builder couldn't classify the target as a known
    // function entry — neither a defined function nor a switch table — so
    // it left this block as IndirectJmp. Promoting to TailCall here
    // recovers `return (*ptr)(args);` in the pseudo-C; the previous
    // shape rendered as a bare `unreachable;` and dropped the call entirely.
    // Switch dispatch goes through BlockKind::Switch and never reaches here.
    if (ctx.blk->kind == BlockKind::IndirectJmp &&
        op.kind != Operand::Kind::Relative) {
        lift_call(ctx);
        lift_ret(ctx);
        ctx.blk->kind = BlockKind::TailCall;
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

IrValue jcc_predicate(Mnemonic mn, LiftCtx& ctx) {
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
            // After a scalar-FP compare (ucomi*/comi*), PF means "unordered"
            // — at least one operand is NaN. Lower to a typed intrinsic so
            // the reader sees `if (unordered_fp_compare(a, b))`, the SSA
            // pass keeps both operands live, and the cleanup pass doesn't
            // try to apply the integer parity formula to FP values.
            if (ctx.last_fp_cmp_a.kind != IrValueKind::None &&
                ctx.last_fp_cmp_b.kind != IrValueKind::None) {
                IrInst inst;
                inst.op   = IrOp::Intrinsic;
                inst.name = "unordered_fp_compare";
                inst.dst  = ctx.temp(IrType::I1);
                inst.srcs[0] = ctx.last_fp_cmp_a;
                inst.srcs[1] = ctx.last_fp_cmp_b;
                inst.src_count = 2;
                IrValue v = inst.dst;
                ctx.emit(std::move(inst));
                return (mn == Mnemonic::Jp) ? v : ctx.emit_unop(IrOp::Not, v);
            }
            // PF = even parity of the low 8 bits of the most recent flag-
            // setting computation. We model that with the standard XOR-fold:
            //   v8 = trunc8(src);
            //   x  = v8 ^ (v8 >> 4);
            //   x  = x  ^ (x  >> 2);
            //   x  = x  ^ (x  >> 1);
            //   pf = (x & 1) == 0
            // When no in-block flag source is available, fall back to the
            // opaque intrinsic so cross-block / first-instruction Jp still
            // lifts (rare, but legal).
            if (ctx.last_flag_src.kind == IrValueKind::None) {
                IrValue t = ctx.temp(IrType::I1);
                IrInst inst;
                inst.op   = IrOp::Intrinsic;
                inst.dst  = t;
                inst.name = (mn == Mnemonic::Jp) ? "parity" : "not_parity";
                ctx.emit(std::move(inst));
                return t;
            }
            IrValue v = ctx.last_flag_src;
            IrValue v8 = (v.type == IrType::I8)
                ? v
                : ctx.emit_convert(IrOp::Trunc, v, IrType::I8);
            IrValue x1 = ctx.emit_binop(IrOp::Xor, v8,
                            ctx.emit_binop(IrOp::Lshr, v8, ctx.imm(4, IrType::I8)));
            IrValue x2 = ctx.emit_binop(IrOp::Xor, x1,
                            ctx.emit_binop(IrOp::Lshr, x1, ctx.imm(2, IrType::I8)));
            IrValue x3 = ctx.emit_binop(IrOp::Xor, x2,
                            ctx.emit_binop(IrOp::Lshr, x2, ctx.imm(1, IrType::I8)));
            IrValue lo = ctx.emit_binop(IrOp::And, x3, ctx.imm(1, IrType::I8));
            IrValue is_even = ctx.emit_cmp(IrOp::CmpEq, lo, ctx.imm(0, IrType::I8));
            return (mn == Mnemonic::Jp)
                ? is_even
                : ctx.emit_unop(IrOp::Not, is_even);
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
    const auto& insn = *ctx.insn;
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    // Pull up to 3 operands through as sources so atomics (xadd, cmpxchg,
    // lock xchg, ...) render with their arguments instead of as empty
    // `xadd();` calls. Memory operands lift as loads, which is accurate
    // for the read-modify-write side and at worst slightly lossy for the
    // write-back — still more useful than nothing.
    for (u8 j = 0; j < insn.num_operands && j < 3; ++j) {
        IrValue v = materialize_rvalue(insn.operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
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

// ----- Packed SIMD intrinsics --------------------------------------------
//
// XMM dataflow at the register-width level uses IrType::I128 — the actual
// 128-bit width — so the upper 64 bits aren't silently truncated by the
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
[[nodiscard]] IrValue read_xmm(LiftCtx& ctx, const Operand& op, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        return IrValue::make_reg(op.reg, t);
    }
    if (op.kind == Operand::Kind::Memory) {
        IrValue ea = compute_ea(op.mem, ctx);
        return ctx.emit_load(ea, t, op.mem.segment);
    }
    return IrValue{};
}

void write_xmm(LiftCtx& ctx, const Operand& op, IrValue v, IrType t) {
    if (op.kind == Operand::Kind::Register) {
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
//   - F32 / F64 for scalar-low-lane ops (`_mm_min_ss`, `_mm_max_sd`, etc.) —
//     architecturally these only modify the low lane and the compiler treats
//     the result as scalar. Keeping them at scalar width lets the surrounding
//     scalar-FP code (Movss/Movsd loads, return values) flow naturally.
void lift_simd_binop(LiftCtx& ctx, std::string_view name, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue a = read_xmm(ctx, insn.operands[0], t);
    IrValue b = read_xmm(ctx, insn.operands[1], t);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None) return;

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst  = ctx.temp(t);
    i.srcs[0]   = a;
    i.srcs[1]   = b;
    i.src_count = 2;
    // Three-operand forms (Pshufd's immediate selector) tag the imm onto
    // src[2] so the intrinsic shows the shuffle pattern in its argument list.
    if (insn.num_operands == 3 &&
        insn.operands[2].kind == Operand::Kind::Immediate) {
        const Imm& im = insn.operands[2].imm;
        i.srcs[2]   = ctx.imm(im.value, type_for_bits(im.size * 8));
        i.src_count = 3;
    }
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    write_xmm(ctx, insn.operands[0], result, t);
}

// SSE2 immediate-shift shape: `psllw xmm, imm8` and friends. The
// regular lift_simd_binop path tries to `read_xmm(operands[1])`,
// which fails for immediates — so the shift would silently emit
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

// `movdqa xmm, xmm/m128` (and unaligned `movdqu`). Treated as a typed
// load+store at the chosen SIMD width — the IR carries the dataflow, the
// emitter prints `xmm0 = *(__m128i*)(rsi);` style.
void lift_simd_mov(LiftCtx& ctx, IrType t, bool storing) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    (void)storing;  // operand order already encodes it
    IrValue v = read_xmm(ctx, insn.operands[1], t);
    if (v.kind == IrValueKind::None) return;
    write_xmm(ctx, insn.operands[0], v, t);
}

// `ucomiss xmm0, xmm1` / `ucomisd xmm0, xmm1`: scalar FP compare that sets
// ZF / CF / PF. The architecturally faithful mapping is:
//   ordered:    ZF = (a == b)   CF = (a < b)   PF = 0
//   unordered:  ZF = 1          CF = 1         PF = 1     (one of a, b is NaN)
//
// We model the ordered case directly with CmpEq / CmpUlt — that's what
// downstream `ja`/`jb`/`je` need to render as `if (a > b)` etc, and it's
// correct for any compare where neither operand is NaN (the overwhelming
// common case).
//
// For PF (the "unordered" predicate): we record both operands on the
// LiftCtx; a subsequent Jp/Jnp/Setp/Cmovp picks them up and lowers to an
// `unordered_fp_compare(a, b)` intrinsic instead of the integer XOR-fold
// parity formula that's correct for arith results but meaningless after
// a scalar-FP compare. NaN-aware codecs (audio decoders, math kernels)
// rely on `jp` after `ucomi*` to detect unordered — without this they
// would silently take the ordered branch. `last_flag_src` is intentionally
// left as-is: it carries integer-arith provenance, the FP pair takes
// precedence in the parity-lowering path.
void lift_ucomi(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue a = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue b = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (a.kind == IrValueKind::None || b.kind == IrValueKind::None) return;
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq,  a, b));
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpUlt, a, b));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    ctx.last_fp_cmp_a = a;
    ctx.last_fp_cmp_b = b;
}

// Scalar-FP unary with no clean infix: sqrtss/sqrtsd. Models as a named
// intrinsic so the reader sees `sqrtf(x)` / `sqrt(x)` (the libm names),
// plus the usual two-operand x86 `dst, src` form where dst==operand[0].
void lift_fp_unop(LiftCtx& ctx, std::string_view name, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, t);
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
// rather than introducing a dedicated IrOp::FpConv — the cast itself is
// the dataflow, and the emitter prints `xmm0 = cvtsi2ss(rax);` cleanly.
void lift_int_to_fp(LiftCtx& ctx, std::string_view name, IrType dst_t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
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
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, src_t);
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
        case Mnemonic::Mul:     lift_mul(ctx);     break;
        case Mnemonic::Div:     lift_div_one_op(ctx, /*signed_div=*/false); break;
        case Mnemonic::Idiv:    lift_div_one_op(ctx, /*signed_div=*/true);  break;
        case Mnemonic::Adc:     lift_adc_sbb(ctx, /*subtract=*/false); break;
        case Mnemonic::Sbb:     lift_adc_sbb(ctx, /*subtract=*/true);  break;
        case Mnemonic::Xchg:    lift_xchg(ctx);    break;
        case Mnemonic::Xadd:    lift_xadd(ctx);    break;
        case Mnemonic::Cmpxchg: lift_cmpxchg(ctx); break;
        case Mnemonic::Bsf:     lift_bit_scan(ctx, "bsf"); break;
        case Mnemonic::Bsr:     lift_bit_scan(ctx, "bsr"); break;
        case Mnemonic::Bt:      lift_bit_test(ctx, 't'); break;
        case Mnemonic::Bts:     lift_bit_test(ctx, 's'); break;
        case Mnemonic::Btr:     lift_bit_test(ctx, 'r'); break;
        case Mnemonic::Btc:     lift_bit_test(ctx, 'c'); break;
        case Mnemonic::Shld:    lift_double_shift(ctx, /*right=*/false); break;
        case Mnemonic::Shrd:    lift_double_shift(ctx, /*right=*/true);  break;
        case Mnemonic::Bswap:   lift_bswap(ctx);   break;

        case Mnemonic::Cmovo: case Mnemonic::Cmovno:
        case Mnemonic::Cmovb: case Mnemonic::Cmovae:
        case Mnemonic::Cmove: case Mnemonic::Cmovne:
        case Mnemonic::Cmovbe: case Mnemonic::Cmova:
        case Mnemonic::Cmovs: case Mnemonic::Cmovns:
        case Mnemonic::Cmovp: case Mnemonic::Cmovnp:
        case Mnemonic::Cmovl: case Mnemonic::Cmovge:
        case Mnemonic::Cmovle: case Mnemonic::Cmovg:
            lift_cmov(ctx, insn.mnemonic);
            break;

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
        case Mnemonic::Cpuid:   lift_intrinsic(ctx, "x64.cpuid");  break;
        case Mnemonic::Rdtsc:   lift_intrinsic(ctx, "x64.rdtsc");  break;
        case Mnemonic::Rdtscp:  lift_intrinsic(ctx, "x64.rdtscp"); break;
        case Mnemonic::Rdmsr:   lift_intrinsic(ctx, "x64.rdmsr");  break;
        case Mnemonic::Wrmsr:   lift_intrinsic(ctx, "x64.wrmsr");  break;
        case Mnemonic::Rdpmc:   lift_intrinsic(ctx, "x64.rdpmc");  break;
        case Mnemonic::Pause:   lift_intrinsic(ctx, "x64.pause");  break;
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
        // movaps/movups transfer all 128 bits of an XMM register; route
        // through the SIMD-mov path with I128 so the upper 64 bits aren't
        // truncated by lift_fp_mov's scalar F64 path.
        case Mnemonic::Movaps:       lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovapsStore:  lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movups:       lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovupsStore:  lift_simd_mov(ctx, IrType::I128, true);  break;
        // Scalar-FP unary (intrinsic, libm-style names).
        case Mnemonic::Sqrtss: lift_fp_unop(ctx, "sqrtf", IrType::F32); break;
        case Mnemonic::Sqrtsd: lift_fp_unop(ctx, "sqrt",  IrType::F64); break;

        // Scalar min/max — modeled as named intrinsics (`_mm_min_ss`,
        // `_mm_max_sd`, …). The compiler emits these for `(a < b) ? a : b`
        // patterns; recovering the ternary requires lifting them as
        // IrOp::Select with a proper FP compare, which we don't have a
        // clean way to express yet.
        case Mnemonic::Minss: lift_simd_binop(ctx, "_mm_min_ss", IrType::F32); break;
        case Mnemonic::Maxss: lift_simd_binop(ctx, "_mm_max_ss", IrType::F32); break;
        case Mnemonic::Minsd: lift_simd_binop(ctx, "_mm_min_sd", IrType::F64); break;
        case Mnemonic::Maxsd: lift_simd_binop(ctx, "_mm_max_sd", IrType::F64); break;
        case Mnemonic::Minps: lift_simd_binop(ctx, "_mm_min_ps", IrType::I128); break;
        case Mnemonic::Maxps: lift_simd_binop(ctx, "_mm_max_ps", IrType::I128); break;
        case Mnemonic::Minpd: lift_simd_binop(ctx, "_mm_min_pd", IrType::I128); break;
        case Mnemonic::Maxpd: lift_simd_binop(ctx, "_mm_max_pd", IrType::I128); break;

        // gpr -> xmm conversions (size of the gpr operand drives src width).
        case Mnemonic::Cvtsi2ss: lift_int_to_fp(ctx, "cvtsi2ss", IrType::F32); break;
        case Mnemonic::Cvtsi2sd: lift_int_to_fp(ctx, "cvtsi2sd", IrType::F64); break;

        // xmm -> gpr (truncating). Operand 0 is gpr, operand 1 is xmm/m.
        case Mnemonic::Cvttss2si: lift_fp_to_int(ctx, "cvttss2si", IrType::F32); break;
        case Mnemonic::Cvttsd2si: lift_fp_to_int(ctx, "cvttsd2si", IrType::F64); break;

        // xmm width changes.
        case Mnemonic::Cvtss2sd:
            lift_fp_to_fp(ctx, "cvtss2sd", IrType::F32, IrType::F64); break;
        case Mnemonic::Cvtsd2ss:
            lift_fp_to_fp(ctx, "cvtsd2ss", IrType::F64, IrType::F32); break;

        // Scalar FP compare → ZF/CF/PF. Lets downstream `ja`/`jb`/`je` read
        // out as `if (a > b)` etc. instead of an opaque `ucomiss(...)` plus
        // a stale-flag jcc.
        case Mnemonic::Ucomiss: lift_ucomi(ctx, IrType::F32); break;
        case Mnemonic::Ucomisd: lift_ucomi(ctx, IrType::F64); break;
        // comiss/comisd: same flag effect as ucomiss/ucomisd; the only
        // difference is the QNaN-vs-SNaN exception behaviour, which the
        // emitted code reads identically.
        case Mnemonic::Comiss:  lift_ucomi(ctx, IrType::F32); break;
        case Mnemonic::Comisd:  lift_ucomi(ctx, IrType::F64); break;

        // ---- Packed SSE: arithmetic / logical / unpack / shuffle / compare.
        // Lifted as named intrinsics carrying both source xmm operands.
        // F32 vs F64 chosen to match the scalar element type the mnemonic
        // implies; for packed-integer ops we still flow through F64 (the
        // dataflow is what matters, the named intrinsic carries the lane
        // semantics).
        case Mnemonic::Andps:  lift_simd_binop(ctx, "_mm_and_ps",    IrType::I128); break;
        case Mnemonic::Andnps: lift_simd_binop(ctx, "_mm_andnot_ps", IrType::I128); break;
        case Mnemonic::Orps:   lift_simd_binop(ctx, "_mm_or_ps",     IrType::I128); break;
        case Mnemonic::Xorps:  lift_simd_binop(ctx, "_mm_xor_ps",    IrType::I128); break;
        case Mnemonic::Addps:  lift_simd_binop(ctx, "_mm_add_ps",    IrType::I128); break;
        case Mnemonic::Mulps:  lift_simd_binop(ctx, "_mm_mul_ps",    IrType::I128); break;
        case Mnemonic::Subps:  lift_simd_binop(ctx, "_mm_sub_ps",    IrType::I128); break;
        case Mnemonic::Divps:  lift_simd_binop(ctx, "_mm_div_ps",    IrType::I128); break;
        case Mnemonic::Andpd:  lift_simd_binop(ctx, "_mm_and_pd",    IrType::I128); break;
        case Mnemonic::Andnpd: lift_simd_binop(ctx, "_mm_andnot_pd", IrType::I128); break;
        case Mnemonic::Orpd:   lift_simd_binop(ctx, "_mm_or_pd",     IrType::I128); break;
        case Mnemonic::Xorpd:  lift_simd_binop(ctx, "_mm_xor_pd",    IrType::I128); break;
        case Mnemonic::Addpd:  lift_simd_binop(ctx, "_mm_add_pd",    IrType::I128); break;
        case Mnemonic::Mulpd:  lift_simd_binop(ctx, "_mm_mul_pd",    IrType::I128); break;
        case Mnemonic::Subpd:  lift_simd_binop(ctx, "_mm_sub_pd",    IrType::I128); break;
        case Mnemonic::Divpd:  lift_simd_binop(ctx, "_mm_div_pd",    IrType::I128); break;

        case Mnemonic::Pxor:    lift_simd_binop(ctx, "_mm_xor_si128",    IrType::I128); break;
        case Mnemonic::Pand:    lift_simd_binop(ctx, "_mm_and_si128",    IrType::I128); break;
        case Mnemonic::Pandn:   lift_simd_binop(ctx, "_mm_andnot_si128", IrType::I128); break;
        case Mnemonic::Por:     lift_simd_binop(ctx, "_mm_or_si128",     IrType::I128); break;
        case Mnemonic::Paddq:   lift_simd_binop(ctx, "_mm_add_epi64",    IrType::I128); break;
        case Mnemonic::Pcmpeqb: lift_simd_binop(ctx, "_mm_cmpeq_epi8",   IrType::I128); break;
        case Mnemonic::Pcmpeqw: lift_simd_binop(ctx, "_mm_cmpeq_epi16",  IrType::I128); break;
        case Mnemonic::Pcmpeqd: lift_simd_binop(ctx, "_mm_cmpeq_epi32",  IrType::I128); break;
        case Mnemonic::Pminub:  lift_simd_binop(ctx, "_mm_min_epu8",     IrType::I128); break;

        case Mnemonic::Punpcklbw:  lift_simd_binop(ctx, "_mm_unpacklo_epi8",  IrType::I128); break;
        case Mnemonic::Punpcklwd:  lift_simd_binop(ctx, "_mm_unpacklo_epi16", IrType::I128); break;
        case Mnemonic::Punpckldq:  lift_simd_binop(ctx, "_mm_unpacklo_epi32", IrType::I128); break;
        case Mnemonic::Punpcklqdq: lift_simd_binop(ctx, "_mm_unpacklo_epi64", IrType::I128); break;
        case Mnemonic::Punpckhqdq: lift_simd_binop(ctx, "_mm_unpackhi_epi64", IrType::I128); break;
        case Mnemonic::Pshufd:     lift_simd_binop(ctx, "_mm_shuffle_epi32",  IrType::I128); break;
        case Mnemonic::Pshuflw:    lift_simd_binop(ctx, "_mm_shufflelo_epi16", IrType::I128); break;
        case Mnemonic::Pshufhw:    lift_simd_binop(ctx, "_mm_shufflehi_epi16", IrType::I128); break;

        // Packed integer arithmetic — same xmm-binop shape as Pxor/Pand.
        case Mnemonic::Paddb:   lift_simd_binop(ctx, "_mm_add_epi8",   IrType::I128); break;
        case Mnemonic::Paddw:   lift_simd_binop(ctx, "_mm_add_epi16",  IrType::I128); break;
        case Mnemonic::Paddd:   lift_simd_binop(ctx, "_mm_add_epi32",  IrType::I128); break;
        case Mnemonic::Psubb:   lift_simd_binop(ctx, "_mm_sub_epi8",   IrType::I128); break;
        case Mnemonic::Psubw:   lift_simd_binop(ctx, "_mm_sub_epi16",  IrType::I128); break;
        case Mnemonic::Psubd:   lift_simd_binop(ctx, "_mm_sub_epi32",  IrType::I128); break;
        case Mnemonic::Psubq:   lift_simd_binop(ctx, "_mm_sub_epi64",  IrType::I128); break;
        case Mnemonic::Pmullw:  lift_simd_binop(ctx, "_mm_mullo_epi16", IrType::I128); break;
        case Mnemonic::Pmulhw:  lift_simd_binop(ctx, "_mm_mulhi_epi16", IrType::I128); break;
        case Mnemonic::Pmulhuw: lift_simd_binop(ctx, "_mm_mulhi_epu16", IrType::I128); break;
        case Mnemonic::Pmuludq: lift_simd_binop(ctx, "_mm_mul_epu32",   IrType::I128); break;
        case Mnemonic::Pmaddwd: lift_simd_binop(ctx, "_mm_madd_epi16",  IrType::I128); break;
        case Mnemonic::Pinsrw:  lift_simd_binop(ctx, "_mm_insert_epi16", IrType::I128); break;
        case Mnemonic::Pextrw:  lift_simd_binop(ctx, "_mm_extract_epi16", IrType::I128); break;

        // Saturating arith.
        case Mnemonic::Psubusb: lift_simd_binop(ctx, "_mm_subs_epu8",  IrType::I128); break;
        case Mnemonic::Psubusw: lift_simd_binop(ctx, "_mm_subs_epu16", IrType::I128); break;
        case Mnemonic::Paddusb: lift_simd_binop(ctx, "_mm_adds_epu8",  IrType::I128); break;
        case Mnemonic::Paddusw: lift_simd_binop(ctx, "_mm_adds_epu16", IrType::I128); break;
        case Mnemonic::Psubsb:  lift_simd_binop(ctx, "_mm_subs_epi8",  IrType::I128); break;
        case Mnemonic::Psubsw:  lift_simd_binop(ctx, "_mm_subs_epi16", IrType::I128); break;
        case Mnemonic::Paddsb:  lift_simd_binop(ctx, "_mm_adds_epi8",  IrType::I128); break;
        case Mnemonic::Paddsw:  lift_simd_binop(ctx, "_mm_adds_epi16", IrType::I128); break;

        // Min / max / averages.
        case Mnemonic::Pmaxub:  lift_simd_binop(ctx, "_mm_max_epu8",  IrType::I128); break;
        case Mnemonic::Pminsw:  lift_simd_binop(ctx, "_mm_min_epi16", IrType::I128); break;
        case Mnemonic::Pmaxsw:  lift_simd_binop(ctx, "_mm_max_epi16", IrType::I128); break;
        case Mnemonic::Pavgb:   lift_simd_binop(ctx, "_mm_avg_epu8",  IrType::I128); break;
        case Mnemonic::Pavgw:   lift_simd_binop(ctx, "_mm_avg_epu16", IrType::I128); break;

        // Greater-than compares.
        case Mnemonic::Pcmpgtb: lift_simd_binop(ctx, "_mm_cmpgt_epi8",  IrType::I128); break;
        case Mnemonic::Pcmpgtw: lift_simd_binop(ctx, "_mm_cmpgt_epi16", IrType::I128); break;
        case Mnemonic::Pcmpgtd: lift_simd_binop(ctx, "_mm_cmpgt_epi32", IrType::I128); break;

        // High-half unpacks.
        case Mnemonic::Punpckhbw: lift_simd_binop(ctx, "_mm_unpackhi_epi8",  IrType::I128); break;
        case Mnemonic::Punpckhwd: lift_simd_binop(ctx, "_mm_unpackhi_epi16", IrType::I128); break;
        case Mnemonic::Punpckhdq: lift_simd_binop(ctx, "_mm_unpackhi_epi32", IrType::I128); break;

        // Float shuffles take an imm8 selector — same 3-operand shape
        // lift_simd_binop already handles for Pshufd.
        case Mnemonic::Shufps:  lift_simd_binop(ctx, "_mm_shuffle_ps", IrType::I128); break;
        case Mnemonic::Shufpd:  lift_simd_binop(ctx, "_mm_shuffle_pd", IrType::I128); break;

        // SSE2 shift family — same mnemonic doubles for the imm8 form
        // (0x66 0F 71/72/73 /N) and the xmm-count form (0x66 0F D1..F3).
        // Branch on operand[1].kind to pick the matching intrinsic.
        case Mnemonic::Psllw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi16", IrType::I128);
            break;
        case Mnemonic::Pslld:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi32", IrType::I128);
            break;
        case Mnemonic::Psllq:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_slli_epi64", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sll_epi64", IrType::I128);
            break;
        case Mnemonic::Pslldq: lift_simd_shift_imm(ctx, "_mm_slli_si128", IrType::I128); break;
        case Mnemonic::Psrlw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi16", IrType::I128);
            break;
        case Mnemonic::Psrld:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi32", IrType::I128);
            break;
        case Mnemonic::Psrlq:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srli_epi64", IrType::I128);
            else lift_simd_binop(ctx, "_mm_srl_epi64", IrType::I128);
            break;
        case Mnemonic::Psrldq: lift_simd_shift_imm(ctx, "_mm_srli_si128", IrType::I128); break;
        case Mnemonic::Psraw:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srai_epi16", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sra_epi16", IrType::I128);
            break;
        case Mnemonic::Psrad:
            if (insn.num_operands >= 2 && insn.operands[1].kind == Operand::Kind::Immediate)
                lift_simd_shift_imm(ctx, "_mm_srai_epi32", IrType::I128);
            else lift_simd_binop(ctx, "_mm_sra_epi32", IrType::I128);
            break;

        // 128-bit aligned + unaligned moves. Operand 0 may be memory for the
        // *Store variants — lift_simd_mov handles either direction.
        // movdqa/movdqu transfer the entire 128-bit register; pin I128 so the
        // upper 64 bits aren't dropped by the F64 surrogate. movhps/movlps
        // genuinely transfer 64 bits to one half of the register and stay at
        // F64 — the half-merge semantics are still approximate (we don't
        // model the unmodified half of the XMM destination), separate issue.
        case Mnemonic::Movdqa:      lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovdqaStore: lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movdqu:      lift_simd_mov(ctx, IrType::I128, false); break;
        case Mnemonic::MovdquStore: lift_simd_mov(ctx, IrType::I128, true);  break;
        case Mnemonic::Movhps:      lift_simd_mov(ctx, IrType::F64,  false); break;
        case Mnemonic::Movlps:      lift_simd_mov(ctx, IrType::F64,  false); break;

        // movd / movq: 32 / 64-bit transfer between xmm and gpr-or-mem. Model
        // as a copy at the matching scalar width — the destination type
        // tracks naturally.
        case Mnemonic::Movd:        lift_simd_mov(ctx, IrType::I32, false); break;
        case Mnemonic::MovdStore:   lift_simd_mov(ctx, IrType::I32, true);  break;
        case Mnemonic::MovqXmm:     lift_simd_mov(ctx, IrType::I64, false); break;
        case Mnemonic::MovqStore:   lift_simd_mov(ctx, IrType::I64, true);  break;

        // pmovmskb dst, xmm: extract per-byte sign bits to a 16-bit gpr mask.
        // Single-source intrinsic to a gpr destination.
        case Mnemonic::Pmovmskb: {
            if (insn.num_operands == 2) {
                IrValue src = read_xmm(ctx, insn.operands[1], IrType::F64);
                IrInst i;
                i.op   = IrOp::Intrinsic;
                i.name = "_mm_movemask_epi8";
                i.dst  = ctx.temp(IrType::I32);
                i.srcs[0]   = src;
                i.src_count = 1;
                IrValue r = i.dst;
                ctx.emit(std::move(i));
                store_lvalue(insn.operands[0], r, ctx);
            }
            break;
        }

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
                // Unmodeled mnemonic. Tag with `x64.` so the emitter can
                // render the intrinsic as a `/* ... */` comment rather
                // than `xorps(xmm0, xmm0);` which reads like a real C
                // call. Intrinsics the lifter handles on purpose
                // (sqrtss, ucomiss, …) keep their bare names.
                lift_intrinsic(ctx, std::format("x64.{}",
                                                mnemonic_name(insn.mnemonic)));
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
        ctx.abi = abi_;

        for (const auto& insn : src_bb.instructions) {
            ctx.insn = &insn;
            lift_instruction(ctx);
        }

        ensure_terminator(dst_bb);
    }

    return ir;
}

}  // namespace ember
