#pragma once

// Shared state and per-instruction lifters of the x86-64 lifter. Private
// to the x64_lifter*.cpp translation units.

#include <string_view>
#include <utility>

#include <spelunk/ir/x64_lifter.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ssa.hpp>  // canonical_reg

namespace spelunk::x64_lift {

// ah/bh/ch/dh - the upper 8 bits of the low 16.
[[nodiscard]] constexpr bool is_high_byte(Reg r) noexcept {
    return r == Reg::Ah || r == Reg::Bh || r == Reg::Ch || r == Reg::Dh;
}

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;
    Abi                abi  = Abi::SysVAmd64;
    bool preserve_scalar_lanes = false;

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

    // PF is not a first-class Flag in the IR. Most parity users derive it
    // from `last_flag_src`; SAHF restores it directly from AH, so carry that
    // one explicit i1 override until an instruction writes a fresh PF source.
    IrValue last_pf_value = {};

    // Set by CDQ/CQO until the next write to RAX/RDX. Lets the immediately
    // following IDIV use `sext(rax/eax)` as its dividend instead of rebuilding
    // the literal high:low pair, which keeps signed `/` and `%` readable.
    bool   last_signext_dividend_valid = false;
    IrType last_signext_dividend_type  = IrType::I64;

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

    IrValue snapshot(IrValue value) {
        if (value.kind != IrValueKind::Reg && value.kind != IrValueKind::Flag)
            return value;
        IrValue saved = temp(value.type);
        emit_assign(saved, value);
        return saved;
    }

    IrValue select(IrValue condition, IrValue yes, IrValue no) {
        IrInst i;
        i.op = IrOp::Select;
        i.dst = temp(yes.type);
        i.srcs[0] = condition;
        i.srcs[1] = yes;
        i.srcs[2] = no;
        i.src_count = 3;
        IrValue result = i.dst;
        emit(std::move(i));
        return result;
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
        // Integer flag-setter happened - any prior FP-compare context is now
        // invalid for PF interpretation.
        last_fp_cmp_a = {};
        last_fp_cmp_b = {};
        last_pf_value = {};
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
            // Own canonical - read at the register's natural width.
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
        if (canon == Reg::Rax || canon == Reg::Rdx) {
            last_signext_dividend_valid = false;
        }

        if (canon == r) {
            // Own canonical - direct assign at natural width. No partial-
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

[[nodiscard]] IrValue compute_ea(const Mem& m, LiftCtx& ctx);

[[nodiscard]] IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx);

void store_lvalue(const Operand& op, IrValue value, LiftCtx& ctx);

[[nodiscard]] IrType operand_type(const Operand& op) noexcept;

// ========== Individual lifters ==========
// Forward decl: cmov_predicate (defined alongside lift_cmov earlier in the
// dispatch order) reuses jcc_predicate's flag-combining logic, but
// jcc_predicate is naturally placed next to the jcc/setcc family further
// down. Decl up here lets us keep both groupings.
[[nodiscard]] IrValue jcc_predicate(Mnemonic mn, LiftCtx& ctx);
void update_shift_parity(LiftCtx& ctx, IrValue result,
                         IrValue original_count, IrValue nonzero);

void lift_mov(LiftCtx& ctx);

void lift_movzx(LiftCtx& ctx);

void lift_movsx(LiftCtx& ctx);

void lift_lea(LiftCtx& ctx);

void lift_arith(LiftCtx& ctx, IrOp op, IrOp carry_op, IrOp overflow_op,
                bool store_result, bool set_flags);

void lift_add(LiftCtx& ctx);

void lift_sub(LiftCtx& ctx);

void lift_cmp(LiftCtx& ctx);

void lift_bitwise(LiftCtx& ctx, IrOp op, bool store_result);

void lift_and(LiftCtx& ctx);

void lift_or (LiftCtx& ctx);

void lift_xor(LiftCtx& ctx);

void lift_test(LiftCtx& ctx);

void lift_inc(LiftCtx& ctx);

void lift_dec(LiftCtx& ctx);

void lift_neg(LiftCtx& ctx);

void lift_not(LiftCtx& ctx);

void lift_shift(LiftCtx& ctx, IrOp op);

void lift_shl(LiftCtx& ctx);

void lift_shr(LiftCtx& ctx);

void lift_sar(LiftCtx& ctx);

void lift_rotate(LiftCtx& ctx, bool right);

void lift_rotate_through_carry(LiftCtx& ctx, bool right);

void lift_double_shift(LiftCtx& ctx, bool right);

void lift_mul_one_op(LiftCtx& ctx, bool signed_mul);

void lift_imul(LiftCtx& ctx);

void lift_mul(LiftCtx& ctx);

void lift_div_one_op(LiftCtx& ctx, bool signed_div);

void lift_sign_extend_dividend_high(LiftCtx& ctx, IrType t);

void lift_adc_sbb(LiftCtx& ctx, bool subtract);

[[nodiscard]] IrValue cmov_predicate(Mnemonic mn, LiftCtx& ctx);

void lift_cmov(LiftCtx& ctx, Mnemonic mn);

void lift_xchg(LiftCtx& ctx);

void lift_xadd(LiftCtx& ctx);

void lift_cmpxchg(LiftCtx& ctx);

void lift_bit_scan(LiftCtx& ctx, std::string_view name);

void lift_popcnt(LiftCtx& ctx);

void lift_bit_test(LiftCtx& ctx, char op);

void lift_bswap(LiftCtx& ctx);

void lift_push(LiftCtx& ctx);

void lift_pop(LiftCtx& ctx);

IrValue flag_to_i64_bit(LiftCtx& ctx, IrValue flag, unsigned shift);

IrValue bit_from_i64(LiftCtx& ctx, IrValue v, unsigned bit);

IrValue build_rflags_value(LiftCtx& ctx);

void restore_rflags_value(LiftCtx& ctx, IrValue rflags);

void lift_pushf(LiftCtx& ctx);

void lift_popf(LiftCtx& ctx);

void lift_leave(LiftCtx& ctx);

void emit_call_clobbers(LiftCtx& ctx);

void emit_arg_barriers(LiftCtx& ctx);

void lift_call(LiftCtx& ctx);

void lift_ret(LiftCtx& ctx);

void lift_jmp(LiftCtx& ctx);

void lift_jcc(LiftCtx& ctx, Mnemonic mn);

void lift_nop(LiftCtx& ctx);

void lift_unreachable(LiftCtx& ctx);

IrValue flag_to_i8_bit(LiftCtx& ctx, IrValue flag, unsigned shift);

IrValue bit_from_ah(LiftCtx& ctx, IrValue ah, unsigned bit);

void lift_lahf(LiftCtx& ctx);

void lift_sahf(LiftCtx& ctx);

void lift_carry_flag_op(LiftCtx& ctx, Mnemonic mn);

[[nodiscard]] IrValue read_xmm(LiftCtx& ctx, const Operand& op, IrType t);

void write_xmm(LiftCtx& ctx, const Operand& op, IrValue value, IrType t);

void lift_bmi_three_operand(LiftCtx& ctx, Mnemonic mnemonic);

void lift_mulx(LiftCtx& ctx);

void lift_fma(LiftCtx& ctx);

void lift_intrinsic(LiftCtx& ctx, std::string_view name);

[[nodiscard]] IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t);

void store_fp_lvalue(const Operand& op, IrValue value, LiftCtx& ctx, IrType t);

void lift_fp_binop(LiftCtx& ctx, IrOp op, IrType t);
void lift_cmpss(LiftCtx& ctx);

void lift_fp_mov(LiftCtx& ctx, IrType t, bool storing);

void lift_simd_binop(LiftCtx& ctx, std::string_view name, IrType t);

void lift_simd_shift_imm(LiftCtx& ctx, std::string_view name, IrType t);

void lift_pinsrw(LiftCtx& ctx);

void lift_pextrw(LiftCtx& ctx);

void lift_simd_mov(LiftCtx& ctx, IrType t, bool storing);

void lift_gpr_scalar_to_xmm(LiftCtx& ctx);

void lift_gpr_scalar_from_xmm(LiftCtx& ctx);

void lift_ucomi(LiftCtx& ctx, IrType t);

void lift_fp_unop(LiftCtx& ctx, std::string_view name, IrType t);

void lift_int_to_fp(LiftCtx& ctx, std::string_view name, IrType dst_t);

void lift_fp_to_int(LiftCtx& ctx, std::string_view name, IrType src_t);

void lift_fp_to_fp(LiftCtx& ctx, std::string_view name, IrType src_t,
                   IrType dst_t);

void lift_setcc(LiftCtx& ctx, Mnemonic mn);

void lift_string_op(LiftCtx& ctx, std::string_view name,
                    bool touches_rsi, bool touches_rax);

void lift_instruction(LiftCtx& ctx);

void ensure_terminator(IrBlock& bb);

}  // namespace spelunk::x64_lift
