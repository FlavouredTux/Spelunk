#pragma once

// Shared state and per-instruction lifters of the PowerPC lifter. Private
// to the ppc_lifter*.cpp translation units.

#include <string_view>
#include <utility>

#include <spelunk/ir/ppc_lifter.hpp>

#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk::ppc_lift {

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;
    Abi                abi  = Abi::Ppc64ElfV2Le;

    [[nodiscard]] u32 new_temp_id() noexcept { return fn->next_temp_id++; }

    [[nodiscard]] bool is_ppc32() const noexcept { return abi == Abi::Ppc32Sysv; }

    [[nodiscard]] IrType ppc_reg_type() const noexcept {
        return is_ppc32() ? IrType::I32 : IrType::I64;
    }

    [[nodiscard]] IrType reg_type(Reg r) const noexcept {
        const auto v = static_cast<unsigned>(r);
        if ((v >= static_cast<unsigned>(Reg::PpcR0) &&
             v <= static_cast<unsigned>(Reg::PpcR31)) ||
            r == Reg::PpcLr || r == Reg::PpcCtr) {
            return ppc_reg_type();
        }
        if (v >= static_cast<unsigned>(Reg::PpcXer) &&
            v <= static_cast<unsigned>(Reg::PpcGqr7)) return IrType::I32;
        if (is_ppc_fpr(r)) return IrType::F64;
        return type_for_bits(reg_size(r) * 8);
    }

    [[nodiscard]] IrValue temp(IrType t) noexcept {
        return IrValue::make_temp(new_temp_id(), t);
    }
    [[nodiscard]] IrValue reg(Reg r) noexcept {
        return IrValue::make_reg(r, reg_type(r));
    }
    [[nodiscard]] IrValue imm(i64 v, IrType t = IrType::I64) noexcept {
        return IrValue::make_imm(v, t);
    }
    [[nodiscard]] IrValue flag_val(Flag f) noexcept {
        return IrValue::make_flag(f);
    }

    void emit(IrInst i) {
        i.source_addr = insn ? insn->address : 0;
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

    [[nodiscard]] IrValue emit_binop(IrOp op, IrValue a, IrValue b, IrType out = IrType::I64) {
        IrValue t = temp(out);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.srcs[1]   = b;
        i.src_count = 2;
        emit(std::move(i));
        return t;
    }

    [[nodiscard]] IrValue emit_unop(IrOp op, IrValue a, IrType out) {
        IrValue t = temp(out);
        IrInst i;
        i.op        = op;
        i.dst       = t;
        i.srcs[0]   = a;
        i.src_count = 1;
        emit(std::move(i));
        return t;
    }

    [[nodiscard]] IrValue emit_cmp(IrOp op, IrValue a, IrValue b) {
        return emit_binop(op, a, b, IrType::I1);
    }

    [[nodiscard]] IrValue emit_load(IrValue addr, IrType t) {
        IrValue dst = temp(t);
        IrInst i;
        i.op        = IrOp::Load;
        i.dst       = dst;
        i.srcs[0]   = addr;
        i.src_count = 1;
        emit(std::move(i));
        return dst;
    }

    void emit_store(IrValue addr, IrValue value) {
        IrInst i;
        i.op        = IrOp::Store;
        i.srcs[0]   = addr;
        i.srcs[1]   = value;
        i.src_count = 2;
        emit(std::move(i));
    }

    void emit_set_flag(Flag f, IrValue v) {
        emit_assign(IrValue::make_flag(f), v);
    }

    [[nodiscard]] IrValue match_size(IrValue v, IrType target, bool sign_ext = false) {
        if (v.type == target) return v;
        const unsigned vb = type_bits(v.type);
        const unsigned tb = type_bits(target);
        if (vb < tb) {
            return emit_unop(sign_ext ? IrOp::SExt : IrOp::ZExt, v, target);
        }
        return emit_unop(IrOp::Trunc, v, target);
    }

    [[nodiscard]] IrValue read_reg(Reg r) noexcept {
        const Reg canon = canonical_reg(r);
        return IrValue::make_reg(canon, reg_type(canon));
    }

    void write_reg(Reg r, IrValue value) {
        const Reg canon = canonical_reg(r);
        const IrType t = reg_type(canon);
        emit_assign(IrValue::make_reg(canon, t), match_size(value, t));
    }
};

[[nodiscard]] IrType ppc_abi_reg_type(Abi abi) noexcept;

[[nodiscard]] IrValue compute_ea(const Mem& mem, LiftCtx& ctx);

[[nodiscard]] u32 ppc_mask32(u32 mb, u32 me) noexcept;

[[nodiscard]] IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx);

void store_lvalue(const Operand& op, IrValue value, LiftCtx& ctx);

[[nodiscard]] IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t);

void store_fp_lvalue(const Operand& op, IrValue value, LiftCtx& ctx, IrType t);

void lift_fp_mov(LiftCtx& ctx, IrType t);

void lift_fp_store(LiftCtx& ctx, IrType t);

void lift_fp_binop(LiftCtx& ctx, IrOp op, IrType t);

void lift_fp_unop(LiftCtx& ctx, IrOp op, IrType t);

void lift_fp_fused_op(LiftCtx& ctx, IrType t, bool subtract, bool negate);

void lift_frsp(LiftCtx& ctx);

[[nodiscard]] IrValue lift_fctiwz_value(LiftCtx& ctx);

[[nodiscard]] bool lift_fctiwz_spill(LiftCtx& ctx,
                                     const Instruction& store,
                                     const Instruction& load);

void set_cr_field(LiftCtx& ctx, u8 field, IrValue lt, IrValue gt,
                  IrValue eq, IrValue so);

void lift_fp_cmp(LiftCtx& ctx, IrType t);

void lift_call(LiftCtx& ctx);

void lift_ret(LiftCtx& ctx);

void lift_jmp(LiftCtx& ctx);

void set_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field);

void set_unsigned_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field);

void lift_cond_branch(LiftCtx& ctx);

void lift_cr_logical(LiftCtx& ctx);

[[nodiscard]] IrValue materialize_ps_value(const Operand& operand, LiftCtx& ctx);

void lift_ps_compare(LiftCtx& ctx, std::string_view base_name);

void set_record_result(LiftCtx& ctx, IrValue value);

void lift_intrinsic(LiftCtx& ctx, std::string_view name);

void lift_dst_intrinsic(LiftCtx& ctx, std::string_view name);

void lift_ps_dst_intrinsic(LiftCtx& ctx, std::string_view name);

void lift_ps_binop(LiftCtx& ctx, IrOp op);

void lift_ps_unop(LiftCtx& ctx, IrOp op);

void lift_ps_fused_op(LiftCtx& ctx, bool subtract, bool negate);

void lift_psq_memory(LiftCtx& ctx, bool load, bool update);

}  // namespace spelunk::ppc_lift
