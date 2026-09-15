// Calls, branches and condition-register logic.

#include <array>
#include <cstddef>
#include <format>
#include <span>
#include <string_view>
#include <utility>

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>

#include "ppc_lifter_internal.hpp"

namespace spelunk::ppc_lift {

namespace {

void emit_call_clobbers(LiftCtx& ctx) {
    for (Reg r : caller_saved_int_regs(ctx.abi)) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    }
    for (Reg r : caller_saved_fp_regs(ctx.abi)) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = IrValue::make_reg(r, IrType::F64);
        ctx.emit(std::move(c));
    }
}

void emit_arg_barriers(LiftCtx& ctx) {
    auto emit_bank = [&](std::span<const Reg> args, std::string_view prefix) {
        for (std::size_t lo = 0, group = 1; lo < args.size(); lo += 3, ++group) {
            IrInst in;
            in.op   = IrOp::Intrinsic;
            in.name = std::format("{}.{}", prefix, group);
            for (std::size_t i = 0; i < 3 && lo + i < args.size(); ++i) {
                in.srcs[in.src_count++] = ctx.reg(args[lo + i]);
            }
            ctx.emit(std::move(in));
        }
    };
    emit_bank(int_arg_regs(ctx.abi), "call.args");
    emit_bank(fp_arg_regs(ctx.abi), "call.fp_args");
}

[[nodiscard]] IrValue ppc_branch_predicate(LiftCtx& ctx) {
    const Instruction& insn = *ctx.insn;
    const u8 bo = insn.ppc_bo;
    const u8 bi = insn.ppc_bi;
    IrValue predicate = ctx.imm(1, IrType::I1);
    bool has_predicate = false;

    // BO[0] == 0 checks CR[BI], with BO[1] selecting the expected value.
    if ((bo & 0x10u) == 0) {
        IrValue cr = ctx.flag_val(ppc_cr_flag(static_cast<u8>(bi / 4u),
                                              static_cast<u8>(bi % 4u)));
        if ((bo & 0x08u) == 0) cr = ctx.emit_unop(IrOp::Not, cr, IrType::I1);
        predicate = cr;
        has_predicate = true;
    }

    // BO[2] == 0 decrements CTR before testing it. BO[3] selects zero vs
    // nonzero. Combined BO forms require both the CR and CTR predicates.
    if ((bo & 0x04u) == 0) {
        IrValue ctr = ctx.read_reg(Reg::PpcCtr);
        IrValue next = ctx.emit_binop(IrOp::Sub, ctr, ctx.imm(1, ctr.type), ctr.type);
        ctx.write_reg(Reg::PpcCtr, next);
        IrValue ctr_ok = ctx.emit_cmp((bo & 0x02u) != 0 ? IrOp::CmpEq : IrOp::CmpNe,
                                      next, ctx.imm(0, next.type));
        predicate = has_predicate
            ? ctx.emit_binop(IrOp::And, predicate, ctr_ok, IrType::I1)
            : ctr_ok;
    }
    return predicate;
}

}  // namespace

void lift_call(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    emit_arg_barriers(ctx);

    IrInst i;
    const auto& op = insn.operands[0];
    if (op.kind == Operand::Kind::Relative) {
        i.op      = IrOp::Call;
        i.target1 = op.rel.target;
    } else {
        i.op        = IrOp::CallIndirect;
        i.srcs[0]   = materialize_rvalue(op, ctx);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));
    emit_call_clobbers(ctx);
}

void lift_ret(LiftCtx& ctx) {
    IrInst i;
    i.op = IrOp::Return;
    const Reg int_ret = int_return_reg(ctx.abi);
    if (int_ret != Reg::None) {
        i.srcs[i.src_count++] = ctx.read_reg(int_ret);
    }
    const Reg fp_ret = fp_return_reg(ctx.abi);
    if (fp_ret != Reg::None) {
        i.srcs[i.src_count++] = IrValue::make_reg(fp_ret, IrType::F64);
    }
    ctx.emit(std::move(i));
}

void lift_jmp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const auto& op = insn.operands[0];

    if (ctx.blk->kind == BlockKind::TailCall) {
        if (!ctx.blk->successors.empty()) {
            emit_arg_barriers(ctx);
            IrInst c;
            c.op      = IrOp::Call;
            c.target1 = ctx.blk->successors.front();
            ctx.emit(std::move(c));
            emit_call_clobbers(ctx);
            lift_ret(ctx);
            return;
        }
        lift_call(ctx);
        lift_ret(ctx);
        return;
    }

    IrInst i;
    if (op.kind == Operand::Kind::Relative) {
        i.op      = IrOp::Branch;
        i.target1 = op.rel.target;
    } else {
        i.op        = IrOp::BranchIndirect;
        i.srcs[0]   = materialize_rvalue(op, ctx);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));
}

void set_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field) {
    const IrType type = ctx.ppc_reg_type();
    lhs = ctx.match_size(lhs, type, true);
    rhs = ctx.match_size(rhs, type, true);
    set_cr_field(ctx, field,
                 ctx.emit_cmp(IrOp::CmpSlt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpSgt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpEq, lhs, rhs),
                 ctx.imm(0, IrType::I1));
}

void set_unsigned_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field) {
    const IrType type = ctx.ppc_reg_type();
    lhs = ctx.match_size(lhs, type);
    rhs = ctx.match_size(rhs, type);
    set_cr_field(ctx, field,
                 ctx.emit_cmp(IrOp::CmpUlt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpUgt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpEq, lhs, rhs),
                 ctx.imm(0, IrType::I1));
}

void lift_cond_branch(LiftCtx& ctx) {
    if (ctx.blk->successors.size() != 2 || ctx.insn->ppc_bo == 0xff) return;

    IrInst i;
    i.op        = IrOp::CondBranch;
    i.srcs[0]   = ppc_branch_predicate(ctx);
    i.src_count = 1;
    i.target1   = ctx.blk->successors[0];
    i.target2   = ctx.blk->successors[1];
    ctx.emit(std::move(i));
}

void lift_cr_logical(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const auto bit = [&](u8 operand) {
        const u8 n = static_cast<u8>(insn.operands[operand].imm.value) & 31u;
        return ctx.flag_val(ppc_cr_flag(static_cast<u8>(n / 4u),
                                        static_cast<u8>(n % 4u)));
    };
    IrValue a = bit(1);
    IrValue b = bit(2);
    IrValue result;
    switch (insn.mnemonic) {
        case Mnemonic::Crand:  result = ctx.emit_binop(IrOp::And, a, b, IrType::I1); break;
        case Mnemonic::Crandc: result = ctx.emit_binop(IrOp::And, a,
            ctx.emit_unop(IrOp::Not, b, IrType::I1), IrType::I1); break;
        case Mnemonic::Creqv: result = ctx.emit_unop(IrOp::Not,
            ctx.emit_binop(IrOp::Xor, a, b, IrType::I1), IrType::I1); break;
        case Mnemonic::Crnand: result = ctx.emit_unop(IrOp::Not,
            ctx.emit_binop(IrOp::And, a, b, IrType::I1), IrType::I1); break;
        case Mnemonic::Crnor: result = ctx.emit_unop(IrOp::Not,
            ctx.emit_binop(IrOp::Or, a, b, IrType::I1), IrType::I1); break;
        case Mnemonic::Cror: result = ctx.emit_binop(IrOp::Or, a, b, IrType::I1); break;
        case Mnemonic::Crorc: result = ctx.emit_binop(IrOp::Or, a,
            ctx.emit_unop(IrOp::Not, b, IrType::I1), IrType::I1); break;
        case Mnemonic::Crxor: result = ctx.emit_binop(IrOp::Xor, a, b, IrType::I1); break;
        default: return;
    }
    const u8 dst = static_cast<u8>(insn.operands[0].imm.value) & 31u;
    ctx.emit_set_flag(ppc_cr_flag(static_cast<u8>(dst / 4u),
                                  static_cast<u8>(dst % 4u)), result);
}

}  // namespace spelunk::ppc_lift
