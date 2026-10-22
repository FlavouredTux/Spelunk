// Calls, returns, jumps and conditional branches.

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {

void emit_call_clobbers(LiftCtx& ctx) {
    const std::vector<Reg>* preserved = nullptr;
    if (ctx.call_preserved) {
        if (auto found = ctx.call_preserved->find(ctx.insn->address);
            found != ctx.call_preserved->end()) {
            preserved = &found->second;
        }
    }
    for (Reg r : caller_saved_int_regs(ctx.abi)) {
        if (preserved && std::ranges::find(*preserved, canonical_reg(r)) != preserved->end())
            continue;
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    }
    for (Reg r : caller_saved_fp_regs(ctx.abi)) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = IrValue::make_reg(r, IrType::I128);
        ctx.emit(std::move(c));
    }
    if (ctx.mode32()) {
        for (unsigned n = 0; n < 8; ++n) {
            IrInst c;
            c.op = IrOp::Clobber;
            c.dst = IrValue::make_reg(static_cast<Reg>(static_cast<unsigned>(Reg::St0) + n), IrType::F64);
            ctx.emit(std::move(c));
        }
    }
}

// Emit the ABI barriers that keep argument-register setup code live
// through DCE. `call.args.1` carries slots 0-2 and `call.args.2` carries
// slots 3-5; Win64 only uses 4 slots so slots 4-5 are unset there. Every
// slot is looked up from the current ABI's int_arg_regs table so the
// same sig_inference logic that reads these can decode Win64 too.
void emit_arg_barriers(LiftCtx& ctx) {
    // Preserve the outgoing stack base for argument recovery after SSA/DCE.
    // A tail jump reuses the caller's return address, unlike CALL.
    IrInst stack;
    stack.op = IrOp::Intrinsic;
    stack.name = "call.stack_pointer";
    stack.srcs[0] = ctx.insn->mnemonic == Mnemonic::Jmp
        ? ctx.emit_binop(IrOp::Add, ctx.reg(Reg::Rsp), ctx.imm(ctx.word_size(), ctx.word_type()))
        : ctx.reg(Reg::Rsp);
    stack.src_count = 1;
    ctx.emit(std::move(stack));
    const auto args = int_arg_regs(ctx.mode32() ? Abi::Win32Fastcall : ctx.abi);
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

    const auto fp_args = fp_arg_regs(ctx.abi);
    auto fill_fp = [&](std::string_view name, std::size_t lo) {
        IrInst in;
        in.op   = IrOp::Intrinsic;
        in.name = std::string(name);
        u8 count = 0;
        for (std::size_t i = 0; i < 3 && lo + i < fp_args.size(); ++i) {
            in.srcs[count++] = IrValue::make_reg(fp_args[lo + i], IrType::I128);
        }
        if (count == 0) return;
        in.src_count = count;
        ctx.emit(std::move(in));
    };
    fill_fp("call.fp_args.1", 0);
    fill_fp("call.fp_args.2", 3);
    fill_fp("call.fp_args.3", 6);
}

// A call into an MSVC frame helper (__SEH_prolog4 and kin) builds or tears
// down this function's frame: apply its effect on ebp and esp in place of a
// call, and mark the exception registration it links.
bool lift_frame_helper_call(LiftCtx& ctx) {
    if (!ctx.mode32() || !ctx.frame_helpers) return false;
    const auto found = ctx.frame_helpers->find(ctx.insn->address);
    if (found == ctx.frame_helpers->end()) return false;
    const X86FrameHelper& helper = found->second;
    const IrValue sp = ctx.read_reg(Reg::Rsp);
    const IrValue fp = ctx.read_reg(Reg::Rbp);
    const auto value = [&](const X86FrameValue& v) {
        const IrValue base = v.base == X86FrameValue::Base::CallSp ? sp : fp;
        const IrValue at = v.offset == 0 ? base
            : ctx.emit_binop(IrOp::Add, base, ctx.imm(v.offset, IrType::I32));
        return v.load ? ctx.emit_load(at, IrType::I32) : at;
    };
    const IrValue new_fp = value(helper.fp);
    const IrValue new_sp = value(helper.sp);
    ctx.write_reg(Reg::Rbp, new_fp);
    ctx.write_reg(Reg::Rsp, new_sp);
    for (Reg r : helper.clobbers) {
        IrInst clobber;
        clobber.op = IrOp::Clobber;
        clobber.dst = ctx.reg(r);
        ctx.emit(std::move(clobber));
    }
    if (helper.links_seh) {
        // The try level lives just below the frame pointer.
        IrInst mark;
        mark.op = IrOp::Intrinsic;
        mark.name = "x86.seh_frame";
        mark.srcs[0] = ctx.emit_binop(IrOp::Add, ctx.read_reg(Reg::Rbp), ctx.imm(-4, IrType::I32));
        mark.srcs[1] = ctx.imm(helper.handler.value_or(0), IrType::I32);
        mark.src_count = 2;
        ctx.emit(std::move(mark));
    }
    return true;
}

void lift_call(LiftCtx& ctx) {
    if (lift_frame_helper_call(ctx)) return;
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
    if (ctx.mode32() && ctx.call_pops) {
        if (auto pop = ctx.call_pops->find(ctx.insn->address); pop != ctx.call_pops->end()) {
            const IrValue sp = ctx.reg(Reg::Rsp);
            ctx.emit_assign(sp, ctx.emit_binop(IrOp::Add, sp, ctx.imm(pop->second, IrType::I32)));
        }
    }
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
    if (ctx.mode32()) i.srcs[1] = IrValue::make_reg(Reg::St0, IrType::F64);
    ctx.emit(std::move(i));
}

void lift_jmp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const auto& op = insn.operands[0];

    // Tail call: the CFG builder marked this jmp's block as TailCall because
    // the target is a known function entry. Lift as `call target; return rax;`
    // - the same shape as a regular call, which gives us the call.args.*
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
    // function entry - neither a defined function nor a switch table - so
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
    if (ctx.fp_outcome.known) {
        if (auto condition = fp_outcome_condition(mn, ctx)) return *condition;
    }
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
            if (ctx.last_pf_value.kind != IrValueKind::None) {
                return (mn == Mnemonic::Jp)
                    ? ctx.last_pf_value
                    : ctx.emit_unop(IrOp::Not, ctx.last_pf_value);
            }
            // After a scalar-FP compare (ucomi*/comi*), PF means "unordered"
            // - at least one operand is NaN. Lower to a typed intrinsic so
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

}  // namespace spelunk::x64_lift
