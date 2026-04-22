#include <ember/ir/ppc_lifter.hpp>

#include <array>
#include <string_view>
#include <utility>

#include <ember/disasm/register.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;
    Abi                abi  = Abi::Ppc64ElfV2Le;

    [[nodiscard]] u32 new_temp_id() noexcept { return fn->next_temp_id++; }

    [[nodiscard]] IrValue temp(IrType t) noexcept {
        return IrValue::make_temp(new_temp_id(), t);
    }
    [[nodiscard]] IrValue reg(Reg r) noexcept {
        return IrValue::make_reg(r, type_for_bits(reg_size(r) * 8));
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
        return IrValue::make_reg(canonical_reg(r), type_for_bits(reg_size(canonical_reg(r)) * 8));
    }

    void write_reg(Reg r, IrValue value) {
        const Reg canon = canonical_reg(r);
        const IrType t = type_for_bits(reg_size(canon) * 8);
        emit_assign(IrValue::make_reg(canon, t), match_size(value, t));
    }
};

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

[[nodiscard]] IrValue compute_ea(const Mem& mem, LiftCtx& ctx) {
    IrValue base = mem.base == Reg::None ? ctx.imm(0) : ctx.read_reg(mem.base);
    if (!mem.has_disp || mem.disp == 0) return base;
    return ctx.emit_binop(IrOp::Add, base, ctx.imm(mem.disp));
}

[[nodiscard]] IrValue materialize_rvalue(const Operand& op, LiftCtx& ctx) {
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

void emit_call_clobbers(LiftCtx& ctx) {
    for (Reg r : caller_saved_int_regs(ctx.abi)) {
        IrInst c;
        c.op  = IrOp::Clobber;
        c.dst = ctx.reg(r);
        ctx.emit(std::move(c));
    }
}

void emit_arg_barriers(LiftCtx& ctx) {
    const auto args = int_arg_regs(ctx.abi);
    auto fill = [&](std::string_view name, std::size_t lo) {
        IrInst in;
        in.op   = IrOp::Intrinsic;
        in.name = std::string(name);
        for (std::size_t i = 0; i < 3 && lo + i < args.size(); ++i) {
            in.srcs[in.src_count++] = ctx.reg(args[lo + i]);
        }
        if (in.src_count > 0) ctx.emit(std::move(in));
    };
    fill("call.args.1", 0);
    fill("call.args.2", 3);
    fill("call.args.3", 6);
}

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

void set_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs) {
    lhs = ctx.match_size(lhs, IrType::I64, true);
    rhs = ctx.match_size(rhs, IrType::I64, true);
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, lhs, rhs));
    ctx.emit_set_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, lhs, rhs));
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpUlt, lhs, rhs));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
}

[[nodiscard]] IrValue branch_predicate(LiftCtx& ctx, Mnemonic mn) {
    const IrValue zf = ctx.flag_val(Flag::Zf);
    const IrValue sf = ctx.flag_val(Flag::Sf);

    switch (mn) {
        case Mnemonic::Beq:
            return zf;
        case Mnemonic::Bne:
            return ctx.emit_unop(IrOp::Not, zf, IrType::I1);
        case Mnemonic::Blt:
            return sf;
        case Mnemonic::Bge:
            return ctx.emit_unop(IrOp::Not, sf, IrType::I1);
        case Mnemonic::Bgt: {
            IrValue nzf = ctx.emit_unop(IrOp::Not, zf, IrType::I1);
            IrValue nsf = ctx.emit_unop(IrOp::Not, sf, IrType::I1);
            return ctx.emit_binop(IrOp::And, nzf, nsf, IrType::I1);
        }
        case Mnemonic::Ble:
            return ctx.emit_binop(IrOp::Or, zf, sf, IrType::I1);
        default:
            return ctx.imm(0, IrType::I1);
    }
}

void lift_cond_branch(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1 || insn.operands[0].kind != Operand::Kind::Relative) return;

    IrValue cond;
    if (insn.mnemonic == Mnemonic::Bdnz || insn.mnemonic == Mnemonic::Bdz) {
        IrValue ctr = ctx.read_reg(Reg::PpcCtr);
        IrValue next = ctx.emit_binop(IrOp::Sub, ctr, ctx.imm(1));
        ctx.write_reg(Reg::PpcCtr, next);
        cond = ctx.emit_cmp(insn.mnemonic == Mnemonic::Bdnz ? IrOp::CmpNe : IrOp::CmpEq,
                            next, ctx.imm(0));
    } else {
        cond = branch_predicate(ctx, insn.mnemonic);
    }

    IrInst i;
    i.op        = IrOp::CondBranch;
    i.srcs[0]   = cond;
    i.src_count = 1;
    i.target1   = insn.operands[0].rel.target;
    i.target2   = insn.address + insn.length;
    ctx.emit(std::move(i));
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = std::string(name);
    for (u8 j = 0; j < ctx.insn->num_operands && j < 3; ++j) {
        IrValue v = materialize_rvalue(ctx.insn->operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

void lift_instruction(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;

    auto binop = [&](IrOp op) {
        if (insn.num_operands < 2) return;
        IrValue lhs = (insn.num_operands >= 3)
            ? materialize_rvalue(insn.operands[1], ctx)
            : ctx.imm(0);
        IrValue rhs = materialize_rvalue(insn.operands[insn.num_operands - 1], ctx);
        IrValue out = ctx.emit_binop(op, ctx.match_size(lhs, IrType::I64, true),
                                     ctx.match_size(rhs, IrType::I64, true));
        store_lvalue(insn.operands[0], out, ctx);
    };

    switch (insn.mnemonic) {
        case Mnemonic::Mov:
            if (insn.num_operands == 2) {
                store_lvalue(insn.operands[0], materialize_rvalue(insn.operands[1], ctx), ctx);
            }
            break;
        case Mnemonic::Addi:
        case Mnemonic::Addis:
            if (insn.num_operands >= 2) {
                IrValue lhs = (insn.num_operands == 3)
                    ? materialize_rvalue(insn.operands[1], ctx)
                    : ctx.imm(0);
                i64 imm = insn.operands[insn.num_operands - 1].imm.value;
                if (insn.mnemonic == Mnemonic::Addis) imm <<= 16;
                IrValue out = ctx.emit_binop(IrOp::Add,
                                             ctx.match_size(lhs, IrType::I64, true),
                                             ctx.imm(imm));
                store_lvalue(insn.operands[0], out, ctx);
            }
            break;
        case Mnemonic::Add: binop(IrOp::Add); break;
        case Mnemonic::Sub: binop(IrOp::Sub); break;
        case Mnemonic::And: binop(IrOp::And); break;
        case Mnemonic::Or:  binop(IrOp::Or);  break;
        case Mnemonic::Xor: binop(IrOp::Xor); break;
        case Mnemonic::Cmp:
            if (insn.num_operands == 2) {
                set_compare_flags(ctx, materialize_rvalue(insn.operands[0], ctx),
                                  materialize_rvalue(insn.operands[1], ctx));
            }
            break;
        case Mnemonic::Ld:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                IrValue out = ctx.emit_load(compute_ea(insn.operands[1].mem, ctx), IrType::I64);
                store_lvalue(insn.operands[0], out, ctx);
            }
            break;
        case Mnemonic::Lwz:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                IrValue out = ctx.emit_load(compute_ea(insn.operands[1].mem, ctx), IrType::I32);
                out = ctx.emit_unop(IrOp::ZExt, out, IrType::I64);
                store_lvalue(insn.operands[0], out, ctx);
            }
            break;
        case Mnemonic::Std:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                ctx.emit_store(compute_ea(insn.operands[1].mem, ctx),
                               ctx.match_size(materialize_rvalue(insn.operands[0], ctx), IrType::I64));
            }
            break;
        case Mnemonic::Stw:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                IrValue out = ctx.match_size(materialize_rvalue(insn.operands[0], ctx), IrType::I32);
                ctx.emit_store(compute_ea(insn.operands[1].mem, ctx), out);
            }
            break;
        case Mnemonic::Call:
            lift_call(ctx);
            break;
        case Mnemonic::Ret:
            lift_ret(ctx);
            break;
        case Mnemonic::Jmp:
            lift_jmp(ctx);
            break;
        case Mnemonic::Beq:
        case Mnemonic::Bne:
        case Mnemonic::Blt:
        case Mnemonic::Bge:
        case Mnemonic::Bgt:
        case Mnemonic::Ble:
        case Mnemonic::Bdnz:
        case Mnemonic::Bdz:
            lift_cond_branch(ctx);
            break;
        case Mnemonic::Nop: {
            IrInst i;
            i.op = IrOp::Nop;
            ctx.emit(std::move(i));
            break;
        }
        default:
            lift_intrinsic(ctx, mnemonic_name(insn.mnemonic));
            break;
    }
}

void append_return_terminator(IrBlock& bb, Abi abi) {
    IrInst i;
    i.op = IrOp::Return;
    const Reg int_ret = int_return_reg(abi);
    if (int_ret != Reg::None) {
        i.srcs[i.src_count++] = IrValue::make_reg(int_ret, IrType::I64);
    }
    const Reg fp_ret = fp_return_reg(abi);
    if (fp_ret != Reg::None) {
        i.srcs[i.src_count++] = IrValue::make_reg(fp_ret, IrType::F64);
    }
    bb.insts.push_back(std::move(i));
}

void ensure_terminator(IrBlock& bb, Abi abi) {
    if (!bb.insts.empty() && is_terminator(bb.insts.back().op)) return;

    switch (bb.kind) {
        case BlockKind::Return:
            append_return_terminator(bb, abi);
            break;
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::Conditional:
            if (!bb.successors.empty()) {
                IrInst i;
                i.op      = IrOp::Branch;
                i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::IndirectJmp:
        case BlockKind::Switch:
        case BlockKind::TailCall:
            break;
    }
}

}  // namespace

Result<IrFunction> PpcLifter::lift(const Function& fn) const {
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
        LiftCtx ctx;
        ctx.fn  = &ir;
        ctx.blk = &ir.blocks[i];
        ctx.abi = abi_;

        for (const auto& insn : fn.blocks[i].instructions) {
            ctx.insn = &insn;
            lift_instruction(ctx);
        }

        ensure_terminator(ir.blocks[i], abi_);
    }

    return ir;
}

}  // namespace ember
