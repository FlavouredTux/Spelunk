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

[[nodiscard]] IrType ppc_abi_reg_type(Abi abi) noexcept {
    return abi == Abi::Ppc32Sysv ? IrType::I32 : IrType::I64;
}

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
    if (mem.index != Reg::None) {
        IrValue idx = ctx.read_reg(mem.index);
        if (mem.scale != 1) {
            idx = ctx.emit_binop(IrOp::Mul, idx, ctx.imm(mem.scale, idx.type), idx.type);
        }
        base = ctx.emit_binop(IrOp::Add, ctx.match_size(base, idx.type), idx, idx.type);
    }
    if (!mem.has_disp || mem.disp == 0) return base;
    return ctx.emit_binop(IrOp::Add, base, ctx.imm(mem.disp, base.type), base.type);
}

[[nodiscard]] u32 ppc_mask32(u32 mb, u32 me) noexcept {
    u32 mask = 0;
    for (u32 i = 0; i < 32; ++i) {
        const bool in_range = mb <= me ? (i >= mb && i <= me) : (i >= mb || i <= me);
        if (in_range) mask |= 1u << (31u - i);
    }
    return mask;
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

[[nodiscard]] IrValue materialize_fp_rvalue(const Operand& op, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) return IrValue::make_reg(op.reg, t);
    if (op.kind == Operand::Kind::Memory) return ctx.emit_load(compute_ea(op.mem, ctx), t);
    return {};
}

void store_fp_lvalue(const Operand& op, IrValue value, LiftCtx& ctx, IrType t) {
    if (op.kind == Operand::Kind::Register) {
        ctx.emit_assign(IrValue::make_reg(op.reg, t), value);
        return;
    }
    if (op.kind == Operand::Kind::Memory) ctx.emit_store(compute_ea(op.mem, ctx), value);
}

void lift_fp_mov(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue v = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (v.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], v, ctx, t);
}

void lift_fp_store(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue v = materialize_fp_rvalue(insn.operands[0], ctx, t);
    if (v.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[1], v, ctx, t);
}

void lift_fp_binop(LiftCtx& ctx, IrOp op, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue lhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[2], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], ctx.emit_binop(op, lhs, rhs, t), ctx, t);
}

void lift_fp_unop(LiftCtx& ctx, IrOp op, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (src.kind == IrValueKind::None) return;
    store_fp_lvalue(insn.operands[0], ctx.emit_unop(op, src, t), ctx, t);
}

void set_fp_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs) {
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, lhs, rhs));
    ctx.emit_set_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, lhs, rhs));
    ctx.emit_set_flag(Flag::Cf, ctx.imm(0, IrType::I1));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
}

void lift_fp_cmp(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue lhs = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None) return;
    set_fp_compare_flags(ctx, lhs, rhs);
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

void lift_dst_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 0 || insn.operands[0].kind != Operand::Kind::Register) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = ctx.reg(insn.operands[0].reg);
    for (u8 j = 1; j < insn.num_operands && j < 4; ++j) {
        IrValue v = materialize_rvalue(insn.operands[j], ctx);
        if (v.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

void lift_instruction(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;

    auto binop = [&](IrOp op) {
        if (insn.num_operands < 2) return;
        const IrType ty = ctx.ppc_reg_type();
        IrValue lhs = (insn.num_operands >= 3)
            ? materialize_rvalue(insn.operands[1], ctx)
            : ctx.imm(0, ty);
        IrValue rhs = materialize_rvalue(insn.operands[insn.num_operands - 1], ctx);
        IrValue out = ctx.emit_binop(op, ctx.match_size(lhs, ty, true),
                                     ctx.match_size(rhs, ty, true), ty);
        store_lvalue(insn.operands[0], out, ctx);
    };

    auto unop = [&](IrOp op) {
        if (insn.num_operands != 2) return;
        const IrType ty = ctx.ppc_reg_type();
        IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), ty, true);
        store_lvalue(insn.operands[0], ctx.emit_unop(op, src, ty), ctx);
    };

    auto load_int = [&](IrType mem_ty, bool sign_ext, bool update_base = false) {
        if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
            const Mem& mem = insn.operands[1].mem;
            IrValue ea = compute_ea(mem, ctx);
            IrValue out = ctx.emit_load(ea, mem_ty);
            out = ctx.match_size(out, ctx.ppc_reg_type(), sign_ext);
            store_lvalue(insn.operands[0], out, ctx);
            if (update_base && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
        }
    };

    auto store_int = [&](IrType mem_ty, bool update_base) {
        if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
            const Mem& mem = insn.operands[1].mem;
            IrValue ea = compute_ea(mem, ctx);
            IrValue out = ctx.match_size(materialize_rvalue(insn.operands[0], ctx), mem_ty);
            ctx.emit_store(ea, out);
            if (update_base && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
        }
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
                const IrType ty = ctx.ppc_reg_type();
                IrValue lhs = (insn.num_operands == 3)
                    ? materialize_rvalue(insn.operands[1], ctx)
                    : ctx.imm(0, ty);
                i64 imm = insn.operands[insn.num_operands - 1].imm.value;
                if (insn.mnemonic == Mnemonic::Addis) imm <<= 16;
                IrValue out = ctx.emit_binop(IrOp::Add,
                                             ctx.match_size(lhs, ty, true),
                                             ctx.imm(imm, ty), ty);
                store_lvalue(insn.operands[0], out, ctx);
            }
            break;
        case Mnemonic::Mulli:
            binop(IrOp::Mul);
            break;
        case Mnemonic::Add: binop(IrOp::Add); break;
        case Mnemonic::Sub: binop(IrOp::Sub); break;
        case Mnemonic::Mul: binop(IrOp::Mul); break;
        case Mnemonic::Mulhw: lift_dst_intrinsic(ctx, "ppc.mulhw"); break;
        case Mnemonic::And: binop(IrOp::And); break;
        case Mnemonic::Or:  binop(IrOp::Or);  break;
        case Mnemonic::Xor: binop(IrOp::Xor); break;
        case Mnemonic::Neg: unop(IrOp::Neg); break;
        case Mnemonic::Not: unop(IrOp::Not); break;
        case Mnemonic::Shl: binop(IrOp::Shl); break;
        case Mnemonic::Shr: binop(IrOp::Lshr); break;
        case Mnemonic::Sar: binop(IrOp::Ashr); break;
        case Mnemonic::Rlwinm:
            if (insn.num_operands == 5) {
                const u32 sh = static_cast<u32>(insn.operands[2].imm.value) & 31u;
                const u32 mb = static_cast<u32>(insn.operands[3].imm.value) & 31u;
                const u32 me = static_cast<u32>(insn.operands[4].imm.value) & 31u;
                IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx),
                                             IrType::I32);
                IrValue rot = src;
                if (sh != 0) {
                    IrValue left = ctx.emit_binop(IrOp::Shl, src, ctx.imm(sh, IrType::I32),
                                                  IrType::I32);
                    IrValue right = ctx.emit_binop(IrOp::Lshr, src, ctx.imm(32u - sh, IrType::I32),
                                                   IrType::I32);
                    rot = ctx.emit_binop(IrOp::Or, left, right, IrType::I32);
                }
                const u32 mask = ppc_mask32(mb, me);
                IrValue out = (mask == 0xffffffffu)
                    ? rot
                    : ctx.emit_binop(IrOp::And, rot,
                                     ctx.imm(static_cast<i64>(mask), IrType::I32), IrType::I32);
                store_lvalue(insn.operands[0], ctx.match_size(out, ctx.ppc_reg_type()), ctx);
            }
            break;
        case Mnemonic::Cmp:
            if (insn.num_operands == 2) {
                set_compare_flags(ctx, materialize_rvalue(insn.operands[0], ctx),
                                  materialize_rvalue(insn.operands[1], ctx));
            }
            break;
        case Mnemonic::Mfcr:
            lift_dst_intrinsic(ctx, "ppc.mfcr");
            break;
        case Mnemonic::Cror:
            lift_intrinsic(ctx, "ppc.cror");
            break;
        case Mnemonic::Ld:
        case Mnemonic::Ldu:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                const Mem& mem = insn.operands[1].mem;
                IrValue ea = compute_ea(mem, ctx);
                IrValue out = ctx.emit_load(ea, IrType::I64);
                store_lvalue(insn.operands[0], out, ctx);
                if (insn.mnemonic == Mnemonic::Ldu && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
            }
            break;
        case Mnemonic::Lwa:
            load_int(IrType::I32, true);
            break;
        case Mnemonic::Lwz:
        case Mnemonic::Lwzx:
            load_int(IrType::I32, false);
            break;
        case Mnemonic::Lwzu:
            load_int(IrType::I32, false, true);
            break;
        case Mnemonic::Lbz:
        case Mnemonic::Lbzx:
            load_int(IrType::I8, false);
            break;
        case Mnemonic::Lbzu:
            load_int(IrType::I8, false, true);
            break;
        case Mnemonic::Lhz:
        case Mnemonic::Lhzx:
            load_int(IrType::I16, false);
            break;
        case Mnemonic::Lhzu:
            load_int(IrType::I16, false, true);
            break;
        case Mnemonic::Lha:
        case Mnemonic::Lhax:
            load_int(IrType::I16, true);
            break;
        case Mnemonic::Lhau:
            load_int(IrType::I16, true, true);
            break;
        case Mnemonic::Lfs:
            lift_fp_mov(ctx, IrType::F32);
            break;
        case Mnemonic::Lfd:
            lift_fp_mov(ctx, IrType::F64);
            break;
        case Mnemonic::Fadds:
            lift_fp_binop(ctx, IrOp::Add, IrType::F32);
            break;
        case Mnemonic::Fsubs:
            lift_fp_binop(ctx, IrOp::Sub, IrType::F32);
            break;
        case Mnemonic::Fmuls:
            lift_fp_binop(ctx, IrOp::Mul, IrType::F32);
            break;
        case Mnemonic::Fdivs:
            lift_fp_binop(ctx, IrOp::Div, IrType::F32);
            break;
        case Mnemonic::Fadd:
            lift_fp_binop(ctx, IrOp::Add, IrType::F64);
            break;
        case Mnemonic::Fsub:
            lift_fp_binop(ctx, IrOp::Sub, IrType::F64);
            break;
        case Mnemonic::Fmul:
            lift_fp_binop(ctx, IrOp::Mul, IrType::F64);
            break;
        case Mnemonic::Fdiv:
            lift_fp_binop(ctx, IrOp::Div, IrType::F64);
            break;
        case Mnemonic::Fabs:
        case Mnemonic::Fmr:
            lift_fp_mov(ctx, IrType::F64);
            break;
        case Mnemonic::Fneg:
            lift_fp_unop(ctx, IrOp::Neg, IrType::F64);
            break;
        case Mnemonic::Fcmpu:
        case Mnemonic::Fcmpo:
            lift_fp_cmp(ctx, IrType::F64);
            break;
        case Mnemonic::Std:
        case Mnemonic::Stdu:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                const Mem& mem = insn.operands[1].mem;
                IrValue ea = compute_ea(mem, ctx);
                ctx.emit_store(ea,
                               ctx.match_size(materialize_rvalue(insn.operands[0], ctx), IrType::I64));
                if (insn.mnemonic == Mnemonic::Stdu && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
            }
            break;
        case Mnemonic::Stw:
        case Mnemonic::Stwx:
            store_int(IrType::I32, false);
            break;
        case Mnemonic::Stwu:
            store_int(IrType::I32, true);
            break;
        case Mnemonic::Stb:
        case Mnemonic::Stbx:
            store_int(IrType::I8, false);
            break;
        case Mnemonic::Stbu:
            store_int(IrType::I8, true);
            break;
        case Mnemonic::Sth:
        case Mnemonic::Sthx:
            store_int(IrType::I16, false);
            break;
        case Mnemonic::Sthu:
            store_int(IrType::I16, true);
            break;
        case Mnemonic::Stfs:
            lift_fp_store(ctx, IrType::F32);
            break;
        case Mnemonic::Stfd:
            lift_fp_store(ctx, IrType::F64);
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
        i.srcs[i.src_count++] = IrValue::make_reg(int_ret, ppc_abi_reg_type(abi));
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
