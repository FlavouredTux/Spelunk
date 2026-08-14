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

void set_cr_field(LiftCtx& ctx, u8 field, IrValue lt, IrValue gt,
                  IrValue eq, IrValue so) {
    ctx.emit_set_flag(ppc_cr_flag(field, 0), lt);
    ctx.emit_set_flag(ppc_cr_flag(field, 1), gt);
    ctx.emit_set_flag(ppc_cr_flag(field, 2), eq);
    ctx.emit_set_flag(ppc_cr_flag(field, 3), so);

    // Keep CR0 mirrored in the legacy generic flags. Other architectures use
    // these flags, and retaining the aliases avoids needless churn in existing
    // PPC32 output while CR1..CR7 remain fully independent.
    if (field == 0) {
        ctx.emit_set_flag(Flag::Sf, lt);
        ctx.emit_set_flag(Flag::Zf, eq);
        ctx.emit_set_flag(Flag::Cf, lt);
        ctx.emit_set_flag(Flag::Of, so);
    }
}

void set_fp_compare_flags(LiftCtx& ctx, IrValue lhs, IrValue rhs, u8 field) {
    set_cr_field(ctx, field,
                 ctx.emit_cmp(IrOp::CmpSlt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpSgt, lhs, rhs),
                 ctx.emit_cmp(IrOp::CmpEq, lhs, rhs),
                 ctx.imm(0, IrType::I1));
}

void lift_fp_cmp(LiftCtx& ctx, IrType t) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue lhs = materialize_fp_rvalue(insn.operands[0], ctx, t);
    IrValue rhs = materialize_fp_rvalue(insn.operands[1], ctx, t);
    if (lhs.kind == IrValueKind::None || rhs.kind == IrValueKind::None) return;
    set_fp_compare_flags(ctx, lhs, rhs, insn.ppc_cr_field);
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

[[nodiscard]] IrValue materialize_ps_value(const Operand& operand, LiftCtx& ctx) {
    if (operand.kind == Operand::Kind::Register) {
        return IrValue::make_reg(operand.reg, IrType::V2F32);
    }
    return materialize_rvalue(operand, ctx);
}

void lift_ps_compare(LiftCtx& ctx, std::string_view base_name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const u8 field = static_cast<u8>(insn.operands[0].imm.value) & 7u;
    const IrValue lhs = materialize_ps_value(insn.operands[1], ctx);
    const IrValue rhs = materialize_ps_value(insn.operands[2], ctx);
    constexpr std::array<std::string_view, 3> suffixes = {".lt", ".gt", ".eq"};
    for (u8 bit = 0; bit < suffixes.size(); ++bit) {
        IrInst i;
        i.op = IrOp::Intrinsic;
        i.name = std::string(base_name) + std::string(suffixes[bit]);
        i.dst = IrValue::make_flag(ppc_cr_flag(field, bit));
        i.srcs[0] = lhs;
        i.srcs[1] = rhs;
        i.src_count = 2;
        ctx.emit(std::move(i));
    }
    ctx.emit_set_flag(ppc_cr_flag(field, 3), ctx.imm(0, IrType::I1));
}

void set_record_result(LiftCtx& ctx, IrValue value) {
    value = ctx.match_size(value, ctx.ppc_reg_type(), true);
    const IrValue zero = ctx.imm(0, value.type);
    set_cr_field(ctx, 0,
                 ctx.emit_cmp(IrOp::CmpSlt, value, zero),
                 ctx.emit_cmp(IrOp::CmpSgt, value, zero),
                 ctx.emit_cmp(IrOp::CmpEq, value, zero),
                 ctx.imm(0, IrType::I1));
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
    if (insn.ppc_record) set_record_result(ctx, ctx.read_reg(insn.operands[0].reg));
}

void lift_ps_dst_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 0 || insn.operands[0].kind != Operand::Kind::Register) return;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    i.dst = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    for (u8 j = 1; j < insn.num_operands && j < 4; ++j) {
        IrValue value = materialize_ps_value(insn.operands[j], ctx);
        if (value.kind == IrValueKind::None) break;
        i.srcs[i.src_count++] = value;
    }
    ctx.emit(std::move(i));
}

void lift_ps_binop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue lhs = materialize_ps_value(insn.operands[1], ctx);
    IrValue rhs = materialize_ps_value(insn.operands[2], ctx);
    IrValue result = ctx.emit_binop(op, lhs, rhs, IrType::V2F32);
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32), result);
}

void lift_ps_unop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue result = ctx.emit_unop(op, materialize_ps_value(insn.operands[1], ctx),
                                   IrType::V2F32);
    ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32), result);
}

void lift_psq_intrinsic(LiftCtx& ctx, std::string_view name, bool load, bool update) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 4 ||
        insn.operands[0].kind != Operand::Kind::Register ||
        insn.operands[1].kind != Operand::Kind::Memory ||
        insn.operands[2].kind != Operand::Kind::Immediate ||
        insn.operands[3].kind != Operand::Kind::Immediate) {
        return;
    }

    const Mem& mem = insn.operands[1].mem;
    const IrValue ea = compute_ea(mem, ctx);
    const u8 w = static_cast<u8>(insn.operands[2].imm.value) & 1u;
    const u8 gqr = static_cast<u8>(insn.operands[3].imm.value) & 7u;

    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::string(name);
    if (load) {
        i.dst = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    } else {
        i.srcs[i.src_count++] = IrValue::make_reg(insn.operands[0].reg, IrType::V2F32);
    }
    i.srcs[i.src_count++] = ea;
    i.srcs[i.src_count++] = ctx.imm(w, IrType::I8);
    i.srcs[i.src_count++] = ctx.read_reg(static_cast<Reg>(
        static_cast<unsigned>(Reg::PpcGqr0) + gqr));
    ctx.emit(std::move(i));

    if (update && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
}

void lift_sign_extend_from(LiftCtx& ctx, IrType narrow) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), narrow);
    IrValue out = ctx.match_size(src, ctx.ppc_reg_type(), true);
    store_lvalue(insn.operands[0], out, ctx);
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
        if (insn.ppc_record) set_record_result(ctx, out);
    };

    auto unop = [&](IrOp op) {
        if (insn.num_operands != 2) return;
        const IrType ty = ctx.ppc_reg_type();
        IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), ty, true);
        IrValue out = ctx.emit_unop(op, src, ty);
        store_lvalue(insn.operands[0], out, ctx);
        if (insn.ppc_record) set_record_result(ctx, out);
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
                IrValue value = materialize_rvalue(insn.operands[1], ctx);
                store_lvalue(insn.operands[0], value, ctx);
                if (insn.ppc_record) set_record_result(ctx, value);
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
        case Mnemonic::Mulhwu: lift_dst_intrinsic(ctx, "ppc.mulhwu"); break;
        case Mnemonic::Addc: lift_dst_intrinsic(ctx, "ppc.addc"); break;
        case Mnemonic::Adde: lift_dst_intrinsic(ctx, "ppc.adde"); break;
        case Mnemonic::Addze: lift_dst_intrinsic(ctx, "ppc.addze"); break;
        case Mnemonic::Subfc: lift_dst_intrinsic(ctx, "ppc.subfc"); break;
        case Mnemonic::Subfze: lift_dst_intrinsic(ctx, "ppc.subfze"); break;
        case Mnemonic::Subfe: lift_dst_intrinsic(ctx, "ppc.subfe"); break;
        case Mnemonic::Divw: lift_dst_intrinsic(ctx, "ppc.divw"); break;
        case Mnemonic::Divwu: lift_dst_intrinsic(ctx, "ppc.divwu"); break;
        case Mnemonic::Andc: lift_dst_intrinsic(ctx, "ppc.andc"); break;
        case Mnemonic::Nor: lift_dst_intrinsic(ctx, "ppc.nor"); break;
        case Mnemonic::Orc: lift_dst_intrinsic(ctx, "ppc.orc"); break;
        case Mnemonic::And: binop(IrOp::And); break;
        case Mnemonic::Or:  binop(IrOp::Or);  break;
        case Mnemonic::Xor: binop(IrOp::Xor); break;
        case Mnemonic::Neg: unop(IrOp::Neg); break;
        case Mnemonic::Not: unop(IrOp::Not); break;
        case Mnemonic::Shl: binop(IrOp::Shl); break;
        case Mnemonic::Shr: binop(IrOp::Lshr); break;
        case Mnemonic::Sar: binop(IrOp::Ashr); break;
        case Mnemonic::Extsb:
            lift_sign_extend_from(ctx, IrType::I8);
            break;
        case Mnemonic::Extsh:
            lift_sign_extend_from(ctx, IrType::I16);
            break;
        case Mnemonic::Cntlzw:
            lift_dst_intrinsic(ctx, "ppc.cntlzw");
            break;
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
                if (insn.ppc_record) set_record_result(ctx, out);
            }
            break;
        case Mnemonic::Rlwimi:
            lift_dst_intrinsic(ctx, "ppc.rlwimi");
            break;
        case Mnemonic::Cmp:
            if (insn.num_operands == 2) {
                set_compare_flags(ctx, materialize_rvalue(insn.operands[0], ctx),
                                  materialize_rvalue(insn.operands[1], ctx),
                                  insn.ppc_cr_field);
            }
            break;
        case Mnemonic::Cmpl:
            if (insn.num_operands == 2) {
                set_unsigned_compare_flags(ctx, materialize_rvalue(insn.operands[0], ctx),
                                           materialize_rvalue(insn.operands[1], ctx),
                                           insn.ppc_cr_field);
            }
            break;
        case Mnemonic::Crand:
        case Mnemonic::Crandc:
        case Mnemonic::Creqv:
        case Mnemonic::Crnand:
        case Mnemonic::Crnor:
        case Mnemonic::Cror:
        case Mnemonic::Crorc:
        case Mnemonic::Crxor:
            lift_cr_logical(ctx);
            break;
        case Mnemonic::Mfcr:
            lift_dst_intrinsic(ctx, "ppc.mfcr");
            break;
        case Mnemonic::Mtcrf:
            lift_intrinsic(ctx, "ppc.mtcrf");
            break;
        case Mnemonic::Mfspr:
            lift_dst_intrinsic(ctx, "ppc.mfspr");
            break;
        case Mnemonic::Mtspr:
            lift_intrinsic(ctx, "ppc.mtspr");
            break;
        case Mnemonic::Mfsr:
            lift_dst_intrinsic(ctx, "ppc.mfsr");
            break;
        case Mnemonic::Mtsr:
            lift_intrinsic(ctx, "ppc.mtsr");
            break;
        case Mnemonic::Mfmsr:
            lift_dst_intrinsic(ctx, "ppc.mfmsr");
            break;
        case Mnemonic::Mtmsr:
            lift_intrinsic(ctx, "ppc.mtmsr");
            break;
        case Mnemonic::Mftb:
            lift_dst_intrinsic(ctx, "ppc.mftb");
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
        case Mnemonic::Lwzux:
            load_int(IrType::I32, false, true);
            break;
        case Mnemonic::Lbz:
        case Mnemonic::Lbzx:
            load_int(IrType::I8, false);
            break;
        case Mnemonic::Lbzu:
        case Mnemonic::Lbzux:
            load_int(IrType::I8, false, true);
            break;
        case Mnemonic::Lhz:
        case Mnemonic::Lhzx:
            load_int(IrType::I16, false);
            break;
        case Mnemonic::Lhzu:
        case Mnemonic::Lhzux:
            load_int(IrType::I16, false, true);
            break;
        case Mnemonic::Lha:
        case Mnemonic::Lhax:
            load_int(IrType::I16, true);
            break;
        case Mnemonic::Lhau:
        case Mnemonic::Lhaux:
            load_int(IrType::I16, true, true);
            break;
        case Mnemonic::Lfs:
        case Mnemonic::Lfsx:
            lift_fp_mov(ctx, IrType::F32);
            break;
        case Mnemonic::Lfsu:
            lift_dst_intrinsic(ctx, "ppc.lfsu");
            break;
        case Mnemonic::Lfd:
        case Mnemonic::Lfdx:
            lift_fp_mov(ctx, IrType::F64);
            break;
        case Mnemonic::Lfdu:
            lift_dst_intrinsic(ctx, "ppc.lfdu");
            break;
        case Mnemonic::Lfsux:
            lift_dst_intrinsic(ctx, "ppc.lfsux");
            break;
        case Mnemonic::Lfdux:
            lift_dst_intrinsic(ctx, "ppc.lfdux");
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
        case Mnemonic::Fmadds:
            lift_dst_intrinsic(ctx, "ppc.fmadds");
            break;
        case Mnemonic::Fmsubs:
            lift_dst_intrinsic(ctx, "ppc.fmsubs");
            break;
        case Mnemonic::Fnmadds:
            lift_dst_intrinsic(ctx, "ppc.fnmadds");
            break;
        case Mnemonic::Fnmsubs:
            lift_dst_intrinsic(ctx, "ppc.fnmsubs");
            break;
        case Mnemonic::Fmadd:
            lift_dst_intrinsic(ctx, "ppc.fmadd");
            break;
        case Mnemonic::Fmsub:
            lift_dst_intrinsic(ctx, "ppc.fmsub");
            break;
        case Mnemonic::Fnmadd:
            lift_dst_intrinsic(ctx, "ppc.fnmadd");
            break;
        case Mnemonic::Fnmsub:
            lift_dst_intrinsic(ctx, "ppc.fnmsub");
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
        case Mnemonic::Fnabs:
            lift_dst_intrinsic(ctx, "ppc.fnabs");
            break;
        case Mnemonic::Fneg:
            lift_fp_unop(ctx, IrOp::Neg, IrType::F64);
            break;
        case Mnemonic::Frsp:
            lift_dst_intrinsic(ctx, "ppc.frsp");
            break;
        case Mnemonic::Fres:
            lift_dst_intrinsic(ctx, "ppc.fres");
            break;
        case Mnemonic::Frsqrte:
            lift_dst_intrinsic(ctx, "ppc.frsqrte");
            break;
        case Mnemonic::Fsel:
            lift_dst_intrinsic(ctx, "ppc.fsel");
            break;
        case Mnemonic::Fctiw:
            lift_dst_intrinsic(ctx, "ppc.fctiw");
            break;
        case Mnemonic::Fctiwz:
            lift_dst_intrinsic(ctx, "ppc.fctiwz");
            break;
        case Mnemonic::Fcmpu:
        case Mnemonic::Fcmpo:
            lift_fp_cmp(ctx, IrType::F64);
            break;
        case Mnemonic::Mffs:
            lift_dst_intrinsic(ctx, "ppc.mffs");
            break;
        case Mnemonic::Mcrfs:
            lift_intrinsic(ctx, "ppc.mcrfs");
            break;
        case Mnemonic::Mtfsb0:
            lift_intrinsic(ctx, "ppc.mtfsb0");
            break;
        case Mnemonic::Mtfsb1:
            lift_intrinsic(ctx, "ppc.mtfsb1");
            break;
        case Mnemonic::Mtfsfi:
            lift_intrinsic(ctx, "ppc.mtfsfi");
            break;
        case Mnemonic::Mtfsf:
            lift_intrinsic(ctx, "ppc.mtfsf");
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
        case Mnemonic::Stwux:
            store_int(IrType::I32, true);
            break;
        case Mnemonic::Stb:
        case Mnemonic::Stbx:
            store_int(IrType::I8, false);
            break;
        case Mnemonic::Stbu:
        case Mnemonic::Stbux:
            store_int(IrType::I8, true);
            break;
        case Mnemonic::Sth:
        case Mnemonic::Sthx:
            store_int(IrType::I16, false);
            break;
        case Mnemonic::Sthbrx:
            if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
                IrValue src = ctx.match_size(materialize_rvalue(insn.operands[0], ctx),
                                             IrType::I16);
                IrValue lo = ctx.emit_binop(IrOp::And, src, ctx.imm(0xff, IrType::I16),
                                            IrType::I16);
                lo = ctx.emit_binop(IrOp::Shl, lo, ctx.imm(8, IrType::I16), IrType::I16);
                IrValue hi = ctx.emit_binop(IrOp::Lshr, src, ctx.imm(8, IrType::I16),
                                            IrType::I16);
                ctx.emit_store(compute_ea(insn.operands[1].mem, ctx),
                               ctx.emit_binop(IrOp::Or, lo, hi, IrType::I16));
            }
            break;
        case Mnemonic::Sthu:
        case Mnemonic::Sthux:
            store_int(IrType::I16, true);
            break;
        case Mnemonic::Lmw:
            lift_dst_intrinsic(ctx, "ppc.lmw");
            break;
        case Mnemonic::Stmw:
            lift_intrinsic(ctx, "ppc.stmw");
            break;
        case Mnemonic::Stfs:
        case Mnemonic::Stfsx:
            lift_fp_store(ctx, IrType::F32);
            break;
        case Mnemonic::Stfsu:
            lift_intrinsic(ctx, "ppc.stfsu");
            break;
        case Mnemonic::Stfd:
        case Mnemonic::Stfdx:
            lift_fp_store(ctx, IrType::F64);
            break;
        case Mnemonic::Stfdu:
            lift_intrinsic(ctx, "ppc.stfdu");
            break;
        case Mnemonic::Stfsux:
            lift_intrinsic(ctx, "ppc.stfsux");
            break;
        case Mnemonic::Stfdux:
            lift_intrinsic(ctx, "ppc.stfdux");
            break;
        case Mnemonic::PsqL:
        case Mnemonic::PsqLu:
            lift_psq_intrinsic(ctx, insn.mnemonic == Mnemonic::PsqL
                ? "ppc.psq_l" : "ppc.psq_lu", true, insn.mnemonic == Mnemonic::PsqLu);
            break;
        case Mnemonic::PsqSt:
            lift_psq_intrinsic(ctx, "ppc.psq_st", false, false);
            break;
        case Mnemonic::PsqStu:
            lift_psq_intrinsic(ctx, "ppc.psq_stu", false, true);
            break;
        case Mnemonic::PsqLx:
        case Mnemonic::PsqLux:
            lift_psq_intrinsic(ctx, insn.mnemonic == Mnemonic::PsqLx
                ? "ppc.psq_lx" : "ppc.psq_lux", true, insn.mnemonic == Mnemonic::PsqLux);
            break;
        case Mnemonic::PsqStx:
            lift_psq_intrinsic(ctx, "ppc.psq_stx", false, false);
            break;
        case Mnemonic::PsqStux:
            lift_psq_intrinsic(ctx, "ppc.psq_stux", false, true);
            break;
        case Mnemonic::PsMr:
            if (insn.num_operands == 2) {
                ctx.emit_assign(IrValue::make_reg(insn.operands[0].reg, IrType::V2F32),
                                materialize_ps_value(insn.operands[1], ctx));
            }
            break;
        case Mnemonic::PsNeg:
            lift_ps_unop(ctx, IrOp::Neg);
            break;
        case Mnemonic::PsNabs:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_nabs");
            break;
        case Mnemonic::PsAbs:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_abs");
            break;
        case Mnemonic::PsMerge00:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_merge00");
            break;
        case Mnemonic::PsMerge01:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_merge01");
            break;
        case Mnemonic::PsMerge10:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_merge10");
            break;
        case Mnemonic::PsMerge11:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_merge11");
            break;
        case Mnemonic::PsSum0:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_sum0");
            break;
        case Mnemonic::PsSum1:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_sum1");
            break;
        case Mnemonic::PsMuls0:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_muls0");
            break;
        case Mnemonic::PsMuls1:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_muls1");
            break;
        case Mnemonic::PsMadds0:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_madds0");
            break;
        case Mnemonic::PsMadds1:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_madds1");
            break;
        case Mnemonic::PsDiv:
            lift_ps_binop(ctx, IrOp::Div);
            break;
        case Mnemonic::PsSub:
            lift_ps_binop(ctx, IrOp::Sub);
            break;
        case Mnemonic::PsAdd:
            lift_ps_binop(ctx, IrOp::Add);
            break;
        case Mnemonic::PsSel:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_sel");
            break;
        case Mnemonic::PsRes:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_res");
            break;
        case Mnemonic::PsMul:
            lift_ps_binop(ctx, IrOp::Mul);
            break;
        case Mnemonic::PsRsqrte:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_rsqrte");
            break;
        case Mnemonic::PsMsub:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_msub");
            break;
        case Mnemonic::PsMadd:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_madd");
            break;
        case Mnemonic::PsNmsub:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_nmsub");
            break;
        case Mnemonic::PsNmadd:
            lift_ps_dst_intrinsic(ctx, "ppc.ps_nmadd");
            break;
        case Mnemonic::PsCmpu0:
            lift_ps_compare(ctx, "ppc.ps_cmpu0");
            break;
        case Mnemonic::PsCmpo0:
            lift_ps_compare(ctx, "ppc.ps_cmpo0");
            break;
        case Mnemonic::PsCmpu1:
            lift_ps_compare(ctx, "ppc.ps_cmpu1");
            break;
        case Mnemonic::PsCmpo1:
            lift_ps_compare(ctx, "ppc.ps_cmpo1");
            break;
        case Mnemonic::PsOp4:
            lift_intrinsic(ctx, "ppc.ps.op4");
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
        case Mnemonic::Bclr:
        case Mnemonic::Bc:
        case Mnemonic::Bcctr:
            lift_cond_branch(ctx);
            break;
        case Mnemonic::Nop: {
            IrInst i;
            i.op = IrOp::Nop;
            ctx.emit(std::move(i));
            break;
        }
        case Mnemonic::Isync:
            lift_intrinsic(ctx, "ppc.isync");
            break;
        case Mnemonic::Sync:
            lift_intrinsic(ctx, "ppc.sync");
            break;
        case Mnemonic::Rfi:
            lift_intrinsic(ctx, "ppc.rfi");
            break;
        case Mnemonic::Sc:
            lift_intrinsic(ctx, "ppc.sc");
            break;
        case Mnemonic::Twi:
            lift_intrinsic(ctx, "ppc.twi");
            break;
        case Mnemonic::Dcbf:
            lift_intrinsic(ctx, "ppc.dcbf");
            break;
        case Mnemonic::Dcbst:
            lift_intrinsic(ctx, "ppc.dcbst");
            break;
        case Mnemonic::Dcbi:
            lift_intrinsic(ctx, "ppc.dcbi");
            break;
        case Mnemonic::Dcbz:
            lift_intrinsic(ctx, "ppc.dcbz");
            break;
        case Mnemonic::DcbzL:
            lift_intrinsic(ctx, "ppc.dcbz_l");
            break;
        case Mnemonic::Icbi:
            lift_intrinsic(ctx, "ppc.icbi");
            break;
        case Mnemonic::FpOp:
            lift_intrinsic(ctx, "ppc.fp.op");
            break;
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
