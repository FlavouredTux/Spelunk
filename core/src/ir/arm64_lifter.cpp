#include <ember/ir/arm64_lifter.hpp>

#include <format>
#include <string>
#include <utility>

#include <ember/disasm/instruction.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// AArch64 condition encoding (4-bit). Used both by B.cc and the
// CSEL/CSET-family.
[[nodiscard]] IrValue cond_to_pred(unsigned cond, IrValue zf, IrValue nf,
                                    IrValue cf, IrValue vf,
                                    auto& emit_unop, auto& emit_binop_i1) {
    switch (cond & 0xf) {
        case 0x0: return zf;                                              // EQ
        case 0x1: return emit_unop(IrOp::Not, zf);                        // NE
        case 0x2: return cf;                                              // CS/HS
        case 0x3: return emit_unop(IrOp::Not, cf);                        // CC/LO
        case 0x4: return nf;                                              // MI
        case 0x5: return emit_unop(IrOp::Not, nf);                        // PL
        case 0x6: return vf;                                              // VS
        case 0x7: return emit_unop(IrOp::Not, vf);                        // VC
        case 0x8: {  // HI = C && !Z
            IrValue nz = emit_unop(IrOp::Not, zf);
            return emit_binop_i1(IrOp::And, cf, nz);
        }
        case 0x9: {  // LS = !C || Z
            IrValue ncf = emit_unop(IrOp::Not, cf);
            return emit_binop_i1(IrOp::Or, ncf, zf);
        }
        case 0xa: {  // GE = N == V
            IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);
            return emit_unop(IrOp::Not, ne);
        }
        case 0xb: {  // LT = N != V
            return emit_binop_i1(IrOp::Xor, nf, vf);
        }
        case 0xc: {  // GT = !Z && (N == V)
            IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);
            IrValue eq = emit_unop(IrOp::Not, ne);
            IrValue nz = emit_unop(IrOp::Not, zf);
            return emit_binop_i1(IrOp::And, nz, eq);
        }
        case 0xd: {  // LE = Z || (N != V)
            IrValue ne = emit_binop_i1(IrOp::Xor, nf, vf);
            return emit_binop_i1(IrOp::Or, zf, ne);
        }
        case 0xe: return IrValue::make_imm(1, IrType::I1);                // AL
        case 0xf: return IrValue::make_imm(1, IrType::I1);                // NV (same as AL)
    }
    return IrValue::make_imm(0, IrType::I1);
}

struct LiftCtx {
    IrFunction*        fn   = nullptr;
    IrBlock*           blk  = nullptr;
    const Instruction* insn = nullptr;
    Abi                abi  = Abi::Aapcs64;

    [[nodiscard]] u32 new_temp_id() noexcept { return fn->next_temp_id++; }
    [[nodiscard]] IrValue temp(IrType t) noexcept {
        return IrValue::make_temp(new_temp_id(), t);
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
        i.op = IrOp::Assign;
        i.dst = dst;
        i.srcs[0] = src;
        i.src_count = 1;
        emit(std::move(i));
    }

    IrValue emit_binop(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(a.type);
        IrInst i;
        i.op = op;
        i.dst = t;
        i.srcs[0] = a;
        i.srcs[1] = b;
        i.src_count = 2;
        emit(std::move(i));
        return t;
    }

    IrValue emit_unop(IrOp op, IrValue a) {
        IrValue t = temp(a.type);
        IrInst i;
        i.op = op;
        i.dst = t;
        i.srcs[0] = a;
        i.src_count = 1;
        emit(std::move(i));
        return t;
    }

    IrValue emit_convert(IrOp op, IrValue a, IrType result_type) {
        IrValue t = temp(result_type);
        IrInst i;
        i.op = op;
        i.dst = t;
        i.srcs[0] = a;
        i.src_count = 1;
        emit(std::move(i));
        return t;
    }

    IrValue emit_cmp(IrOp op, IrValue a, IrValue b) {
        IrValue t = temp(IrType::I1);
        IrInst i;
        i.op = op;
        i.dst = t;
        i.srcs[0] = a;
        i.srcs[1] = b;
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

    IrValue emit_load(IrValue addr, IrType t) {
        IrValue dst = temp(t);
        IrInst i;
        i.op = IrOp::Load;
        i.dst = dst;
        i.srcs[0] = addr;
        i.src_count = 1;
        emit(std::move(i));
        return dst;
    }

    void emit_store(IrValue addr, IrValue value) {
        IrInst i;
        i.op = IrOp::Store;
        i.srcs[0] = addr;
        i.srcs[1] = value;
        i.src_count = 2;
        emit(std::move(i));
    }

    // Read a Wn / Xn register. Wn is a Trunc view of the canonical Xn.
    [[nodiscard]] IrValue read_reg(Reg r) {
        if (r == Reg::Xzr || r == Reg::Wzr) {
            return imm(0, r == Reg::Xzr ? IrType::I64 : IrType::I32);
        }
        const Reg canon = canonical_reg(r);
        const unsigned bytes = reg_size(r);
        const IrType t = type_for_bits(bytes * 8);
        if (canon == r) return IrValue::make_reg(r, t);
        // Wn → Trunc of Xn.
        IrValue x = IrValue::make_reg(canon, IrType::I64);
        return emit_convert(IrOp::Trunc, x, t);
    }

    // Write a Wn / Xn register. A 32-bit write zero-extends into the X.
    void write_reg(Reg r, IrValue value) {
        if (r == Reg::Xzr || r == Reg::Wzr) return;  // discarded
        const Reg canon = canonical_reg(r);
        const unsigned bytes = reg_size(r);
        const IrType t = type_for_bits(bytes * 8);
        if (canon == r) {
            if (value.type != t) {
                value = (type_bits(value.type) < type_bits(t))
                    ? emit_convert(IrOp::ZExt, value, t)
                    : emit_convert(IrOp::Trunc, value, t);
            }
            emit_assign(IrValue::make_reg(r, t), value);
            return;
        }
        // Wn write: zero-extend to 64-bit and store back to canonical Xn.
        if (value.type != t) {
            value = (type_bits(value.type) < type_bits(t))
                ? emit_convert(IrOp::ZExt, value, t)
                : emit_convert(IrOp::Trunc, value, t);
        }
        IrValue widened = emit_convert(IrOp::ZExt, value, IrType::I64);
        emit_assign(IrValue::make_reg(canon, IrType::I64), widened);
    }

    IrValue materialize_op(const Operand& op) {
        switch (op.kind) {
            case Operand::Kind::Register: return read_reg(op.reg);
            case Operand::Kind::Immediate: {
                const IrType t = (op.imm.size >= 8) ? IrType::I64 : IrType::I32;
                return imm(op.imm.value, t);
            }
            case Operand::Kind::Relative:
                return imm(static_cast<i64>(op.rel.target), IrType::I64);
            case Operand::Kind::Memory: {
                const IrType t = type_for_bits(op.mem.size * 8);
                IrValue ea = compute_ea(op.mem);
                return emit_load(ea, t);
            }
            case Operand::Kind::None: return IrValue{};
        }
        return IrValue{};
    }

    IrValue compute_ea(const Mem& m) {
        IrValue base = (m.base != Reg::None)
            ? read_reg(m.base)
            : imm(0, IrType::I64);
        if (base.type != IrType::I64) {
            base = emit_convert(IrOp::ZExt, base, IrType::I64);
        }
        if (m.index != Reg::None) {
            IrValue idx = read_reg(m.index);
            if (idx.type != IrType::I64) {
                idx = emit_convert(IrOp::ZExt, idx, IrType::I64);
            }
            if (m.scale > 1) {
                idx = emit_binop(IrOp::Mul, idx,
                                  imm(static_cast<i64>(m.scale), IrType::I64));
            }
            base = emit_binop(IrOp::Add, base, idx);
        }
        if (m.disp != 0 || m.base == Reg::None) {
            base = emit_binop(IrOp::Add, base,
                              imm(m.disp, IrType::I64));
        }
        return base;
    }
};

// Set NZCV flags after an arithmetic op. We approximate:
//   Z = (result == 0)
//   N = (result < 0)              (signed compare with 0)
//   C = unsigned-no-borrow         (modeled via AddCarry / SubBorrow)
//   V = signed-overflow            (modeled via Add/SubOverflow)
// `subtract` selects sub-shape (CMP/CMN/SUBS) vs add-shape (ADDS/CMN).
void set_nzcv(LiftCtx& ctx, IrValue a, IrValue b, IrValue result, bool subtract) {
    const IrType t = result.type;
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, result, ctx.imm(0, t)));
    ctx.emit_set_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, result, ctx.imm(0, t)));
    ctx.emit_set_flag(Flag::Cf,
        subtract ? ctx.emit_binop_i1(IrOp::SubBorrow, a, b)
                  : ctx.emit_binop_i1(IrOp::AddCarry, a, b));
    ctx.emit_set_flag(Flag::Of,
        subtract ? ctx.emit_binop_i1(IrOp::SubOverflow, a, b)
                  : ctx.emit_binop_i1(IrOp::AddOverflow, a, b));
}

void lift_arith(LiftCtx& ctx, IrOp op, bool set_flags, bool subtract) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3 && !(set_flags && insn.num_operands == 2)) return;
    IrValue rn, src;
    if (set_flags && insn.num_operands == 2) {
        // CMP/CMN alias: `cmp rn, rm/imm` → SUBS xzr, rn, rm/imm.
        rn  = ctx.materialize_op(insn.operands[0]);
        src = ctx.materialize_op(insn.operands[1]);
    } else {
        rn  = ctx.materialize_op(insn.operands[1]);
        src = ctx.materialize_op(insn.operands[2]);
    }
    if (src.type != rn.type) {
        src = (type_bits(src.type) < type_bits(rn.type))
            ? ctx.emit_convert(IrOp::ZExt, src, rn.type)
            : ctx.emit_convert(IrOp::Trunc, src, rn.type);
    }
    IrValue result = ctx.emit_binop(op, rn, src);
    if (set_flags) set_nzcv(ctx, rn, src, result, subtract);
    if (insn.operands[0].kind == Operand::Kind::Register &&
        !(set_flags && insn.num_operands == 2)) {
        ctx.write_reg(insn.operands[0].reg, result);
    }
}

void lift_logical(LiftCtx& ctx, IrOp op, bool set_flags, bool invert_rhs) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    IrValue rn  = ctx.materialize_op(insn.operands[1]);
    IrValue src = ctx.materialize_op(insn.operands[2]);
    if (invert_rhs) src = ctx.emit_unop(IrOp::Not, src);
    if (src.type != rn.type) {
        src = (type_bits(src.type) < type_bits(rn.type))
            ? ctx.emit_convert(IrOp::ZExt, src, rn.type)
            : ctx.emit_convert(IrOp::Trunc, src, rn.type);
    }
    IrValue r = ctx.emit_binop(op, rn, src);
    if (set_flags) {
        ctx.emit_set_flag(Flag::Zf,
            ctx.emit_cmp(IrOp::CmpEq, r, ctx.imm(0, r.type)));
        ctx.emit_set_flag(Flag::Sf,
            ctx.emit_cmp(IrOp::CmpSlt, r, ctx.imm(0, r.type)));
        ctx.emit_set_flag(Flag::Cf, ctx.imm(0, IrType::I1));
        ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    }
    ctx.write_reg(insn.operands[0].reg, r);
}

void lift_mov(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue src = ctx.materialize_op(insn.operands[1]);
    ctx.write_reg(insn.operands[0].reg, src);
}

void lift_movz(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue src = ctx.materialize_op(insn.operands[1]);
    ctx.write_reg(insn.operands[0].reg, src);
}

void lift_movk(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    const Reg dst = insn.operands[0].reg;
    IrValue cur = ctx.read_reg(dst);
    const u64 shift = static_cast<u64>(insn.operands[2].imm.value & 0x3f);
    const u64 mask = u64{0xffff} << shift;
    const u64 imm_v = static_cast<u64>(insn.operands[1].imm.value) << shift;
    IrValue mask_v = ctx.imm(static_cast<i64>(~mask), cur.type);
    IrValue clear  = ctx.emit_binop(IrOp::And, cur, mask_v);
    IrValue merged = ctx.emit_binop(IrOp::Or, clear,
                                    ctx.imm(static_cast<i64>(imm_v), cur.type));
    ctx.write_reg(dst, merged);
}

void lift_shift_imm(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    IrValue rn  = ctx.materialize_op(insn.operands[1]);
    IrValue cnt = ctx.imm(insn.operands[2].imm.value, rn.type);
    IrValue r = ctx.emit_binop(op, rn, cnt);
    ctx.write_reg(insn.operands[0].reg, r);
}

void lift_extend(LiftCtx& ctx, unsigned src_bits, bool sign) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue src = ctx.materialize_op(insn.operands[1]);
    IrValue narrowed = ctx.emit_convert(IrOp::Trunc, src,
                                        type_for_bits(src_bits));
    IrValue widened = ctx.emit_convert(sign ? IrOp::SExt : IrOp::ZExt,
                                       narrowed, IrType::I64);
    ctx.write_reg(insn.operands[0].reg, widened);
}

void lift_load(LiftCtx& ctx, unsigned access_bits, bool sign_extend) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue ea;
    if (insn.operands[1].kind == Operand::Kind::Memory) {
        ea = ctx.compute_ea(insn.operands[1].mem);
    } else if (insn.operands[1].kind == Operand::Kind::Relative) {
        ea = ctx.imm(static_cast<i64>(insn.operands[1].rel.target), IrType::I64);
    } else {
        return;
    }
    IrValue val = ctx.emit_load(ea, type_for_bits(access_bits));
    if (val.type != IrType::I64) {
        val = ctx.emit_convert(sign_extend ? IrOp::SExt : IrOp::ZExt,
                                val, IrType::I64);
    }
    ctx.write_reg(insn.operands[0].reg, val);
}

void lift_store(LiftCtx& ctx, unsigned access_bits) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue val = ctx.read_reg(insn.operands[0].reg);
    const IrType narrow = type_for_bits(access_bits);
    if (val.type != narrow) {
        val = ctx.emit_convert(IrOp::Trunc, val, narrow);
    }
    if (insn.operands[1].kind == Operand::Kind::Memory) {
        ctx.emit_store(ctx.compute_ea(insn.operands[1].mem), val);
    }
}

void lift_ldp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    if (insn.operands[2].kind != Operand::Kind::Memory) return;
    const u8 elem_bytes = insn.operands[2].mem.size;
    const IrType t = type_for_bits(elem_bytes * 8);
    IrValue ea = ctx.compute_ea(insn.operands[2].mem);
    IrValue first = ctx.emit_load(ea, t);
    IrValue offs  = ctx.imm(elem_bytes, IrType::I64);
    IrValue ea2   = ctx.emit_binop(IrOp::Add, ea, offs);
    IrValue second = ctx.emit_load(ea2, t);
    ctx.write_reg(insn.operands[0].reg, first);
    ctx.write_reg(insn.operands[1].reg, second);
}

void lift_stp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    if (insn.operands[2].kind != Operand::Kind::Memory) return;
    const u8 elem_bytes = insn.operands[2].mem.size;
    const IrType t = type_for_bits(elem_bytes * 8);
    IrValue ea = ctx.compute_ea(insn.operands[2].mem);
    IrValue first  = ctx.read_reg(insn.operands[0].reg);
    IrValue second = ctx.read_reg(insn.operands[1].reg);
    if (first.type != t) first = ctx.emit_convert(IrOp::Trunc, first, t);
    if (second.type != t) second = ctx.emit_convert(IrOp::Trunc, second, t);
    ctx.emit_store(ea, first);
    IrValue offs = ctx.imm(elem_bytes, IrType::I64);
    IrValue ea2  = ctx.emit_binop(IrOp::Add, ea, offs);
    ctx.emit_store(ea2, second);
}

[[nodiscard]] IrValue cond_predicate(LiftCtx& ctx, unsigned cond) {
    IrValue zf = ctx.flag_val(Flag::Zf);
    IrValue nf = ctx.flag_val(Flag::Sf);
    IrValue cf = ctx.flag_val(Flag::Cf);
    IrValue vf = ctx.flag_val(Flag::Of);
    auto u = [&](IrOp op, IrValue a) { return ctx.emit_unop(op, a); };
    auto b = [&](IrOp op, IrValue a, IrValue bb) {
        return ctx.emit_binop_i1(op, a, bb);
    };
    return cond_to_pred(cond, zf, nf, cf, vf, u, b);
}

void lift_csel(LiftCtx& ctx, IrOp transform_rhs, bool negate_rhs) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 4) return;
    IrValue tval = ctx.materialize_op(insn.operands[1]);
    IrValue fval = ctx.materialize_op(insn.operands[2]);
    if (transform_rhs == IrOp::Add) {
        fval = ctx.emit_binop(IrOp::Add, fval, ctx.imm(1, fval.type));
    } else if (transform_rhs == IrOp::Not) {
        fval = ctx.emit_unop(IrOp::Not, fval);
    }
    if (negate_rhs) fval = ctx.emit_unop(IrOp::Neg, fval);
    const unsigned cond = static_cast<unsigned>(insn.operands[3].imm.value);
    IrValue pred = cond_predicate(ctx, cond);
    IrInst i;
    i.op = IrOp::Select;
    i.dst = ctx.temp(tval.type);
    i.srcs[0] = pred;
    i.srcs[1] = tval;
    i.srcs[2] = fval;
    i.src_count = 3;
    IrValue r = i.dst;
    ctx.emit(std::move(i));
    ctx.write_reg(insn.operands[0].reg, r);
}

void lift_call(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    IrInst i;
    i.op = IrOp::Call;
    if (insn.num_operands >= 1 &&
        insn.operands[0].kind == Operand::Kind::Relative) {
        i.target1 = insn.operands[0].rel.target;
    } else if (insn.num_operands >= 1 &&
               insn.operands[0].kind == Operand::Kind::Register) {
        i.op = IrOp::CallIndirect;
        i.srcs[0] = ctx.read_reg(insn.operands[0].reg);
        i.src_count = 1;
    }
    ctx.emit(std::move(i));
}

void lift_ret(LiftCtx& ctx) {
    IrInst i;
    i.op = IrOp::Return;
    i.srcs[0] = ctx.read_reg(Reg::X0);
    i.srcs[1] = IrValue::make_reg(Reg::V0, IrType::F64);
    i.src_count = 2;
    ctx.emit(std::move(i));
}

void lift_b(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    IrInst i;
    if (insn.num_operands >= 1 &&
        insn.operands[0].kind == Operand::Kind::Relative) {
        i.op = IrOp::Branch;
        i.target1 = insn.operands[0].rel.target;
    } else {
        i.op = IrOp::BranchIndirect;
        if (insn.num_operands >= 1 &&
            insn.operands[0].kind == Operand::Kind::Register) {
            i.srcs[0] = ctx.read_reg(insn.operands[0].reg);
            i.src_count = 1;
        }
    }
    ctx.emit(std::move(i));
}

void lift_bcc(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    const unsigned cond = static_cast<unsigned>(insn.operands[0].imm.value);
    IrValue pred = cond_predicate(ctx, cond);
    IrInst i;
    i.op = IrOp::CondBranch;
    i.srcs[0] = pred;
    i.src_count = 1;
    i.target1 = insn.operands[1].rel.target;
    ctx.emit(std::move(i));
}

void lift_cbz(LiftCtx& ctx, bool not_zero) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 2) return;
    IrValue rt = ctx.read_reg(insn.operands[0].reg);
    IrValue pred = ctx.emit_cmp(not_zero ? IrOp::CmpNe : IrOp::CmpEq,
                                 rt, ctx.imm(0, rt.type));
    IrInst i;
    i.op = IrOp::CondBranch;
    i.srcs[0] = pred;
    i.src_count = 1;
    i.target1 = insn.operands[1].rel.target;
    ctx.emit(std::move(i));
}

void lift_tbz(LiftCtx& ctx, bool not_zero) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands < 3) return;
    IrValue rt = ctx.read_reg(insn.operands[0].reg);
    IrValue mask = ctx.imm(i64{1} << insn.operands[1].imm.value, rt.type);
    IrValue masked = ctx.emit_binop(IrOp::And, rt, mask);
    IrValue pred = ctx.emit_cmp(not_zero ? IrOp::CmpNe : IrOp::CmpEq,
                                 masked, ctx.imm(0, rt.type));
    IrInst i;
    i.op = IrOp::CondBranch;
    i.srcs[0] = pred;
    i.src_count = 1;
    i.target1 = insn.operands[2].rel.target;
    ctx.emit(std::move(i));
}

void lift_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("arm64.{}", name);
    for (u8 j = 0; j < insn.num_operands && j < 3; ++j) {
        IrValue v = ctx.materialize_op(insn.operands[j]);
        if (v.kind != IrValueKind::None) i.srcs[i.src_count++] = v;
    }
    ctx.emit(std::move(i));
}

void lift_instruction(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
        case Mnemonic::A64Add:  lift_arith(ctx, IrOp::Add, false, false); break;
        case Mnemonic::A64Sub:  lift_arith(ctx, IrOp::Sub, false, true);  break;
        case Mnemonic::A64Adds: lift_arith(ctx, IrOp::Add, true,  false); break;
        case Mnemonic::A64Subs: lift_arith(ctx, IrOp::Sub, true,  true);  break;
        case Mnemonic::Cmp:     lift_arith(ctx, IrOp::Sub, true,  true);  break;
        case Mnemonic::Cmn:     lift_arith(ctx, IrOp::Add, true,  false); break;
        case Mnemonic::A64And:  lift_logical(ctx, IrOp::And, false, false); break;
        case Mnemonic::A64Ands: lift_logical(ctx, IrOp::And, true,  false); break;
        case Mnemonic::A64Bic:  lift_logical(ctx, IrOp::And, false, true);  break;
        case Mnemonic::A64Bics: lift_logical(ctx, IrOp::And, true,  true);  break;
        case Mnemonic::A64Orr:  lift_logical(ctx, IrOp::Or,  false, false); break;
        case Mnemonic::A64Orn:  lift_logical(ctx, IrOp::Or,  false, true);  break;
        case Mnemonic::A64Eor:  lift_logical(ctx, IrOp::Xor, false, false); break;
        case Mnemonic::A64Eon:  lift_logical(ctx, IrOp::Xor, false, true);  break;
        case Mnemonic::A64Mov:  lift_mov(ctx); break;
        case Mnemonic::A64Movz: lift_movz(ctx); break;
        case Mnemonic::A64Movn: {
            // MOVN: dst = ~imm.
            const auto& I = *ctx.insn;
            if (I.num_operands < 2) break;
            IrValue v = ctx.materialize_op(I.operands[1]);
            v = ctx.emit_unop(IrOp::Not, v);
            ctx.write_reg(I.operands[0].reg, v);
            break;
        }
        case Mnemonic::A64Movk: lift_movk(ctx); break;
        case Mnemonic::A64Mvn: {
            const auto& I = *ctx.insn;
            if (I.num_operands < 2) break;
            IrValue v = ctx.materialize_op(I.operands[1]);
            ctx.write_reg(I.operands[0].reg, ctx.emit_unop(IrOp::Not, v));
            break;
        }
        case Mnemonic::A64Neg: case Mnemonic::A64Negs: {
            const auto& I = *ctx.insn;
            if (I.num_operands < 2) break;
            IrValue v = ctx.materialize_op(I.operands[1]);
            IrValue r = ctx.emit_unop(IrOp::Neg, v);
            if (insn.mnemonic == Mnemonic::A64Negs)
                set_nzcv(ctx, ctx.imm(0, v.type), v, r, true);
            ctx.write_reg(I.operands[0].reg, r);
            break;
        }
        case Mnemonic::A64Lsl: lift_shift_imm(ctx, IrOp::Shl);  break;
        case Mnemonic::A64Lsr: lift_shift_imm(ctx, IrOp::Lshr); break;
        case Mnemonic::A64Asr: lift_shift_imm(ctx, IrOp::Ashr); break;
        case Mnemonic::A64Ror: lift_intrinsic(ctx, "ror"); break;
        case Mnemonic::A64Lslv: case Mnemonic::A64Lsrv:
        case Mnemonic::A64Asrv: case Mnemonic::A64Rorv: {
            // Variable-shift register form.
            IrOp op = (insn.mnemonic == Mnemonic::A64Lslv) ? IrOp::Shl :
                      (insn.mnemonic == Mnemonic::A64Lsrv) ? IrOp::Lshr :
                      (insn.mnemonic == Mnemonic::A64Asrv) ? IrOp::Ashr :
                                                              IrOp::Lshr;
            lift_arith(ctx, op, false, false);
            break;
        }
        case Mnemonic::A64Mul: {
            // mul rd, rn, rm
            if (insn.num_operands < 3) break;
            IrValue a = ctx.materialize_op(insn.operands[1]);
            IrValue b = ctx.materialize_op(insn.operands[2]);
            ctx.write_reg(insn.operands[0].reg, ctx.emit_binop(IrOp::Mul, a, b));
            break;
        }
        case Mnemonic::A64Madd: {
            // madd rd, rn, rm, ra → ra + rn*rm
            if (insn.num_operands < 4) break;
            IrValue rn = ctx.materialize_op(insn.operands[1]);
            IrValue rm = ctx.materialize_op(insn.operands[2]);
            IrValue ra = ctx.materialize_op(insn.operands[3]);
            IrValue p  = ctx.emit_binop(IrOp::Mul, rn, rm);
            ctx.write_reg(insn.operands[0].reg, ctx.emit_binop(IrOp::Add, ra, p));
            break;
        }
        case Mnemonic::A64Msub: {
            if (insn.num_operands < 4) break;
            IrValue rn = ctx.materialize_op(insn.operands[1]);
            IrValue rm = ctx.materialize_op(insn.operands[2]);
            IrValue ra = ctx.materialize_op(insn.operands[3]);
            IrValue p  = ctx.emit_binop(IrOp::Mul, rn, rm);
            ctx.write_reg(insn.operands[0].reg, ctx.emit_binop(IrOp::Sub, ra, p));
            break;
        }
        case Mnemonic::A64Sdiv: {
            if (insn.num_operands < 3) break;
            IrValue a = ctx.materialize_op(insn.operands[1]);
            IrValue b = ctx.materialize_op(insn.operands[2]);
            ctx.write_reg(insn.operands[0].reg, ctx.emit_binop(IrOp::Div, a, b));
            break;
        }
        case Mnemonic::A64Udiv: {
            if (insn.num_operands < 3) break;
            IrValue a = ctx.materialize_op(insn.operands[1]);
            IrValue b = ctx.materialize_op(insn.operands[2]);
            ctx.write_reg(insn.operands[0].reg, ctx.emit_binop(IrOp::Div, a, b));
            break;
        }
        case Mnemonic::A64Sxtb: lift_extend(ctx, 8,  true); break;
        case Mnemonic::A64Sxth: lift_extend(ctx, 16, true); break;
        case Mnemonic::A64Sxtw: lift_extend(ctx, 32, true); break;
        case Mnemonic::A64Uxtb: lift_extend(ctx, 8,  false); break;
        case Mnemonic::A64Uxth: lift_extend(ctx, 16, false); break;
        case Mnemonic::A64Uxtw: lift_extend(ctx, 32, false); break;

        case Mnemonic::A64Adr: case Mnemonic::A64Adrp: {
            // Both reduce to "loaded the address of operand 1 into operand 0".
            if (insn.num_operands < 2) break;
            IrValue v = ctx.imm(static_cast<i64>(insn.operands[1].rel.target),
                                IrType::I64);
            ctx.write_reg(insn.operands[0].reg, v);
            break;
        }

        case Mnemonic::A64Ldr:    lift_load(ctx, 64, false); break;
        case Mnemonic::A64Ldrb:   lift_load(ctx, 8,  false); break;
        case Mnemonic::A64Ldrh:   lift_load(ctx, 16, false); break;
        case Mnemonic::A64Ldrsb:  lift_load(ctx, 8,  true);  break;
        case Mnemonic::A64Ldrsh:  lift_load(ctx, 16, true);  break;
        case Mnemonic::A64Ldrsw:  lift_load(ctx, 32, true);  break;
        case Mnemonic::A64Ldur:   lift_load(ctx, 64, false); break;
        case Mnemonic::A64Ldurb:  lift_load(ctx, 8,  false); break;
        case Mnemonic::A64Ldurh:  lift_load(ctx, 16, false); break;
        case Mnemonic::A64Ldursb: lift_load(ctx, 8,  true);  break;
        case Mnemonic::A64Ldursh: lift_load(ctx, 16, true);  break;
        case Mnemonic::A64Ldursw: lift_load(ctx, 32, true);  break;
        case Mnemonic::A64Str:    lift_store(ctx, 64); break;
        case Mnemonic::A64Strb:   lift_store(ctx, 8);  break;
        case Mnemonic::A64Strh:   lift_store(ctx, 16); break;
        case Mnemonic::A64Stur:   lift_store(ctx, 64); break;
        case Mnemonic::A64Sturb:  lift_store(ctx, 8);  break;
        case Mnemonic::A64Sturh:  lift_store(ctx, 16); break;
        case Mnemonic::A64Ldp: case Mnemonic::A64Ldpsw: lift_ldp(ctx); break;
        case Mnemonic::A64Stp:                          lift_stp(ctx); break;

        case Mnemonic::A64Csel:  lift_csel(ctx, IrOp::Nop, false); break;
        case Mnemonic::A64Csinc: lift_csel(ctx, IrOp::Add, false); break;
        case Mnemonic::A64Csinv: lift_csel(ctx, IrOp::Not, false); break;
        case Mnemonic::A64Csneg: lift_csel(ctx, IrOp::Nop, true);  break;

        case Mnemonic::A64Cset: case Mnemonic::A64Csetm: {
            // CSET rd, cond → rd = cond ? 1 : 0.
            if (insn.num_operands < 2) break;
            const unsigned cond = static_cast<unsigned>(insn.operands[1].imm.value);
            IrValue p = cond_predicate(ctx, cond);
            IrValue z = ctx.emit_convert(IrOp::ZExt, p, IrType::I64);
            if (insn.mnemonic == Mnemonic::A64Csetm) {
                z = ctx.emit_unop(IrOp::Neg, z);
            }
            ctx.write_reg(insn.operands[0].reg, z);
            break;
        }

        case Mnemonic::A64B:    lift_b(ctx); break;
        case Mnemonic::A64Br:   lift_b(ctx); break;
        case Mnemonic::A64Bl:   lift_call(ctx); break;
        case Mnemonic::A64Blr:  lift_call(ctx); break;
        case Mnemonic::A64Ret:  lift_ret(ctx); break;
        case Mnemonic::A64Bcc:  lift_bcc(ctx); break;
        case Mnemonic::A64Cbz:  lift_cbz(ctx, false); break;
        case Mnemonic::A64Cbnz: lift_cbz(ctx, true);  break;
        case Mnemonic::A64Tbz:  lift_tbz(ctx, false); break;
        case Mnemonic::A64Tbnz: lift_tbz(ctx, true);  break;

        case Mnemonic::A64Nop:                           break;
        case Mnemonic::A64Brk: case Mnemonic::A64Udf:    {
            IrInst i;
            i.op = IrOp::Unreachable;
            ctx.emit(std::move(i));
            break;
        }
        case Mnemonic::A64Svc: case Mnemonic::A64Hvc:
        case Mnemonic::A64Smc:
            lift_intrinsic(ctx, "syscall");
            break;

        default:
            // Unmodeled mnemonic — emit as named intrinsic so the reader sees
            // *something* rather than an empty block.
            lift_intrinsic(ctx, mnemonic_name(insn.mnemonic));
            break;
    }
}

void ensure_terminator(IrBlock& bb) {
    if (!bb.insts.empty() && is_terminator(bb.insts.back().op)) return;
    switch (bb.kind) {
        case BlockKind::Return: {
            IrInst i; i.op = IrOp::Return;
            bb.insts.push_back(std::move(i));
            break;
        }
        case BlockKind::Unconditional:
        case BlockKind::Fallthrough:
            if (!bb.successors.empty()) {
                IrInst i; i.op = IrOp::Branch; i.target1 = bb.successors[0];
                bb.insts.push_back(std::move(i));
            } else {
                IrInst i; i.op = IrOp::Unreachable;
                bb.insts.push_back(std::move(i));
            }
            break;
        case BlockKind::IndirectJmp: {
            IrInst i; i.op = IrOp::Unreachable;
            bb.insts.push_back(std::move(i));
            break;
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

Result<IrFunction> Arm64Lifter::lift(const Function& fn) const {
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
