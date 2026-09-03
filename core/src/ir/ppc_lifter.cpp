// Instruction dispatch and the PpcLifter entry point.

#include <ember/ir/ppc_lifter.hpp>

#include <array>
#include <cstddef>
#include <string_view>
#include <tuple>
#include <utility>

#include <ember/analysis/function.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

#include "ppc_lifter_internal.hpp"

namespace ember::ppc_lift {

namespace {

void lift_sign_extend_from(LiftCtx& ctx, IrType narrow) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), narrow);
    IrValue out = ctx.match_size(src, ctx.ppc_reg_type(), true);
    store_lvalue(insn.operands[0], out, ctx);
}

void lift_multiple_word(LiftCtx& ctx, bool load) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2 ||
        insn.operands[0].kind != Operand::Kind::Register ||
        insn.operands[1].kind != Operand::Kind::Memory) {
        return;
    }
    const Reg first = canonical_reg(insn.operands[0].reg);
    if (first < Reg::PpcR0 || first > Reg::PpcR31) return;

    const unsigned first_index = static_cast<unsigned>(first) -
                                 static_cast<unsigned>(Reg::PpcR0);
    const IrValue first_ea = compute_ea(insn.operands[1].mem, ctx);
    for (unsigned index = first_index; index < 32; ++index) {
        IrValue ea = first_ea;
        const unsigned byte_offset = (index - first_index) * 4u;
        if (byte_offset != 0) {
            ea = ctx.emit_binop(IrOp::Add, first_ea,
                                ctx.imm(byte_offset, first_ea.type), first_ea.type);
        }
        const Reg reg = static_cast<Reg>(static_cast<unsigned>(Reg::PpcR0) + index);
        if (load) {
            ctx.write_reg(reg, ctx.emit_load(ea, IrType::I32));
        } else {
            ctx.emit_store(ea, ctx.match_size(ctx.read_reg(reg), IrType::I32));
        }
    }
}
void binop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
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
}

void unop(LiftCtx& ctx, IrOp op) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    const IrType ty = ctx.ppc_reg_type();
    IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), ty, true);
    IrValue out = ctx.emit_unop(op, src, ty);
    store_lvalue(insn.operands[0], out, ctx);
    if (insn.ppc_record) set_record_result(ctx, out);
}

void complemented_logic(LiftCtx& ctx, IrOp op, bool complement_rhs,
                                  bool complement_result) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const IrType ty = ctx.ppc_reg_type();
    IrValue lhs = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), ty);
    IrValue rhs = ctx.match_size(materialize_rvalue(insn.operands[2], ctx), ty);
    if (complement_rhs) rhs = ctx.emit_unop(IrOp::Not, rhs, ty);
    IrValue out = ctx.emit_binop(op, lhs, rhs, ty);
    if (complement_result) out = ctx.emit_unop(IrOp::Not, out, ty);
    store_lvalue(insn.operands[0], out, ctx);
    if (insn.ppc_record) set_record_result(ctx, out);
}

void mul_high_word(LiftCtx& ctx, bool is_signed) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    IrValue lhs = ctx.match_size(materialize_rvalue(insn.operands[1], ctx),
                                 IrType::I32);
    IrValue rhs = ctx.match_size(materialize_rvalue(insn.operands[2], ctx),
                                 IrType::I32);
    lhs = ctx.match_size(lhs, IrType::I64, is_signed);
    rhs = ctx.match_size(rhs, IrType::I64, is_signed);
    IrValue product = ctx.emit_binop(IrOp::Mul, lhs, rhs, IrType::I64);
    IrValue high = ctx.emit_binop(is_signed ? IrOp::Ashr : IrOp::Lshr,
                                  product, ctx.imm(32, IrType::I64),
                                  IrType::I64);
    high = ctx.match_size(high, IrType::I32);
    store_lvalue(insn.operands[0], high, ctx);
    if (insn.ppc_record) set_record_result(ctx, high);
}

IrValue carry_add(LiftCtx& ctx, IrValue a, IrValue b) {
    return ctx.emit_binop(IrOp::AddCarry, a, b, IrType::I1);
}

std::pair<IrValue, IrValue> carry_pair(LiftCtx& ctx, IrValue a, IrValue b, IrValue carry_in) {
    IrValue first = ctx.emit_binop(IrOp::Add, a, b, a.type);
    IrValue out = ctx.emit_binop(IrOp::Add, first, carry_in, a.type);
    IrValue c1 = carry_add(ctx, a, b);
    IrValue c2 = carry_add(ctx, first, carry_in);
    IrValue carry = ctx.emit_binop(IrOp::Or, c1, c2, IrType::I1);
    return std::pair{out, carry};
}

void lift_carry_arithmetic(LiftCtx& ctx, Mnemonic mnemonic) {
    const auto& insn = *ctx.insn;
    const IrType ty = ctx.ppc_reg_type();
    if (insn.num_operands < 2) return;
    IrValue a = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), ty);
    IrValue out;
    IrValue carry;
    if (mnemonic == Mnemonic::Addc && insn.num_operands == 3) {
        IrValue b = ctx.match_size(materialize_rvalue(insn.operands[2], ctx), ty);
        out = ctx.emit_binop(IrOp::Add, a, b, ty);
        carry = carry_add(ctx, a, b);
    } else if (mnemonic == Mnemonic::Adde && insn.num_operands == 3) {
        IrValue b = ctx.match_size(materialize_rvalue(insn.operands[2], ctx), ty);
        IrValue carry_in = ctx.match_size(ctx.flag_val(Flag::PpcCa), ty);
        std::tie(out, carry) = carry_pair(ctx, a, b, carry_in);
    } else if (mnemonic == Mnemonic::Addze) {
        IrValue carry_in = ctx.match_size(ctx.flag_val(Flag::PpcCa), ty);
        out = ctx.emit_binop(IrOp::Add, a, carry_in, ty);
        carry = carry_add(ctx, a, carry_in);
    } else if (mnemonic == Mnemonic::Subfc && insn.num_operands == 3) {
        IrValue b = ctx.match_size(materialize_rvalue(insn.operands[2], ctx), ty);
        out = ctx.emit_binop(IrOp::Sub, b, a, ty);
        IrValue borrow = ctx.emit_binop(IrOp::SubBorrow, b, a, IrType::I1);
        carry = ctx.emit_unop(IrOp::Not, borrow, IrType::I1);
    } else if ((mnemonic == Mnemonic::Subfe || mnemonic == Mnemonic::Subfze)) {
        IrValue inverted = ctx.emit_unop(IrOp::Not, a, ty);
        IrValue b = mnemonic == Mnemonic::Subfe && insn.num_operands == 3
            ? ctx.match_size(materialize_rvalue(insn.operands[2], ctx), ty)
            : ctx.imm(0, ty);
        IrValue carry_in = ctx.match_size(ctx.flag_val(Flag::PpcCa), ty);
        std::tie(out, carry) = carry_pair(ctx, inverted, b, carry_in);
    } else {
        return;
    }
    store_lvalue(insn.operands[0], out, ctx);
    ctx.emit_set_flag(Flag::PpcCa, carry);
    if (insn.ppc_record) set_record_result(ctx, out);
}

void load_int(LiftCtx& ctx, IrType mem_ty, bool sign_ext, bool update_base = false) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
        const Mem& mem = insn.operands[1].mem;
        IrValue ea = compute_ea(mem, ctx);
        IrValue out = ctx.emit_load(ea, mem_ty);
        out = ctx.match_size(out, ctx.ppc_reg_type(), sign_ext);
        store_lvalue(insn.operands[0], out, ctx);
        if (update_base && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
    }
}

void store_int(LiftCtx& ctx, IrType mem_ty, bool update_base) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands == 2 && insn.operands[1].kind == Operand::Kind::Memory) {
        const Mem& mem = insn.operands[1].mem;
        IrValue ea = compute_ea(mem, ctx);
        IrValue out = ctx.match_size(materialize_rvalue(insn.operands[0], ctx), mem_ty);
        ctx.emit_store(ea, out);
        if (update_base && mem.base != Reg::None) ctx.write_reg(mem.base, ea);
    }
}

// Integer arithmetic, logic, shifts, rotates, compares, CR and SPR moves.
bool lift_integer_op(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
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
            binop(ctx, IrOp::Mul);
            break;
        case Mnemonic::Add: binop(ctx, IrOp::Add); break;
        case Mnemonic::Sub: binop(ctx, IrOp::Sub); break;
        case Mnemonic::Mul: binop(ctx, IrOp::Mul); break;
        case Mnemonic::Mulhw: mul_high_word(ctx, true); break;
        case Mnemonic::Mulhwu: mul_high_word(ctx, false); break;
        case Mnemonic::Addc: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Adde: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Addze: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Subfc: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Subfze: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Subfe: lift_carry_arithmetic(ctx, insn.mnemonic); break;
        case Mnemonic::Divw: lift_dst_intrinsic(ctx, "ppc.divw"); break;
        case Mnemonic::Divwu: lift_dst_intrinsic(ctx, "ppc.divwu"); break;
        case Mnemonic::Andc: complemented_logic(ctx, IrOp::And, true, false); break;
        case Mnemonic::Nor: complemented_logic(ctx, IrOp::Or, false, true); break;
        case Mnemonic::Orc: complemented_logic(ctx, IrOp::Or, true, false); break;
        case Mnemonic::And: binop(ctx, IrOp::And); break;
        case Mnemonic::Or:  binop(ctx, IrOp::Or);  break;
        case Mnemonic::Xor: binop(ctx, IrOp::Xor); break;
        case Mnemonic::Neg: unop(ctx, IrOp::Neg); break;
        case Mnemonic::Not: unop(ctx, IrOp::Not); break;
        case Mnemonic::Shl: binop(ctx, IrOp::Shl); break;
        case Mnemonic::Shr: binop(ctx, IrOp::Lshr); break;
        case Mnemonic::Sar: binop(ctx, IrOp::Ashr); break;
        case Mnemonic::Extsb:
            lift_sign_extend_from(ctx, IrType::I8);
            break;
        case Mnemonic::Extsh:
            lift_sign_extend_from(ctx, IrType::I16);
            break;
        case Mnemonic::Cntlzw:
            if (insn.num_operands == 2) {
                IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx),
                                             IrType::I32);
                IrValue out = ctx.emit_unop(IrOp::Clz, src, IrType::I32);
                store_lvalue(insn.operands[0], ctx.match_size(out, ctx.ppc_reg_type()), ctx);
                if (insn.ppc_record) set_record_result(ctx, out);
            }
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
            if (insn.num_operands == 5) {
                const u32 sh = static_cast<u32>(insn.operands[2].imm.value) & 31u;
                const u32 mb = static_cast<u32>(insn.operands[3].imm.value) & 31u;
                const u32 me = static_cast<u32>(insn.operands[4].imm.value) & 31u;
                const IrValue old = ctx.match_size(
                    materialize_rvalue(insn.operands[0], ctx), IrType::I32);
                const IrValue src = ctx.match_size(
                    materialize_rvalue(insn.operands[1], ctx), IrType::I32);
                IrValue rot = src;
                if (sh != 0) {
                    const IrValue left = ctx.emit_binop(
                        IrOp::Shl, src, ctx.imm(sh, IrType::I32), IrType::I32);
                    const IrValue right = ctx.emit_binop(
                        IrOp::Lshr, src, ctx.imm(32u - sh, IrType::I32), IrType::I32);
                    rot = ctx.emit_binop(IrOp::Or, left, right, IrType::I32);
                }
                const u32 mask = ppc_mask32(mb, me);
                IrValue inserted = mask == 0xffffffffu
                    ? rot
                    : ctx.emit_binop(IrOp::And, rot,
                                     ctx.imm(static_cast<i64>(mask), IrType::I32),
                                     IrType::I32);
                IrValue out = inserted;
                if (mask != 0xffffffffu) {
                    const IrValue kept = ctx.emit_binop(
                        IrOp::And, old,
                        ctx.imm(static_cast<i64>(~mask), IrType::I32), IrType::I32);
                    out = ctx.emit_binop(IrOp::Or, kept, inserted, IrType::I32);
                }
                store_lvalue(insn.operands[0], ctx.match_size(out, ctx.ppc_reg_type()), ctx);
                if (insn.ppc_record) set_record_result(ctx, out);
            }
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
            if (insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register &&
                insn.operands[1].kind == Operand::Kind::Register &&
                insn.operands[1].reg >= Reg::PpcGqr0 &&
                insn.operands[1].reg <= Reg::PpcGqr7) {
                store_lvalue(insn.operands[0], ctx.read_reg(insn.operands[1].reg), ctx);
            } else {
                lift_dst_intrinsic(ctx, "ppc.mfspr");
            }
            break;
        case Mnemonic::Mtspr:
            if (insn.num_operands == 2 &&
                insn.operands[0].kind == Operand::Kind::Register &&
                insn.operands[0].reg >= Reg::PpcGqr0 &&
                insn.operands[0].reg <= Reg::PpcGqr7) {
                ctx.write_reg(insn.operands[0].reg,
                              materialize_rvalue(insn.operands[1], ctx));
            } else {
                lift_intrinsic(ctx, "ppc.mtspr");
            }
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
        default:
            return false;
    }
    return true;
}

// Integer and floating-point loads, with and without update.
bool lift_load(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
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
            load_int(ctx, IrType::I32, true);
            break;
        case Mnemonic::Lwz:
        case Mnemonic::Lwzx:
            load_int(ctx, IrType::I32, false);
            break;
        case Mnemonic::Lwzu:
        case Mnemonic::Lwzux:
            load_int(ctx, IrType::I32, false, true);
            break;
        case Mnemonic::Lbz:
        case Mnemonic::Lbzx:
            load_int(ctx, IrType::I8, false);
            break;
        case Mnemonic::Lbzu:
        case Mnemonic::Lbzux:
            load_int(ctx, IrType::I8, false, true);
            break;
        case Mnemonic::Lhz:
        case Mnemonic::Lhzx:
            load_int(ctx, IrType::I16, false);
            break;
        case Mnemonic::Lhzu:
        case Mnemonic::Lhzux:
            load_int(ctx, IrType::I16, false, true);
            break;
        case Mnemonic::Lha:
        case Mnemonic::Lhax:
            load_int(ctx, IrType::I16, true);
            break;
        case Mnemonic::Lhau:
        case Mnemonic::Lhaux:
            load_int(ctx, IrType::I16, true, true);
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
        default:
            return false;
    }
    return true;
}

// Scalar floating point and FPSCR access.
bool lift_float_op(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
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
            lift_fp_fused_op(ctx, IrType::F32, false, false);
            break;
        case Mnemonic::Fmsubs:
            lift_fp_fused_op(ctx, IrType::F32, true, false);
            break;
        case Mnemonic::Fnmadds:
            lift_fp_fused_op(ctx, IrType::F32, false, true);
            break;
        case Mnemonic::Fnmsubs:
            lift_fp_fused_op(ctx, IrType::F32, true, true);
            break;
        case Mnemonic::Fmadd:
            lift_fp_fused_op(ctx, IrType::F64, false, false);
            break;
        case Mnemonic::Fmsub:
            lift_fp_fused_op(ctx, IrType::F64, true, false);
            break;
        case Mnemonic::Fnmadd:
            lift_fp_fused_op(ctx, IrType::F64, false, true);
            break;
        case Mnemonic::Fnmsub:
            lift_fp_fused_op(ctx, IrType::F64, true, true);
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
            lift_frsp(ctx);
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
            (void)lift_fctiwz_value(ctx);
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
        default:
            return false;
    }
    return true;
}

// Integer and floating-point stores, including multiple-word forms.
bool lift_store(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
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
            store_int(ctx, IrType::I32, false);
            break;
        case Mnemonic::Stwu:
        case Mnemonic::Stwux:
            store_int(ctx, IrType::I32, true);
            break;
        case Mnemonic::Stb:
        case Mnemonic::Stbx:
            store_int(ctx, IrType::I8, false);
            break;
        case Mnemonic::Stbu:
        case Mnemonic::Stbux:
            store_int(ctx, IrType::I8, true);
            break;
        case Mnemonic::Sth:
        case Mnemonic::Sthx:
            store_int(ctx, IrType::I16, false);
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
            store_int(ctx, IrType::I16, true);
            break;
        case Mnemonic::Lmw:
            lift_multiple_word(ctx, true);
            break;
        case Mnemonic::Stmw:
            lift_multiple_word(ctx, false);
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
        default:
            return false;
    }
    return true;
}

// Gekko paired-single loads, stores and arithmetic.
bool lift_paired_single(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
        case Mnemonic::PsqL:
        case Mnemonic::PsqLu:
            lift_psq_memory(ctx, true, insn.mnemonic == Mnemonic::PsqLu);
            break;
        case Mnemonic::PsqSt:
            lift_psq_memory(ctx, false, false);
            break;
        case Mnemonic::PsqStu:
            lift_psq_memory(ctx, false, true);
            break;
        case Mnemonic::PsqLx:
        case Mnemonic::PsqLux:
            lift_psq_memory(ctx, true, insn.mnemonic == Mnemonic::PsqLux);
            break;
        case Mnemonic::PsqStx:
            lift_psq_memory(ctx, false, false);
            break;
        case Mnemonic::PsqStux:
            lift_psq_memory(ctx, false, true);
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
            lift_ps_fused_op(ctx, true, false);
            break;
        case Mnemonic::PsMadd:
            lift_ps_fused_op(ctx, false, false);
            break;
        case Mnemonic::PsNmsub:
            lift_ps_fused_op(ctx, true, true);
            break;
        case Mnemonic::PsNmadd:
            lift_ps_fused_op(ctx, false, true);
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
        default:
            return false;
    }
    return true;
}

// Calls, returns, branches and CR-conditional branches.
bool lift_control(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
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
        default:
            return false;
    }
    return true;
}

// Cache, synchronisation and privileged instructions as intrinsics.
bool lift_system(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
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
            return false;
    }
    return true;
}

void lift_instruction(LiftCtx& ctx) {
    if (lift_integer_op(ctx) || lift_load(ctx) || lift_store(ctx) ||
        lift_float_op(ctx) || lift_paired_single(ctx) || lift_control(ctx) ||
        lift_system(ctx)) {
        return;
    }
    lift_intrinsic(ctx, mnemonic_name(ctx.insn->mnemonic));
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

}  // namespace ember::ppc_lift

namespace ember {

using namespace ppc_lift;

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

        const auto& instructions = fn.blocks[i].instructions;
        for (std::size_t j = 0; j < instructions.size(); ++j) {
            ctx.insn = &instructions[j];
            if (j + 2 < instructions.size() &&
                lift_fctiwz_spill(ctx, instructions[j + 1], instructions[j + 2])) {
                j += 2;
                continue;
            }
            lift_instruction(ctx);
        }

        ensure_terminator(ir.blocks[i], abi_);
    }

    return ir;
}

}  // namespace ember
