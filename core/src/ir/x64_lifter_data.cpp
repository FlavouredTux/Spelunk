// Data movement: cmov, xchg/xadd/cmpxchg, bit scan/test, bswap, push/pop.

#include <format>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/ir.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {

// Build the same i1 condition that jcc would produce, given the CMOVcc
// mnemonic. Reuses jcc_predicate by mapping cmov→jcc.
IrValue cmov_predicate(Mnemonic mn, LiftCtx& ctx) {
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
// emitter renders it as `dst = (cond ? src : dst);` - matches the source
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

// Capture both values and effective addresses before either destination write.
void lift_xchg(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue addresses[2];
    IrValue values[2];
    for (u8 i = 0; i < 2; ++i) {
        const auto& operand = insn.operands[i];
        if (operand.kind == Operand::Kind::Memory) {
            addresses[i] = ctx.snapshot(compute_ea(operand.mem, ctx));
            values[i] = ctx.emit_load(addresses[i], operand_type(operand),
                                      operand.mem.segment);
        } else {
            values[i] = ctx.snapshot(materialize_rvalue(operand, ctx));
        }
    }
    for (u8 i = 0; i < 2; ++i) {
        const auto& operand = insn.operands[i];
        IrValue value = ctx.match_size(values[1 - i], operand_type(operand), false);
        if (operand.kind == Operand::Kind::Memory)
            ctx.emit_store(addresses[i], value, operand.mem.segment);
        else
            store_lvalue(operand, value, ctx);
    }
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
    // Integer flag-setter - invalidate any prior FP-compare context so a
    // later Jp/Jnp doesn't lower against stale ucomi operands.
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = {};
    ctx.last_flag_src = {};

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
    // Integer flag-setter - clear any prior FP-compare context.
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = {};
    ctx.last_flag_src = {};

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

// LZCNT / TZCNT dst, src. A 16-bit source goes through the 32-bit
// intrinsic with a sentinel bit that makes zero count as 16. CF reports a
// zero source and ZF a zero count.
void lift_bit_count(LiftCtx& ctx, bool leading) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    const IrType t = operand_type(insn.operands[0]);
    IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), t, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpEq, src, ctx.imm(0, t)));
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = {};
    ctx.last_flag_src = {};
    IrValue operand = src;
    if (t == IrType::I16) {
        operand = ctx.match_size(src, IrType::I32, /*sign_ext=*/false);
        if (leading) {
            operand = ctx.emit_binop(IrOp::Or,
                ctx.emit_binop(IrOp::Shl, operand, ctx.imm(16, IrType::I32)),
                ctx.imm(0x8000, IrType::I32));
        } else {
            operand = ctx.emit_binop(IrOp::Or, operand, ctx.imm(0x10000, IrType::I32));
        }
    }
    const bool wide = t == IrType::I64;
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("{}_u{}", leading ? "_lzcnt" : "_tzcnt", wide ? 64 : 32);
    i.dst = ctx.temp(wide ? IrType::I64 : IrType::I32);
    i.srcs[0] = operand;
    i.src_count = 1;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, t, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, result, ctx.imm(0, t)));
    store_lvalue(insn.operands[0], result, ctx);
}

// BLSR / BLSMSK / BLSI dst(vvvv), src: lowest-set-bit arithmetic.
void lift_bmi1(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    const IrType t = operand_type(insn.operands[0]);
    const IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), t, /*sign_ext=*/false);
    const IrValue zero = ctx.imm(0, t);
    IrValue result;
    if (insn.mnemonic == Mnemonic::Blsi) {
        result = ctx.emit_binop(IrOp::And, src, ctx.emit_binop(IrOp::Sub, zero, src));
        ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpNe, src, zero));
    } else {
        const IrValue below = ctx.emit_binop(IrOp::Sub, src, ctx.imm(1, t));
        result = ctx.emit_binop(insn.mnemonic == Mnemonic::Blsr ? IrOp::And : IrOp::Xor, src, below);
        ctx.emit_set_flag(Flag::Cf, ctx.emit_cmp(IrOp::CmpEq, src, zero));
    }
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, result, zero));
    ctx.emit_set_flag(Flag::Sf, ctx.emit_cmp(IrOp::CmpSlt, result, zero));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = {};
    ctx.last_flag_src = {};
    store_lvalue(insn.operands[0], result, ctx);
}

// BEXTR dst, src, control: the field at control[7:0] of length control[15:8].
void lift_bextr(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3) return;
    const IrType t = operand_type(insn.operands[0]);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = t == IrType::I64 ? "__bextr_u64" : "__bextr_u32";
    i.dst = ctx.temp(t == IrType::I64 ? IrType::I64 : IrType::I32);
    i.srcs[0] = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), i.dst.type, false);
    i.srcs[1] = ctx.match_size(materialize_rvalue(insn.operands[2], ctx), i.dst.type, false);
    i.src_count = 2;
    IrValue result = i.dst;
    ctx.emit(std::move(i));
    result = ctx.match_size(result, t, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, result, ctx.imm(0, t)));
    ctx.emit_set_flag(Flag::Cf, ctx.imm(0, IrType::I1));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = {};
    ctx.last_flag_src = {};
    store_lvalue(insn.operands[0], result, ctx);
}

// RORX dst, src, imm8: rotate right without touching the flags.
void lift_rorx(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 3 || insn.operands[2].kind != Operand::Kind::Immediate) return;
    const IrType t = operand_type(insn.operands[0]);
    const unsigned width = type_bits(t);
    const IrValue src = ctx.match_size(materialize_rvalue(insn.operands[1], ctx), t, /*sign_ext=*/false);
    const auto count = static_cast<unsigned>(insn.operands[2].imm.value) & (width - 1);
    IrValue result = src;
    if (count != 0) {
        result = ctx.emit_binop(IrOp::Or,
            ctx.emit_binop(IrOp::Lshr, src, ctx.imm(count, t)),
            ctx.emit_binop(IrOp::Shl, src, ctx.imm(width - count, t)));
    }
    store_lvalue(insn.operands[0], result, ctx);
}

// An operand-less instruction that produces its destination (rdrand,
// rdseed, rdssp). RDRAND/RDSEED report success in CF; model success so the
// retry loop around them reads as such.
void lift_value_intrinsic(LiftCtx& ctx, std::string_view name) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const IrType t = operand_type(insn.operands[0]);
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = std::format("{}{}", name, type_bits(t));
    i.dst = ctx.temp(t);
    const IrValue result = i.dst;
    ctx.emit(std::move(i));
    if (insn.mnemonic == Mnemonic::Rdrand || insn.mnemonic == Mnemonic::Rdseed) {
        ctx.emit_set_flag(Flag::Cf, ctx.imm(1, IrType::I1));
    }
    store_lvalue(insn.operands[0], result, ctx);
}

// XGETBV: EDX:EAX = XCR[ECX].
void lift_xgetbv(LiftCtx& ctx) {
    IrInst i;
    i.op = IrOp::Intrinsic;
    i.name = "_xgetbv";
    i.dst = ctx.temp(IrType::I64);
    i.srcs[0] = ctx.match_size(ctx.read_reg(Reg::Ecx), IrType::I32, /*sign_ext=*/false);
    i.src_count = 1;
    const IrValue value = i.dst;
    ctx.emit(std::move(i));
    store_lvalue(Operand::make_reg(Reg::Eax),
                 ctx.match_size(value, IrType::I32, /*sign_ext=*/false), ctx);
    store_lvalue(Operand::make_reg(Reg::Edx),
                 ctx.match_size(ctx.emit_binop(IrOp::Lshr, value, ctx.imm(32, IrType::I64)),
                                IrType::I32, /*sign_ext=*/false), ctx);
}

// POPCNT dst, src: dst = number of set bits in src. ZF reflects whether the
// source was zero; other status flags are architecturally cleared, but ZF is
// the one emitted code commonly consumes.
void lift_popcnt(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 2) return;
    IrValue src = materialize_rvalue(insn.operands[1], ctx);
    const IrType t = operand_type(insn.operands[0]);
    src = ctx.match_size(src, t, /*sign_ext=*/false);
    ctx.emit_set_flag(Flag::Zf, ctx.emit_cmp(IrOp::CmpEq, src, ctx.imm(0, t)));
    ctx.last_fp_cmp_a = {};
    ctx.last_fp_cmp_b = {};
    ctx.last_pf_value = ctx.imm(0, IrType::I1);
    ctx.last_flag_src = {};

    IrInst i;
    i.op   = IrOp::Intrinsic;
    i.name = "popcnt";
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
    const u64 width_mask = static_cast<u64>(type_bits(base.type)) - 1;

    // SDM: the bit offset is taken modulo the operand width, so `bt %ecx,
    // %eax` tests bit (cl & 31) and a wide immediate like `btw $100, %ax`
    // still lands inside the operand. Applying the mask up front keeps the
    // common immediate form as plain constants (`lshr rdi, 0x3`) instead of
    // a zext-of-imm temp feeding both the shift and the mask rebuild; it
    // also keeps every emitted shift in range where the raw offset could
    // run past the width. Caveat we accept: the memory form can legally
    // straddle into the following quadword, which this single-load model
    // does not reproduce either way.
    IrValue off;
    if (insn.operands[1].kind == Operand::Kind::Immediate) {
        off = ctx.imm(static_cast<i64>(static_cast<u64>(insn.operands[1].imm.value) &
                                        width_mask),
                      base.type);
    } else {
        off = materialize_rvalue(insn.operands[1], ctx);
        off = ctx.match_size(off, base.type, /*sign_ext=*/false);
        off = ctx.emit_binop(IrOp::And, off,
                             ctx.imm(static_cast<i64>(width_mask), base.type));
    }

    IrValue shifted = ctx.emit_binop(IrOp::Lshr, base, off);
    IrValue one_t   = ctx.imm(1, base.type);
    IrValue bit     = ctx.emit_binop(IrOp::And, shifted, one_t);
    ctx.emit_set_flag(Flag::Cf,
                      ctx.emit_cmp(IrOp::CmpNe, bit, ctx.imm(0, base.type)));

    if (op == 't') return;  // BT - read-only

    // BTS/BTR/BTC write the bit back; with an immediate offset the mask is
    // a compile-time constant, so emit it directly rather than shl(1, off)
    // and let the reader see `xor rdi, 0x8` instead of `xor rdi, 1 << t0`.
    IrValue mask = (off.kind == IrValueKind::Imm)
        ? ctx.imm(static_cast<i64>(u64{1} << static_cast<u64>(off.imm)), base.type)
        : ctx.emit_binop(IrOp::Shl, one_t, off);
    IrValue r;
    if (op == 's') {
        r = ctx.emit_binop(IrOp::Or, base, mask);
    } else if (op == 'r') {
        IrValue inv_mask = ctx.emit_unop(IrOp::Not, mask);
        r = ctx.emit_binop(IrOp::And, base, inv_mask);
    } else {  // 'c' - complement
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
    const bool word = insn.prefixes.opsize;
    const IrType stack_type = word ? IrType::I16 : ctx.word_type();
    const i64 stack_size = word ? 2 : ctx.word_size();
    if (val.type != stack_type) {
        val = ctx.match_size(val, stack_type, /*sign_ext=*/true);
    }
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue new_rsp = ctx.emit_binop(IrOp::Sub, rsp,
                                     ctx.imm(stack_size, ctx.word_type()));
    ctx.emit_store(new_rsp, val);
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
}

void lift_pop(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    if (insn.num_operands != 1) return;
    const IrType t = operand_type(insn.operands[0]);
    const bool word = insn.prefixes.opsize;
    const IrType stack_type = word ? IrType::I16 : ctx.word_type();
    const i64 stack_size = word ? 2 : ctx.word_size();
    IrValue rsp = ctx.reg(Reg::Rsp);
    IrValue val = ctx.emit_load(rsp, stack_type);
    IrValue new_rsp = ctx.emit_binop(IrOp::Add, rsp,
                                     ctx.imm(stack_size, ctx.word_type()));
    ctx.emit_assign(ctx.reg(Reg::Rsp), new_rsp);
    val = ctx.match_size(val, t, /*sign_ext=*/false);
    store_lvalue(insn.operands[0], val, ctx);
}

}  // namespace spelunk::x64_lift
