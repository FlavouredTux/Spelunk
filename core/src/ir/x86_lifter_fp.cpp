#include <array>
#include <bit>
#include <initializer_list>
#include <numbers>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include <spelunk/binary/binary.hpp>
#include <spelunk/common/bytes.hpp>

#include "x64_lifter_internal.hpp"

namespace spelunk::x64_lift {
namespace {

// The x87 register stack is modelled as eight F64 registers holding
// st(0)..st(7) by position: pushes and pops shift values between them, so
// ordinary SSA merges also describe the stack across control flow. Values
// are carried as double; 80-bit extended operands stay explicit intrinsics.
IrValue st(unsigned index) {
    return IrValue::make_reg(static_cast<Reg>(static_cast<unsigned>(Reg::St0) + (index & 7u)),
                             IrType::F64);
}

IrValue emit_intrinsic(LiftCtx& ctx, std::string_view name, std::optional<IrType> type,
                       std::initializer_list<IrValue> srcs) {
    IrInst inst;
    inst.op = IrOp::Intrinsic;
    inst.name = std::string(name);
    if (type) inst.dst = ctx.temp(*type);
    for (const IrValue& src : srcs) inst.srcs[inst.src_count++] = src;
    const IrValue result = inst.dst;
    ctx.emit(std::move(inst));
    return result;
}

IrValue intrinsic(LiftCtx& ctx, std::string_view name, IrType type,
                  std::initializer_list<IrValue> srcs) {
    return emit_intrinsic(ctx, name, type, srcs);
}

// An intrinsic kept for its effect on memory or FPU state.
void side_effect(LiftCtx& ctx, std::string_view name, std::initializer_list<IrValue> srcs) {
    emit_intrinsic(ctx, name, std::nullopt, srcs);
}

IrValue fp_imm(LiftCtx& ctx, double value) {
    return ctx.imm(std::bit_cast<i64>(value), IrType::F64);
}

IrValue fp_cast(LiftCtx& ctx, IrValue value, IrType type) {
    if (value.type == type) return value;
    return intrinsic(ctx, type == IrType::F64 ? "cvtss2sd" : "cvtsd2ss", type, {value});
}

IrValue address(LiftCtx& ctx, const Operand& operand) {
    return compute_ea(operand.mem, ctx);
}

IrType int_type(const Operand& operand) {
    return operand.mem.size == 2 ? IrType::I16
        : operand.mem.size == 8 ? IrType::I64 : IrType::I32;
}

IrValue load_int_as_fp(LiftCtx& ctx, const Operand& operand) {
    IrValue value = ctx.emit_load(address(ctx, operand), int_type(operand), operand.mem.segment);
    value = ctx.match_size(value, IrType::I64, /*sign_ext=*/true);
    return intrinsic(ctx, "cvtsi2sd", IrType::F64, {value});
}

// A literal in read-only data (`fld dword [0x402000]`), read here so the
// widening every x87 load does folds into the constant.
std::optional<double> read_only_constant(const LiftCtx& ctx, const Operand& operand) {
    const Mem& m = operand.mem;
    if (!ctx.binary || m.segment != Reg::None || m.index != Reg::None ||
        (m.size != 4 && m.size != 8)) {
        return std::nullopt;
    }
    addr_t va = 0;
    if (m.base == Reg::None) {
        va = ctx.mode32() ? static_cast<u32>(m.disp) : static_cast<addr_t>(m.disp);
    } else if (m.base == Reg::Rip) {
        va = ctx.insn->address + ctx.insn->length + static_cast<addr_t>(m.disp);
    } else {
        return std::nullopt;
    }
    for (const auto& section : ctx.binary->sections()) {
        if (va < section.vaddr || va - section.vaddr >= section.size) continue;
        if (section.flags.writable || section.flags.executable ||
            m.size > section.size - (va - section.vaddr)) {
            return std::nullopt;
        }
        const auto bytes = ctx.binary->bytes_at(va);
        if (bytes.size() < m.size) return std::nullopt;
        if (m.size == 4) {
            return static_cast<double>(std::bit_cast<float>(read_le_at<u32>(bytes.data())));
        }
        return std::bit_cast<double>(read_le_at<u64>(bytes.data()));
    }
    return std::nullopt;
}

IrValue fp_operand(LiftCtx& ctx, const Operand& operand) {
    if (operand.kind == Operand::Kind::Register) return st(operand.x87_stack);
    if (operand.mem.size == 10) {
        return intrinsic(ctx, "x87.load80", IrType::F64, {address(ctx, operand)});
    }
    if (auto constant = read_only_constant(ctx, operand)) return fp_imm(ctx, *constant);
    return fp_cast(ctx, ctx.emit_load(address(ctx, operand),
        operand.mem.size == 4 ? IrType::F32 : IrType::F64, operand.mem.segment), IrType::F64);
}

void push(LiftCtx& ctx, IrValue value) {
    value = ctx.snapshot(value);
    for (unsigned i = 7; i > 0; --i) ctx.emit_assign(st(i), st(i - 1));
    ctx.emit_assign(st(0), value);
}

void pop(LiftCtx& ctx) {
    for (unsigned i = 0; i < 7; ++i) ctx.emit_assign(st(i), st(i + 1));
    IrInst clobber;
    clobber.op = IrOp::Clobber;
    clobber.dst = st(7);
    ctx.emit(std::move(clobber));
}

void clobber_stack(LiftCtx& ctx) {
    for (unsigned i = 0; i < 8; ++i) {
        IrInst clobber;
        clobber.op = IrOp::Clobber;
        clobber.dst = st(i);
        ctx.emit(std::move(clobber));
    }
}

std::optional<double> stack_constant(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::X87Fld1:   return 1.0;
        case Mnemonic::X87Fldz:   return 0.0;
        case Mnemonic::X87Fldpi:  return std::numbers::pi;
        case Mnemonic::X87Fldl2e: return std::numbers::log2e;
        case Mnemonic::X87Fldl2t: return std::numbers::ln10 / std::numbers::ln2;
        case Mnemonic::X87Fldlg2: return std::numbers::ln2 / std::numbers::ln10;
        case Mnemonic::X87Fldln2: return std::numbers::ln2;
        default:                  return std::nullopt;
    }
}

// The condition codes fnstsw stores in AH, per outcome: C0 is bit 0, C2
// bit 2, C3 bit 6. Greater clears all three; unordered sets all three.
constexpr std::array<u8, 4> kStatusImage = {0x00, 0x01, 0x40, 0x45};

// Bit `bit` of each outcome's byte as a truth table.
u8 table_of(const std::array<u8, 4>& bytes, unsigned bit) {
    u8 table = 0;
    for (unsigned outcome = 0; outcome < 4; ++outcome) {
        if ((bytes[outcome] >> bit) & 1u) table = static_cast<u8>(table | (1u << outcome));
    }
    return table;
}

u8 table_where(const std::array<bool, 4>& holds) {
    u8 table = 0;
    for (unsigned outcome = 0; outcome < 4; ++outcome) {
        if (holds[outcome]) table = static_cast<u8>(table | (1u << outcome));
    }
    return table;
}

// st(0) compared with `operand`. fcomi and friends write EFLAGS like
// ucomisd; the others leave C0/C2/C3 for fnstsw.
void compare(LiftCtx& ctx, IrValue lhs, IrValue rhs, bool eflags) {
    FpOutcome outcome;
    outcome.a = ctx.snapshot(lhs);
    outcome.b = ctx.snapshot(rhs);
    ctx.fp_outcome = outcome;
    if (!eflags) return;
    const IrValue zf = fp_outcome_predicate(ctx, kFpEqual | kFpUnordered);
    const IrValue cf = fp_outcome_predicate(ctx, kFpLess | kFpUnordered);
    const IrValue pf = fp_outcome_predicate(ctx, kFpUnordered);
    ctx.emit_set_flag(Flag::Zf, zf);
    ctx.emit_set_flag(Flag::Cf, cf);
    ctx.emit_set_flag(Flag::Sf, ctx.imm(0, IrType::I1));
    ctx.emit_set_flag(Flag::Of, ctx.imm(0, IrType::I1));
    ctx.last_flag_src = {};
    ctx.last_pf_value = pf;
    ctx.last_fp_cmp_a = outcome.a;
    ctx.last_fp_cmp_b = outcome.b;
    ctx.fp_outcome.known = kFpZf | kFpCf | kFpSf | kFpOf | kFpPf;
    ctx.fp_outcome.zf = kFpEqual | kFpUnordered;
    ctx.fp_outcome.cf = kFpLess | kFpUnordered;
    ctx.fp_outcome.pf = kFpUnordered;
}

// The status word of the last compare in this block: C0, C2 and C3 in
// bits 8, 10 and 14. Without one the condition codes are not modelled.
IrValue status_word(LiftCtx& ctx) {
    if (ctx.fp_outcome.a.kind == IrValueKind::None) {
        return intrinsic(ctx, "x87.status_word", IrType::I16, {});
    }
    struct ConditionCode {
        i64 bit;
        u8  table;
    };
    static constexpr std::array<ConditionCode, 3> kCodes = {{
        {8, kFpLess | kFpUnordered},   // C0
        {10, kFpUnordered},            // C2
        {14, kFpEqual | kFpUnordered}, // C3
    }};
    IrValue word = ctx.imm(0, IrType::I16);
    for (const auto [bit, table] : kCodes) {
        IrValue code = ctx.emit_convert(IrOp::ZExt, fp_outcome_predicate(ctx, table),
                                        IrType::I16);
        code = ctx.emit_binop(IrOp::Shl, code, ctx.imm(bit, IrType::I16));
        word = ctx.emit_binop(IrOp::Or, word, code);
    }
    return word;
}

Mnemonic fcmov_condition(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::X87Fcmovb:   return Mnemonic::Jb;
        case Mnemonic::X87Fcmove:   return Mnemonic::Je;
        case Mnemonic::X87Fcmovbe:  return Mnemonic::Jbe;
        case Mnemonic::X87Fcmovu:   return Mnemonic::Jp;
        case Mnemonic::X87Fcmovnb:  return Mnemonic::Jae;
        case Mnemonic::X87Fcmovne:  return Mnemonic::Jne;
        case Mnemonic::X87Fcmovnbe: return Mnemonic::Ja;
        case Mnemonic::X87Fcmovnu:  return Mnemonic::Jnp;
        default:                    return Mnemonic::Invalid;
    }
}

// Stores st(0) as an integer. fisttp truncates; fist and fistp round by the
// control word, which compilers set to truncation around C casts.
void store_int(LiftCtx& ctx, const Operand& operand, bool truncate) {
    const IrType type = int_type(operand);
    const IrType wide = type == IrType::I64 ? IrType::I64 : IrType::I32;
    IrValue value = truncate || ctx.x87_control_word_loaded
        ? ctx.emit_convert(IrOp::FpToInt, st(0), wide)
        : intrinsic(ctx, wide == IrType::I64 ? "llrint" : "lrint", wide, {st(0)});
    value = ctx.match_size(value, type, /*sign_ext=*/false);
    ctx.emit_store(address(ctx, operand), value, operand.mem.segment);
}

bool lift_arithmetic(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    const auto mnemonic = insn.mnemonic;
    IrOp op;
    bool reverse = false;
    bool popping = false;
    bool integer = false;
    switch (mnemonic) {
        case Mnemonic::X87Faddp:  popping = true; [[fallthrough]];
        case Mnemonic::X87Fadd:   op = IrOp::Add; break;
        case Mnemonic::X87Fmulp:  popping = true; [[fallthrough]];
        case Mnemonic::X87Fmul:   op = IrOp::Mul; break;
        case Mnemonic::X87Fsubp:  popping = true; [[fallthrough]];
        case Mnemonic::X87Fsub:   op = IrOp::Sub; break;
        case Mnemonic::X87Fsubrp: popping = true; [[fallthrough]];
        case Mnemonic::X87Fsubr:  op = IrOp::Sub; reverse = true; break;
        case Mnemonic::X87Fdivp:  popping = true; [[fallthrough]];
        case Mnemonic::X87Fdiv:   op = IrOp::Div; break;
        case Mnemonic::X87Fdivrp: popping = true; [[fallthrough]];
        case Mnemonic::X87Fdivr:  op = IrOp::Div; reverse = true; break;
        case Mnemonic::X87Fiadd:  op = IrOp::Add; integer = true; break;
        case Mnemonic::X87Fimul:  op = IrOp::Mul; integer = true; break;
        case Mnemonic::X87Fisub:  op = IrOp::Sub; integer = true; break;
        case Mnemonic::X87Fisubr: op = IrOp::Sub; integer = true; reverse = true; break;
        case Mnemonic::X87Fidiv:  op = IrOp::Div; integer = true; break;
        case Mnemonic::X87Fidivr: op = IrOp::Div; integer = true; reverse = true; break;
        default: return false;
    }
    if (!insn.num_operands) return false;
    const bool memory = insn.operands[0].kind == Operand::Kind::Memory;
    unsigned escape = 0;
    for (u8 i = 0; i < insn.length; ++i) {
        const auto byte = static_cast<u8>(insn.raw_bytes[i]);
        if (byte >= 0xd8 && byte <= 0xdf) { escape = byte; break; }
    }
    // Register forms name st(i) in one operand and st(0) in the other; DC
    // and the popping DE rows write st(i), D8 writes st(0).
    const unsigned index = memory ? 0
        : (insn.operands[0].x87_stack | (insn.num_operands > 1 ? insn.operands[1].x87_stack : 0));
    const unsigned destination = popping || escape == 0xdc ? index : 0;
    IrValue lhs = st(destination);
    IrValue rhs = integer ? load_int_as_fp(ctx, insn.operands[0])
        : memory ? fp_operand(ctx, insn.operands[0]) : st(destination == 0 ? index : 0);
    if (reverse) std::swap(lhs, rhs);
    ctx.emit_assign(st(destination), ctx.emit_binop(op, lhs, rhs));
    if (popping) pop(ctx);
    return true;
}

bool lift_compare(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    unsigned pops = 0;
    bool eflags = false;
    bool integer = false;
    switch (insn.mnemonic) {
        case Mnemonic::X87Fcom: case Mnemonic::X87Fucom: break;
        case Mnemonic::X87Fcomp: case Mnemonic::X87Fucomp: pops = 1; break;
        case Mnemonic::X87Fcompp: case Mnemonic::X87Fucompp: pops = 2; break;
        case Mnemonic::X87Ficom: integer = true; break;
        case Mnemonic::X87Ficomp: integer = true; pops = 1; break;
        case Mnemonic::X87Fcomi: case Mnemonic::X87Fucomi: eflags = true; break;
        case Mnemonic::X87Fcomip: case Mnemonic::X87Fucomip: eflags = true; pops = 1; break;
        case Mnemonic::X87Ftst: compare(ctx, st(0), fp_imm(ctx, 0.0), false); return true;
        default: return false;
    }
    IrValue rhs = st(1);
    if (insn.num_operands) {
        rhs = integer ? load_int_as_fp(ctx, insn.operands[0]) : fp_operand(ctx, insn.operands[0]);
    }
    compare(ctx, st(0), rhs, eflags);
    for (unsigned i = 0; i < pops; ++i) pop(ctx);
    return true;
}

std::optional<std::string_view> unary_function(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::X87Fabs:    return "fabs";
        case Mnemonic::X87Fsqrt:   return "sqrt";
        case Mnemonic::X87Fsin:    return "sin";
        case Mnemonic::X87Fcos:    return "cos";
        case Mnemonic::X87Frndint: return "rint";
        case Mnemonic::X87F2xm1:   return "x87.f2xm1";
        default:                   return std::nullopt;
    }
}

// Operations on st(1) and st(0): st(1) = f(st(1), st(0)), then pop.
std::optional<std::string_view> folding_function(Mnemonic mnemonic) {
    switch (mnemonic) {
        case Mnemonic::X87Fpatan:  return "atan2";
        case Mnemonic::X87Fyl2x:   return "x87.fyl2x";
        case Mnemonic::X87Fyl2xp1: return "x87.fyl2xp1";
        default:                   return std::nullopt;
    }
}

bool lift_transcendental(LiftCtx& ctx) {
    const auto mnemonic = ctx.insn->mnemonic;
    if (auto name = unary_function(mnemonic)) {
        ctx.emit_assign(st(0), intrinsic(ctx, *name, IrType::F64, {st(0)}));
        return true;
    }
    if (auto name = folding_function(mnemonic)) {
        ctx.emit_assign(st(1), intrinsic(ctx, *name, IrType::F64, {st(1), st(0)}));
        pop(ctx);
        return true;
    }
    switch (mnemonic) {
        case Mnemonic::X87Fchs:
            ctx.emit_assign(st(0), ctx.emit_unop(IrOp::Neg, st(0)));
            return true;
        case Mnemonic::X87Fscale:
            ctx.emit_assign(st(0), intrinsic(ctx, "x87.fscale", IrType::F64, {st(0), st(1)}));
            return true;
        case Mnemonic::X87Fprem:
            ctx.emit_assign(st(0), intrinsic(ctx, "fmod", IrType::F64, {st(0), st(1)}));
            return true;
        case Mnemonic::X87Fprem1:
            ctx.emit_assign(st(0), intrinsic(ctx, "remainder", IrType::F64, {st(0), st(1)}));
            return true;
        case Mnemonic::X87Fptan:
            ctx.emit_assign(st(0), intrinsic(ctx, "tan", IrType::F64, {st(0)}));
            push(ctx, fp_imm(ctx, 1.0));
            return true;
        case Mnemonic::X87Fsincos: {
            const IrValue value = ctx.snapshot(st(0));
            ctx.emit_assign(st(0), intrinsic(ctx, "sin", IrType::F64, {value}));
            push(ctx, intrinsic(ctx, "cos", IrType::F64, {value}));
            return true;
        }
        case Mnemonic::X87Fxtract: {
            const IrValue value = ctx.snapshot(st(0));
            ctx.emit_assign(st(0), intrinsic(ctx, "x87.exponent", IrType::F64, {value}));
            push(ctx, intrinsic(ctx, "x87.significand", IrType::F64, {value}));
            return true;
        }
        default:
            return false;
    }
}

bool lift_control(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    switch (insn.mnemonic) {
        case Mnemonic::X87Fnop:
        case Mnemonic::X87Fnclex:
        case Mnemonic::X87Ffree:
            return true;
        case Mnemonic::X87Fldcw:
            // Only the rounding of later fist/fistp depends on it.
            ctx.x87_control_word_loaded = true;
            return true;
        case Mnemonic::X87Fnstcw:
            if (!insn.num_operands) return false;
            ctx.emit_store(address(ctx, insn.operands[0]),
                           intrinsic(ctx, "x87.control_word", IrType::I16, {}),
                           insn.operands[0].mem.segment);
            return true;
        case Mnemonic::X87Fnstsw:
            if (!insn.num_operands) return false;
            if (insn.operands[0].kind == Operand::Kind::Register) {
                const FpOutcome outcome = ctx.fp_outcome;
                ctx.write_reg(Reg::Ax, status_word(ctx));
                if (outcome.a.kind != IrValueKind::None) {
                    ctx.fp_outcome.ah = true;
                    ctx.fp_outcome.ah_image = kStatusImage;
                }
            } else {
                ctx.emit_store(address(ctx, insn.operands[0]), status_word(ctx),
                               insn.operands[0].mem.segment);
            }
            return true;
        case Mnemonic::X87Fxam:
            // Classifies st(0) into C0-C3; not a comparison of two values.
            ctx.fp_outcome = {};
            return true;
        case Mnemonic::X87Finit:
            ctx.fp_outcome = {};
            clobber_stack(ctx);
            return true;
        case Mnemonic::X87Fnsave:
        case Mnemonic::X87Frstor:
            if (!insn.num_operands) return false;
            side_effect(ctx, insn.mnemonic == Mnemonic::X87Fnsave ? "x87.fnsave" : "x87.frstor",
                        {address(ctx, insn.operands[0])});
            ctx.fp_outcome = {};
            clobber_stack(ctx);
            return true;
        case Mnemonic::X87Fldenv:
        case Mnemonic::X87Fnstenv:
            if (!insn.num_operands) return false;
            side_effect(ctx, insn.mnemonic == Mnemonic::X87Fldenv ? "x87.fldenv" : "x87.fnstenv",
                        {address(ctx, insn.operands[0])});
            return true;
        case Mnemonic::X87Fincstp: {
            const IrValue top = ctx.snapshot(st(0));
            for (unsigned i = 0; i < 7; ++i) ctx.emit_assign(st(i), st(i + 1));
            ctx.emit_assign(st(7), top);
            return true;
        }
        case Mnemonic::X87Fdecstp: {
            const IrValue bottom = ctx.snapshot(st(7));
            for (unsigned i = 7; i > 0; --i) ctx.emit_assign(st(i), st(i - 1));
            ctx.emit_assign(st(0), bottom);
            return true;
        }
        default:
            return false;
    }
}

}  // namespace

IrValue fp_outcome_predicate(LiftCtx& ctx, u8 table) {
    table &= 0xf;
    if (table == 0) return ctx.imm(0, IrType::I1);
    if (table == 0xf) return ctx.imm(1, IrType::I1);
    const IrValue a = ctx.fp_outcome.a;
    const IrValue b = ctx.fp_outcome.b;
    switch (table) {
        case kFpGreater:                return ctx.emit_cmp(IrOp::CmpSgt, a, b);
        case kFpLess:                   return ctx.emit_cmp(IrOp::CmpSlt, a, b);
        case kFpEqual:                  return ctx.emit_cmp(IrOp::CmpEq, a, b);
        case kFpGreater | kFpEqual:     return ctx.emit_cmp(IrOp::CmpSge, a, b);
        case kFpLess | kFpEqual:        return ctx.emit_cmp(IrOp::CmpSle, a, b);
        case kFpGreater | kFpLess:
            return ctx.emit_binop_i1(IrOp::Or, ctx.emit_cmp(IrOp::CmpSlt, a, b),
                                     ctx.emit_cmp(IrOp::CmpSgt, a, b));
        case kFpUnordered:
            return intrinsic(ctx, "unordered_fp_compare", IrType::I1, {a, b});
        // C's != is the one comparison that holds when unordered.
        case kFpGreater | kFpLess | kFpUnordered: return ctx.emit_cmp(IrOp::CmpNe, a, b);
        default:
            return ctx.emit_unop(IrOp::Not, fp_outcome_predicate(ctx, static_cast<u8>(0xf ^ table)));
    }
}

std::optional<IrValue> fp_outcome_condition(Mnemonic jcc, LiftCtx& ctx) {
    const FpOutcome& outcome = ctx.fp_outcome;
    u8 needs = 0;
    switch (jcc) {
        case Mnemonic::Jo: case Mnemonic::Jno: needs = kFpOf; break;
        case Mnemonic::Jb: case Mnemonic::Jae: needs = kFpCf; break;
        case Mnemonic::Je: case Mnemonic::Jne: needs = kFpZf; break;
        case Mnemonic::Jbe: case Mnemonic::Ja: needs = kFpCf | kFpZf; break;
        case Mnemonic::Js: case Mnemonic::Jns: needs = kFpSf; break;
        case Mnemonic::Jp: case Mnemonic::Jnp: needs = kFpPf; break;
        case Mnemonic::Jl: case Mnemonic::Jge: needs = kFpSf | kFpOf; break;
        case Mnemonic::Jle: case Mnemonic::Jg: needs = kFpSf | kFpOf | kFpZf; break;
        default: return std::nullopt;
    }
    if ((outcome.known & needs) != needs) return std::nullopt;
    std::array<bool, 4> holds{};
    for (unsigned o = 0; o < 4; ++o) {
        const bool zf = (outcome.zf >> o) & 1u;
        const bool cf = (outcome.cf >> o) & 1u;
        const bool sf = (outcome.sf >> o) & 1u;
        const bool of = (outcome.of >> o) & 1u;
        const bool pf = (outcome.pf >> o) & 1u;
        switch (jcc) {
            case Mnemonic::Jo:  holds[o] = of; break;
            case Mnemonic::Jno: holds[o] = !of; break;
            case Mnemonic::Jb:  holds[o] = cf; break;
            case Mnemonic::Jae: holds[o] = !cf; break;
            case Mnemonic::Je:  holds[o] = zf; break;
            case Mnemonic::Jne: holds[o] = !zf; break;
            case Mnemonic::Jbe: holds[o] = cf || zf; break;
            case Mnemonic::Ja:  holds[o] = !cf && !zf; break;
            case Mnemonic::Js:  holds[o] = sf; break;
            case Mnemonic::Jns: holds[o] = !sf; break;
            case Mnemonic::Jp:  holds[o] = pf; break;
            case Mnemonic::Jnp: holds[o] = !pf; break;
            case Mnemonic::Jl:  holds[o] = sf != of; break;
            case Mnemonic::Jge: holds[o] = sf == of; break;
            case Mnemonic::Jle: holds[o] = zf || sf != of; break;
            case Mnemonic::Jg:  holds[o] = !zf && sf == of; break;
            default: break;
        }
    }
    return fp_outcome_predicate(ctx, table_where(holds));
}

void refine_fp_status_use(LiftCtx& ctx, const FpOutcome& before) {
    const auto& insn = *ctx.insn;
    const auto& image = before.ah_image;
    std::array<u8, 4> result = image;
    bool writes = false;
    std::optional<u8> cf;
    std::optional<u8> of;
    if (insn.mnemonic == Mnemonic::Sahf) {
        // AH bits 0, 2, 6 and 7 become CF, PF, ZF and SF; OF is untouched.
        const u8 zf = table_of(image, 6);
        const u8 pf = table_of(image, 2);
        const u8 sf = table_of(image, 7);
        ctx.emit_set_flag(Flag::Cf, fp_outcome_predicate(ctx, table_of(image, 0)));
        ctx.emit_set_flag(Flag::Zf, fp_outcome_predicate(ctx, zf));
        ctx.emit_set_flag(Flag::Sf, fp_outcome_predicate(ctx, sf));
        ctx.last_pf_value = fp_outcome_predicate(ctx, pf);
        ctx.fp_outcome = before;
        ctx.fp_outcome.known = static_cast<u8>(kFpZf | kFpCf | kFpSf | kFpPf |
                                               (before.known & kFpOf));
        ctx.fp_outcome.cf = table_of(image, 0);
        ctx.fp_outcome.zf = zf;
        ctx.fp_outcome.sf = sf;
        ctx.fp_outcome.pf = pf;
        return;
    }
    const bool ah_first = insn.num_operands >= 1 &&
        insn.operands[0].kind == Operand::Kind::Register && insn.operands[0].reg == Reg::Ah;
    if (!ah_first) return;
    const bool has_imm = insn.num_operands == 2 &&
        insn.operands[1].kind == Operand::Kind::Immediate;
    const auto imm = static_cast<u8>(has_imm ? insn.operands[1].imm.value : 1);
    switch (insn.mnemonic) {
        case Mnemonic::Test: case Mnemonic::And: case Mnemonic::Or: case Mnemonic::Xor:
            if (!has_imm) return;
            for (auto& byte : result) {
                byte = insn.mnemonic == Mnemonic::Or ? static_cast<u8>(byte | imm)
                    : insn.mnemonic == Mnemonic::Xor ? static_cast<u8>(byte ^ imm)
                    : static_cast<u8>(byte & imm);
            }
            writes = insn.mnemonic != Mnemonic::Test;
            cf = 0;
            of = 0;
            break;
        case Mnemonic::Cmp: case Mnemonic::Sub: case Mnemonic::Dec: {
            if (insn.mnemonic != Mnemonic::Dec && !has_imm) return;
            std::array<bool, 4> borrow{};
            std::array<bool, 4> overflow{};
            for (unsigned o = 0; o < 4; ++o) {
                const u8 lhs = image[o];
                result[o] = static_cast<u8>(lhs - imm);
                borrow[o] = lhs < imm;
                overflow[o] = ((lhs ^ imm) & (lhs ^ result[o]) & 0x80u) != 0;
            }
            writes = insn.mnemonic != Mnemonic::Cmp;
            if (insn.mnemonic != Mnemonic::Dec) cf = table_where(borrow);
            of = table_where(overflow);
            break;
        }
        case Mnemonic::Add: case Mnemonic::Inc: {
            if (insn.mnemonic == Mnemonic::Add && !has_imm) return;
            std::array<bool, 4> carry{};
            std::array<bool, 4> overflow{};
            for (unsigned o = 0; o < 4; ++o) {
                const u8 lhs = image[o];
                result[o] = static_cast<u8>(lhs + imm);
                carry[o] = lhs + imm > 0xffu;
                overflow[o] = (~(lhs ^ imm) & (lhs ^ result[o]) & 0x80u) != 0;
            }
            writes = true;
            if (insn.mnemonic == Mnemonic::Add) cf = table_where(carry);
            of = table_where(overflow);
            break;
        }
        default:
            return;
    }
    std::array<bool, 4> zero{};
    std::array<bool, 4> even{};
    for (unsigned o = 0; o < 4; ++o) {
        zero[o] = result[o] == 0;
        even[o] = (std::popcount(result[o]) & 1) == 0;
    }
    const u8 zf = table_where(zero);
    const u8 sf = table_of(result, 7);
    const u8 pf = table_where(even);
    // inc and dec keep CF, which is only tabled if it already was.
    const bool cf_known = cf.has_value() || (before.known & kFpCf);
    const u8 cf_table = cf.value_or(before.cf);
    ctx.emit_set_flag(Flag::Zf, fp_outcome_predicate(ctx, zf));
    ctx.emit_set_flag(Flag::Sf, fp_outcome_predicate(ctx, sf));
    if (cf) ctx.emit_set_flag(Flag::Cf, fp_outcome_predicate(ctx, *cf));
    if (of) ctx.emit_set_flag(Flag::Of, fp_outcome_predicate(ctx, *of));
    ctx.last_pf_value = fp_outcome_predicate(ctx, pf);
    ctx.fp_outcome = before;
    ctx.fp_outcome.ah = writes ? true : before.ah;
    if (writes) ctx.fp_outcome.ah_image = result;
    ctx.fp_outcome.known = static_cast<u8>(kFpZf | kFpSf | kFpPf | (of ? kFpOf : 0) |
                                           (cf_known ? kFpCf : 0));
    ctx.fp_outcome.zf = zf;
    ctx.fp_outcome.sf = sf;
    ctx.fp_outcome.pf = pf;
    ctx.fp_outcome.cf = cf_table;
    ctx.fp_outcome.of = of.value_or(0);
}

// x87 dataflow over the modelled register stack. Returns false only for
// a malformed instruction, which then lifts as an opaque intrinsic.
bool lift_x86_fp(LiftCtx& ctx) {
    const auto& insn = *ctx.insn;
    const auto mnemonic = insn.mnemonic;
    if (auto constant = stack_constant(mnemonic)) {
        push(ctx, fp_imm(ctx, *constant));
        return true;
    }
    switch (mnemonic) {
        case Mnemonic::X87Fld:
            if (!insn.num_operands) return false;
            push(ctx, fp_operand(ctx, insn.operands[0]));
            return true;
        case Mnemonic::X87Fild:
            if (!insn.num_operands) return false;
            push(ctx, load_int_as_fp(ctx, insn.operands[0]));
            return true;
        case Mnemonic::X87Fbld:
            if (!insn.num_operands) return false;
            push(ctx, intrinsic(ctx, "x87.fbld", IrType::F64, {address(ctx, insn.operands[0])}));
            return true;
        case Mnemonic::X87Fst:
        case Mnemonic::X87Fstp: {
            if (!insn.num_operands) return false;
            const auto& operand = insn.operands[0];
            if (operand.kind == Operand::Kind::Register) {
                ctx.emit_assign(st(operand.x87_stack), st(0));
            } else if (operand.mem.size == 10) {
                side_effect(ctx, "x87.store80", {address(ctx, operand), st(0)});
            } else {
                ctx.emit_store(address(ctx, operand),
                    fp_cast(ctx, st(0), operand.mem.size == 4 ? IrType::F32 : IrType::F64),
                    operand.mem.segment);
            }
            if (mnemonic == Mnemonic::X87Fstp) pop(ctx);
            return true;
        }
        case Mnemonic::X87Fist:
        case Mnemonic::X87Fistp:
        case Mnemonic::X87Fisttp:
            if (!insn.num_operands) return false;
            store_int(ctx, insn.operands[0], mnemonic == Mnemonic::X87Fisttp);
            if (mnemonic != Mnemonic::X87Fist) pop(ctx);
            return true;
        case Mnemonic::X87Fbstp:
            if (!insn.num_operands) return false;
            side_effect(ctx, "x87.fbstp", {address(ctx, insn.operands[0]), st(0)});
            pop(ctx);
            return true;
        case Mnemonic::X87Fxch: {
            if (!insn.num_operands) return false;
            const unsigned other = insn.operands[0].x87_stack;
            const IrValue value = ctx.snapshot(st(0));
            ctx.emit_assign(st(0), st(other));
            ctx.emit_assign(st(other), value);
            return true;
        }
        default:
            break;
    }
    if (const Mnemonic condition = fcmov_condition(mnemonic); condition != Mnemonic::Invalid) {
        if (insn.num_operands < 2) return false;
        const IrValue taken = jcc_predicate(condition, ctx);
        ctx.emit_assign(st(0), ctx.select(taken, st(insn.operands[1].x87_stack), st(0)));
        return true;
    }
    return lift_arithmetic(ctx) || lift_compare(ctx) || lift_transcendental(ctx) ||
        lift_control(ctx);
}

}  // namespace spelunk::x64_lift
