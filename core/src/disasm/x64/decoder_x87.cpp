#include <algorithm>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <utility>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>

#include "decoder_internal.hpp"

namespace spelunk::x64_decode {

namespace {

// x87 memory forms dispatch by the ModR/M /reg field and use a fixed width
// for each escape. Register forms dispatch by the low six bits; their operand
// order depends on the escape byte.

enum X87Shape : u8 {
    xs_none,      // zero-operand state op (fchs, fabs, fsqrt, fld1, finit, fcompp)
    xs_sti,       // single st(i) operand
    xs_sti_st0,   // st(i), st(0)
    xs_st0_sti,   // st(0), st(i)
    xs_ax,        // implicit AX destination (fnstsw ax)
};

struct X87MemEntry {
    Mnemonic m    = Mnemonic::Invalid;
    u8       size = 0;   // memory operand width; 0 = reserved/not modeled
};

struct X87RegForm {
    Mnemonic m     = Mnemonic::Invalid;
    u8       shape = xs_none;
};

[[nodiscard]] constexpr X87RegForm x87_d9_reg_form(u8 b) noexcept {
    const auto top = static_cast<u8>(b & 0xf8);
    if (top == 0xC0) return {Mnemonic::X87Fld,  xs_sti};
    if (top == 0xC8) return {Mnemonic::X87Fxch, xs_sti};
    switch (b) {
        case 0xD0: return {Mnemonic::X87Fnop,    xs_none};
        case 0xE0: return {Mnemonic::X87Fchs,    xs_none};
        case 0xE1: return {Mnemonic::X87Fabs,    xs_none};
        case 0xE4: return {Mnemonic::X87Ftst,    xs_none};
        case 0xE5: return {Mnemonic::X87Fxam,    xs_none};
        case 0xE8: return {Mnemonic::X87Fld1,    xs_none};
        case 0xE9: return {Mnemonic::X87Fldl2t,  xs_none};
        case 0xEA: return {Mnemonic::X87Fldl2e,  xs_none};
        case 0xEB: return {Mnemonic::X87Fldpi,   xs_none};
        case 0xEC: return {Mnemonic::X87Fldlg2,  xs_none};
        case 0xED: return {Mnemonic::X87Fldln2,  xs_none};
        case 0xEE: return {Mnemonic::X87Fldz,    xs_none};
        case 0xF0: return {Mnemonic::X87F2xm1,   xs_none};
        case 0xF1: return {Mnemonic::X87Fyl2x,   xs_none};
        case 0xF2: return {Mnemonic::X87Fptan,   xs_none};
        case 0xF3: return {Mnemonic::X87Fpatan,  xs_none};
        case 0xF4: return {Mnemonic::X87Fxtract, xs_none};
        case 0xF5: return {Mnemonic::X87Fprem1,  xs_none};
        case 0xF6: return {Mnemonic::X87Fdecstp, xs_none};
        case 0xF7: return {Mnemonic::X87Fincstp, xs_none};
        case 0xF8: return {Mnemonic::X87Fprem,   xs_none};
        case 0xF9: return {Mnemonic::X87Fyl2xp1, xs_none};
        case 0xFA: return {Mnemonic::X87Fsqrt,   xs_none};
        case 0xFB: return {Mnemonic::X87Fsincos, xs_none};
        case 0xFC: return {Mnemonic::X87Frndint, xs_none};
        case 0xFD: return {Mnemonic::X87Fscale,  xs_none};
        case 0xFE: return {Mnemonic::X87Fsin,    xs_none};
        case 0xFF: return {Mnemonic::X87Fcos,    xs_none};
        default:   return {};
    }
}

[[nodiscard]] constexpr X87RegForm x87_reg_form(u8 esc, u8 b) noexcept {
    const auto top = static_cast<u8>(b & 0xf8);   // mod==3 + reg field
    switch (esc) {
        case 0xD8:
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fadd,  xs_sti_st0};
                case 0xC8: return {Mnemonic::X87Fmul,  xs_sti_st0};
                case 0xD0: return {Mnemonic::X87Fcom,  xs_sti};
                case 0xD8: return {Mnemonic::X87Fcomp, xs_sti};
                case 0xE0: return {Mnemonic::X87Fsub,  xs_sti_st0};
                case 0xE8: return {Mnemonic::X87Fsubr, xs_sti_st0};
                case 0xF0: return {Mnemonic::X87Fdiv,  xs_sti_st0};
                case 0xF8: return {Mnemonic::X87Fdivr, xs_sti_st0};
                default:   return {};
            }
        case 0xD9:
            return x87_d9_reg_form(b);
        case 0xDA:
            // P6 conditional moves into st(0); DA E9 is the lone fucompp.
            if (b == 0xE9) return {Mnemonic::X87Fucompp, xs_none};
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fcmovb,  xs_st0_sti};
                case 0xC8: return {Mnemonic::X87Fcmove,  xs_st0_sti};
                case 0xD0: return {Mnemonic::X87Fcmovbe, xs_st0_sti};
                case 0xD8: return {Mnemonic::X87Fcmovu,  xs_st0_sti};
                default:   return {};
            }
        case 0xDC:
            // Register rows keep st(0) as destination, and the SUB/DIV
            // directions swap relative to D8: DC E0 is fsubr, DC E8 is
            // fsub (mirror of D8 E0/E8 where st(i) is written).
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fadd,  xs_st0_sti};
                case 0xC8: return {Mnemonic::X87Fmul,  xs_st0_sti};
                case 0xE0: return {Mnemonic::X87Fsubr, xs_st0_sti};
                case 0xE8: return {Mnemonic::X87Fsub,  xs_st0_sti};
                case 0xF0: return {Mnemonic::X87Fdivr, xs_st0_sti};
                case 0xF8: return {Mnemonic::X87Fdiv,  xs_st0_sti};
                default:   return {};   // D0-D7 reserved
            }
        case 0xDD:
            switch (top) {
                case 0xC0: return {Mnemonic::X87Ffree,  xs_sti};
                case 0xD0: return {Mnemonic::X87Fst,    xs_sti};
                case 0xD8: return {Mnemonic::X87Fstp,   xs_sti};
                case 0xE0: return {Mnemonic::X87Fucom,  xs_sti};
                case 0xE8: return {Mnemonic::X87Fucomp, xs_sti};
                default:   return {};
            }
        case 0xDE:
            // Pop variants write st(i) then pop; DE D9 is the lone fcompp.
            if (b == 0xD9) return {Mnemonic::X87Fcompp, xs_none};
            switch (top) {
                case 0xC0: return {Mnemonic::X87Faddp,  xs_sti_st0};
                case 0xC8: return {Mnemonic::X87Fmulp,  xs_sti_st0};
                case 0xE0: return {Mnemonic::X87Fsubrp, xs_sti_st0};
                case 0xE8: return {Mnemonic::X87Fsubp,  xs_sti_st0};
                case 0xF0: return {Mnemonic::X87Fdivrp, xs_sti_st0};
                case 0xF8: return {Mnemonic::X87Fdivp,  xs_sti_st0};
                default:   return {};   // D0-D8 minus D9 reserved
            }
        case 0xDB:
            // FCOMI/FUCOMI compare into EFLAGS; E2/E3 are fnclex/finit.
            if (b == 0xE2) return {Mnemonic::X87Fnclex, xs_none};
            if (b == 0xE3) return {Mnemonic::X87Finit,  xs_none};
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fcmovnb,  xs_st0_sti};
                case 0xC8: return {Mnemonic::X87Fcmovne,  xs_st0_sti};
                case 0xD0: return {Mnemonic::X87Fcmovnbe, xs_st0_sti};
                case 0xD8: return {Mnemonic::X87Fcmovnu,  xs_st0_sti};
                case 0xE8: return {Mnemonic::X87Fucomi,   xs_sti};
                case 0xF0: return {Mnemonic::X87Fcomi,    xs_sti};
                default:   return {};
            }
        case 0xDF:
            if (b == 0xE0) return {Mnemonic::X87Fnstsw, xs_ax};
            if (top == 0xE8) return {Mnemonic::X87Fucomip, xs_sti};
            if (top == 0xF0) return {Mnemonic::X87Fcomip,  xs_sti};
            return {};
        default:
            return {};
    }
}

// Environment and save-area forms carry 28- and 108-byte protected-mode
// images; 80-bit loads and stores use the 10-byte extended format.
constexpr u8 kX87EnvBytes  = 28;
constexpr u8 kX87SaveBytes = 108;
constexpr u8 kX87ExtBytes  = 10;

constexpr X87MemEntry kX87MemD8[8] = {
    {Mnemonic::X87Fadd, 4}, {Mnemonic::X87Fmul, 4},
    {Mnemonic::X87Fcom, 4}, {Mnemonic::X87Fcomp, 4},
    {Mnemonic::X87Fsub, 4}, {Mnemonic::X87Fsubr, 4},
    {Mnemonic::X87Fdiv, 4}, {Mnemonic::X87Fdivr, 4},
};
constexpr X87MemEntry kX87MemD9[8] = {
    {Mnemonic::X87Fld, 4},                 {},
    {Mnemonic::X87Fst, 4},                 {Mnemonic::X87Fstp, 4},
    {Mnemonic::X87Fldenv, kX87EnvBytes},   {Mnemonic::X87Fldcw, 2},
    {Mnemonic::X87Fnstenv, kX87EnvBytes},  {Mnemonic::X87Fnstcw, 2},
};
constexpr X87MemEntry kX87MemDA[8] = {
    {Mnemonic::X87Fiadd, 4}, {Mnemonic::X87Fimul, 4},
    {Mnemonic::X87Ficom, 4}, {Mnemonic::X87Ficomp, 4},
    {Mnemonic::X87Fisub, 4}, {Mnemonic::X87Fisubr, 4},
    {Mnemonic::X87Fidiv, 4}, {Mnemonic::X87Fidivr, 4},
};
constexpr X87MemEntry kX87MemDB[8] = {
    {Mnemonic::X87Fild, 4},   {Mnemonic::X87Fisttp, 4},
    {Mnemonic::X87Fist, 4},   {Mnemonic::X87Fistp, 4},
    {},                       {Mnemonic::X87Fld, kX87ExtBytes},
    {},                       {Mnemonic::X87Fstp, kX87ExtBytes},
};
constexpr X87MemEntry kX87MemDC[8] = {
    {Mnemonic::X87Fadd, 8}, {Mnemonic::X87Fmul, 8},
    {Mnemonic::X87Fcom, 8}, {Mnemonic::X87Fcomp, 8},
    {Mnemonic::X87Fsub, 8}, {Mnemonic::X87Fsubr, 8},
    {Mnemonic::X87Fdiv, 8}, {Mnemonic::X87Fdivr, 8},
};
constexpr X87MemEntry kX87MemDD[8] = {
    {Mnemonic::X87Fld, 8},                {Mnemonic::X87Fisttp, 8},
    {Mnemonic::X87Fst, 8},                {Mnemonic::X87Fstp, 8},
    {Mnemonic::X87Frstor, kX87SaveBytes}, {},
    {Mnemonic::X87Fnsave, kX87SaveBytes}, {Mnemonic::X87Fnstsw, 2},
};
constexpr X87MemEntry kX87MemDE[8] = {
    {Mnemonic::X87Fiadd, 2}, {Mnemonic::X87Fimul, 2},
    {Mnemonic::X87Ficom, 2}, {Mnemonic::X87Ficomp, 2},
    {Mnemonic::X87Fisub, 2}, {Mnemonic::X87Fisubr, 2},
    {Mnemonic::X87Fidiv, 2}, {Mnemonic::X87Fidivr, 2},
};
constexpr X87MemEntry kX87MemDF[8] = {
    {Mnemonic::X87Fild, 2},               {Mnemonic::X87Fisttp, 2},
    {Mnemonic::X87Fist, 2},               {Mnemonic::X87Fistp, 2},
    {Mnemonic::X87Fbld, kX87ExtBytes},    {Mnemonic::X87Fild, 8},
    {Mnemonic::X87Fbstp, kX87ExtBytes},   {Mnemonic::X87Fistp, 8},
};

[[nodiscard]] const X87MemEntry& x87_mem_form(u8 esc, u8 reg) noexcept {
    switch (esc) {
        case 0xD8: return kX87MemD8[reg];
        case 0xD9: return kX87MemD9[reg];
        case 0xDA: return kX87MemDA[reg];
        case 0xDB: return kX87MemDB[reg];
        case 0xDC: return kX87MemDC[reg];
        case 0xDD: return kX87MemDD[reg];
        case 0xDE: return kX87MemDE[reg];
        case 0xDF: return kX87MemDF[reg];
        default:   break;
    }
    static constexpr X87MemEntry none{};
    return none;
}

[[nodiscard]] Operand make_stack_reg(u8 i) noexcept {
    Operand o;
    o.kind      = Operand::Kind::Register;
    o.reg       = Reg::None;
    o.x87_stack = static_cast<u8>(i & 7u);
    return o;
}

}  // anonymous namespace

[[nodiscard]] Result<Instruction>
decode_x87_escape(Context& ctx, addr_t addr) noexcept {
    auto m_r = ctx.read_u8();
    if (!m_r) return std::unexpected(std::move(m_r).error());
    ctx.modrm = *m_r;

    const u8 esc = ctx.opcode;
    const u8 reg = static_cast<u8>((ctx.modrm >> 3) & 7);

    Instruction insn;
    insn.address  = addr;
    insn.prefixes = ctx.prefix;

    if ((ctx.modrm >> 6) != 3) {
        const auto& e = x87_mem_form(esc, reg);
        if (e.m == Mnemonic::Invalid || e.size == 0) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported x87 memory form {:02x} /{} at {:#x}",
                esc, reg, addr)));
        }
        insn.mnemonic = e.m;
        auto op = decode_modrm_rm(ctx, e.size, /*mem_only=*/true);
        if (!op) return std::unexpected(std::move(op).error());
        insn.operands[0]  = *op;
        insn.num_operands = 1;
    } else {
        const auto e = x87_reg_form(esc, ctx.modrm);
        if (e.m == Mnemonic::Invalid) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported x87 register form {:02x} {:02x} at {:#x}",
                esc, ctx.modrm, addr)));
        }
        insn.mnemonic = e.m;
        const u8 i = static_cast<u8>(ctx.modrm & 7);
        switch (e.shape) {
            case xs_sti:
                insn.operands[0]  = make_stack_reg(i);
                insn.num_operands = 1;
                break;
            case xs_sti_st0:
                insn.operands[0]  = make_stack_reg(i);
                insn.operands[1]  = make_stack_reg(0);
                insn.num_operands = 2;
                break;
            case xs_st0_sti:
                insn.operands[0]  = make_stack_reg(0);
                insn.operands[1]  = make_stack_reg(i);
                insn.num_operands = 2;
                break;
            case xs_ax:
                insn.operands[0]  = Operand::make_reg(Reg::Ax);
                insn.num_operands = 1;
                break;
            case xs_none:
            default:
                break;
        }
    }

    insn.length = static_cast<u8>(ctx.pos);
    std::memcpy(insn.raw_bytes.data(), ctx.code.data(),
                std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
    return insn;
}

}  // namespace spelunk::x64_decode
