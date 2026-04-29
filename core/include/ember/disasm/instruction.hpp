#pragma once

#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>

namespace ember {

enum class Mnemonic : u16 {
    Invalid = 0,

    Mov, Movzx, Movsx, Movsxd, Lea, Xchg,
    Push, Pop,
    Addi, Addis,
    Ld, Std, Lwz, Stw,

    Add, Sub, Adc, Sbb, Inc, Dec, Neg,
    Mul, Imul, Div, Idiv,

    And, Or, Xor, Not,
    Shl, Shr, Sar, Rol, Ror, Rcl, Rcr,

    Cmp, Cmn, Test,

    Jmp, Call, Ret, Leave,

    Jo, Jno, Jb, Jae, Je, Jne, Jbe, Ja,
    Js, Jns, Jp, Jnp, Jl, Jge, Jle, Jg,
    Beq, Bne, Blt, Bge, Bgt, Ble, Bdnz, Bdz,

    Nop, Hlt, Int, Int3, Syscall, Ud2,
    Cdq, Cqo, Cwde, Cdqe,
    Endbr64, Endbr32,

    // ---- SetCC: write 0/1 byte based on a flag predicate ------------------
    Seto, Setno, Setb, Setae, Sete, Setne, Setbe, Seta,
    Sets, Setns, Setp, Setnp, Setl, Setge, Setle, Setg,

    // ---- CMovCC: conditional move (reg ← r/m if cond) ---------------------
    Cmovo, Cmovno, Cmovb, Cmovae, Cmove, Cmovne, Cmovbe, Cmova,
    Cmovs, Cmovns, Cmovp, Cmovnp, Cmovl, Cmovge, Cmovle, Cmovg,

    // ---- String ops (implicit rdi/rsi/rcx; rep-prefixable) ----------------
    Movsb, Movsd, Movsq,
    Cmpsb, Cmpsd, Cmpsq,
    Stosb, Stosd, Stosq,
    Lodsb, Lodsd, Lodsq,
    Scasb, Scasd, Scasq,

    // ---- Bit / atomic / misc ----------------------------------------------
    Bt, Bts, Btr, Btc,
    Bswap,
    Cmpxchg, Xadd,

    // ---- SSE (decoded to advance length; lifted as intrinsics) ------------
    Movd,        // 0x66 0x0F 6E — movd xmm, r/m32
    Movdqa,      // 0x66 0x0F 6F — movdqa xmm, xmm/m128
    MovdqaStore, // 0x66 0x0F 7F — movdqa xmm/m128, xmm
    Movdqu,      // 0xF3 0x0F 6F — movdqu xmm, xmm/m128
    MovdquStore, // 0xF3 0x0F 7F — movdqu xmm/m128, xmm
    MovqXmm,     // 0xF3 0x0F 7E — movq xmm, xmm/m64 (scalar)
    MovdStore,   // 0x66 0x0F 7E — movd r/m32, xmm
    Pxor,        // 0x66 0x0F EF — pxor xmm, xmm/m128
    Pand,        // 0x66 0x0F DB
    Pandn,       // 0x66 0x0F DF
    Por,         // 0x66 0x0F EB
    Pcmpeqb,     // 0x66 0x0F 74
    Pminub,      // 0x66 0x0F DA
    Pmovmskb,    // 0x66 0x0F D7
    Movups,      // 0x0F 10 — movups xmm, xmm/m128
    MovupsStore, // 0x0F 11 — movups xmm/m128, xmm
    Movaps,      // 0x0F 28
    MovapsStore, // 0x0F 29
    Movhps,      // 0x0F 16
    Movlps,      // 0x0F 12
    // Packed-single logical / arithmetic (0x0F 5x, no mandatory prefix).
    // The 0x0F 0x50–0x5F range was entirely absent before, so any
    // `xorps xmm0, xmm0` stopped linear disassembly dead and the caller
    // skipped one byte, dragging the ModR/M byte into a bogus next
    // decode. Keep them as decode-only (length-advance) for now.
    Andps,       // 0x0F 54
    Andnps,      // 0x0F 55
    Orps,        // 0x0F 56
    Xorps,       // 0x0F 57
    Addps,       // 0x0F 58
    Mulps,       // 0x0F 59
    Subps,       // 0x0F 5C
    Divps,       // 0x0F 5E
    // Packed-double counterparts (0x66 0x0F 5x).
    Andpd,       // 0x66 0x0F 54
    Andnpd,      // 0x66 0x0F 55
    Orpd,        // 0x66 0x0F 56
    Xorpd,       // 0x66 0x0F 57
    Addpd,       // 0x66 0x0F 58
    Mulpd,       // 0x66 0x0F 59
    Subpd,       // 0x66 0x0F 5C
    Divpd,       // 0x66 0x0F 5E
    Punpcklbw,   // 0x66 0x0F 60
    Punpcklwd,   // 0x66 0x0F 61
    Punpckldq,   // 0x66 0x0F 62
    Punpcklqdq,  // 0x66 0x0F 6C
    Punpckhqdq,  // 0x66 0x0F 6D
    Pshufd,      // 0x66 0x0F 70 — takes an Ib extra
    Pshuflw,     // 0xF2 0x0F 70 — takes an Ib extra
    Pshufhw,     // 0xF3 0x0F 70 — takes an Ib extra
    MovqStore,   // 0x66 0x0F D6 — movq m64, xmm (low 64 bits)
    Pcmpeqd,     // 0x66 0x0F 76
    Pcmpeqw,     // 0x66 0x0F 75
    Paddb,       // 0x66 0x0F FC
    Paddw,       // 0x66 0x0F FD
    Paddd,       // 0x66 0x0F FE
    Paddq,       // 0x66 0x0F D4
    // Packed integer subtract — symmetric to padd family.
    Psubb,       // 0x66 0x0F F8
    Psubw,       // 0x66 0x0F F9
    Psubd,       // 0x66 0x0F FA
    Psubq,       // 0x66 0x0F FB
    // Packed integer multiply.
    Pmullw,      // 0x66 0x0F D5  — multiply low signed words
    Pmulhw,      // 0x66 0x0F E5  — multiply high signed words
    Pmulhuw,     // 0x66 0x0F E4  — multiply high unsigned words
    Pmuludq,     // 0x66 0x0F F4  — multiply unsigned 32→64 bits
    Pmaddwd,     // 0x66 0x0F F5  — multiply-and-add 16→32 bits
    // Saturating add / subtract — packed integer with clamp-on-overflow.
    Psubusb,     // 0x66 0x0F D8
    Psubusw,     // 0x66 0x0F D9
    Paddusb,     // 0x66 0x0F DC
    Paddusw,     // 0x66 0x0F DD
    Psubsb,      // 0x66 0x0F E8
    Psubsw,      // 0x66 0x0F E9
    Paddsb,      // 0x66 0x0F EC
    Paddsw,      // 0x66 0x0F ED
    // Packed min / max / averages.
    Pmaxub,      // 0x66 0x0F DE
    Pminsw,      // 0x66 0x0F EA
    Pmaxsw,      // 0x66 0x0F EE
    Pavgb,       // 0x66 0x0F E0
    Pavgw,       // 0x66 0x0F E3
    // Packed greater-than compares (signed).
    Pcmpgtb,     // 0x66 0x0F 64
    Pcmpgtw,     // 0x66 0x0F 65
    Pcmpgtd,     // 0x66 0x0F 66
    // Unpack-high siblings of Punpcklbw / Punpcklwd / Punpckldq.
    Punpckhbw,   // 0x66 0x0F 68
    Punpckhwd,   // 0x66 0x0F 69
    Punpckhdq,   // 0x66 0x0F 6A
    // Float shuffles with imm8 selector.
    Shufps,      // 0x0F C6
    Shufpd,      // 0x66 0x0F C6
    // Word extract — destination is a GPR.
    Pextrw,      // 0x66 0x0F C5
    // SSE2 immediate-shift family (0x66 0x0F 71/72/73 with /N opcode
    // extension).
    Psllw, Pslld, Psllq, Pslldq,
    Psrlw, Psrld, Psrlq, Psrldq,
    Psraw, Psrad,
    Pinsrw,      // 0x66 0x0F C4 — pinsrw xmm, r32, imm8
    // Bit-scan and double-shift — GPR ops, not SSE.
    Bsf,         // 0x0F BC
    Bsr,         // 0x0F BD
    Shld,        // 0x0F A4 (imm) / A5 (CL)
    Shrd,        // 0x0F AC (imm) / AD (CL)

    // ---- Scalar floating-point (real IR lifting) --------------------------
    // Single-precision (F3 0F ..):
    MovssLoad,        // movss xmm, xmm/m32
    MovssStore,       // movss xmm/m32, xmm
    Addss, Subss, Mulss, Divss, Sqrtss,
    Minss, Maxss,
    Cvtsi2ss,         // xmm <- r/m32|64
    Cvttss2si,        // r32|64 <- xmm/m32 (truncation)
    Cvtss2sd,         // f64 <- f32
    Ucomiss,          // compare, sets ZF/PF/CF
    Comiss,           // ordered compare (signaling-NaN), same flags as ucomiss
    // Double-precision (F2 0F ..):
    MovsdXmm,         // movsd xmm, xmm/m64   (distinct from the string op)
    MovsdXmmStore,    // movsd xmm/m64, xmm
    Addsd, Subsd, Mulsd, Divsd, Sqrtsd,
    Minsd, Maxsd,
    Cvtsi2sd,
    Cvttsd2si,
    Cvtsd2ss,
    Ucomisd,          // 66 0F 2E
    Comisd,           // 66 0F 2F — ordered compare
    // Packed min/max (no mandatory prefix and 0x66-prefix forms).
    Minps, Maxps,
    Minpd, Maxpd,

    // ---- AArch64 -----------------------------------------------------------
    // Naming convention: prefix `A64` so the namespace doesn't collide with
    // x86 short names (Add, Sub, Mov, Cmp, …). 4-byte fixed-length encoding;
    // every A64 mnemonic carries operands in a uniform way:
    //   - register operands as Reg::X*/W*/V*
    //   - immediates as `Operand::make_imm` typed by the encoded width
    //   - branch targets as Rel
    //   - loads/stores as Mem with `base + disp` (extension/shift via index)
    //
    // Aliases (CMP, CMN, TST, MOV-from-imm, NEG, MVN, LSL/LSR/ASR-imm…) decode
    // straight to their canonical mnemonic so the lifter sees one shape.
    A64Add, A64Sub, A64Adds, A64Subs,
    A64And, A64Orr, A64Eor, A64Bic, A64Orn, A64Eon,
    A64Ands, A64Bics,
    A64Mul, A64Madd, A64Msub,
    A64Smaddl, A64Umaddl, A64Smsubl, A64Umsubl,
    A64Smulh, A64Umulh,
    A64Sdiv, A64Udiv,
    A64Lsl, A64Lsr, A64Asr, A64Ror,
    A64Lslv, A64Lsrv, A64Asrv, A64Rorv,
    A64Mov, A64Movz, A64Movn, A64Movk,
    A64Mvn, A64Neg, A64Negs,
    A64Adr, A64Adrp,
    A64Sbfm, A64Ubfm, A64Bfm,
    A64Sxtb, A64Sxth, A64Sxtw, A64Uxtb, A64Uxth, A64Uxtw,
    A64Clz, A64Cls, A64Rbit, A64Rev, A64Rev16, A64Rev32,
    A64Csel, A64Csinc, A64Csinv, A64Csneg,
    A64Cset, A64Csetm, A64Cinc, A64Cinv, A64Cneg,
    A64Ccmp, A64Ccmn,
    // Loads / stores. Suffix encodes element width + signedness:
    //   B = byte, H = halfword, no suffix = word (X) or doubleword (W),
    //   S = sign-extended into 32-bit (LDRSB), W = ditto into 64-bit
    //   (LDRSW). LDR/STR cover 32/64-bit by Rt size.
    A64Ldr, A64Str, A64Ldrb, A64Strb, A64Ldrh, A64Strh,
    A64Ldrsb, A64Ldrsh, A64Ldrsw,
    A64Ldur, A64Stur, A64Ldurb, A64Sturb, A64Ldurh, A64Sturh,
    A64Ldursb, A64Ldursh, A64Ldursw,
    A64Ldp, A64Stp, A64Ldpsw,
    // Branches. The condition for B.cc and Cset/Csel-family lives in the
    // first immediate operand (encoded 0..15 as the AArch64 condition
    // field). Conditional branches share `A64Bcc`; predicate decoding
    // happens in the lifter via aarch64_cond_to_jcc().
    A64B, A64Bl, A64Br, A64Blr, A64Ret, A64Bcc,
    A64Cbz, A64Cbnz, A64Tbz, A64Tbnz,
    // System / misc.
    A64Nop, A64Brk, A64Svc, A64Hint, A64Hvc, A64Smc, A64Udf,
    A64Eret, A64Drps,
    A64Mrs, A64Msr,
    A64Dmb, A64Dsb, A64Isb, A64Sev, A64Wfe, A64Wfi, A64Yield,
};

[[nodiscard]] std::string_view mnemonic_name(Mnemonic m) noexcept;

struct Mem {
    Reg  segment  = Reg::None;
    Reg  base     = Reg::None;
    Reg  index    = Reg::None;
    u8   scale    = 1;
    i64  disp     = 0;
    u8   size     = 0;
    bool has_disp = false;
};

struct Imm {
    i64  value     = 0;
    u8   size      = 0;
    bool is_signed = true;
};

struct Rel {
    i64    offset = 0;
    addr_t target = 0;
    u8     size   = 0;
};

struct Operand {
    enum class Kind : u8 { None, Register, Memory, Immediate, Relative };

    Kind kind = Kind::None;
    Reg  reg  = Reg::None;
    Mem  mem  = {};
    Imm  imm  = {};
    Rel  rel  = {};

    [[nodiscard]] static Operand make_reg(Reg r) noexcept {
        Operand o; o.kind = Kind::Register; o.reg = r; return o;
    }
    [[nodiscard]] static Operand make_mem(const Mem& m) noexcept {
        Operand o; o.kind = Kind::Memory; o.mem = m; return o;
    }
    [[nodiscard]] static Operand make_imm(const Imm& i) noexcept {
        Operand o; o.kind = Kind::Immediate; o.imm = i; return o;
    }
    [[nodiscard]] static Operand make_rel(const Rel& r) noexcept {
        Operand o; o.kind = Kind::Relative; o.rel = r; return o;
    }
};

struct PrefixSet {
    bool lock     = false;
    bool rep      = false;
    bool repne    = false;
    bool opsize   = false;
    bool addrsize = false;
    Reg  segment  = Reg::None;
};

struct Instruction {
    addr_t                   address      = 0;
    u8                       length       = 0;
    Mnemonic                 mnemonic     = Mnemonic::Invalid;
    PrefixSet                prefixes     = {};
    std::array<Operand, 4>   operands     = {};
    u8                       num_operands = 0;
    std::array<std::byte, 15> raw_bytes   = {};
};

[[nodiscard]] std::string format_instruction(const Instruction& insn);
[[nodiscard]] std::string format_operand(const Instruction& insn, const Operand& op);

[[nodiscard]] constexpr bool is_conditional_branch(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Jo:  case Mnemonic::Jno: case Mnemonic::Jb:  case Mnemonic::Jae:
        case Mnemonic::Je:  case Mnemonic::Jne: case Mnemonic::Jbe: case Mnemonic::Ja:
        case Mnemonic::Js:  case Mnemonic::Jns: case Mnemonic::Jp:  case Mnemonic::Jnp:
        case Mnemonic::Jl:  case Mnemonic::Jge: case Mnemonic::Jle: case Mnemonic::Jg:
        case Mnemonic::Beq: case Mnemonic::Bne: case Mnemonic::Blt: case Mnemonic::Bge:
        case Mnemonic::Bgt: case Mnemonic::Ble: case Mnemonic::Bdnz: case Mnemonic::Bdz:
        case Mnemonic::A64Bcc:
        case Mnemonic::A64Cbz: case Mnemonic::A64Cbnz:
        case Mnemonic::A64Tbz: case Mnemonic::A64Tbnz:
            return true;
        default: return false;
    }
}

[[nodiscard]] constexpr bool is_unconditional_jmp(Mnemonic m) noexcept {
    return m == Mnemonic::Jmp || m == Mnemonic::A64B || m == Mnemonic::A64Br;
}

[[nodiscard]] constexpr bool is_call(Mnemonic m) noexcept {
    return m == Mnemonic::Call || m == Mnemonic::A64Bl || m == Mnemonic::A64Blr;
}

[[nodiscard]] constexpr bool is_return_like(Mnemonic m) noexcept {
    return m == Mnemonic::Ret || m == Mnemonic::Ud2 || m == Mnemonic::Hlt ||
           m == Mnemonic::A64Ret || m == Mnemonic::A64Brk ||
           m == Mnemonic::A64Udf || m == Mnemonic::A64Eret;
}

[[nodiscard]] constexpr bool ends_basic_block(Mnemonic m) noexcept {
    return is_conditional_branch(m) || is_unconditional_jmp(m) || is_return_like(m);
}

[[nodiscard]] inline std::optional<addr_t>
branch_target(const Instruction& insn) noexcept {
    if (insn.num_operands == 0) return std::nullopt;
    const auto& op = insn.operands[0];
    if (op.kind != Operand::Kind::Relative) return std::nullopt;
    return op.rel.target;
}

}  // namespace ember
