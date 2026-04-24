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

    Cmp, Test,

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
    MovqStore,   // 0x66 0x0F D6 — movq m64, xmm (low 64 bits)
    Pcmpeqd,     // 0x66 0x0F 76
    Pcmpeqw,     // 0x66 0x0F 75
    Paddq,       // 0x66 0x0F D4
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
    Cvtsi2ss,         // xmm <- r/m32|64
    Cvttss2si,        // r32|64 <- xmm/m32 (truncation)
    Cvtss2sd,         // f64 <- f32
    Ucomiss,          // compare, sets ZF/PF/CF
    // Double-precision (F2 0F ..):
    MovsdXmm,         // movsd xmm, xmm/m64   (distinct from the string op)
    MovsdXmmStore,    // movsd xmm/m64, xmm
    Addsd, Subsd, Mulsd, Divsd, Sqrtsd,
    Cvtsi2sd,
    Cvttsd2si,
    Cvtsd2ss,
    Ucomisd,          // 66 0F 2E
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
            return true;
        default: return false;
    }
}

[[nodiscard]] constexpr bool is_unconditional_jmp(Mnemonic m) noexcept {
    return m == Mnemonic::Jmp;
}

[[nodiscard]] constexpr bool is_call(Mnemonic m) noexcept {
    return m == Mnemonic::Call;
}

[[nodiscard]] constexpr bool is_return_like(Mnemonic m) noexcept {
    return m == Mnemonic::Ret || m == Mnemonic::Ud2 || m == Mnemonic::Hlt;
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
