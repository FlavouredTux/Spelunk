#include "decoder_internal.hpp"

#include <cstddef>

namespace spelunk::x64_decode {

namespace {

constexpr OpcodeEntry op(Mnemonic m,
                         OpSpec o1 = OpSpec::None,
                         OpSpec o2 = OpSpec::None,
                         OpSpec o3 = OpSpec::None,
                         bool modrm = false,
                         OpSpec o4 = OpSpec::None) noexcept {
    return {m, o1, o2, o3, o4, 0, modrm};
}

constexpr OpcodeEntry grp(GroupId g) noexcept {
    return {Mnemonic::Invalid, OpSpec::None, OpSpec::None, OpSpec::None,
            OpSpec::None, static_cast<u8>(g), true};
}

// ============================================================================
// Primary opcode table (one-byte opcodes)
// ============================================================================

constexpr std::array<OpcodeEntry, 256> build_primary() noexcept {
    std::array<OpcodeEntry, 256> t{};

    struct AluRow { std::size_t base; Mnemonic m; };
    constexpr AluRow alu[] = {
        {0x00, Mnemonic::Add}, {0x08, Mnemonic::Or},
        {0x10, Mnemonic::Adc}, {0x18, Mnemonic::Sbb},
        {0x20, Mnemonic::And}, {0x28, Mnemonic::Sub},
        {0x30, Mnemonic::Xor}, {0x38, Mnemonic::Cmp},
    };
    for (const auto& a : alu) {
        t[a.base + 0] = op(a.m, OpSpec::Eb,  OpSpec::Gb,  OpSpec::None, true);
        t[a.base + 1] = op(a.m, OpSpec::Ev,  OpSpec::Gv,  OpSpec::None, true);
        t[a.base + 2] = op(a.m, OpSpec::Gb,  OpSpec::Eb,  OpSpec::None, true);
        t[a.base + 3] = op(a.m, OpSpec::Gv,  OpSpec::Ev,  OpSpec::None, true);
        t[a.base + 4] = op(a.m, OpSpec::AL,  OpSpec::Ib);
        t[a.base + 5] = op(a.m, OpSpec::RAX, OpSpec::Iz);
    }

    for (std::size_t i = 0; i < 8; ++i) {
        t[0x50 + i] = op(Mnemonic::Push, OpSpec::Zv);
        t[0x58 + i] = op(Mnemonic::Pop,  OpSpec::Zv);
    }

    t[0x63] = op(Mnemonic::Movsxd, OpSpec::Gv, OpSpec::Ed, OpSpec::None, true);
    t[0x68] = op(Mnemonic::Push, OpSpec::Iz);
    t[0x69] = op(Mnemonic::Imul, OpSpec::Gv, OpSpec::Ev, OpSpec::Iz,   true);
    t[0x6A] = op(Mnemonic::Push, OpSpec::Ib);
    t[0x6B] = op(Mnemonic::Imul, OpSpec::Gv, OpSpec::Ev, OpSpec::Ibsext, true);

    constexpr Mnemonic jccs[16] = {
        Mnemonic::Jo,  Mnemonic::Jno, Mnemonic::Jb,  Mnemonic::Jae,
        Mnemonic::Je,  Mnemonic::Jne, Mnemonic::Jbe, Mnemonic::Ja,
        Mnemonic::Js,  Mnemonic::Jns, Mnemonic::Jp,  Mnemonic::Jnp,
        Mnemonic::Jl,  Mnemonic::Jge, Mnemonic::Jle, Mnemonic::Jg,
    };
    for (std::size_t i = 0; i < 16; ++i) {
        t[0x70 + i] = op(jccs[i], OpSpec::Jb);
    }

    t[0x80] = grp(Grp_1_Eb_Ib);
    t[0x81] = grp(Grp_1_Ev_Iz);
    t[0x83] = grp(Grp_1_Ev_Ibs);

    t[0x84] = op(Mnemonic::Test, OpSpec::Eb, OpSpec::Gb, OpSpec::None, true);
    t[0x85] = op(Mnemonic::Test, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0x86] = op(Mnemonic::Xchg, OpSpec::Eb, OpSpec::Gb, OpSpec::None, true);
    t[0x87] = op(Mnemonic::Xchg, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);

    t[0x88] = op(Mnemonic::Mov, OpSpec::Eb, OpSpec::Gb, OpSpec::None, true);
    t[0x89] = op(Mnemonic::Mov, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0x8A] = op(Mnemonic::Mov, OpSpec::Gb, OpSpec::Eb, OpSpec::None, true);
    t[0x8B] = op(Mnemonic::Mov, OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);

    t[0x8D] = op(Mnemonic::Lea, OpSpec::Gv, OpSpec::M, OpSpec::None, true);
    t[0x8F] = grp(Grp_1A);

    t[0x90] = op(Mnemonic::Nop);
    // 0x91..0x97 = xchg <reg>, rAX. Compilers emit `48 92` (xchg rdx, rax)
    // routinely as a tail fixup when a small struct is returned in rdx:rax
    // pair but the assigning code wrote rax:rdx - the xchg flips them so
    // the SysV ABI sees them in the right order. Without this we lose the
    // assignments to rdx, the cleanup pipeline DCEs them as dead, and any
    // string_view-returning function decompiles to empty switch arms.
    for (std::size_t i = 1; i < 8; ++i) {
        t[0x90 + i] = op(Mnemonic::Xchg, OpSpec::Zv, OpSpec::RAX);
    }
    t[0x98] = op(Mnemonic::Cwde);
    t[0x99] = op(Mnemonic::Cdq);
    t[0x9C] = op(Mnemonic::Pushf);
    t[0x9D] = op(Mnemonic::Popf);
    t[0x9E] = op(Mnemonic::Sahf);
    t[0x9F] = op(Mnemonic::Lahf);

    // String ops: no explicit operands (implicit rdi/rsi/rcx/rax, direction
    // flag). The "w"-sized (0x66-prefixed) variants aren't emitted; the -b
    // / default / -q variants cover the vast majority of real code.
    t[0xA0] = op(Mnemonic::Mov, OpSpec::AL, OpSpec::Ob);
    t[0xA1] = op(Mnemonic::Mov, OpSpec::RAX, OpSpec::Ov);
    t[0xA2] = op(Mnemonic::Mov, OpSpec::Ob, OpSpec::AL);
    t[0xA3] = op(Mnemonic::Mov, OpSpec::Ov, OpSpec::RAX);
    t[0xA4] = op(Mnemonic::Movsb);
    t[0xA5] = op(Mnemonic::Movsd);   // promote to Movsq when REX.W
    t[0xA6] = op(Mnemonic::Cmpsb);
    t[0xA7] = op(Mnemonic::Cmpsd);   // promote to Cmpsq when REX.W
    t[0xA8] = op(Mnemonic::Test, OpSpec::AL,  OpSpec::Ib);
    t[0xA9] = op(Mnemonic::Test, OpSpec::RAX, OpSpec::Iz);
    t[0xAA] = op(Mnemonic::Stosb);
    t[0xAB] = op(Mnemonic::Stosd);   // promote to Stosq when REX.W
    t[0xAC] = op(Mnemonic::Lodsb);
    t[0xAD] = op(Mnemonic::Lodsd);   // promote to Lodsq when REX.W
    t[0xAE] = op(Mnemonic::Scasb);
    t[0xAF] = op(Mnemonic::Scasd);   // promote to Scasq when REX.W

    for (std::size_t i = 0; i < 8; ++i) {
        t[0xB0 + i] = op(Mnemonic::Mov, OpSpec::Zb, OpSpec::Ib);
        t[0xB8 + i] = op(Mnemonic::Mov, OpSpec::Zv, OpSpec::Iv);
    }

    t[0xC0] = grp(Grp_2_Eb_Ib);
    t[0xC1] = grp(Grp_2_Ev_Ib);
    t[0xC2] = op(Mnemonic::Ret, OpSpec::Iw);
    t[0xC3] = op(Mnemonic::Ret);
    t[0xC6] = grp(Grp_11_Eb_Ib);
    t[0xC7] = grp(Grp_11_Ev_Iz);
    t[0xC9] = op(Mnemonic::Leave);
    t[0xCC] = op(Mnemonic::Int3);
    t[0xCD] = op(Mnemonic::Int, OpSpec::Ib);

    t[0xD0] = grp(Grp_2_Eb_1);
    t[0xD1] = grp(Grp_2_Ev_1);
    t[0xD2] = grp(Grp_2_Eb_CL);
    t[0xD3] = grp(Grp_2_Ev_CL);

    t[0xE8] = op(Mnemonic::Call, OpSpec::Jz);
    t[0xE9] = op(Mnemonic::Jmp,  OpSpec::Jz);
    t[0xEB] = op(Mnemonic::Jmp,  OpSpec::Jb);

    t[0xF4] = op(Mnemonic::Hlt);
    t[0xF5] = op(Mnemonic::Cmc);
    t[0xF6] = grp(Grp_3_Eb);
    t[0xF7] = grp(Grp_3_Ev);
    t[0xF8] = op(Mnemonic::Clc);
    t[0xF9] = op(Mnemonic::Stc);
    t[0xFA] = op(Mnemonic::Cli);
    t[0xFB] = op(Mnemonic::Sti);
    t[0xFC] = op(Mnemonic::Cld);
    t[0xFD] = op(Mnemonic::StdDir);
    t[0xFE] = grp(Grp_4);
    t[0xFF] = grp(Grp_5);

    return t;
}

// ============================================================================
// Secondary opcode table (0x0F-escaped)
// ============================================================================

constexpr std::array<OpcodeEntry, 256> build_secondary() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x52] = op(Mnemonic::Rsqrtps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x53] = op(Mnemonic::Rcpps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x0d] = op(Mnemonic::Prefetch, OpSpec::M, OpSpec::None, OpSpec::None, true);
    t[0x14] = op(Mnemonic::Unpcklps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x15] = op(Mnemonic::Unpckhps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x18] = op(Mnemonic::Prefetch, OpSpec::M, OpSpec::None, OpSpec::None, true);
    t[0x2b] = op(Mnemonic::Movntps, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x50] = op(Mnemonic::Movmskps, OpSpec::Gv, OpSpec::Wx, OpSpec::None, true);
    t[0x51] = op(Mnemonic::Sqrtps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5a] = op(Mnemonic::Cvtps2pd, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x5b] = op(Mnemonic::Cvtdq2ps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xc2] = op(Mnemonic::Cmpps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0xc3] = op(Mnemonic::Movnti, OpSpec::M, OpSpec::Gv, OpSpec::None, true);
    t[0x05] = op(Mnemonic::Syscall);
    t[0x0B] = op(Mnemonic::Ud2);
    t[0x1F] = op(Mnemonic::Nop, OpSpec::Ev, OpSpec::None, OpSpec::None, true);
    // System-instruction zero-operand opcodes - anti-debug pipelines lean
    // on rdtsc / cpuid heavily, and a single missing entry at any of these
    // aborts linear disassembly mid-function (the next byte is consumed as
    // a fresh opcode and decode error cascades). All take no explicit
    // operands; the lifter models them as side-effecting intrinsics.
    t[0x30] = op(Mnemonic::Wrmsr);
    t[0x31] = op(Mnemonic::Rdtsc);
    t[0x32] = op(Mnemonic::Rdmsr);
    t[0x33] = op(Mnemonic::Rdpmc);
    t[0xA2] = op(Mnemonic::Cpuid);

    // SSE1: packed-float moves (no mandatory prefix).
    t[0x10] = op(Mnemonic::Movups,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovupsStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    // Half-register moves: the memory forms move 64 bits, the register
    // forms of 12/16 are movhlps / movlhps.
    t[0x12] = op(Mnemonic::Movlps,      OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x13] = op(Mnemonic::MovlpsStore, OpSpec::Wsd, OpSpec::Vx, OpSpec::None, true);
    t[0x16] = op(Mnemonic::Movhps,      OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x17] = op(Mnemonic::MovhpsStore, OpSpec::Wsd, OpSpec::Vx, OpSpec::None, true);
    t[0x28] = op(Mnemonic::Movaps,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x29] = op(Mnemonic::MovapsStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x2E] = op(Mnemonic::Ucomiss,     OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x2F] = op(Mnemonic::Comiss,      OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);

    // Packed-single logical + arithmetic. The whole 0x50–0x5F range was
    // missing before, so `xorps xmm0, xmm0` (0x0F 0x57 0xC0) aborted
    // linear disassembly and the caller's 1-byte-advance dragged the
    // ModR/M byte 0xC0 into a garbage next decode.
    t[0x54] = op(Mnemonic::Andps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x55] = op(Mnemonic::Andnps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x56] = op(Mnemonic::Orps,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x57] = op(Mnemonic::Xorps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x58] = op(Mnemonic::Addps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Mulps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5C] = op(Mnemonic::Subps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5D] = op(Mnemonic::Minps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5E] = op(Mnemonic::Divps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5F] = op(Mnemonic::Maxps,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xC6] = op(Mnemonic::Shufps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);

    // CMovCC: 0x0F 4x - Gv, Ev. Indexed in condition order (o/no/b/ae/…).
    constexpr Mnemonic cmovs[16] = {
        Mnemonic::Cmovo,  Mnemonic::Cmovno, Mnemonic::Cmovb,  Mnemonic::Cmovae,
        Mnemonic::Cmove,  Mnemonic::Cmovne, Mnemonic::Cmovbe, Mnemonic::Cmova,
        Mnemonic::Cmovs,  Mnemonic::Cmovns, Mnemonic::Cmovp,  Mnemonic::Cmovnp,
        Mnemonic::Cmovl,  Mnemonic::Cmovge, Mnemonic::Cmovle, Mnemonic::Cmovg,
    };
    for (std::size_t i = 0; i < 16; ++i) {
        t[0x40 + i] = op(cmovs[i], OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    }

    constexpr Mnemonic jccs[16] = {
        Mnemonic::Jo,  Mnemonic::Jno, Mnemonic::Jb,  Mnemonic::Jae,
        Mnemonic::Je,  Mnemonic::Jne, Mnemonic::Jbe, Mnemonic::Ja,
        Mnemonic::Js,  Mnemonic::Jns, Mnemonic::Jp,  Mnemonic::Jnp,
        Mnemonic::Jl,  Mnemonic::Jge, Mnemonic::Jle, Mnemonic::Jg,
    };
    for (std::size_t i = 0; i < 16; ++i) {
        t[0x80 + i] = op(jccs[i], OpSpec::Jz);
    }

    // SetCC: 0x0F 9x - Eb (byte destination).
    constexpr Mnemonic setccs[16] = {
        Mnemonic::Seto,  Mnemonic::Setno, Mnemonic::Setb,  Mnemonic::Setae,
        Mnemonic::Sete,  Mnemonic::Setne, Mnemonic::Setbe, Mnemonic::Seta,
        Mnemonic::Sets,  Mnemonic::Setns, Mnemonic::Setp,  Mnemonic::Setnp,
        Mnemonic::Setl,  Mnemonic::Setge, Mnemonic::Setle, Mnemonic::Setg,
    };
    for (std::size_t i = 0; i < 16; ++i) {
        t[0x90 + i] = op(setccs[i], OpSpec::Eb, OpSpec::None, OpSpec::None, true);
    }

    // Bit ops (register form of the index).
    t[0xA3] = op(Mnemonic::Bt,  OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0xAB] = op(Mnemonic::Bts, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0xB3] = op(Mnemonic::Btr, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0xBB] = op(Mnemonic::Btc, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);

    // CMPXCHG and XADD (byte + default-sized variants).
    t[0xB0] = op(Mnemonic::Cmpxchg, OpSpec::Eb, OpSpec::Gb, OpSpec::None, true);
    t[0xB1] = op(Mnemonic::Cmpxchg, OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);
    t[0xC0] = op(Mnemonic::Xadd,    OpSpec::Eb, OpSpec::Gb, OpSpec::None, true);
    t[0xC1] = op(Mnemonic::Xadd,    OpSpec::Ev, OpSpec::Gv, OpSpec::None, true);

    // Double-precision shifts.
    t[0xA4] = op(Mnemonic::Shld, OpSpec::Ev, OpSpec::Gv, OpSpec::Ib, true);
    t[0xA5] = op(Mnemonic::Shld, OpSpec::Ev, OpSpec::Gv, OpSpec::CL, true);
    t[0xAC] = op(Mnemonic::Shrd, OpSpec::Ev, OpSpec::Gv, OpSpec::Ib, true);
    t[0xAD] = op(Mnemonic::Shrd, OpSpec::Ev, OpSpec::Gv, OpSpec::CL, true);

    // Bit scan.
    t[0xBC] = op(Mnemonic::Bsf, OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    t[0xBD] = op(Mnemonic::Bsr, OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);

    t[0xAF] = op(Mnemonic::Imul,  OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    t[0xB6] = op(Mnemonic::Movzx, OpSpec::Gv, OpSpec::Eb, OpSpec::None, true);
    t[0xB7] = op(Mnemonic::Movzx, OpSpec::Gv, OpSpec::Ew, OpSpec::None, true);
    t[0xBE] = op(Mnemonic::Movsx, OpSpec::Gv, OpSpec::Eb, OpSpec::None, true);
    t[0xBF] = op(Mnemonic::Movsx, OpSpec::Gv, OpSpec::Ew, OpSpec::None, true);

    // Group 8 (immediate-form bit ops, /4..7 = bt/bts/btr/btc with Ev, Ib).
    t[0xBA] = grp(Grp_8);

    // Bswap: Zv encoding, reg in low 3 bits. Opsize 32/64 only (16-bit UB).
    for (std::size_t i = 0; i < 8; ++i) {
        t[0xC8 + i] = op(Mnemonic::Bswap, OpSpec::Zv);
    }

    return t;
}

// SSE secondary tables, selected by a "mandatory prefix" at the 0x0F escape:
//   0x66 → packed-integer SSE2
//   0xF3 → scalar SSE (single-precision / movdqu / movq)
//   0xF2 → scalar SSE double-precision (rarely emitted outside FP code)
// When a mandatory prefix is consumed for SSE dispatch, the corresponding
// prefix bit is cleared from the instruction's prefix set so it isn't
// misinterpreted as an opsize / rep prefix by the lifter.

constexpr std::array<OpcodeEntry, 256> build_secondary_66() noexcept {
    std::array<OpcodeEntry, 256> t{};
    // movupd / movapd move the same bits as movups / movaps.
    t[0x10] = op(Mnemonic::Movups,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovupsStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x28] = op(Mnemonic::Movaps,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x29] = op(Mnemonic::MovapsStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x7c] = op(Mnemonic::Haddpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7d] = op(Mnemonic::Hsubpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xd0] = op(Mnemonic::Addsubpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    // movlpd / movhpd: the same 64-bit half moves as movlps / movhps.
    t[0x12] = op(Mnemonic::Movlps,      OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x13] = op(Mnemonic::MovlpsStore, OpSpec::Wsd, OpSpec::Vx, OpSpec::None, true);
    t[0x16] = op(Mnemonic::Movhps,      OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x17] = op(Mnemonic::MovhpsStore, OpSpec::Wsd, OpSpec::Vx, OpSpec::None, true);
    t[0x14] = op(Mnemonic::Unpcklpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x15] = op(Mnemonic::Unpckhpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x2b] = op(Mnemonic::Movntpd, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x50] = op(Mnemonic::Movmskpd, OpSpec::Gv, OpSpec::Wx, OpSpec::None, true);
    t[0x51] = op(Mnemonic::Sqrtpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5a] = op(Mnemonic::Cvtpd2ps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5b] = op(Mnemonic::Cvtps2dq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x63] = op(Mnemonic::Packsswb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x67] = op(Mnemonic::Packuswb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x6b] = op(Mnemonic::Packssdw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xc2] = op(Mnemonic::Cmppd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0xe6] = op(Mnemonic::Cvttpd2dq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xe7] = op(Mnemonic::Movntdq, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0xf6] = op(Mnemonic::Psadbw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x2E] = op(Mnemonic::Ucomisd,     OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x2F] = op(Mnemonic::Comisd,      OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    // Packed-double logical + arithmetic, mirroring the packed-single
    // block in build_secondary(). Same motivation: avoid cascading
    // decode failures on everyday SSE2 code.
    t[0x54] = op(Mnemonic::Andpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x55] = op(Mnemonic::Andnpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x56] = op(Mnemonic::Orpd,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x57] = op(Mnemonic::Xorpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x58] = op(Mnemonic::Addpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Mulpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5C] = op(Mnemonic::Subpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5D] = op(Mnemonic::Minpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5E] = op(Mnemonic::Divpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5F] = op(Mnemonic::Maxpd,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x60] = op(Mnemonic::Punpcklbw,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x61] = op(Mnemonic::Punpcklwd,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x62] = op(Mnemonic::Punpckldq,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x6C] = op(Mnemonic::Punpcklqdq,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x6D] = op(Mnemonic::Punpckhqdq,  OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x6E] = op(Mnemonic::Movd,        OpSpec::Vx, OpSpec::Edq, OpSpec::None, true);
    t[0x6F] = op(Mnemonic::Movdqa,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x70] = op(Mnemonic::Pshufd,      OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);
    t[0x74] = op(Mnemonic::Pcmpeqb,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x75] = op(Mnemonic::Pcmpeqw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x76] = op(Mnemonic::Pcmpeqd,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7E] = op(Mnemonic::MovdStore,   OpSpec::Edq, OpSpec::Vx, OpSpec::None, true);
    t[0x7F] = op(Mnemonic::MovdqaStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0xD4] = op(Mnemonic::Paddq,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD6] = op(Mnemonic::MovqStore,   OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0xD7] = op(Mnemonic::Pmovmskb,    OpSpec::Gv, OpSpec::Vx, OpSpec::None, true);
    t[0xDA] = op(Mnemonic::Pminub,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDB] = op(Mnemonic::Pand,        OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDF] = op(Mnemonic::Pandn,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD5] = op(Mnemonic::Pmullw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE4] = op(Mnemonic::Pmulhuw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE5] = op(Mnemonic::Pmulhw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEB] = op(Mnemonic::Por,         OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEF] = op(Mnemonic::Pxor,        OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF4] = op(Mnemonic::Pmuludq,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF5] = op(Mnemonic::Pmaddwd,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF8] = op(Mnemonic::Psubb,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF9] = op(Mnemonic::Psubw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFA] = op(Mnemonic::Psubd,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFB] = op(Mnemonic::Psubq,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFC] = op(Mnemonic::Paddb,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFD] = op(Mnemonic::Paddw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFE] = op(Mnemonic::Paddd,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xC4] = op(Mnemonic::Pinsrw,      OpSpec::Vx, OpSpec::Ev, OpSpec::Ib,   true);
    t[0xC5] = op(Mnemonic::Pextrw,      OpSpec::Gv, OpSpec::Wx, OpSpec::Ib,   true);
    t[0xC6] = op(Mnemonic::Shufpd,      OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);
    // Packed compare-greater-than (signed).
    t[0x64] = op(Mnemonic::Pcmpgtb,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x65] = op(Mnemonic::Pcmpgtw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x66] = op(Mnemonic::Pcmpgtd,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    // Unpack-high siblings of 0x60/0x61/0x62.
    t[0x68] = op(Mnemonic::Punpckhbw,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x69] = op(Mnemonic::Punpckhwd,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x6A] = op(Mnemonic::Punpckhdq,   OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    // Saturating arith / pavg / pmin/max - all (Vx, Wx) shape.
    t[0xD8] = op(Mnemonic::Psubusb,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD9] = op(Mnemonic::Psubusw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDC] = op(Mnemonic::Paddusb,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDD] = op(Mnemonic::Paddusw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDE] = op(Mnemonic::Pmaxub,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE0] = op(Mnemonic::Pavgb,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE3] = op(Mnemonic::Pavgw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE8] = op(Mnemonic::Psubsb,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE9] = op(Mnemonic::Psubsw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEA] = op(Mnemonic::Pminsw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEC] = op(Mnemonic::Paddsb,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xED] = op(Mnemonic::Paddsw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEE] = op(Mnemonic::Pmaxsw,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    // Reg-form shift counterparts of the imm-form group at 71/72/73.
    // The shift amount comes from another xmm; the same Mnemonic
    // doubles for both forms (mnemonic_name renders identically), and
    // the lifter dispatches by operand[1].kind to pick the matching
    // _mm_sll_* (xmm count) vs _mm_slli_* (imm) intrinsic.
    t[0xD1] = op(Mnemonic::Psrlw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD2] = op(Mnemonic::Psrld,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD3] = op(Mnemonic::Psrlq,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE1] = op(Mnemonic::Psraw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xE2] = op(Mnemonic::Psrad,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF1] = op(Mnemonic::Psllw,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF2] = op(Mnemonic::Pslld,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xF3] = op(Mnemonic::Psllq,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    // 0x71/72/73 are opcode-extension groups - the ModR/M reg field
    // selects the actual psllX/psrlX/psraX variant.
    t[0x71] = grp(Grp_71_66);
    t[0x72] = grp(Grp_72_66);
    t[0x73] = grp(Grp_73_66);
    return t;
}

constexpr std::array<OpcodeEntry, 256> build_secondary_f3() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x12] = op(Mnemonic::Movsldup, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x16] = op(Mnemonic::Movshdup, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x5b] = op(Mnemonic::Cvttps2dq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xe6] = op(Mnemonic::Cvtdq2pd, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    // Scalar single-precision.
    t[0x10] = op(Mnemonic::MovssLoad,   OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovssStore,  OpSpec::Wss, OpSpec::Vx, OpSpec::None, true);
    t[0x2A] = op(Mnemonic::Cvtsi2ss,    OpSpec::Vx, OpSpec::Ev,  OpSpec::None, true);
    t[0x2C] = op(Mnemonic::Cvttss2si,   OpSpec::Gv, OpSpec::Wss, OpSpec::None, true);
    t[0x2D] = op(Mnemonic::Cvtss2si,    OpSpec::Gv, OpSpec::Wss, OpSpec::None, true);
    t[0x2E] = op(Mnemonic::Ucomiss,     OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x51] = op(Mnemonic::Sqrtss,      OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x58] = op(Mnemonic::Addss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Mulss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5A] = op(Mnemonic::Cvtss2sd,    OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5C] = op(Mnemonic::Subss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5D] = op(Mnemonic::Minss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5E] = op(Mnemonic::Divss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5F] = op(Mnemonic::Maxss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0xC2] = op(Mnemonic::Cmpss,       OpSpec::Vx, OpSpec::Wss, OpSpec::Ib, true);
    // Existing packed-integer SSE2 entries.
    t[0x6F] = op(Mnemonic::Movdqu,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x70] = op(Mnemonic::Pshufhw,     OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);
    t[0x7E] = op(Mnemonic::MovqXmm,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7F] = op(Mnemonic::MovdquStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    // POPCNT is a mandatory-F3 scalar integer opcode, not SSE. It still
    // routes through this table because F3 0F selects it.
    t[0xB8] = op(Mnemonic::Popcnt,      OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    // LZCNT / TZCNT (ABM / BMI1). On CPUs without them they execute as
    // bsr / bsf, but the encodings mean lzcnt / tzcnt, which differ: lzcnt
    // counts from the top, and both return the operand width for zero.
    t[0xBC] = op(Mnemonic::Tzcnt,       OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    t[0xBD] = op(Mnemonic::Lzcnt,       OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    return t;
}

// 0xF2 mandatory prefix: scalar double-precision.
constexpr std::array<OpcodeEntry, 256> build_secondary_f2() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x12] = op(Mnemonic::Movddup, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x7c] = op(Mnemonic::Haddps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7d] = op(Mnemonic::Hsubps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xd0] = op(Mnemonic::Addsubps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xf0] = op(Mnemonic::Lddqu, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xc2] = op(Mnemonic::CmpsdXmm, OpSpec::Vx, OpSpec::Wsd, OpSpec::Ib, true);
    t[0xe6] = op(Mnemonic::Cvtpd2dq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x10] = op(Mnemonic::MovsdXmm,      OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovsdXmmStore, OpSpec::Wsd, OpSpec::Vx,  OpSpec::None, true);
    t[0x2A] = op(Mnemonic::Cvtsi2sd,      OpSpec::Vx,  OpSpec::Ev,  OpSpec::None, true);
    t[0x2C] = op(Mnemonic::Cvttsd2si,     OpSpec::Gv,  OpSpec::Wsd, OpSpec::None, true);
    t[0x2D] = op(Mnemonic::Cvtsd2si,      OpSpec::Gv,  OpSpec::Wsd, OpSpec::None, true);
    t[0x51] = op(Mnemonic::Sqrtsd,        OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x58] = op(Mnemonic::Addsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Mulsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x5A] = op(Mnemonic::Cvtsd2ss,      OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x5C] = op(Mnemonic::Subsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x5D] = op(Mnemonic::Minsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x5E] = op(Mnemonic::Divsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x5F] = op(Mnemonic::Maxsd,         OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x70] = op(Mnemonic::Pshuflw,       OpSpec::Vx,  OpSpec::Wx,  OpSpec::Ib,   true);
    return t;
}

// Legacy 0F 38 without a mandatory prefix: MOVBE (load and store forms).
constexpr std::array<OpcodeEntry, 256> build_map38_none() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf0] = op(Mnemonic::Movbe, OpSpec::Gv, OpSpec::M, OpSpec::None, true);
    t[0xf1] = op(Mnemonic::Movbe, OpSpec::M, OpSpec::Gv, OpSpec::None, true);
    return t;
}

// 66 0F 38: SSSE3 packed integer, SSE4.1, AES-NI.
constexpr std::array<OpcodeEntry, 256> build_map38_66() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf6] = op(Mnemonic::Adcx, OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    t[0x00] = op(Mnemonic::Pshufb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x01] = op(Mnemonic::Phaddw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x02] = op(Mnemonic::Phaddd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x03] = op(Mnemonic::Phaddsw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x04] = op(Mnemonic::Pmaddubsw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x05] = op(Mnemonic::Phsubw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x06] = op(Mnemonic::Phsubd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x07] = op(Mnemonic::Phsubsw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x08] = op(Mnemonic::Psignb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x09] = op(Mnemonic::Psignw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x0a] = op(Mnemonic::Psignd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x0b] = op(Mnemonic::Pmulhrsw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x10] = op(Mnemonic::Pblendvb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x14] = op(Mnemonic::Blendvps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x15] = op(Mnemonic::Blendvpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x17] = op(Mnemonic::Ptest, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x1c] = op(Mnemonic::Pabsb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x1d] = op(Mnemonic::Pabsw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x1e] = op(Mnemonic::Pabsd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x20] = op(Mnemonic::Pmovsxbw, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x21] = op(Mnemonic::Pmovsxbd, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x22] = op(Mnemonic::Pmovsxbq, OpSpec::Vx, OpSpec::Ww, OpSpec::None, true);
    t[0x23] = op(Mnemonic::Pmovsxwd, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x24] = op(Mnemonic::Pmovsxwq, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x25] = op(Mnemonic::Pmovsxdq, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x28] = op(Mnemonic::Pmuldq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x29] = op(Mnemonic::Pcmpeqq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x2a] = op(Mnemonic::Movntdqa, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x2b] = op(Mnemonic::Packusdw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x30] = op(Mnemonic::Pmovzxbw, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x31] = op(Mnemonic::Pmovzxbd, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x32] = op(Mnemonic::Pmovzxbq, OpSpec::Vx, OpSpec::Ww, OpSpec::None, true);
    t[0x33] = op(Mnemonic::Pmovzxwd, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x34] = op(Mnemonic::Pmovzxwq, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x35] = op(Mnemonic::Pmovzxdq, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x37] = op(Mnemonic::Pcmpgtq, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x38] = op(Mnemonic::Pminsb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x39] = op(Mnemonic::Pminsd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3a] = op(Mnemonic::Pminuw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3b] = op(Mnemonic::Pminud, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3c] = op(Mnemonic::Pmaxsb, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3d] = op(Mnemonic::Pmaxsd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3e] = op(Mnemonic::Pmaxuw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x3f] = op(Mnemonic::Pmaxud, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x40] = op(Mnemonic::Pmulld, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x41] = op(Mnemonic::Phminposuw, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xdb] = op(Mnemonic::Aesimc, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xdc] = op(Mnemonic::Aesenc, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xdd] = op(Mnemonic::Aesenclast, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xde] = op(Mnemonic::Aesdec, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xdf] = op(Mnemonic::Aesdeclast, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    return t;
}

// F2 0F 38: SSE4.2 CRC32 (byte and default-size sources).
constexpr std::array<OpcodeEntry, 256> build_map38_f2() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf0] = op(Mnemonic::Crc32, OpSpec::Gdq, OpSpec::Eb, OpSpec::None, true);
    t[0xf1] = op(Mnemonic::Crc32, OpSpec::Gdq, OpSpec::Ev, OpSpec::None, true);
    return t;
}

// 66 0F 3A: imm8-controlled SSE4.1 / PCLMUL / AES key generation.
constexpr std::array<OpcodeEntry, 256> build_map3a_66() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x08] = op(Mnemonic::Roundps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x09] = op(Mnemonic::Roundpd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x0a] = op(Mnemonic::Roundss, OpSpec::Vx, OpSpec::Wss, OpSpec::Ib, true);
    t[0x0b] = op(Mnemonic::Roundsd, OpSpec::Vx, OpSpec::Wsd, OpSpec::Ib, true);
    t[0x0c] = op(Mnemonic::Blendps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x0d] = op(Mnemonic::Blendpd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x0e] = op(Mnemonic::Pblendw, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x0f] = op(Mnemonic::Palignr, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x14] = op(Mnemonic::Pextrb, OpSpec::RdMb, OpSpec::Vx, OpSpec::Ib, true);
    t[0x15] = op(Mnemonic::Pextrw, OpSpec::RdMw, OpSpec::Vx, OpSpec::Ib, true);
    t[0x16] = op(Mnemonic::Pextrd, OpSpec::Edq, OpSpec::Vx, OpSpec::Ib, true);
    t[0x17] = op(Mnemonic::Extractps, OpSpec::Ed, OpSpec::Vx, OpSpec::Ib, true);
    t[0x20] = op(Mnemonic::Pinsrb, OpSpec::Vx, OpSpec::RdMb, OpSpec::Ib, true);
    t[0x21] = op(Mnemonic::Insertps, OpSpec::Vx, OpSpec::Wss, OpSpec::Ib, true);
    t[0x22] = op(Mnemonic::Pinsrd, OpSpec::Vx, OpSpec::Edq, OpSpec::Ib, true);
    t[0x40] = op(Mnemonic::Dpps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x41] = op(Mnemonic::Dppd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x42] = op(Mnemonic::Mpsadbw, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x44] = op(Mnemonic::Pclmulqdq, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0xdf] = op(Mnemonic::Aeskeygenassist, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    return t;
}

// VEX map 0F3A, 66: AVX/AVX2 permutes, lane inserts/extracts, F16C and
// the four-operand blends. Anything else falls back to the legacy 0F 3A
// table with a vvvv source.
constexpr std::array<OpcodeEntry, 256> build_vex_map3_66() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x5c] = op(Mnemonic::Fma4Fmaddsubps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x5d] = op(Mnemonic::Fma4Fmaddsubpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x5e] = op(Mnemonic::Fma4Fmsubaddps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x5f] = op(Mnemonic::Fma4Fmsubaddpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x68] = op(Mnemonic::Fma4Fmaddps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x69] = op(Mnemonic::Fma4Fmaddpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x6a] = op(Mnemonic::Fma4Fmaddss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true, OpSpec::Lx);
    t[0x6b] = op(Mnemonic::Fma4Fmaddsd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wsd, true, OpSpec::Lx);
    t[0x6c] = op(Mnemonic::Fma4Fmsubps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x6d] = op(Mnemonic::Fma4Fmsubpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x6e] = op(Mnemonic::Fma4Fmsubss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true, OpSpec::Lx);
    t[0x6f] = op(Mnemonic::Fma4Fmsubsd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wsd, true, OpSpec::Lx);
    t[0x78] = op(Mnemonic::Fma4Fnmaddps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x79] = op(Mnemonic::Fma4Fnmaddpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x7a] = op(Mnemonic::Fma4Fnmaddss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true, OpSpec::Lx);
    t[0x7b] = op(Mnemonic::Fma4Fnmaddsd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wsd, true, OpSpec::Lx);
    t[0x7c] = op(Mnemonic::Fma4Fnmsubps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x7d] = op(Mnemonic::Fma4Fnmsubpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x7e] = op(Mnemonic::Fma4Fnmsubss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true, OpSpec::Lx);
    t[0x7f] = op(Mnemonic::Fma4Fnmsubsd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wsd, true, OpSpec::Lx);
    t[0x00] = op(Mnemonic::Vpermq, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x01] = op(Mnemonic::Vpermpd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x02] = op(Mnemonic::Vpblendd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Ib);
    t[0x04] = op(Mnemonic::Vpermilps, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x05] = op(Mnemonic::Vpermilpd, OpSpec::Vx, OpSpec::Wx, OpSpec::Ib, true);
    t[0x06] = op(Mnemonic::Vperm2f128, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Ib);
    t[0x18] = op(Mnemonic::Vinsertf128, OpSpec::Vx, OpSpec::Hx, OpSpec::Wdq, true, OpSpec::Ib);
    t[0x19] = op(Mnemonic::Vextractf128, OpSpec::Wdq, OpSpec::Vx, OpSpec::Ib, true);
    t[0x1d] = op(Mnemonic::Vcvtps2ph, OpSpec::Wsd, OpSpec::Vx, OpSpec::Ib, true);
    t[0x38] = op(Mnemonic::Vinserti128, OpSpec::Vx, OpSpec::Hx, OpSpec::Wdq, true, OpSpec::Ib);
    t[0x39] = op(Mnemonic::Vextracti128, OpSpec::Wdq, OpSpec::Vx, OpSpec::Ib, true);
    t[0x46] = op(Mnemonic::Vperm2i128, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Ib);
    t[0x4a] = op(Mnemonic::Blendvps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x4b] = op(Mnemonic::Blendvpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    t[0x4c] = op(Mnemonic::Pblendvb, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true, OpSpec::Lx);
    return t;
}

// VEX map 0F3A, F2: BMI2 RORX.
constexpr std::array<OpcodeEntry, 256> build_vex_map3_f2() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf0] = op(Mnemonic::Rorx, OpSpec::Gv, OpSpec::Ev, OpSpec::Ib, true);
    return t;
}

// F3 0F 38: ADOX.
constexpr std::array<OpcodeEntry, 256> build_map38_f3() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf6] = op(Mnemonic::Adox, OpSpec::Gv, OpSpec::Ev, OpSpec::None, true);
    return t;
}

// VEX map 0F38 (m-mmmm=2). These are the high-value scalar BMI/BMI2
// families emitted by modern compilers. AVX/AVX2 packed operations in map 0F
// reuse the legacy SSE tables above with a non-destructive vvvv operand.
constexpr std::array<OpcodeEntry, 256> build_vex_map2_none() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xf3] = grp(Grp_17_Vex);
    t[0xf7] = op(Mnemonic::Bextr, OpSpec::Gv, OpSpec::Ev, OpSpec::Hv, true);
    t[0xF2] = op(Mnemonic::Andn, OpSpec::Gv, OpSpec::Hv, OpSpec::Ev, true);
    t[0xF5] = op(Mnemonic::Bzhi, OpSpec::Gv, OpSpec::Ev, OpSpec::Hv, true);
    return t;
}

constexpr std::array<OpcodeEntry, 256> build_vex_map2_66() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xF7] = op(Mnemonic::Shlx, OpSpec::Gv, OpSpec::Ev, OpSpec::Hv, true);
    t[0x0c] = op(Mnemonic::Vpermilps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x0d] = op(Mnemonic::Vpermilpd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x0e] = op(Mnemonic::Vtestps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x0f] = op(Mnemonic::Vtestpd, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x13] = op(Mnemonic::Vcvtph2ps, OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x16] = op(Mnemonic::Vpermps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x18] = op(Mnemonic::Vbroadcastss, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x19] = op(Mnemonic::Vbroadcastsd, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x1a] = op(Mnemonic::Vbroadcastf128, OpSpec::Vx, OpSpec::Wdq, OpSpec::None, true);
    t[0x2c] = op(Mnemonic::Vmaskmovps, OpSpec::Vx, OpSpec::Hx, OpSpec::M, true);
    t[0x2d] = op(Mnemonic::Vmaskmovpd, OpSpec::Vx, OpSpec::Hx, OpSpec::M, true);
    t[0x2e] = op(Mnemonic::VmaskmovpsStore, OpSpec::M, OpSpec::Hx, OpSpec::Vx, true);
    t[0x2f] = op(Mnemonic::VmaskmovpdStore, OpSpec::M, OpSpec::Hx, OpSpec::Vx, true);
    t[0x36] = op(Mnemonic::Vpermd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x45] = op(Mnemonic::Vpsrlvd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x46] = op(Mnemonic::Vpsravd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x47] = op(Mnemonic::Vpsllvd, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x58] = op(Mnemonic::Vpbroadcastd, OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Vpbroadcastq, OpSpec::Vx, OpSpec::Wsd, OpSpec::None, true);
    t[0x5a] = op(Mnemonic::Vbroadcasti128, OpSpec::Vx, OpSpec::Wdq, OpSpec::None, true);
    t[0x78] = op(Mnemonic::Vpbroadcastb, OpSpec::Vx, OpSpec::Wb, OpSpec::None, true);
    t[0x79] = op(Mnemonic::Vpbroadcastw, OpSpec::Vx, OpSpec::Ww, OpSpec::None, true);
    t[0x8c] = op(Mnemonic::Vpmaskmovd, OpSpec::Vx, OpSpec::Hx, OpSpec::M, true);
    t[0x8e] = op(Mnemonic::VpmaskmovdStore, OpSpec::M, OpSpec::Hx, OpSpec::Vx, true);
    t[0x96] = op(Mnemonic::Vfmaddsub132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x97] = op(Mnemonic::Vfmsubadd132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x98] = op(Mnemonic::Vfmadd132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x99] = op(Mnemonic::Vfmadd132ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0x9a] = op(Mnemonic::Vfmsub132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x9b] = op(Mnemonic::Vfmsub132ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0x9c] = op(Mnemonic::Vfnmadd132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x9d] = op(Mnemonic::Vfnmadd132ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0x9e] = op(Mnemonic::Vfnmsub132ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0x9f] = op(Mnemonic::Vfnmsub132ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xa6] = op(Mnemonic::Vfmaddsub213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xa7] = op(Mnemonic::Vfmsubadd213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xa8] = op(Mnemonic::Vfmadd213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xa9] = op(Mnemonic::Vfmadd213ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xaa] = op(Mnemonic::Vfmsub213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xab] = op(Mnemonic::Vfmsub213ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xac] = op(Mnemonic::Vfnmadd213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xad] = op(Mnemonic::Vfnmadd213ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xae] = op(Mnemonic::Vfnmsub213ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xaf] = op(Mnemonic::Vfnmsub213ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xb6] = op(Mnemonic::Vfmaddsub231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xb7] = op(Mnemonic::Vfmsubadd231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xb8] = op(Mnemonic::Vfmadd231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xb9] = op(Mnemonic::Vfmadd231ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xba] = op(Mnemonic::Vfmsub231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xbb] = op(Mnemonic::Vfmsub231ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xbc] = op(Mnemonic::Vfnmadd231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xbd] = op(Mnemonic::Vfnmadd231ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    t[0xbe] = op(Mnemonic::Vfnmsub231ps, OpSpec::Vx, OpSpec::Hx, OpSpec::Wx, true);
    t[0xbf] = op(Mnemonic::Vfnmsub231ss, OpSpec::Vx, OpSpec::Hx, OpSpec::Wss, true);
    return t;
}

constexpr std::array<OpcodeEntry, 256> build_vex_map2_f3() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xF5] = op(Mnemonic::Pext, OpSpec::Gv, OpSpec::Hv, OpSpec::Ev, true);
    t[0xF7] = op(Mnemonic::Sarx, OpSpec::Gv, OpSpec::Ev, OpSpec::Hv, true);
    return t;
}

constexpr std::array<OpcodeEntry, 256> build_vex_map2_f2() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0xF5] = op(Mnemonic::Pdep, OpSpec::Gv, OpSpec::Hv, OpSpec::Ev, true);
    t[0xF6] = op(Mnemonic::Mulx, OpSpec::Gv, OpSpec::Hv, OpSpec::Ev, true);
    t[0xF7] = op(Mnemonic::Shrx, OpSpec::Gv, OpSpec::Ev, OpSpec::Hv, true);
    return t;
}

// ============================================================================
// Group tables (ModR/M.reg selects mnemonic/operand pattern)
// ============================================================================

constexpr std::array<std::array<OpcodeEntry, 8>, Grp_Count> build_groups() noexcept {
    std::array<std::array<OpcodeEntry, 8>, Grp_Count> g{};

    constexpr Mnemonic alu[8] = {
        Mnemonic::Add, Mnemonic::Or,  Mnemonic::Adc, Mnemonic::Sbb,
        Mnemonic::And, Mnemonic::Sub, Mnemonic::Xor, Mnemonic::Cmp,
    };
    for (std::size_t i = 0; i < 8; ++i) {
        g[Grp_1_Eb_Ib][i]  = op(alu[i], OpSpec::Eb, OpSpec::Ib);
        g[Grp_1_Ev_Iz][i]  = op(alu[i], OpSpec::Ev, OpSpec::Iz);
        g[Grp_1_Ev_Ibs][i] = op(alu[i], OpSpec::Ev, OpSpec::Ibsext);
    }

    g[Grp_1A][0] = op(Mnemonic::Pop, OpSpec::Ev);

    constexpr Mnemonic shifts[8] = {
        Mnemonic::Rol, Mnemonic::Ror, Mnemonic::Rcl, Mnemonic::Rcr,
        Mnemonic::Shl, Mnemonic::Shr, Mnemonic::Shl, Mnemonic::Sar,
    };
    for (std::size_t i = 0; i < 8; ++i) {
        g[Grp_2_Eb_Ib][i] = op(shifts[i], OpSpec::Eb, OpSpec::Ib);
        g[Grp_2_Ev_Ib][i] = op(shifts[i], OpSpec::Ev, OpSpec::Ib);
        g[Grp_2_Eb_1][i]  = op(shifts[i], OpSpec::Eb, OpSpec::One);
        g[Grp_2_Ev_1][i]  = op(shifts[i], OpSpec::Ev, OpSpec::One);
        g[Grp_2_Eb_CL][i] = op(shifts[i], OpSpec::Eb, OpSpec::CL);
        g[Grp_2_Ev_CL][i] = op(shifts[i], OpSpec::Ev, OpSpec::CL);
    }

    g[Grp_3_Eb][0] = op(Mnemonic::Test, OpSpec::Eb, OpSpec::Ib);
    g[Grp_3_Eb][1] = op(Mnemonic::Test, OpSpec::Eb, OpSpec::Ib);
    g[Grp_3_Eb][2] = op(Mnemonic::Not,  OpSpec::Eb);
    g[Grp_3_Eb][3] = op(Mnemonic::Neg,  OpSpec::Eb);
    g[Grp_3_Eb][4] = op(Mnemonic::Mul,  OpSpec::Eb);
    g[Grp_3_Eb][5] = op(Mnemonic::Imul, OpSpec::Eb);
    g[Grp_3_Eb][6] = op(Mnemonic::Div,  OpSpec::Eb);
    g[Grp_3_Eb][7] = op(Mnemonic::Idiv, OpSpec::Eb);

    g[Grp_3_Ev][0] = op(Mnemonic::Test, OpSpec::Ev, OpSpec::Iz);
    g[Grp_3_Ev][1] = op(Mnemonic::Test, OpSpec::Ev, OpSpec::Iz);
    g[Grp_3_Ev][2] = op(Mnemonic::Not,  OpSpec::Ev);
    g[Grp_3_Ev][3] = op(Mnemonic::Neg,  OpSpec::Ev);
    g[Grp_3_Ev][4] = op(Mnemonic::Mul,  OpSpec::Ev);
    g[Grp_3_Ev][5] = op(Mnemonic::Imul, OpSpec::Ev);
    g[Grp_3_Ev][6] = op(Mnemonic::Div,  OpSpec::Ev);
    g[Grp_3_Ev][7] = op(Mnemonic::Idiv, OpSpec::Ev);

    g[Grp_4][0] = op(Mnemonic::Inc, OpSpec::Eb);
    g[Grp_4][1] = op(Mnemonic::Dec, OpSpec::Eb);

    g[Grp_5][0] = op(Mnemonic::Inc,  OpSpec::Ev);
    g[Grp_5][1] = op(Mnemonic::Dec,  OpSpec::Ev);
    g[Grp_5][2] = op(Mnemonic::Call, OpSpec::Ev);
    g[Grp_5][4] = op(Mnemonic::Jmp,  OpSpec::Ev);
    g[Grp_5][6] = op(Mnemonic::Push, OpSpec::Ev);

    g[Grp_11_Eb_Ib][0] = op(Mnemonic::Mov, OpSpec::Eb, OpSpec::Ib);
    g[Grp_11_Ev_Iz][0] = op(Mnemonic::Mov, OpSpec::Ev, OpSpec::Iz);

    // Group 8: 0F BA /4..7 = BT/BTS/BTR/BTC with (Ev, Ib).
    g[Grp_8][4] = op(Mnemonic::Bt,  OpSpec::Ev, OpSpec::Ib);
    g[Grp_8][5] = op(Mnemonic::Bts, OpSpec::Ev, OpSpec::Ib);
    g[Grp_8][6] = op(Mnemonic::Btr, OpSpec::Ev, OpSpec::Ib);
    g[Grp_8][7] = op(Mnemonic::Btc, OpSpec::Ev, OpSpec::Ib);

    // SSE2 immediate-shift groups under the 66 prefix. Each row's
    // /N opcode-extension picks the actual operation; (Wx, Ib) is
    // the (xmm-from-r/m, imm8) shape. Reserved slots stay Invalid
    // so the dispatch errors instead of silently mis-decoding.
    g[Grp_71_66][2] = op(Mnemonic::Psrlw, OpSpec::Wx, OpSpec::Ib);
    g[Grp_71_66][4] = op(Mnemonic::Psraw, OpSpec::Wx, OpSpec::Ib);
    g[Grp_71_66][6] = op(Mnemonic::Psllw, OpSpec::Wx, OpSpec::Ib);

    g[Grp_72_66][2] = op(Mnemonic::Psrld, OpSpec::Wx, OpSpec::Ib);
    g[Grp_72_66][4] = op(Mnemonic::Psrad, OpSpec::Wx, OpSpec::Ib);
    g[Grp_72_66][6] = op(Mnemonic::Pslld, OpSpec::Wx, OpSpec::Ib);

    g[Grp_73_66][2] = op(Mnemonic::Psrlq,  OpSpec::Wx, OpSpec::Ib);
    g[Grp_73_66][3] = op(Mnemonic::Psrldq, OpSpec::Wx, OpSpec::Ib);
    g[Grp_73_66][6] = op(Mnemonic::Psllq,  OpSpec::Wx, OpSpec::Ib);
    g[Grp_73_66][7] = op(Mnemonic::Pslldq, OpSpec::Wx, OpSpec::Ib);

    // VEX 0F38 F3 (BMI1): the destination is vvvv.
    g[Grp_17_Vex][1] = op(Mnemonic::Blsr,   OpSpec::Hv, OpSpec::Ev);
    g[Grp_17_Vex][2] = op(Mnemonic::Blsmsk, OpSpec::Hv, OpSpec::Ev);
    g[Grp_17_Vex][3] = op(Mnemonic::Blsi,   OpSpec::Hv, OpSpec::Ev);

    return g;
}

}  // namespace

constinit const std::array<OpcodeEntry, 256> kPrimary = build_primary();
constinit const std::array<OpcodeEntry, 256> kSecondary = build_secondary();
constinit const std::array<OpcodeEntry, 256> kSecondary_66 = build_secondary_66();
constinit const std::array<OpcodeEntry, 256> kSecondary_F3 = build_secondary_f3();
constinit const std::array<OpcodeEntry, 256> kSecondary_F2 = build_secondary_f2();
constinit const std::array<OpcodeEntry, 256> kMap38 = build_map38_none();
constinit const std::array<OpcodeEntry, 256> kMap38_66 = build_map38_66();
constinit const std::array<OpcodeEntry, 256> kMap38_F2 = build_map38_f2();
constinit const std::array<OpcodeEntry, 256> kMap38_F3 = build_map38_f3();
constinit const std::array<OpcodeEntry, 256> kMap3A_66 = build_map3a_66();
constinit const std::array<OpcodeEntry, 256> kVexMap3_66 = build_vex_map3_66();
constinit const std::array<OpcodeEntry, 256> kVexMap3_F2 = build_vex_map3_f2();
constinit const std::array<OpcodeEntry, 256> kVexMap2 = build_vex_map2_none();
constinit const std::array<OpcodeEntry, 256> kVexMap2_66 = build_vex_map2_66();
constinit const std::array<OpcodeEntry, 256> kVexMap2_F3 = build_vex_map2_f3();
constinit const std::array<OpcodeEntry, 256> kVexMap2_F2 = build_vex_map2_f2();
constinit const std::array<std::array<OpcodeEntry, 8>, Grp_Count> kGroups =
    build_groups();
constinit const OpcodeEntry kVzeroupper = op(Mnemonic::Vzeroupper);

}  // namespace spelunk::x64_decode
