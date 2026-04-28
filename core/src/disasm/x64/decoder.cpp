#include <ember/disasm/x64_decoder.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <format>
#include <type_traits>

#include <ember/common/bytes.hpp>

namespace ember {

namespace {

// ============================================================================
// Opcode table types
// ============================================================================

enum class OpSpec : u8 {
    None,
    Eb, Ev, Ew, Ed, M,
    Gb, Gv, Gw,
    Ib, Iw, Iz, Iv,
    Ibsext,
    Jb, Jz,
    AL, RAX, CL,
    One,
    Zb, Zv,
    // SSE xmm register from ModR/M.reg field (with REX.R extension).
    Vx,
    // SSE xmm register or 128-bit memory from ModR/M.r/m. Used for packed
    // (SIMD) instructions that read a full 128-bit operand.
    Wx,
    // Scalar-FP forms: xmm register or 4-byte / 8-byte memory from r/m.
    // Emitted for `movss`/`addss`/... (32-bit scalar single) and
    // `movsd`/`addsd`/... (64-bit scalar double).
    Wss, Wsd,
};

struct OpcodeEntry {
    Mnemonic mnemonic = Mnemonic::Invalid;
    OpSpec   op1      = OpSpec::None;
    OpSpec   op2      = OpSpec::None;
    OpSpec   op3      = OpSpec::None;
    u8       group    = 0;
    bool     modrm    = false;
};

enum GroupId : u8 {
    Grp_None = 0,
    Grp_1_Eb_Ib,
    Grp_1_Ev_Iz,
    Grp_1_Ev_Ibs,
    Grp_1A,
    Grp_2_Eb_Ib, Grp_2_Ev_Ib,
    Grp_2_Eb_1,  Grp_2_Ev_1,
    Grp_2_Eb_CL, Grp_2_Ev_CL,
    Grp_3_Eb, Grp_3_Ev,
    Grp_4, Grp_5,
    Grp_11_Eb_Ib, Grp_11_Ev_Iz,
    Grp_8,
    // SSE2 immediate-shift groups: 0x66 0x0F 71/72/73 with /N opcode
    // extension select psllw/pslld/psllq/pslldq, psrlw/psrld/psrlq/
    // psrldq, psraw/psrad over the (xmm-from-r/m, imm8) shape.
    Grp_71_66, Grp_72_66, Grp_73_66,
    Grp_Count,
};

constexpr OpcodeEntry op(Mnemonic m,
                         OpSpec o1 = OpSpec::None,
                         OpSpec o2 = OpSpec::None,
                         OpSpec o3 = OpSpec::None,
                         bool modrm = false) noexcept {
    return {m, o1, o2, o3, 0, modrm};
}

constexpr OpcodeEntry grp(GroupId g) noexcept {
    return {Mnemonic::Invalid, OpSpec::None, OpSpec::None, OpSpec::None,
            static_cast<u8>(g), true};
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
    t[0x98] = op(Mnemonic::Cwde);
    t[0x99] = op(Mnemonic::Cdq);

    // String ops: no explicit operands (implicit rdi/rsi/rcx/rax, direction
    // flag). The "w"-sized (0x66-prefixed) variants aren't emitted; the -b
    // / default / -q variants cover the vast majority of real code.
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
    t[0xF6] = grp(Grp_3_Eb);
    t[0xF7] = grp(Grp_3_Ev);
    t[0xFE] = grp(Grp_4);
    t[0xFF] = grp(Grp_5);

    return t;
}

// ============================================================================
// Secondary opcode table (0x0F-escaped)
// ============================================================================

constexpr std::array<OpcodeEntry, 256> build_secondary() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x05] = op(Mnemonic::Syscall);
    t[0x0B] = op(Mnemonic::Ud2);
    t[0x1F] = op(Mnemonic::Nop, OpSpec::Ev, OpSpec::None, OpSpec::None, true);

    // SSE1: packed-float moves (no mandatory prefix).
    t[0x10] = op(Mnemonic::Movups,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovupsStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0x12] = op(Mnemonic::Movlps,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x16] = op(Mnemonic::Movhps,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
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

    // CMovCC: 0x0F 4x — Gv, Ev. Indexed in condition order (o/no/b/ae/…).
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

    // SetCC: 0x0F 9x — Eb (byte destination).
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
    t[0x6E] = op(Mnemonic::Movd,        OpSpec::Vx, OpSpec::Ed, OpSpec::None, true);
    t[0x6F] = op(Mnemonic::Movdqa,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x70] = op(Mnemonic::Pshufd,      OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);
    t[0x74] = op(Mnemonic::Pcmpeqb,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x75] = op(Mnemonic::Pcmpeqw,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x76] = op(Mnemonic::Pcmpeqd,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7E] = op(Mnemonic::MovdStore,   OpSpec::Ed, OpSpec::Vx, OpSpec::None, true);
    t[0x7F] = op(Mnemonic::MovdqaStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0xD4] = op(Mnemonic::Paddq,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xD6] = op(Mnemonic::MovqStore,   OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    t[0xD7] = op(Mnemonic::Pmovmskb,    OpSpec::Gv, OpSpec::Vx, OpSpec::None, true);
    t[0xDA] = op(Mnemonic::Pminub,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDB] = op(Mnemonic::Pand,        OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xDF] = op(Mnemonic::Pandn,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEB] = op(Mnemonic::Por,         OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xEF] = op(Mnemonic::Pxor,        OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFC] = op(Mnemonic::Paddb,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xFE] = op(Mnemonic::Paddd,       OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0xC4] = op(Mnemonic::Pinsrw,      OpSpec::Vx, OpSpec::Ev, OpSpec::Ib,   true);
    // 0x71/72/73 are opcode-extension groups — the ModR/M reg field
    // selects the actual psllX/psrlX/psraX variant.
    t[0x71] = grp(Grp_71_66);
    t[0x72] = grp(Grp_72_66);
    t[0x73] = grp(Grp_73_66);
    return t;
}

constexpr std::array<OpcodeEntry, 256> build_secondary_f3() noexcept {
    std::array<OpcodeEntry, 256> t{};
    // Scalar single-precision.
    t[0x10] = op(Mnemonic::MovssLoad,   OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovssStore,  OpSpec::Wss, OpSpec::Vx, OpSpec::None, true);
    t[0x2A] = op(Mnemonic::Cvtsi2ss,    OpSpec::Vx, OpSpec::Ev,  OpSpec::None, true);
    t[0x2C] = op(Mnemonic::Cvttss2si,   OpSpec::Gv, OpSpec::Wss, OpSpec::None, true);
    t[0x2E] = op(Mnemonic::Ucomiss,     OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x51] = op(Mnemonic::Sqrtss,      OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x58] = op(Mnemonic::Addss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x59] = op(Mnemonic::Mulss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5A] = op(Mnemonic::Cvtss2sd,    OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5C] = op(Mnemonic::Subss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5D] = op(Mnemonic::Minss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5E] = op(Mnemonic::Divss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    t[0x5F] = op(Mnemonic::Maxss,       OpSpec::Vx, OpSpec::Wss, OpSpec::None, true);
    // Existing packed-integer SSE2 entries.
    t[0x6F] = op(Mnemonic::Movdqu,      OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x70] = op(Mnemonic::Pshufhw,     OpSpec::Vx, OpSpec::Wx, OpSpec::Ib,   true);
    t[0x7E] = op(Mnemonic::MovqXmm,     OpSpec::Vx, OpSpec::Wx, OpSpec::None, true);
    t[0x7F] = op(Mnemonic::MovdquStore, OpSpec::Wx, OpSpec::Vx, OpSpec::None, true);
    return t;
}

// 0xF2 mandatory prefix: scalar double-precision.
constexpr std::array<OpcodeEntry, 256> build_secondary_f2() noexcept {
    std::array<OpcodeEntry, 256> t{};
    t[0x10] = op(Mnemonic::MovsdXmm,      OpSpec::Vx,  OpSpec::Wsd, OpSpec::None, true);
    t[0x11] = op(Mnemonic::MovsdXmmStore, OpSpec::Wsd, OpSpec::Vx,  OpSpec::None, true);
    t[0x2A] = op(Mnemonic::Cvtsi2sd,      OpSpec::Vx,  OpSpec::Ev,  OpSpec::None, true);
    t[0x2C] = op(Mnemonic::Cvttsd2si,     OpSpec::Gv,  OpSpec::Wsd, OpSpec::None, true);
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

    return g;
}

constexpr auto kPrimary      = build_primary();
constexpr auto kSecondary    = build_secondary();
constexpr auto kSecondary_66 = build_secondary_66();
constexpr auto kSecondary_F3 = build_secondary_f3();
constexpr auto kSecondary_F2 = build_secondary_f2();
constexpr auto kGroups       = build_groups();

// ============================================================================
// Register lookup tables
// ============================================================================

constexpr Reg kGpr8Legacy[8] = {
    Reg::Al, Reg::Cl, Reg::Dl, Reg::Bl,
    Reg::Ah, Reg::Ch, Reg::Dh, Reg::Bh,
};
constexpr Reg kGpr8Rex[16] = {
    Reg::Al,  Reg::Cl,  Reg::Dl,  Reg::Bl,
    Reg::Spl, Reg::Bpl, Reg::Sil, Reg::Dil,
    Reg::R8b, Reg::R9b, Reg::R10b, Reg::R11b,
    Reg::R12b, Reg::R13b, Reg::R14b, Reg::R15b,
};
constexpr Reg kGpr16[16] = {
    Reg::Ax, Reg::Cx, Reg::Dx, Reg::Bx,
    Reg::Sp, Reg::Bp, Reg::Si, Reg::Di,
    Reg::R8w, Reg::R9w, Reg::R10w, Reg::R11w,
    Reg::R12w, Reg::R13w, Reg::R14w, Reg::R15w,
};
constexpr Reg kGpr32[16] = {
    Reg::Eax, Reg::Ecx, Reg::Edx, Reg::Ebx,
    Reg::Esp, Reg::Ebp, Reg::Esi, Reg::Edi,
    Reg::R8d, Reg::R9d, Reg::R10d, Reg::R11d,
    Reg::R12d, Reg::R13d, Reg::R14d, Reg::R15d,
};
constexpr Reg kGpr64[16] = {
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
};

[[nodiscard]] constexpr Reg gpr(u8 idx, unsigned size, bool rex_present) noexcept {
    idx &= 0xF;
    switch (size) {
        case 1: return rex_present ? kGpr8Rex[idx] : (idx < 8 ? kGpr8Legacy[idx] : Reg::None);
        case 2: return kGpr16[idx];
        case 4: return kGpr32[idx];
        case 8: return kGpr64[idx];
        default: return Reg::None;
    }
}

// ============================================================================
// Decode context
// ============================================================================

struct Context {
    std::span<const std::byte> code{};
    std::size_t pos  = 0;
    addr_t      addr = 0;
    PrefixSet   prefix{};
    bool rex_present = false;
    bool rex_w = false;
    bool rex_r = false;
    bool rex_x = false;
    bool rex_b = false;
    bool default_64 = false;
    u8 opcode = 0;
    u8 opcode_low3 = 0;
    u8 modrm = 0;
    bool have_modrm = false;

    [[nodiscard]] bool eof() const noexcept { return pos >= code.size(); }

    [[nodiscard]] unsigned opsize() const noexcept {
        if (default_64) return prefix.opsize ? 2u : 8u;
        if (rex_w) return 8;
        if (prefix.opsize) return 2;
        return 4;
    }

    [[nodiscard]] Result<u8> read_u8() noexcept {
        if (pos >= code.size()) {
            return std::unexpected(Error::truncated("x64: truncated opcode stream"));
        }
        return static_cast<u8>(code[pos++]);
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] Result<T> read_le() noexcept {
        if (pos > code.size() || code.size() - pos < sizeof(T)) {
            return std::unexpected(Error::truncated(std::format(
                "x64: truncated {}-byte operand at pos {:#x}", sizeof(T), pos)));
        }
        const T v = read_le_at<T>(code.data() + pos);
        pos += sizeof(T);
        return v;
    }
};

// ============================================================================
// Decoding helpers
// ============================================================================

[[nodiscard]] bool parse_legacy_prefix(Context& ctx, u8 b) noexcept {
    switch (b) {
        case 0x26: ctx.prefix.segment  = Reg::Es; return true;
        case 0x2E: ctx.prefix.segment  = Reg::Cs; return true;
        case 0x36: ctx.prefix.segment  = Reg::Ss; return true;
        case 0x3E: ctx.prefix.segment  = Reg::Ds; return true;
        case 0x64: ctx.prefix.segment  = Reg::Fs; return true;
        case 0x65: ctx.prefix.segment  = Reg::Gs; return true;
        case 0x66: ctx.prefix.opsize   = true;    return true;
        case 0x67: ctx.prefix.addrsize = true;    return true;
        case 0xF0: ctx.prefix.lock     = true;    return true;
        case 0xF2: ctx.prefix.repne    = true;    return true;
        case 0xF3: ctx.prefix.rep      = true;    return true;
        default:   return false;
    }
}

[[nodiscard]] Result<Operand>
decode_modrm_rm(Context& ctx, unsigned size, bool mem_only) noexcept {
    const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
    const u8 rm  = static_cast<u8>( ctx.modrm & 7);
    const u8 rm_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | rm);

    if (mod == 3) {
        if (mem_only) {
            return std::unexpected(Error::invalid_format(
                "x64: memory operand required but ModR/M.mod=3"));
        }
        return Operand::make_reg(gpr(rm_ext, size, ctx.rex_present));
    }

    Mem m;
    m.size    = static_cast<u8>(size);
    m.segment = ctx.prefix.segment;

    if (rm == 4) {
        auto sib_r = ctx.read_u8();
        if (!sib_r) return std::unexpected(std::move(sib_r).error());
        const u8 sib         = *sib_r;
        const u8 scale_bits  = static_cast<u8>((sib >> 6) & 3);
        const u8 index_bits  = static_cast<u8>((sib >> 3) & 7);
        const u8 base_bits   = static_cast<u8>( sib & 7);
        const u8 index_ext   = static_cast<u8>((ctx.rex_x ? 8u : 0u) | index_bits);
        const u8 base_ext    = static_cast<u8>((ctx.rex_b ? 8u : 0u) | base_bits);

        if (!(index_bits == 4 && !ctx.rex_x)) {
            m.index = gpr(index_ext, 8, /*rex_present=*/true);
            m.scale = static_cast<u8>(1u << scale_bits);
        }

        if (mod == 0 && base_bits == 5) {
            auto d = ctx.read_le<u32>();
            if (!d) return std::unexpected(std::move(d).error());
            m.disp = static_cast<i64>(static_cast<i32>(*d));
            m.has_disp = true;
        } else {
            m.base = gpr(base_ext, 8, /*rex_present=*/true);
        }
    } else if (mod == 0 && rm == 5) {
        auto d = ctx.read_le<u32>();
        if (!d) return std::unexpected(std::move(d).error());
        m.base = Reg::Rip;
        m.disp = static_cast<i64>(static_cast<i32>(*d));
        m.has_disp = true;
    } else {
        m.base = gpr(rm_ext, 8, /*rex_present=*/true);
    }

    if (mod == 1) {
        auto d = ctx.read_le<u8>();
        if (!d) return std::unexpected(std::move(d).error());
        m.disp += static_cast<i64>(static_cast<i8>(*d));
        m.has_disp = true;
    } else if (mod == 2) {
        auto d = ctx.read_le<u32>();
        if (!d) return std::unexpected(std::move(d).error());
        m.disp += static_cast<i64>(static_cast<i32>(*d));
        m.has_disp = true;
    }

    return Operand::make_mem(m);
}

[[nodiscard]] Result<Imm>
read_imm(Context& ctx, unsigned size, unsigned sign_ext_to, bool signed_val) noexcept {
    i64 value = 0;
    switch (size) {
        case 1: {
            auto v = ctx.read_le<u8>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i8>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 2: {
            auto v = ctx.read_le<u16>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i16>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 4: {
            auto v = ctx.read_le<u32>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i32>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 8: {
            auto v = ctx.read_le<u64>();
            if (!v) return std::unexpected(std::move(v).error());
            value = static_cast<i64>(*v);
            break;
        }
        default:
            return std::unexpected(Error::invalid_format("x64: bad immediate size"));
    }
    Imm imm;
    imm.value     = value;
    imm.size      = static_cast<u8>(sign_ext_to != 0 ? sign_ext_to : size);
    imm.is_signed = signed_val;
    return imm;
}

[[nodiscard]] Result<Operand>
decode_rel(Context& ctx, unsigned size, addr_t insn_addr) noexcept {
    i64 off = 0;
    switch (size) {
        case 1: {
            auto v = ctx.read_le<u8>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i8>(*v));
            break;
        }
        case 2: {
            auto v = ctx.read_le<u16>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i16>(*v));
            break;
        }
        case 4: {
            auto v = ctx.read_le<u32>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i32>(*v));
            break;
        }
        default:
            return std::unexpected(Error::invalid_format("x64: bad relative size"));
    }
    Rel r;
    r.offset = off;
    r.size   = static_cast<u8>(size);
    r.target = insn_addr + static_cast<u64>(ctx.pos) + static_cast<u64>(off);
    return Operand::make_rel(r);
}

[[nodiscard]] unsigned iz_size(const Context& ctx) noexcept {
    return (ctx.opsize() == 2) ? 2 : 4;
}

[[nodiscard]] Result<Operand>
decode_operand(Context& ctx, OpSpec spec, addr_t insn_addr) noexcept {
    const unsigned os = ctx.opsize();
    switch (spec) {
        case OpSpec::None: return Operand{};

        case OpSpec::Gb: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, 1, ctx.rex_present));
        }
        case OpSpec::Gv: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, os, ctx.rex_present));
        }
        case OpSpec::Gw: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, 2, ctx.rex_present));
        }

        case OpSpec::Eb: return decode_modrm_rm(ctx, 1,  false);
        case OpSpec::Ev: return decode_modrm_rm(ctx, os, false);
        case OpSpec::Ew: return decode_modrm_rm(ctx, 2,  false);
        case OpSpec::Ed: return decode_modrm_rm(ctx, 4,  false);
        case OpSpec::M:  return decode_modrm_rm(ctx, os, true);

        case OpSpec::Ib: {
            auto imm = read_imm(ctx, 1, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iw: {
            auto imm = read_imm(ctx, 2, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iz: {
            auto imm = read_imm(ctx, iz_size(ctx), 0, true);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iv: {
            auto imm = read_imm(ctx, os, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Ibsext: {
            auto imm = read_imm(ctx, 1, os, true);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }

        case OpSpec::Jb: return decode_rel(ctx, 1, insn_addr);
        case OpSpec::Jz: return decode_rel(ctx, (os == 2) ? 2 : 4, insn_addr);

        case OpSpec::AL:  return Operand::make_reg(Reg::Al);
        case OpSpec::CL:  return Operand::make_reg(Reg::Cl);
        case OpSpec::RAX: {
            const Reg r = (os == 8) ? Reg::Rax : (os == 2 ? Reg::Ax : Reg::Eax);
            return Operand::make_reg(r);
        }

        case OpSpec::One: {
            Imm imm;
            imm.value     = 1;
            imm.size      = 1;
            imm.is_signed = false;
            return Operand::make_imm(imm);
        }

        case OpSpec::Zb: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | ctx.opcode_low3);
            return Operand::make_reg(gpr(reg_ext, 1, ctx.rex_present));
        }
        case OpSpec::Zv: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | ctx.opcode_low3);
            return Operand::make_reg(gpr(reg_ext, os, ctx.rex_present));
        }

        case OpSpec::Vx: {
            // Xmm register from ModR/M.reg. REX.R extends to Xmm8..15.
            const u8 reg_ext =
                static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(static_cast<Reg>(
                static_cast<u8>(Reg::Xmm0) + reg_ext));
        }
        case OpSpec::Wx: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(static_cast<Reg>(
                    static_cast<u8>(Reg::Xmm0) + rm_ext));
            }
            return decode_modrm_rm(ctx, /*size=*/16, /*mem_only=*/true);
        }
        case OpSpec::Wss: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(static_cast<Reg>(
                    static_cast<u8>(Reg::Xmm0) + rm_ext));
            }
            return decode_modrm_rm(ctx, /*size=*/4, /*mem_only=*/true);
        }
        case OpSpec::Wsd: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(static_cast<Reg>(
                    static_cast<u8>(Reg::Xmm0) + rm_ext));
            }
            return decode_modrm_rm(ctx, /*size=*/8, /*mem_only=*/true);
        }
    }
    return std::unexpected(Error::not_implemented("x64: unhandled operand spec"));
}

[[nodiscard]] constexpr bool is_default_64(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Push:
        case Mnemonic::Pop:
        case Mnemonic::Call:
        case Mnemonic::Jmp:
        case Mnemonic::Ret:
        case Mnemonic::Leave:
        case Mnemonic::Jo:  case Mnemonic::Jno: case Mnemonic::Jb:  case Mnemonic::Jae:
        case Mnemonic::Je:  case Mnemonic::Jne: case Mnemonic::Jbe: case Mnemonic::Ja:
        case Mnemonic::Js:  case Mnemonic::Jns: case Mnemonic::Jp:  case Mnemonic::Jnp:
        case Mnemonic::Jl:  case Mnemonic::Jge: case Mnemonic::Jle: case Mnemonic::Jg:
            return true;
        default:
            return false;
    }
}

void promote_size_sensitive_mnemonics(const Context& ctx, Instruction& insn) noexcept {
    if (insn.mnemonic == Mnemonic::Cwde && ctx.opsize() == 8) {
        insn.mnemonic = Mnemonic::Cdqe;
    } else if (insn.mnemonic == Mnemonic::Cdq && ctx.opsize() == 8) {
        insn.mnemonic = Mnemonic::Cqo;
    }
    // 64-bit promotion for the default-sized string ops (REX.W).
    if (ctx.opsize() == 8) {
        switch (insn.mnemonic) {
            case Mnemonic::Movsd: insn.mnemonic = Mnemonic::Movsq; break;
            case Mnemonic::Cmpsd: insn.mnemonic = Mnemonic::Cmpsq; break;
            case Mnemonic::Stosd: insn.mnemonic = Mnemonic::Stosq; break;
            case Mnemonic::Lodsd: insn.mnemonic = Mnemonic::Lodsq; break;
            case Mnemonic::Scasd: insn.mnemonic = Mnemonic::Scasq; break;
            default: break;
        }
    }
}

}  // anonymous namespace

Result<Instruction>
X64Decoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.empty()) {
        return std::unexpected(Error::truncated("x64: empty code buffer"));
    }

    Context ctx;
    ctx.code = code;
    ctx.addr = addr;

    while (!ctx.eof()) {
        const u8 b = static_cast<u8>(ctx.code[ctx.pos]);
        if (!parse_legacy_prefix(ctx, b)) break;
        ++ctx.pos;
        if (ctx.pos >= 14) {
            return std::unexpected(Error::invalid_format(
                "x64: more than 14 prefix bytes"));
        }
    }

    if (!ctx.eof()) {
        const u8 b = static_cast<u8>(ctx.code[ctx.pos]);
        if ((b & 0xF0) == 0x40) {
            ctx.rex_present = true;
            ctx.rex_w = (b & 0x8) != 0;
            ctx.rex_r = (b & 0x4) != 0;
            ctx.rex_x = (b & 0x2) != 0;
            ctx.rex_b = (b & 0x1) != 0;
            ++ctx.pos;
        }
    }

    auto op0_r = ctx.read_u8();
    if (!op0_r) return std::unexpected(std::move(op0_r).error());
    u8 opcode = *op0_r;

    const OpcodeEntry* entry = nullptr;
    if (opcode == 0x0F) {
        auto op1_r = ctx.read_u8();
        if (!op1_r) return std::unexpected(std::move(op1_r).error());
        opcode = *op1_r;
        ctx.opcode = opcode;
        ctx.opcode_low3 = static_cast<u8>(opcode & 7);

        if (opcode == 0x1E && ctx.prefix.rep && !ctx.eof()) {
            const u8 m = static_cast<u8>(ctx.code[ctx.pos]);
            if (m == 0xFA || m == 0xFB) {
                ++ctx.pos;
                Instruction insn;
                insn.address  = addr;
                insn.mnemonic = (m == 0xFA) ? Mnemonic::Endbr64 : Mnemonic::Endbr32;
                ctx.prefix.rep = false;
                insn.prefixes = ctx.prefix;
                insn.length   = static_cast<u8>(ctx.pos);
                std::memcpy(insn.raw_bytes.data(), code.data(),
                            std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
                return insn;
            }
        }

        // Mandatory-prefix dispatch: 0x66 / 0xF3 / 0xF2 before 0x0F select
        // SSE secondary tables. Consuming the prefix for dispatch means we
        // shouldn't also interpret it as opsize/rep — clear the bit.
        // Either a real mnemonic OR a group entry (mnemonic=Invalid,
        // group!=0 — opcode-extension dispatch) counts as "the 66 table
        // owns this opcode".
        const auto has_entry = [](const OpcodeEntry& e) {
            return e.mnemonic != Mnemonic::Invalid || e.group != 0;
        };
        entry = &kSecondary[opcode];
        if (ctx.prefix.opsize && has_entry(kSecondary_66[opcode])) {
            entry = &kSecondary_66[opcode];
            ctx.prefix.opsize = false;
        } else if (ctx.prefix.rep && has_entry(kSecondary_F3[opcode])) {
            entry = &kSecondary_F3[opcode];
            ctx.prefix.rep = false;
        } else if (ctx.prefix.repne && has_entry(kSecondary_F2[opcode])) {
            entry = &kSecondary_F2[opcode];
            ctx.prefix.repne = false;
        }
    } else {
        ctx.opcode = opcode;
        ctx.opcode_low3 = static_cast<u8>(opcode & 7);
        entry = &kPrimary[opcode];
    }

    if (entry->mnemonic == Mnemonic::Invalid && entry->group == 0) {
        return std::unexpected(Error::not_implemented(std::format(
            "x64: unsupported opcode {:#04x} at {:#x}", opcode, addr)));
    }

    if (entry->modrm) {
        auto m_r = ctx.read_u8();
        if (!m_r) return std::unexpected(std::move(m_r).error());
        ctx.modrm = *m_r;
        ctx.have_modrm = true;
    }

    if (entry->group != 0) {
        const u8 reg = static_cast<u8>((ctx.modrm >> 3) & 7);
        entry = &kGroups[entry->group][reg];
        if (entry->mnemonic == Mnemonic::Invalid) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: reserved group entry (opcode {:#04x}, /{}) at {:#x}",
                ctx.opcode, reg, addr)));
        }
    }

    Instruction insn;
    insn.address  = addr;
    insn.mnemonic = entry->mnemonic;
    insn.prefixes = ctx.prefix;

    ctx.default_64 = is_default_64(entry->mnemonic);

    const OpSpec specs[3] = {entry->op1, entry->op2, entry->op3};
    for (std::size_t i = 0; i < 3; ++i) {
        if (specs[i] == OpSpec::None) break;
        auto o = decode_operand(ctx, specs[i], addr);
        if (!o) return std::unexpected(std::move(o).error());
        insn.operands[i] = *o;
        insn.num_operands = static_cast<u8>(i + 1);
    }

    promote_size_sensitive_mnemonics(ctx, insn);

    insn.length = static_cast<u8>(ctx.pos);
    std::memcpy(insn.raw_bytes.data(), code.data(),
                std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
    return insn;
}

}  // namespace ember
