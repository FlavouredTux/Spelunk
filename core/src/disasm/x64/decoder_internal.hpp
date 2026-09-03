#pragma once

#include <array>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember::x64_decode {

enum class OpSpec : u8 {
    None,
    Eb, Ev, Ew, Ed, Edq, M,
    Gb, Gv, Gw,
    Ib, Iw, Iz, Iv,
    Ibsext,
    Jb, Jz,
    AL, RAX, CL,
    One,
    Zb, Zv,
    // SSE xmm register from ModR/M.reg field (with REX.R extension).
    Vx,
    // VEX/EVEX non-destructive first source from the encoded inverted vvvv
    // field. The selected XMM/YMM/ZMM width comes from the prefix.
    Hx,
    // VEX vvvv interpreted as a general-purpose register (BMI/BMI2).
    Hv,
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
    OpSpec   op4      = OpSpec::None;
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

extern const std::array<OpcodeEntry, 256> kPrimary;
extern const std::array<OpcodeEntry, 256> kSecondary;
extern const std::array<OpcodeEntry, 256> kSecondary_66;
extern const std::array<OpcodeEntry, 256> kSecondary_F3;
extern const std::array<OpcodeEntry, 256> kSecondary_F2;
extern const std::array<OpcodeEntry, 256> kVexMap2;
extern const std::array<OpcodeEntry, 256> kVexMap2_66;
extern const std::array<OpcodeEntry, 256> kVexMap2_F3;
extern const std::array<OpcodeEntry, 256> kVexMap2_F2;
extern const std::array<std::array<OpcodeEntry, 8>, Grp_Count> kGroups;
extern const OpcodeEntry kVzeroupper;

}  // namespace ember::x64_decode

