#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <format>
#include <span>
#include <type_traits>

#include <spelunk/common/bytes.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>

namespace spelunk::x64_decode {

enum class OpSpec : u8 {
    None,
    Eb, Ev, Ew, Ed, Edq, M,
    Gb, Gv, Gw,
    // GPR from ModR/M.reg, 32-bit unless REX.W: the 66 prefix sizes only
    // the other operand (CRC32's destination).
    Gdq,
    Ib, Iw, Iz, Iv,
    Ibsext,
    Jb, Jz,
    AL, RAX, CL, Ob, Ov,
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
    // xmm register or 2-byte memory (pmovsxbq / pmovzxbq / wq sources).
    Ww,
    // 32-bit GPR from r/m, or byte / word memory (pextrb, pinsrb, pextrw).
    RdMb, RdMw,
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

struct Context {
    std::span<const std::byte> code{};
    std::size_t pos  = 0;
    PrefixSet   prefix{};
    bool rex_present = false;
    bool rex_w = false;
    bool rex_r = false;
    bool rex_x = false;
    bool rex_b = false;
    bool vex_r2 = false;
    bool vex_b2 = false;
    bool vex = false;
    bool evex = false;
    u8 vex_map = 0;
    u8 vex_pp = 0;
    u8 vex_vvvv = 0;
    u8 vector_bytes = 16;
    u8 vector_mask = 0;
    bool vector_zeroing = false;
    bool vector_broadcast = false;
    bool default_64 = false;
    bool mode64 = true;
    u8 opcode = 0;
    u8 opcode_low3 = 0;
    u8 modrm = 0;

    [[nodiscard]] bool eof() const noexcept { return pos >= code.size(); }

    [[nodiscard]] unsigned opsize() const noexcept {
        if (default_64) return prefix.opsize ? 2u : 8u;
        if (rex_w) return 8;
        if (prefix.opsize) return 2;
        return 4;
    }
    [[nodiscard]] unsigned address_size() const noexcept {
        return mode64 ? (prefix.addrsize ? 4u : 8u)
                      : (prefix.addrsize ? 2u : 4u);
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

[[nodiscard]] bool parse_legacy_prefix(Context& ctx, u8 b) noexcept;

[[nodiscard]] Result<Operand>
decode_modrm_rm(Context& ctx, unsigned size, bool mem_only) noexcept;

[[nodiscard]] Result<Operand>
decode_operand(Context& ctx, OpSpec spec, addr_t insn_addr) noexcept;

[[nodiscard]] Result<Instruction>
decode_x87_escape(Context& ctx, addr_t addr) noexcept;

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
// Legacy three-byte maps 0F 38 / 0F 3A (SSSE3, SSE4.x, AES-NI, CRC32).
extern const std::array<OpcodeEntry, 256> kMap38;
extern const std::array<OpcodeEntry, 256> kMap38_66;
extern const std::array<OpcodeEntry, 256> kMap38_F2;
extern const std::array<OpcodeEntry, 256> kMap3A_66;
extern const std::array<OpcodeEntry, 256> kVexMap2;
extern const std::array<OpcodeEntry, 256> kVexMap2_66;
extern const std::array<OpcodeEntry, 256> kVexMap2_F3;
extern const std::array<OpcodeEntry, 256> kVexMap2_F2;
extern const std::array<std::array<OpcodeEntry, 8>, Grp_Count> kGroups;
extern const OpcodeEntry kVzeroupper;

}  // namespace spelunk::x64_decode
