#pragma once

#include <optional>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>

namespace ember::ppc_decode {

struct Fields {
    u32 word = 0;

    [[nodiscard]] constexpr u32 rt() const noexcept {
        return (word >> 21) & 0x1f;
    }

    [[nodiscard]] constexpr u32 ra() const noexcept {
        return (word >> 16) & 0x1f;
    }

    [[nodiscard]] constexpr u32 rb() const noexcept {
        return (word >> 11) & 0x1f;
    }

    [[nodiscard]] constexpr u32 xo() const noexcept {
        return (word >> 1) & 0x3ff;
    }
};

[[nodiscard]] inline i64 sign_extend(u64 value, unsigned bits) noexcept {
    const u64 sign = 1ULL << (bits - 1);
    const u64 mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
}

[[nodiscard]] inline Reg ppc_gpr(u32 n) noexcept {
    return static_cast<Reg>(static_cast<unsigned>(Reg::PpcR0) + n);
}

[[nodiscard]] inline Reg ppc_fpr(u32 n) noexcept {
    return static_cast<Reg>(static_cast<unsigned>(Reg::PpcF0) + n);
}

[[nodiscard]] inline std::optional<Reg> decode_spr(u32 spr) noexcept {
    switch (spr) {
        case 1: return Reg::PpcXer;
        case 8: return Reg::PpcLr;
        case 9: return Reg::PpcCtr;
        default:
            if (spr >= 912 && spr <= 919) {
                return static_cast<Reg>(static_cast<unsigned>(Reg::PpcGqr0) +
                                        (spr - 912));
            }
            return std::nullopt;
    }
}

[[nodiscard]] inline Mem make_mem(Reg base, i64 disp, u8 size) noexcept {
    Mem mem;
    mem.base = base;
    mem.disp = disp;
    mem.has_disp = true;
    mem.size = size;
    return mem;
}

[[nodiscard]] inline Mem make_indexed_mem(Reg base, Reg index,
                                          u8 size) noexcept {
    Mem mem;
    mem.base = base;
    mem.index = index;
    mem.scale = 1;
    mem.size = size;
    return mem;
}

[[nodiscard]] inline std::optional<Mnemonic>
cond_branch_mnemonic(u32 bo, u32 bi) noexcept {
    if (bo == 12) {
        switch (bi & 0x3) {
            case 0: return Mnemonic::Blt;
            case 1: return Mnemonic::Bgt;
            case 2: return Mnemonic::Beq;
            default: break;
        }
    }
    if (bo == 4) {
        switch (bi & 0x3) {
            case 0: return Mnemonic::Bge;
            case 1: return Mnemonic::Ble;
            case 2: return Mnemonic::Bne;
            default: break;
        }
    }
    if (bo == 16) return Mnemonic::Bdnz;
    if (bo == 18) return Mnemonic::Bdz;
    return std::nullopt;
}

inline void set_cr_logical_operands(Instruction& insn, u32 word) noexcept {
    const auto cr_bit = [](u32 n) noexcept {
        return Operand::make_imm(
            Imm{static_cast<i64>(n & 0x1f), 1, false});
    };
    insn.operands[0] = cr_bit((word >> 21) & 0x1f);
    insn.operands[1] = cr_bit((word >> 16) & 0x1f);
    insn.operands[2] = cr_bit((word >> 11) & 0x1f);
    insn.num_operands = 3;
}

// Each handler owns one complete primary-opcode family. A false return means
// the family's extended opcode was not recognized; the caller then reports
// the same unsupported-opcode error as the top-level decoder.
[[nodiscard]] bool decode_paired_single(Fields fields,
                                        Instruction& insn) noexcept;
[[nodiscard]] bool decode_branch_register(Fields fields,
                                          Instruction& insn) noexcept;
[[nodiscard]] bool decode_integer_extended(Fields fields,
                                           Instruction& insn) noexcept;
[[nodiscard]] bool decode_floating_point(Fields fields, bool single,
                                         Instruction& insn) noexcept;

}  // namespace ember::ppc_decode
