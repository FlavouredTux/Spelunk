#include <ember/disasm/ppc_decoder.hpp>

#include <algorithm>
#include <optional>

#include <ember/common/bytes.hpp>

namespace ember {

namespace {

[[nodiscard]] i64 sign_extend(u64 value, unsigned bits) noexcept {
    const u64 sign = 1ULL << (bits - 1);
    const u64 mask = (bits == 64) ? ~0ULL : ((1ULL << bits) - 1);
    value &= mask;
    return static_cast<i64>((value ^ sign) - sign);
}

[[nodiscard]] u32 read_word(Endian endian, const std::byte* p) noexcept {
    return endian == Endian::Big ? read_be_at<u32>(p) : read_le_at<u32>(p);
}

[[nodiscard]] Reg ppc_gpr(u32 n) noexcept {
    return static_cast<Reg>(static_cast<unsigned>(Reg::PpcR0) + n);
}

[[nodiscard]] std::optional<Reg> decode_spr(u32 spr) noexcept {
    switch (spr) {
        case 8: return Reg::PpcLr;
        case 9: return Reg::PpcCtr;
        default: return std::nullopt;
    }
}

[[nodiscard]] Mem make_mem(Reg base, i64 disp, u8 size) noexcept {
    Mem m;
    m.base = base;
    m.disp = disp;
    m.has_disp = true;
    m.size = size;
    return m;
}

[[nodiscard]] std::optional<Mnemonic>
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

}  // namespace

Result<Instruction>
PpcDecoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.size() < 4) {
        return std::unexpected(Error::truncated("ppc: need 4 bytes"));
    }

    const u32 w = read_word(endian_, code.data());
    Instruction insn;
    insn.address = addr;
    insn.length = 4;
    std::copy_n(code.data(), 4, insn.raw_bytes.data());

    const u32 op = w >> 26;
    const u32 rt = (w >> 21) & 0x1f;
    const u32 ra = (w >> 16) & 0x1f;
    const u32 rb = (w >> 11) & 0x1f;

    switch (op) {
        case 10:
        case 11: {
            insn.mnemonic = Mnemonic::Cmp;
            const i64 imm = sign_extend(w & 0xffff, 16);
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_imm(Imm{imm, 4, true});
            insn.num_operands = 2;
            return insn;
        }
        case 14:
        case 15: {
            insn.mnemonic = (op == 14) ? Mnemonic::Addi : Mnemonic::Addis;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            if (ra != 0) {
                insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                insn.operands[2] = Operand::make_imm(Imm{sign_extend(w & 0xffff, 16), 4, true});
                insn.num_operands = 3;
            } else {
                insn.operands[1] = Operand::make_imm(Imm{sign_extend(w & 0xffff, 16), 4, true});
                insn.num_operands = 2;
            }
            return insn;
        }
        case 16: {
            const u32 bo = (w >> 21) & 0x1f;
            const u32 bi = (w >> 16) & 0x1f;
            const bool aa = ((w >> 1) & 1u) != 0;
            const bool lk = (w & 1u) != 0;
            const i64 disp = sign_extend(((w >> 2) & 0x3fffu) << 2, 16);
            const addr_t target =
                aa ? static_cast<addr_t>(disp)
                   : static_cast<addr_t>(static_cast<i64>(addr) + disp);
            if (bo == 20) {
                insn.mnemonic = lk ? Mnemonic::Call : Mnemonic::Jmp;
            } else if (auto mn = cond_branch_mnemonic(bo, bi); mn) {
                insn.mnemonic = *mn;
            } else {
                return std::unexpected(Error::unsupported("ppc: unsupported bc form"));
            }
            insn.operands[0] = Operand::make_rel(Rel{disp, target, 4});
            insn.num_operands = 1;
            return insn;
        }
        case 18: {
            const bool aa = ((w >> 1) & 1u) != 0;
            const bool lk = (w & 1u) != 0;
            const i64 disp = sign_extend(((w >> 2) & 0x00ffffffu) << 2, 26);
            const addr_t target =
                aa ? static_cast<addr_t>(disp)
                   : static_cast<addr_t>(static_cast<i64>(addr) + disp);
            insn.mnemonic = lk ? Mnemonic::Call : Mnemonic::Jmp;
            insn.operands[0] = Operand::make_rel(Rel{disp, target, 4});
            insn.num_operands = 1;
            return insn;
        }
        case 19: {
            const u32 xo = (w >> 1) & 0x3ff;
            switch (xo) {
                case 16: {
                    const u32 bo = (w >> 21) & 0x1f;
                    const bool lk = (w & 1u) != 0;
                    if (bo == 20 && !lk) {
                        insn.mnemonic = Mnemonic::Ret;
                        return insn;
                    }
                    return std::unexpected(Error::unsupported("ppc: unsupported bclr form"));
                }
                case 528:
                    insn.mnemonic = (w & 1u) ? Mnemonic::Call : Mnemonic::Jmp;
                    insn.operands[0] = Operand::make_reg(Reg::PpcCtr);
                    insn.num_operands = 1;
                    return insn;
                default:
                    break;
            }
            break;
        }
        case 24:
        case 25:
        case 26:
        case 28: {
            insn.mnemonic = (op == 24) ? Mnemonic::Or
                            : (op == 25) ? Mnemonic::Or
                            : (op == 26) ? Mnemonic::Xor
                                         : Mnemonic::And;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            if (ra != 0) insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[ra == 0 ? 1 : 2] =
                Operand::make_imm(Imm{static_cast<i64>(w & 0xffffu), 4, false});
            insn.num_operands = (ra == 0) ? 2 : 3;
            return insn;
        }
        case 31: {
            const u32 xo = (w >> 1) & 0x3ff;
            switch (xo) {
                case 0:
                case 32:
                    insn.mnemonic = Mnemonic::Cmp;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 2;
                    return insn;
                case 266:
                    insn.mnemonic = Mnemonic::Add;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 40:
                    insn.mnemonic = Mnemonic::Sub;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rb));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(ra));
                    insn.num_operands = 3;
                    return insn;
                case 339: {
                    const u32 spr = ((w >> 16) & 0x1f) | (((w >> 11) & 0x1f) << 5);
                    auto reg = decode_spr(spr);
                    if (!reg) return std::unexpected(Error::unsupported("ppc: unsupported mfspr"));
                    insn.mnemonic = Mnemonic::Mov;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(*reg);
                    insn.num_operands = 2;
                    return insn;
                }
                case 444:
                    insn.mnemonic = Mnemonic::Mov;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 2;
                    if (rt != rb) {
                        insn.mnemonic = Mnemonic::Or;
                        insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                        insn.num_operands = 3;
                    }
                    return insn;
                case 467: {
                    const u32 spr = ((w >> 16) & 0x1f) | (((w >> 11) & 0x1f) << 5);
                    auto reg = decode_spr(spr);
                    if (!reg) return std::unexpected(Error::unsupported("ppc: unsupported mtspr"));
                    insn.mnemonic = Mnemonic::Mov;
                    insn.operands[0] = Operand::make_reg(*reg);
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 2;
                    return insn;
                }
                default:
                    break;
            }
            break;
        }
        case 32:
        case 36: {
            insn.mnemonic = (op == 32) ? Mnemonic::Lwz : Mnemonic::Stw;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0xffff, 16), 4));
            insn.num_operands = 2;
            return insn;
        }
        case 58:
        case 62: {
            insn.mnemonic = (op == 58) ? Mnemonic::Ld : Mnemonic::Std;
            const i64 disp = sign_extend(((w >> 2) & 0x3fffu) << 2, 16);
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          disp, 8));
            insn.num_operands = 2;
            return insn;
        }
        default:
            break;
    }

    return std::unexpected(Error::unsupported("ppc: unsupported opcode"));
}

}  // namespace ember
