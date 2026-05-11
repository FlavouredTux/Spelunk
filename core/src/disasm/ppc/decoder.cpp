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

[[nodiscard]] Reg ppc_fpr(u32 n) noexcept {
    return static_cast<Reg>(static_cast<unsigned>(Reg::PpcF0) + n);
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

[[nodiscard]] Mem make_indexed_mem(Reg base, Reg index, u8 size) noexcept {
    Mem m;
    m.base = base;
    m.index = index;
    m.scale = 1;
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
        case 7: {
            insn.mnemonic = Mnemonic::Mulli;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_imm(Imm{sign_extend(w & 0xffff, 16), 4, true});
            insn.num_operands = 3;
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
                case 449:
                    insn.mnemonic = Mnemonic::Cror;
                    insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>((w >> 21) & 0x1f), 1, false});
                    insn.operands[1] = Operand::make_imm(Imm{static_cast<i64>((w >> 16) & 0x1f), 1, false});
                    insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>((w >> 11) & 0x1f), 1, false});
                    insn.num_operands = 3;
                    return insn;
                default:
                    break;
            }
            break;
        }
        case 24:
        case 25:
        case 26:
        case 27:
        case 28: {
            insn.mnemonic = (op == 24) ? Mnemonic::Or
                            : (op == 25) ? Mnemonic::Or
                            : (op == 26) ? Mnemonic::Xor
                            : (op == 27) ? Mnemonic::Xor
                                          : Mnemonic::And;
            const u64 imm = (op == 25 || op == 27) ? ((w & 0xffffu) << 16) : (w & 0xffffu);
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>(imm), 4, false});
            insn.num_operands = 3;
            return insn;
        }
        case 21: {
            insn.mnemonic = Mnemonic::Rlwinm;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>((w >> 11) & 0x1f), 1, false});
            insn.operands[3] = Operand::make_imm(Imm{static_cast<i64>((w >> 6) & 0x1f), 1, false});
            insn.operands[4] = Operand::make_imm(Imm{static_cast<i64>((w >> 1) & 0x1f), 1, false});
            insn.num_operands = 5;
            return insn;
        }
        case 31: {
            const u32 xo = (w >> 1) & 0x3ff;
            switch (xo) {
                case 24:
                    insn.mnemonic = Mnemonic::Shl;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 28:
                    insn.mnemonic = Mnemonic::And;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
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
                case 104:
                    insn.mnemonic = Mnemonic::Neg;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.num_operands = 2;
                    return insn;
                case 235:
                    insn.mnemonic = Mnemonic::Mul;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 75:
                    insn.mnemonic = Mnemonic::Mulhw;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 316:
                    insn.mnemonic = Mnemonic::Xor;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 23:
                case 87:
                case 279:
                case 343: {
                    insn.mnemonic = (xo == 23) ? Mnemonic::Lwzx
                                    : (xo == 87) ? Mnemonic::Lbzx
                                    : (xo == 279) ? Mnemonic::Lhzx
                                                  : Mnemonic::Lhax;
                    const u8 size = (xo == 87) ? 1 : (xo == 279 || xo == 343) ? 2 : 4;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
                    insn.num_operands = 2;
                    return insn;
                }
                case 151:
                case 215:
                case 407: {
                    insn.mnemonic = (xo == 151) ? Mnemonic::Stwx
                                    : (xo == 215) ? Mnemonic::Stbx
                                                  : Mnemonic::Sthx;
                    const u8 size = (xo == 215) ? 1 : (xo == 407) ? 2 : 4;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
                    insn.num_operands = 2;
                    return insn;
                }
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
                case 19:
                    insn.mnemonic = Mnemonic::Mfcr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 1;
                    return insn;
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
                case 536:
                    insn.mnemonic = Mnemonic::Shr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 792:
                    insn.mnemonic = Mnemonic::Sar;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 824:
                    insn.mnemonic = Mnemonic::Sar;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>(rb), 1, false});
                    insn.num_operands = 3;
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
        case 59:
        case 63: {
            const u32 xo = (w >> 1) & 0x3ff;
            const u32 fp_xo = (w >> 1) & 0x1f;
            const bool single = op == 59;
            switch (fp_xo) {
                case 18:
                case 20:
                case 21: {
                    insn.mnemonic = (xo == 18) ? (single ? Mnemonic::Fdivs : Mnemonic::Fdiv)
                                    : (xo == 20) ? (single ? Mnemonic::Fsubs : Mnemonic::Fsub)
                                                 : (single ? Mnemonic::Fadds : Mnemonic::Fadd);
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 3;
                    return insn;
                }
                case 25: {
                    insn.mnemonic = single ? Mnemonic::Fmuls : Mnemonic::Fmul;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_fpr((w >> 6) & 0x1f));
                    insn.num_operands = 3;
                    return insn;
                }
                default:
                    break;
            }
            switch (xo) {
                case 0:
                case 32:
                    insn.mnemonic = xo == 0 ? Mnemonic::Fcmpu : Mnemonic::Fcmpo;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                case 40:
                case 72:
                case 264:
                    insn.mnemonic = (xo == 40) ? Mnemonic::Fneg
                                    : (xo == 72) ? Mnemonic::Fmr
                                                 : Mnemonic::Fabs;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                default:
                    break;
            }
            break;
        }
        case 32:
        case 33:
        case 34:
        case 35:
        case 36:
        case 37:
        case 38:
        case 39:
        case 40:
        case 41:
        case 42:
        case 43:
        case 44:
        case 45: {
            insn.mnemonic = (op == 32) ? Mnemonic::Lwz
                            : (op == 33) ? Mnemonic::Lwzu
                            : (op == 34) ? Mnemonic::Lbz
                            : (op == 35) ? Mnemonic::Lbzu
                            : (op == 36) ? Mnemonic::Stw
                            : (op == 37) ? Mnemonic::Stwu
                            : (op == 38) ? Mnemonic::Stb
                            : (op == 39) ? Mnemonic::Stbu
                            : (op == 40) ? Mnemonic::Lhz
                            : (op == 41) ? Mnemonic::Lhzu
                            : (op == 42) ? Mnemonic::Lha
                            : (op == 43) ? Mnemonic::Lhau
                            : (op == 44) ? Mnemonic::Sth
                                          : Mnemonic::Sthu;
            const u8 size = (op == 34 || op == 35 || op == 38 || op == 39) ? 1
                          : (op == 40 || op == 41 || op == 42 || op == 43 || op == 44 || op == 45) ? 2
                                                                                                    : 4;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0xffff, 16), size));
            insn.num_operands = 2;
            return insn;
        }
        case 48:
        case 50:
        case 52:
        case 54: {
            insn.mnemonic = (op == 48) ? Mnemonic::Lfs
                            : (op == 50) ? Mnemonic::Lfd
                            : (op == 52) ? Mnemonic::Stfs
                                         : Mnemonic::Stfd;
            const u8 size = (op == 48 || op == 52) ? 4 : 8;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0xffff, 16), size));
            insn.num_operands = 2;
            return insn;
        }
        case 58:
        case 62: {
            const u32 xo = w & 0x3u;
            if (op == 58) {
                if (xo == 0) insn.mnemonic = Mnemonic::Ld;
                else if (xo == 1) insn.mnemonic = Mnemonic::Ldu;
                else if (xo == 2) insn.mnemonic = Mnemonic::Lwa;
                else return std::unexpected(Error::unsupported("ppc: unsupported ld form"));
            } else {
                if (xo == 0) insn.mnemonic = Mnemonic::Std;
                else if (xo == 1) insn.mnemonic = Mnemonic::Stdu;
                else return std::unexpected(Error::unsupported("ppc: unsupported std form"));
            }
            const i64 disp = sign_extend(((w >> 2) & 0x3fffu) << 2, 16);
            const u8 size = (insn.mnemonic == Mnemonic::Lwa) ? 4 : 8;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          disp, size));
            insn.num_operands = 2;
            return insn;
        }
        default:
            break;
    }

    return std::unexpected(Error::unsupported("ppc: unsupported opcode"));
}

}  // namespace ember
