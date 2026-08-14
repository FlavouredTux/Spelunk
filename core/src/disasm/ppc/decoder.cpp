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

[[nodiscard]] Operand make_cr_bit_operand(u32 n) noexcept {
    return Operand::make_imm(Imm{static_cast<i64>(n & 0x1f), 1, false});
}

void set_cr_logical_operands(Instruction& insn, u32 w) noexcept {
    insn.operands[0] = make_cr_bit_operand((w >> 21) & 0x1f);
    insn.operands[1] = make_cr_bit_operand((w >> 16) & 0x1f);
    insn.operands[2] = make_cr_bit_operand((w >> 11) & 0x1f);
    insn.num_operands = 3;
}

}  // namespace

Result<Instruction>
PpcDecoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.size() < 4) {
        return std::unexpected(Error::truncated("ppc: need 4 bytes"));
    }

    const u32 w = read_word(endian_, code.data());
    const u32 op = w >> 26;
    Instruction insn;
    insn.address = addr;
    insn.length = 4;
    insn.ppc_record = (((op == 4 || op == 20 || op == 21 || op == 31 ||
                         op == 59 || op == 63) && (w & 1u) != 0) ||
                       op == 13 || op == 28 || op == 29);
    std::copy_n(code.data(), 4, insn.raw_bytes.data());

    const u32 rt = (w >> 21) & 0x1f;
    const u32 ra = (w >> 16) & 0x1f;
    const u32 rb = (w >> 11) & 0x1f;

    switch (op) {
        case 4: {
            const u32 xo = (w >> 1) & 0x3ff;
            const u32 indexed_xo = (w >> 1) & 0x3f;
            const u32 arithmetic_xo = (w >> 1) & 0x1f;
            const Reg fc = ppc_fpr((w >> 6) & 0x1f);

            auto set_unary = [&](Mnemonic mnemonic) {
                insn.mnemonic = mnemonic;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 2;
            };
            auto set_binary = [&](Mnemonic mnemonic) {
                insn.mnemonic = mnemonic;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                insn.operands[2] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 3;
            };
            auto set_ac = [&](Mnemonic mnemonic) {
                insn.mnemonic = mnemonic;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                insn.operands[2] = Operand::make_reg(fc);
                insn.num_operands = 3;
            };
            auto set_ternary = [&](Mnemonic mnemonic) {
                insn.mnemonic = mnemonic;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                insn.operands[2] = Operand::make_reg(fc);
                insn.operands[3] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 4;
            };

            if (indexed_xo == 6 || indexed_xo == 7 ||
                indexed_xo == 38 || indexed_xo == 39) {
                const bool load = indexed_xo == 6 || indexed_xo == 38;
                const bool update = indexed_xo == 38 || indexed_xo == 39;
                insn.mnemonic = load
                    ? (update ? Mnemonic::PsqLux : Mnemonic::PsqLx)
                    : (update ? Mnemonic::PsqStux : Mnemonic::PsqStx);
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_mem(make_indexed_mem(
                    ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb),
                    ((w >> 10) & 1u) != 0 ? 4 : 8));
                insn.operands[2] = Operand::make_imm(
                    Imm{static_cast<i64>((w >> 10) & 1u), 1, false});
                insn.operands[3] = Operand::make_imm(
                    Imm{static_cast<i64>((w >> 7) & 7u), 1, false});
                insn.num_operands = 4;
                return insn;
            }

            switch (xo) {
                case 0:
                case 32:
                case 64:
                case 96:
                    insn.mnemonic = (xo == 0)  ? Mnemonic::PsCmpu0
                                  : (xo == 32) ? Mnemonic::PsCmpo0
                                  : (xo == 64) ? Mnemonic::PsCmpu1
                                               : Mnemonic::PsCmpo1;
                    insn.ppc_cr_field = static_cast<u8>((w >> 23) & 7u);
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 23) & 7u), 1, false});
                    insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 40:  set_unary(Mnemonic::PsNeg); return insn;
                case 72:  set_unary(Mnemonic::PsMr); return insn;
                case 136: set_unary(Mnemonic::PsNabs); return insn;
                case 264: set_unary(Mnemonic::PsAbs); return insn;
                case 528: set_binary(Mnemonic::PsMerge00); return insn;
                case 560: set_binary(Mnemonic::PsMerge01); return insn;
                case 592: set_binary(Mnemonic::PsMerge10); return insn;
                case 624: set_binary(Mnemonic::PsMerge11); return insn;
                case 1014:
                    insn.mnemonic = Mnemonic::DcbzL;
                    insn.operands[0] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 32));
                    insn.num_operands = 1;
                    return insn;
                default:
                    break;
            }

            switch (arithmetic_xo) {
                case 10: set_ternary(Mnemonic::PsSum0); return insn;
                case 11: set_ternary(Mnemonic::PsSum1); return insn;
                case 12: set_ac(Mnemonic::PsMuls0); return insn;
                case 13: set_ac(Mnemonic::PsMuls1); return insn;
                case 14: set_ternary(Mnemonic::PsMadds0); return insn;
                case 15: set_ternary(Mnemonic::PsMadds1); return insn;
                case 18: set_binary(Mnemonic::PsDiv); return insn;
                case 20: set_binary(Mnemonic::PsSub); return insn;
                case 21: set_binary(Mnemonic::PsAdd); return insn;
                case 23: set_ternary(Mnemonic::PsSel); return insn;
                case 24: set_unary(Mnemonic::PsRes); return insn;
                case 25: set_ac(Mnemonic::PsMul); return insn;
                case 26: set_unary(Mnemonic::PsRsqrte); return insn;
                case 28: set_ternary(Mnemonic::PsMsub); return insn;
                case 29: set_ternary(Mnemonic::PsMadd); return insn;
                case 30: set_ternary(Mnemonic::PsNmsub); return insn;
                case 31: set_ternary(Mnemonic::PsNmadd); return insn;
                default:
                    break;
            }

            insn.mnemonic = Mnemonic::PsOp4;
            insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>(w), 4, false});
            insn.num_operands = 1;
            return insn;
        }
        case 3: {
            insn.mnemonic = Mnemonic::Twi;
            insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>(rt), 1, false});
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_imm(Imm{sign_extend(w & 0xffffu, 16), 4, true});
            insn.num_operands = 3;
            return insn;
        }
        case 10:
        case 11: {
            insn.mnemonic = (op == 10) ? Mnemonic::Cmpl : Mnemonic::Cmp;
            insn.ppc_cr_field = static_cast<u8>((w >> 23) & 7u);
            const i64 imm = (op == 10) ? static_cast<i64>(w & 0xffffu)
                                       : sign_extend(w & 0xffffu, 16);
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_imm(Imm{imm, 4, op != 10});
            insn.num_operands = 2;
            return insn;
        }
        case 8: {
            insn.mnemonic = Mnemonic::Sub;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_imm(Imm{sign_extend(w & 0xffff, 16), 4, true});
            insn.operands[2] = Operand::make_reg(ppc_gpr(ra));
            insn.num_operands = 3;
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
            insn.ppc_bo = static_cast<u8>(bo);
            insn.ppc_bi = static_cast<u8>(bi);
            insn.ppc_link = lk;
            const i64 disp = sign_extend(((w >> 2) & 0x3fffu) << 2, 16);
            const addr_t target =
                aa ? static_cast<addr_t>(disp)
                   : static_cast<addr_t>(static_cast<i64>(addr) + disp);
            if (bo == 20) {
                insn.mnemonic = lk ? Mnemonic::Call : Mnemonic::Jmp;
            } else if (auto mn = cond_branch_mnemonic(bo, bi); mn) {
                insn.mnemonic = *mn;
            } else {
                insn.mnemonic = Mnemonic::Bc;
                insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>(bo), 1, false});
                insn.operands[1] = Operand::make_imm(Imm{static_cast<i64>(bi), 1, false});
                insn.operands[2] = Operand::make_rel(Rel{disp, target, 4});
                insn.num_operands = 3;
                return insn;
            }
            insn.operands[0] = Operand::make_rel(Rel{disp, target, 4});
            insn.num_operands = 1;
            return insn;
        }
        case 17:
            insn.mnemonic = Mnemonic::Sc;
            return insn;
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
                    const u32 bi = (w >> 16) & 0x1f;
                    const bool lk = (w & 1u) != 0;
                    insn.ppc_bo = static_cast<u8>(bo);
                    insn.ppc_bi = static_cast<u8>(bi);
                    insn.ppc_link = lk;
                    if (bo == 20 && !lk) {
                        insn.mnemonic = Mnemonic::Ret;
                        return insn;
                    }
                    if (bo == 20 && lk) {
                        insn.mnemonic = Mnemonic::Call;
                        insn.operands[0] = Operand::make_reg(Reg::PpcLr);
                        insn.num_operands = 1;
                        return insn;
                    }
                    insn.mnemonic = Mnemonic::Bclr;
                    insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>(bo), 1, false});
                    insn.operands[1] = Operand::make_imm(Imm{static_cast<i64>(bi), 1, false});
                    insn.num_operands = 2;
                    return insn;
                }
                case 528:
                    {
                        const u32 bo = (w >> 21) & 0x1f;
                        const u32 bi = (w >> 16) & 0x1f;
                        const bool lk = (w & 1u) != 0;
                        insn.ppc_bo = static_cast<u8>(bo);
                        insn.ppc_bi = static_cast<u8>(bi);
                        insn.ppc_link = lk;
                        if (bo == 20) {
                            insn.mnemonic = lk ? Mnemonic::Call : Mnemonic::Jmp;
                            insn.operands[0] = Operand::make_reg(Reg::PpcCtr);
                            insn.num_operands = 1;
                        } else {
                            insn.mnemonic = Mnemonic::Bcctr;
                            insn.operands[0] = Operand::make_imm(
                                Imm{static_cast<i64>(bo), 1, false});
                            insn.operands[1] = Operand::make_imm(
                                Imm{static_cast<i64>(bi), 1, false});
                            insn.num_operands = 2;
                        }
                        return insn;
                    }
                case 50:
                    insn.mnemonic = Mnemonic::Rfi;
                    return insn;
                case 150:
                    insn.mnemonic = Mnemonic::Isync;
                    return insn;
                case 33:
                case 129:
                case 193:
                case 225:
                case 257:
                case 289:
                case 417:
                case 449:
                    insn.mnemonic = (xo == 33)  ? Mnemonic::Crnor
                                  : (xo == 129) ? Mnemonic::Crandc
                                  : (xo == 193) ? Mnemonic::Crxor
                                  : (xo == 225) ? Mnemonic::Crnand
                                  : (xo == 257) ? Mnemonic::Crand
                                  : (xo == 289) ? Mnemonic::Creqv
                                  : (xo == 417) ? Mnemonic::Crorc
                                                : Mnemonic::Cror;
                    set_cr_logical_operands(insn, w);
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
        case 28:
        case 29: {
            insn.mnemonic = (op == 24) ? Mnemonic::Or
                            : (op == 25) ? Mnemonic::Or
                            : (op == 26) ? Mnemonic::Xor
                            : (op == 27) ? Mnemonic::Xor
                                          : Mnemonic::And;
            const u64 imm = (op == 25 || op == 27 || op == 29) ? ((w & 0xffffu) << 16)
                                                                : (w & 0xffffu);
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>(imm), 4, false});
            insn.num_operands = 3;
            return insn;
        }
        case 12:
        case 13: {
            insn.mnemonic = Mnemonic::Add;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_imm(Imm{sign_extend(w & 0xffffu, 16), 4, true});
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
        case 20: {
            insn.mnemonic = Mnemonic::Rlwimi;
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
                case 10:
                case 138:
                    insn.mnemonic = (xo == 10) ? Mnemonic::Addc : Mnemonic::Adde;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 60:
                case 124: {
                    insn.mnemonic = (xo == 60) ? Mnemonic::Andc : Mnemonic::Nor;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                }
                case 412:
                    insn.mnemonic = Mnemonic::Orc;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 26:
                case 922:
                case 954:
                    insn.mnemonic = (xo == 26) ? Mnemonic::Cntlzw
                                  : (xo == 922) ? Mnemonic::Extsh
                                                : Mnemonic::Extsb;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 2;
                    return insn;
                case 0:
                case 32:
                    insn.mnemonic = (xo == 32) ? Mnemonic::Cmpl : Mnemonic::Cmp;
                    insn.ppc_cr_field = static_cast<u8>((w >> 23) & 7u);
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
                case 8:
                    insn.mnemonic = Mnemonic::Subfc;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
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
                case 11:
                    insn.mnemonic = Mnemonic::Mulhw;
                    if (xo == 11) insn.mnemonic = Mnemonic::Mulhwu;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 459:
                case 491:
                    insn.mnemonic = (xo == 459) ? Mnemonic::Divwu : Mnemonic::Divw;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 136:
                    insn.mnemonic = Mnemonic::Subfe;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 202:
                    insn.mnemonic = Mnemonic::Addze;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.num_operands = 2;
                    return insn;
                case 200:
                    insn.mnemonic = Mnemonic::Subfze;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
                    insn.num_operands = 2;
                    return insn;
                case 316:
                    insn.mnemonic = Mnemonic::Xor;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
                    insn.num_operands = 3;
                    return insn;
                case 23:
                case 55:
                case 87:
                case 119:
                case 279:
                case 311:
                case 343:
                case 375: {
                    insn.mnemonic = (xo == 23)  ? Mnemonic::Lwzx
                                  : (xo == 55)  ? Mnemonic::Lwzux
                                  : (xo == 87)  ? Mnemonic::Lbzx
                                  : (xo == 119) ? Mnemonic::Lbzux
                                  : (xo == 279) ? Mnemonic::Lhzx
                                  : (xo == 311) ? Mnemonic::Lhzux
                                  : (xo == 343) ? Mnemonic::Lhax
                                                : Mnemonic::Lhaux;
                    const u8 size = (xo == 87 || xo == 119) ? 1
                                  : (xo == 279 || xo == 311 || xo == 343 || xo == 375) ? 2
                                                                                       : 4;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
                    insn.num_operands = 2;
                    return insn;
                }
                case 151:
                case 183:
                case 215:
                case 247:
                case 407:
                case 439: {
                    insn.mnemonic = (xo == 151) ? Mnemonic::Stwx
                                  : (xo == 183) ? Mnemonic::Stwux
                                  : (xo == 215) ? Mnemonic::Stbx
                                  : (xo == 247) ? Mnemonic::Stbux
                                  : (xo == 407) ? Mnemonic::Sthx
                                                : Mnemonic::Sthux;
                    const u8 size = (xo == 215 || xo == 247) ? 1
                                  : (xo == 407 || xo == 439) ? 2
                                                             : 4;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
                    insn.num_operands = 2;
                    return insn;
                }
                case 918:
                    insn.mnemonic = Mnemonic::Sthbrx;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 2));
                    insn.num_operands = 2;
                    return insn;
                case 535:
                case 567:
                case 599:
                case 631:
                case 663:
                case 695:
                case 727:
                case 759: {
                    insn.mnemonic = (xo == 535) ? Mnemonic::Lfsx
                                  : (xo == 567) ? Mnemonic::Lfsux
                                  : (xo == 599) ? Mnemonic::Lfdx
                                  : (xo == 631) ? Mnemonic::Lfdux
                                  : (xo == 663) ? Mnemonic::Stfsx
                                  : (xo == 695) ? Mnemonic::Stfsux
                                  : (xo == 727) ? Mnemonic::Stfdx
                                                : Mnemonic::Stfdux;
                    const u8 size = (xo == 535 || xo == 567 || xo == 663 || xo == 695) ? 4 : 8;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
                    insn.num_operands = 2;
                    return insn;
                }
                case 598:
                    insn.mnemonic = Mnemonic::Sync;
                    return insn;
                case 339: {
                    const u32 spr = ((w >> 16) & 0x1f) | (((w >> 11) & 0x1f) << 5);
                    auto reg = decode_spr(spr);
                    insn.mnemonic = reg ? Mnemonic::Mov : Mnemonic::Mfspr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = reg ? Operand::make_reg(*reg)
                                           : Operand::make_imm(Imm{static_cast<i64>(spr), 4, false});
                    insn.num_operands = 2;
                    return insn;
                }
                case 19:
                    insn.mnemonic = Mnemonic::Mfcr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 1;
                    return insn;
                case 144:
                    insn.mnemonic = Mnemonic::Mtcrf;
                    insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>((w >> 12) & 0xff), 1, false});
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 2;
                    return insn;
                case 83:
                    insn.mnemonic = Mnemonic::Mfmsr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 1;
                    return insn;
                case 595:
                    insn.mnemonic = Mnemonic::Mfsr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_imm(
                        Imm{static_cast<i64>(ra), 1, false});
                    insn.num_operands = 2;
                    return insn;
                case 371:
                    insn.mnemonic = Mnemonic::Mftb;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.operands[1] = Operand::make_imm(Imm{static_cast<i64>(((w >> 16) & 0x1f) | (((w >> 11) & 0x1f) << 5)), 4, false});
                    insn.num_operands = 2;
                    return insn;
                case 146:
                    insn.mnemonic = Mnemonic::Mtmsr;
                    insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 1;
                    return insn;
                case 210:
                    insn.mnemonic = Mnemonic::Mtsr;
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>(ra), 1, false});
                    insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
                    insn.num_operands = 2;
                    return insn;
                case 54:
                case 86:
                case 470:
                case 982:
                case 1014: {
                    insn.mnemonic = (xo == 54)  ? Mnemonic::Dcbst
                                  : (xo == 86)  ? Mnemonic::Dcbf
                                  : (xo == 470) ? Mnemonic::Dcbi
                                  : (xo == 982) ? Mnemonic::Icbi
                                                : Mnemonic::Dcbz;
                    insn.operands[0] = Operand::make_mem(make_indexed_mem(
                        ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 32));
                    insn.num_operands = 1;
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
                    insn.mnemonic = reg ? Mnemonic::Mov : Mnemonic::Mtspr;
                    insn.operands[0] = reg ? Operand::make_reg(*reg)
                                           : Operand::make_imm(Imm{static_cast<i64>(spr), 4, false});
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
                case 23:
                    if (!single) {
                        insn.mnemonic = Mnemonic::Fsel;
                        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                        insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                        insn.operands[2] = Operand::make_reg(ppc_fpr((w >> 6) & 0x1f));
                        insn.operands[3] = Operand::make_reg(ppc_fpr(rb));
                        insn.num_operands = 4;
                        return insn;
                    }
                    break;
                case 24:
                    if (single) {
                        insn.mnemonic = Mnemonic::Fres;
                        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                        insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                        insn.num_operands = 2;
                        return insn;
                    }
                    break;
                case 26:
                    if (!single) {
                        insn.mnemonic = Mnemonic::Frsqrte;
                        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                        insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                        insn.num_operands = 2;
                        return insn;
                    }
                    break;
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
                case 28:
                case 29:
                case 30:
                case 31: {
                    insn.mnemonic = (fp_xo == 28) ? (single ? Mnemonic::Fmsubs : Mnemonic::Fmsub)
                                  : (fp_xo == 29) ? (single ? Mnemonic::Fmadds : Mnemonic::Fmadd)
                                  : (fp_xo == 30) ? (single ? Mnemonic::Fnmsubs : Mnemonic::Fnmsub)
                                                  : (single ? Mnemonic::Fnmadds : Mnemonic::Fnmadd);
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[2] = Operand::make_reg(ppc_fpr((w >> 6) & 0x1f));
                    insn.operands[3] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 4;
                    return insn;
                }
                default:
                    break;
            }
            switch (xo) {
                case 0:
                case 32:
                    insn.mnemonic = xo == 0 ? Mnemonic::Fcmpu : Mnemonic::Fcmpo;
                    insn.ppc_cr_field = static_cast<u8>((w >> 23) & 7u);
                    insn.operands[0] = Operand::make_reg(ppc_fpr(ra));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                case 12:
                case 14:
                case 15:
                    insn.mnemonic = (xo == 12) ? Mnemonic::Frsp
                                  : (xo == 14) ? Mnemonic::Fctiw
                                               : Mnemonic::Fctiwz;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                case 40:
                case 72:
                case 136:
                case 264:
                    insn.mnemonic = (xo == 40) ? Mnemonic::Fneg
                                    : (xo == 72) ? Mnemonic::Fmr
                                    : (xo == 136) ? Mnemonic::Fnabs
                                                  : Mnemonic::Fabs;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                case 64:
                    insn.mnemonic = Mnemonic::Mcrfs;
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 23) & 0x7), 1, false});
                    insn.operands[1] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 18) & 0x7), 1, false});
                    insn.num_operands = 2;
                    return insn;
                case 583:
                    insn.mnemonic = Mnemonic::Mffs;
                    insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                    insn.num_operands = 1;
                    return insn;
                case 38:
                case 70:
                    insn.mnemonic = xo == 38 ? Mnemonic::Mtfsb1 : Mnemonic::Mtfsb0;
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>(rt), 1, false});
                    insn.num_operands = 1;
                    return insn;
                case 134:
                    insn.mnemonic = Mnemonic::Mtfsfi;
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 23) & 0x7), 1, false});
                    insn.operands[1] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 12) & 0xf), 1, false});
                    insn.num_operands = 2;
                    return insn;
                case 711:
                    insn.mnemonic = Mnemonic::Mtfsf;
                    insn.operands[0] = Operand::make_imm(
                        Imm{static_cast<i64>((w >> 17) & 0xff), 1, false});
                    insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                    insn.num_operands = 2;
                    return insn;
                default:
                    break;
            }
            insn.mnemonic = Mnemonic::FpOp;
            insn.operands[0] = Operand::make_imm(Imm{static_cast<i64>(w), 4, false});
            insn.num_operands = 1;
            return insn;
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
        case 49:
        case 50:
        case 51:
        case 52:
        case 53:
        case 54:
        case 55: {
            insn.mnemonic = (op == 48) ? Mnemonic::Lfs
                            : (op == 49) ? Mnemonic::Lfsu
                            : (op == 50) ? Mnemonic::Lfd
                            : (op == 51) ? Mnemonic::Lfdu
                            : (op == 52) ? Mnemonic::Stfs
                            : (op == 53) ? Mnemonic::Stfsu
                            : (op == 54) ? Mnemonic::Stfd
                                         : Mnemonic::Stfdu;
            const u8 size = (op == 48 || op == 49 || op == 52 || op == 53) ? 4 : 8;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0xffff, 16), size));
            insn.num_operands = 2;
            return insn;
        }
        case 46:
        case 47: {
            insn.mnemonic = (op == 46) ? Mnemonic::Lmw : Mnemonic::Stmw;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0xffffu, 16),
                                                          static_cast<u8>((32u - rt) * 4u)));
            insn.num_operands = 2;
            return insn;
        }
        case 56:
        case 57:
        case 60:
        case 61: {
            insn.mnemonic = (op == 56) ? Mnemonic::PsqL
                            : (op == 57) ? Mnemonic::PsqLu
                            : (op == 60) ? Mnemonic::PsqSt
                                         : Mnemonic::PsqStu;
            const u32 wbit = (w >> 15) & 0x1u;
            const u32 quant = (w >> 12) & 0x7u;
            const u8 size = wbit ? 4 : 8;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_mem(make_mem(ra == 0 ? Reg::None : ppc_gpr(ra),
                                                          sign_extend(w & 0x0fffu, 12), size));
            insn.operands[2] = Operand::make_imm(Imm{static_cast<i64>(wbit), 1, false});
            insn.operands[3] = Operand::make_imm(Imm{static_cast<i64>(quant), 1, false});
            insn.num_operands = 4;
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
