#include <algorithm>
#include <cstddef>
#include <expected>
#include <span>

#include <ember/binary/arch.hpp>
#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/ppc_decoder.hpp>
#include <ember/disasm/register.hpp>

#include "decoder_internal.hpp"

namespace ember {

namespace {

using ppc_decode::cond_branch_mnemonic;
using ppc_decode::make_mem;
using ppc_decode::ppc_fpr;
using ppc_decode::ppc_gpr;
using ppc_decode::sign_extend;

[[nodiscard]] u32 read_word(Endian endian, const std::byte* p) noexcept {
    return endian == Endian::Big ? read_be_at<u32>(p) : read_le_at<u32>(p);
}

}  // namespace

Result<Instruction>
PpcDecoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.size() < 4) {
        return std::unexpected(Error::truncated("ppc: need 4 bytes"));
    }

    const u32 w = read_word(endian_, code.data());
    const u32 op = w >> 26;
    const ppc_decode::Fields fields{w};
    Instruction insn;
    insn.address = addr;
    insn.length = 4;
    insn.ppc_record = (((op == 4 || op == 20 || op == 21 || op == 31 ||
                         op == 59 || op == 63) && (w & 1u) != 0) ||
                       op == 13 || op == 28 || op == 29);
    std::copy_n(code.data(), 4, insn.raw_bytes.data());

    const u32 rt = fields.rt();
    const u32 ra = fields.ra();

    switch (op) {
        case 4:
            if (ppc_decode::decode_paired_single(fields, insn)) {
                return insn;
            }
            break;
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
        case 19:
            if (ppc_decode::decode_branch_register(fields, insn)) {
                return insn;
            }
            break;
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
        case 31:
            if (ppc_decode::decode_integer_extended(fields, insn)) {
                return insn;
            }
            break;
        case 59:
        case 63:
            if (ppc_decode::decode_floating_point(fields, op == 59, insn)) {
                return insn;
            }
            break;
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
