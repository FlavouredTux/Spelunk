#include "decoder_internal.hpp"

namespace ember::ppc_decode {

bool decode_floating_point(Fields fields, bool single,
                           Instruction& insn) noexcept {
    const u32 w = fields.word;
    const u32 rt = fields.rt();
    const u32 ra = fields.ra();
    const u32 rb = fields.rb();
    const u32 xo = fields.xo();
    const u32 fp_xo = (w >> 1) & 0x1f;

    switch (fp_xo) {
        case 23:
            if (!single) {
                insn.mnemonic = Mnemonic::Fsel;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
                insn.operands[2] = Operand::make_reg(
                    ppc_fpr((w >> 6) & 0x1f));
                insn.operands[3] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 4;
                return true;
            }
            break;
        case 24:
            if (single) {
                insn.mnemonic = Mnemonic::Fres;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 2;
                return true;
            }
            break;
        case 26:
            if (!single) {
                insn.mnemonic = Mnemonic::Frsqrte;
                insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
                insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
                insn.num_operands = 2;
                return true;
            }
            break;
        case 18:
        case 20:
        case 21:
            insn.mnemonic = (xo == 18)
                ? (single ? Mnemonic::Fdivs : Mnemonic::Fdiv)
                : (xo == 20)
                    ? (single ? Mnemonic::Fsubs : Mnemonic::Fsub)
                    : (single ? Mnemonic::Fadds : Mnemonic::Fadd);
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_fpr(rb));
            insn.num_operands = 3;
            return true;
        case 25:
            insn.mnemonic = single ? Mnemonic::Fmuls : Mnemonic::Fmul;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
            insn.operands[2] = Operand::make_reg(
                ppc_fpr((w >> 6) & 0x1f));
            insn.num_operands = 3;
            return true;
        case 28:
        case 29:
        case 30:
        case 31:
            insn.mnemonic = (fp_xo == 28)
                ? (single ? Mnemonic::Fmsubs : Mnemonic::Fmsub)
                : (fp_xo == 29)
                    ? (single ? Mnemonic::Fmadds : Mnemonic::Fmadd)
                    : (fp_xo == 30)
                        ? (single ? Mnemonic::Fnmsubs : Mnemonic::Fnmsub)
                        : (single ? Mnemonic::Fnmadds : Mnemonic::Fnmadd);
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
            insn.operands[2] = Operand::make_reg(
                ppc_fpr((w >> 6) & 0x1f));
            insn.operands[3] = Operand::make_reg(ppc_fpr(rb));
            insn.num_operands = 4;
            return true;
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
            return true;
        case 12:
        case 14:
        case 15:
            insn.mnemonic = (xo == 12) ? Mnemonic::Frsp
                          : (xo == 14) ? Mnemonic::Fctiw
                                       : Mnemonic::Fctiwz;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
            insn.num_operands = 2;
            return true;
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
            return true;
        case 64:
            insn.mnemonic = Mnemonic::Mcrfs;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 23) & 0x7), 1, false});
            insn.operands[1] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 18) & 0x7), 1, false});
            insn.num_operands = 2;
            return true;
        case 583:
            insn.mnemonic = Mnemonic::Mffs;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.num_operands = 1;
            return true;
        case 38:
        case 70:
            insn.mnemonic = xo == 38 ? Mnemonic::Mtfsb1 : Mnemonic::Mtfsb0;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>(rt), 1, false});
            insn.num_operands = 1;
            return true;
        case 134:
            insn.mnemonic = Mnemonic::Mtfsfi;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 23) & 0x7), 1, false});
            insn.operands[1] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 12) & 0xf), 1, false});
            insn.num_operands = 2;
            return true;
        case 711:
            insn.mnemonic = Mnemonic::Mtfsf;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 17) & 0xff), 1, false});
            insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
            insn.num_operands = 2;
            return true;
        default:
            break;
    }

    insn.mnemonic = Mnemonic::FpOp;
    insn.operands[0] = Operand::make_imm(
        Imm{static_cast<i64>(w), 4, false});
    insn.num_operands = 1;
    return true;
}

}  // namespace ember::ppc_decode
