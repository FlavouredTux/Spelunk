#include "decoder_internal.hpp"

namespace ember::ppc_decode {

bool decode_integer_extended(Fields fields, Instruction& insn) noexcept {
    const u32 w = fields.word;
    const u32 rt = fields.rt();
    const u32 ra = fields.ra();
    const u32 rb = fields.rb();
    const u32 xo = fields.xo();

    switch (xo) {
        case 24:
            insn.mnemonic = Mnemonic::Shl;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 28:
            insn.mnemonic = Mnemonic::And;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 10:
        case 138:
            insn.mnemonic = (xo == 10) ? Mnemonic::Addc : Mnemonic::Adde;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 60:
        case 124:
            insn.mnemonic = (xo == 60) ? Mnemonic::Andc : Mnemonic::Nor;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 412:
            insn.mnemonic = Mnemonic::Orc;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 26:
        case 922:
        case 954:
            insn.mnemonic = (xo == 26) ? Mnemonic::Cntlzw
                          : (xo == 922) ? Mnemonic::Extsh
                                        : Mnemonic::Extsb;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 2;
            return true;
        case 0:
        case 32:
            insn.mnemonic = (xo == 32) ? Mnemonic::Cmpl : Mnemonic::Cmp;
            insn.ppc_cr_field = static_cast<u8>((w >> 23) & 7u);
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 2;
            return true;
        case 266:
            insn.mnemonic = Mnemonic::Add;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 40:
            insn.mnemonic = Mnemonic::Sub;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rb));
            insn.operands[2] = Operand::make_reg(ppc_gpr(ra));
            insn.num_operands = 3;
            return true;
        case 8:
            insn.mnemonic = Mnemonic::Subfc;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 104:
            insn.mnemonic = Mnemonic::Neg;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.num_operands = 2;
            return true;
        case 235:
            insn.mnemonic = Mnemonic::Mul;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 75:
        case 11:
            insn.mnemonic = Mnemonic::Mulhw;
            if (xo == 11) insn.mnemonic = Mnemonic::Mulhwu;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 459:
        case 491:
            insn.mnemonic = (xo == 459) ? Mnemonic::Divwu : Mnemonic::Divw;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 136:
            insn.mnemonic = Mnemonic::Subfe;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 202:
            insn.mnemonic = Mnemonic::Addze;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.num_operands = 2;
            return true;
        case 200:
            insn.mnemonic = Mnemonic::Subfze;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_reg(ppc_gpr(ra));
            insn.num_operands = 2;
            return true;
        case 316:
            insn.mnemonic = Mnemonic::Xor;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
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
                          : (xo == 279 || xo == 311 ||
                             xo == 343 || xo == 375) ? 2
                                                     : 4;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_indexed_mem(
                ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
            insn.num_operands = 2;
            return true;
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
            return true;
        }
        case 918:
            insn.mnemonic = Mnemonic::Sthbrx;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_mem(make_indexed_mem(
                ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 2));
            insn.num_operands = 2;
            return true;
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
            const u8 size = (xo == 535 || xo == 567 ||
                             xo == 663 || xo == 695) ? 4 : 8;
            insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
            insn.operands[1] = Operand::make_mem(make_indexed_mem(
                ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), size));
            insn.num_operands = 2;
            return true;
        }
        case 598:
            insn.mnemonic = Mnemonic::Sync;
            return true;
        case 339: {
            const u32 spr = ((w >> 16) & 0x1f) |
                            (((w >> 11) & 0x1f) << 5);
            const auto reg = decode_spr(spr);
            insn.mnemonic = reg ? Mnemonic::Mov : Mnemonic::Mfspr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = reg
                ? Operand::make_reg(*reg)
                : Operand::make_imm(
                      Imm{static_cast<i64>(spr), 4, false});
            insn.num_operands = 2;
            return true;
        }
        case 19:
            insn.mnemonic = Mnemonic::Mfcr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 1;
            return true;
        case 144:
            insn.mnemonic = Mnemonic::Mtcrf;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>((w >> 12) & 0xff), 1, false});
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 2;
            return true;
        case 83:
            insn.mnemonic = Mnemonic::Mfmsr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 1;
            return true;
        case 595:
            insn.mnemonic = Mnemonic::Mfsr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_imm(
                Imm{static_cast<i64>(ra), 1, false});
            insn.num_operands = 2;
            return true;
        case 371:
            insn.mnemonic = Mnemonic::Mftb;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[1] = Operand::make_imm(Imm{
                static_cast<i64>(((w >> 16) & 0x1f) |
                                 (((w >> 11) & 0x1f) << 5)),
                4, false});
            insn.num_operands = 2;
            return true;
        case 146:
            insn.mnemonic = Mnemonic::Mtmsr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 1;
            return true;
        case 210:
            insn.mnemonic = Mnemonic::Mtsr;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>(ra), 1, false});
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 2;
            return true;
        case 54:
        case 86:
        case 470:
        case 982:
        case 1014:
            insn.mnemonic = (xo == 54)  ? Mnemonic::Dcbst
                          : (xo == 86)  ? Mnemonic::Dcbf
                          : (xo == 470) ? Mnemonic::Dcbi
                          : (xo == 982) ? Mnemonic::Icbi
                                        : Mnemonic::Dcbz;
            insn.operands[0] = Operand::make_mem(make_indexed_mem(
                ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 32));
            insn.num_operands = 1;
            return true;
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
            return true;
        case 536:
            insn.mnemonic = Mnemonic::Shr;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 792:
            insn.mnemonic = Mnemonic::Sar;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_reg(ppc_gpr(rb));
            insn.num_operands = 3;
            return true;
        case 824:
            insn.mnemonic = Mnemonic::Sar;
            insn.operands[0] = Operand::make_reg(ppc_gpr(ra));
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.operands[2] = Operand::make_imm(
                Imm{static_cast<i64>(rb), 1, false});
            insn.num_operands = 3;
            return true;
        case 467: {
            const u32 spr = ((w >> 16) & 0x1f) |
                            (((w >> 11) & 0x1f) << 5);
            const auto reg = decode_spr(spr);
            insn.mnemonic = reg ? Mnemonic::Mov : Mnemonic::Mtspr;
            insn.operands[0] = reg
                ? Operand::make_reg(*reg)
                : Operand::make_imm(
                      Imm{static_cast<i64>(spr), 4, false});
            insn.operands[1] = Operand::make_reg(ppc_gpr(rt));
            insn.num_operands = 2;
            return true;
        }
        default:
            return false;
    }
}

}  // namespace ember::ppc_decode
