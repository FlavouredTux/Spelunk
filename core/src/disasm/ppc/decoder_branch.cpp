#include "decoder_internal.hpp"

namespace ember::ppc_decode {

bool decode_branch_register(Fields fields, Instruction& insn) noexcept {
    const u32 w = fields.word;
    const u32 xo = fields.xo();

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
                return true;
            }
            if (bo == 20 && lk) {
                insn.mnemonic = Mnemonic::Call;
                insn.operands[0] = Operand::make_reg(Reg::PpcLr);
                insn.num_operands = 1;
                return true;
            }
            insn.mnemonic = Mnemonic::Bclr;
            insn.operands[0] = Operand::make_imm(
                Imm{static_cast<i64>(bo), 1, false});
            insn.operands[1] = Operand::make_imm(
                Imm{static_cast<i64>(bi), 1, false});
            insn.num_operands = 2;
            return true;
        }
        case 528: {
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
            return true;
        }
        case 50:
            insn.mnemonic = Mnemonic::Rfi;
            return true;
        case 150:
            insn.mnemonic = Mnemonic::Isync;
            return true;
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
            return true;
        default:
            return false;
    }
}

}  // namespace ember::ppc_decode
