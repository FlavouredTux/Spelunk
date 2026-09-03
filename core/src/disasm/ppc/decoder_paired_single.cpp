#include "decoder_internal.hpp"

namespace ember::ppc_decode {

bool decode_paired_single(Fields fields, Instruction& insn) noexcept {
    const u32 w = fields.word;
    const u32 rt = fields.rt();
    const u32 ra = fields.ra();
    const u32 rb = fields.rb();
    const u32 xo = fields.xo();
    const u32 indexed_xo = (w >> 1) & 0x3f;
    const u32 arithmetic_xo = (w >> 1) & 0x1f;
    const Reg fc = ppc_fpr((w >> 6) & 0x1f);

    const auto set_unary = [&](Mnemonic mnemonic) {
        insn.mnemonic = mnemonic;
        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
        insn.operands[1] = Operand::make_reg(ppc_fpr(rb));
        insn.num_operands = 2;
    };
    const auto set_binary = [&](Mnemonic mnemonic) {
        insn.mnemonic = mnemonic;
        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
        insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
        insn.operands[2] = Operand::make_reg(ppc_fpr(rb));
        insn.num_operands = 3;
    };
    const auto set_ac = [&](Mnemonic mnemonic) {
        insn.mnemonic = mnemonic;
        insn.operands[0] = Operand::make_reg(ppc_fpr(rt));
        insn.operands[1] = Operand::make_reg(ppc_fpr(ra));
        insn.operands[2] = Operand::make_reg(fc);
        insn.num_operands = 3;
    };
    const auto set_ternary = [&](Mnemonic mnemonic) {
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
        return true;
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
            return true;
        case 40:  set_unary(Mnemonic::PsNeg); return true;
        case 72:  set_unary(Mnemonic::PsMr); return true;
        case 136: set_unary(Mnemonic::PsNabs); return true;
        case 264: set_unary(Mnemonic::PsAbs); return true;
        case 528: set_binary(Mnemonic::PsMerge00); return true;
        case 560: set_binary(Mnemonic::PsMerge01); return true;
        case 592: set_binary(Mnemonic::PsMerge10); return true;
        case 624: set_binary(Mnemonic::PsMerge11); return true;
        case 1014:
            insn.mnemonic = Mnemonic::DcbzL;
            insn.operands[0] = Operand::make_mem(make_indexed_mem(
                ra == 0 ? Reg::None : ppc_gpr(ra), ppc_gpr(rb), 32));
            insn.num_operands = 1;
            return true;
        default:
            break;
    }

    switch (arithmetic_xo) {
        case 10: set_ternary(Mnemonic::PsSum0); return true;
        case 11: set_ternary(Mnemonic::PsSum1); return true;
        case 12: set_ac(Mnemonic::PsMuls0); return true;
        case 13: set_ac(Mnemonic::PsMuls1); return true;
        case 14: set_ternary(Mnemonic::PsMadds0); return true;
        case 15: set_ternary(Mnemonic::PsMadds1); return true;
        case 18: set_binary(Mnemonic::PsDiv); return true;
        case 20: set_binary(Mnemonic::PsSub); return true;
        case 21: set_binary(Mnemonic::PsAdd); return true;
        case 23: set_ternary(Mnemonic::PsSel); return true;
        case 24: set_unary(Mnemonic::PsRes); return true;
        case 25: set_ac(Mnemonic::PsMul); return true;
        case 26: set_unary(Mnemonic::PsRsqrte); return true;
        case 28: set_ternary(Mnemonic::PsMsub); return true;
        case 29: set_ternary(Mnemonic::PsMadd); return true;
        case 30: set_ternary(Mnemonic::PsNmsub); return true;
        case 31: set_ternary(Mnemonic::PsNmadd); return true;
        default:
            break;
    }

    insn.mnemonic = Mnemonic::PsOp4;
    insn.operands[0] = Operand::make_imm(
        Imm{static_cast<i64>(w), 4, false});
    insn.num_operands = 1;
    return true;
}

}  // namespace ember::ppc_decode
