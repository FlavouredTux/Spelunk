#include "ppc_decoder_test_support.hpp"

namespace ppc_decoder_test {

void test_fp_unary_forms() {
    auto insn = must_decode(fp_unary_word(1, 2, 12));  // frsp f1, f2
    check_eq(insn.mnemonic, spelunk::Mnemonic::Frsp, "frsp mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcF1, "frsp frt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF2, "frsp frb");

    insn = must_decode(fp_unary_word(3, 4, 14));  // fctiw f3, f4
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fctiw, "fctiw mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcF3, "fctiw frt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF4, "fctiw frb");

    insn = must_decode(fp_unary_word(5, 6, 15));  // fctiwz f5, f6
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fctiwz, "fctiwz mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcF5, "fctiwz frt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF6, "fctiwz frb");

    insn = must_decode(fp_a_word(59, 7, 0, 8, 0, 24));  // fres f7, f8
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fres, "fres mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcF7, "fres frt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF8, "fres frb");

    insn = must_decode(fp_a_word(63, 9, 0, 10, 0, 26));  // frsqrte f9, f10
    check_eq(insn.mnemonic, spelunk::Mnemonic::Frsqrte, "frsqrte mnemonic");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF10, "frsqrte frb");

    insn = must_decode(fp_unary_word(11, 12, 136));  // fnabs f11, f12
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fnabs, "fnabs mnemonic");

    insn = must_decode(fp_unary_word(13, 0, 583));  // mffs f13
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mffs, "mffs mnemonic");
    check_eq(insn.num_operands, std::uint8_t{1}, "mffs operands");
}

void test_fp_fused_forms() {
    auto insn = must_decode(0xEC0100BA);  // fmadds f0, f1, f2, f0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fmadds, "fmadds mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcF0, "fmadds frt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF1, "fmadds fra");
    check_eq(insn.operands[2].reg, spelunk::Reg::PpcF2, "fmadds frc");
    check_eq(insn.operands[3].reg, spelunk::Reg::PpcF0, "fmadds frb");

    insn = must_decode(0xFC0110BA);  // fmadd f0, f1, f2, f2
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fmadd, "fmadd mnemonic");

    insn = must_decode(fp_a_word(63, 3, 4, 5, 6, 23));  // fsel f3, f4, f6, f5
    check_eq(insn.mnemonic, spelunk::Mnemonic::Fsel, "fsel mnemonic");
    check_eq(spelunk::format_instruction(insn), std::string{"fsel f3, f4, f6, f5"},
             "fsel operand order");
}

void test_fp_status_forms() {
    auto insn = must_decode((63u << 26) | (3u << 23) | (5u << 18) | (64u << 1));
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mcrfs, "mcrfs mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{3}, "mcrfs crfd");
    check_eq(insn.operands[1].imm.value, std::int64_t{5}, "mcrfs crfs");

    insn = must_decode((63u << 26) | (17u << 21) | (38u << 1));
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtfsb1, "mtfsb1 mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{17}, "mtfsb1 bit");

    insn = must_decode((63u << 26) | (2u << 23) | (0xau << 12) | (134u << 1));
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtfsfi, "mtfsfi mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{2}, "mtfsfi crfd");
    check_eq(insn.operands[1].imm.value, std::int64_t{0xa}, "mtfsfi imm");

    insn = must_decode((63u << 26) | (0xa5u << 17) | (14u << 11) | (711u << 1));
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtfsf, "mtfsf mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{0xa5}, "mtfsf mask");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcF14, "mtfsf frb");
}

void test_floating_point_lifter_forms() {
    auto ir = lift_one(fp_a_word(59, 3, 4, 5, 6, 29));  // fmadds f3, f4, f6, f5
    bool saw_fused_mul = false;
    bool saw_fused_add = false;
    bool saw_fused_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_fused_mul |= inst.op == spelunk::IrOp::Mul &&
                         inst.dst.type == spelunk::IrType::F32 &&
                         inst.srcs[0].reg == spelunk::Reg::PpcF4 &&
                         inst.srcs[1].reg == spelunk::Reg::PpcF6;
        saw_fused_add |= inst.op == spelunk::IrOp::Add &&
                         inst.dst.type == spelunk::IrType::F32 &&
                         inst.srcs[1].reg == spelunk::Reg::PpcF5;
        saw_fused_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                               inst.name == "ppc.fmadds";
    }
    check_eq(saw_fused_mul && saw_fused_add && !saw_fused_intrinsic, true,
             "fmadds lifts to typed multiply-add dataflow");

    ir = lift_one(fp_a_word(59, 3, 4, 5, 6, 30));  // fnmsubs f3, f4, f6, f5
    bool saw_fused_sub = false;
    bool saw_fused_neg = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_fused_sub |= inst.op == spelunk::IrOp::Sub &&
                         inst.dst.type == spelunk::IrType::F32;
        saw_fused_neg |= inst.op == spelunk::IrOp::Neg &&
                         inst.dst.type == spelunk::IrType::F32;
    }
    check_eq(saw_fused_sub && saw_fused_neg, true,
             "fnmsubs lifts subtract and final negation");

    ir = lift_one(fp_unary_word(3, 4, 12));  // frsp f3, f4
    bool saw_frsp_round = false;
    bool saw_frsp_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_frsp_round |= inst.op == spelunk::IrOp::Trunc &&
                          inst.dst.type == spelunk::IrType::F32 &&
                          inst.srcs[0].type == spelunk::IrType::F64 &&
                          inst.srcs[0].reg == spelunk::Reg::PpcF4;
        saw_frsp_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                              inst.name == "ppc.frsp";
    }
    check_eq(saw_frsp_round && !saw_frsp_intrinsic, true,
             "frsp lifts as an explicit float rounding cast");

    ir = lift_one(fp_unary_word(5, 6, 15));  // fctiwz f5, f6
    bool saw_fctiwz_cast = false;
    bool saw_fctiwz_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_fctiwz_cast |= inst.op == spelunk::IrOp::FpToInt &&
                           inst.dst.type == spelunk::IrType::I32 &&
                           inst.srcs[0].type == spelunk::IrType::F64 &&
                           inst.srcs[0].reg == spelunk::Reg::PpcF6;
        saw_fctiwz_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                                inst.name == "ppc.fctiwz";
    }
    check_eq(saw_fctiwz_cast && !saw_fctiwz_intrinsic, true,
             "fctiwz lifts as an explicit signed integer cast");

    // fctiwz f0,f1; stfd f0,8(r1); lwz r4,12(r1)
    ir = lift_words({fp_unary_word(0, 1, 15), 0xD8010008, 0x8081000C});
    bool saw_spill_store = false;
    bool saw_spill_load = false;
    bool saw_direct_gpr = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_spill_store |= inst.op == spelunk::IrOp::Store;
        saw_spill_load |= inst.op == spelunk::IrOp::Load;
        saw_direct_gpr |= inst.op == spelunk::IrOp::Assign &&
                          inst.dst.kind == spelunk::IrValueKind::Reg &&
                          inst.dst.reg == spelunk::Reg::PpcR4 &&
                          inst.srcs[0].type == spelunk::IrType::I32;
    }
    check_eq(saw_direct_gpr && !saw_spill_store && !saw_spill_load, true,
             "fctiwz stack extraction folds directly into the destination GPR");

    ir = lift_one(fp_a_word(63, 3, 4, 5, 6, 23));
    bool saw_fsel = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_fsel |= inst.op == spelunk::IrOp::Intrinsic && inst.name == "ppc.fsel" &&
                    inst.dst.kind == spelunk::IrValueKind::Reg &&
                    inst.dst.reg == spelunk::Reg::PpcF3 && inst.src_count == 3 &&
                    inst.srcs[0].reg == spelunk::Reg::PpcF4 &&
                    inst.srcs[1].reg == spelunk::Reg::PpcF6 &&
                    inst.srcs[2].reg == spelunk::Reg::PpcF5;
    }
    check_eq(saw_fsel, true, "fsel keeps named floating-point dataflow in IR");
}

void run_floating_point_tests() {
    test_fp_unary_forms();
    test_fp_fused_forms();
    test_fp_status_forms();
    test_floating_point_lifter_forms();
}

}  // namespace ppc_decoder_test
