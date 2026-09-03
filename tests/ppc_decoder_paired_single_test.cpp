#include "ppc_decoder_test_support.hpp"

namespace ppc_decoder_test {

void test_paired_single_quantized_forms() {
    auto insn = must_decode(0xE3E10058);  // psq_l f31, 0x58(r1), 0, 0
    check_eq(insn.mnemonic, ember::Mnemonic::PsqL, "psq_l mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF31, "psq_l frt");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR1, "psq_l base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0x58}, "psq_l disp");
    check_eq(insn.operands[1].mem.size, std::uint8_t{8}, "psq_l size");
    check_eq(insn.operands[2].imm.value, std::int64_t{0}, "psq_l w");
    check_eq(insn.operands[3].imm.value, std::int64_t{0}, "psq_l quant");

    insn = must_decode(0xF3E10058);  // psq_st f31, 0x58(r1), 0, 0
    check_eq(insn.mnemonic, ember::Mnemonic::PsqSt, "psq_st mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF31, "psq_st frs");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR1, "psq_st base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0x58}, "psq_st disp");

    insn = must_decode(0xE483F234);  // psq_lu f4, 0x234(r3), 1, 7
    check_eq(insn.mnemonic, ember::Mnemonic::PsqLu, "psq_lu mnemonic");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0x234}, "psq_lu disp");
    check_eq(insn.operands[1].mem.size, std::uint8_t{4}, "psq_lu size");
    check_eq(insn.operands[2].imm.value, std::int64_t{1}, "psq_lu w");
    check_eq(insn.operands[3].imm.value, std::int64_t{7}, "psq_lu quant");
}

void test_paired_single_op4_placeholder() {
    auto insn = must_decode(0x1003068C);  // psq_lx f0, r3, r0, 1, 5
    check_eq(insn.mnemonic, ember::Mnemonic::PsqLx, "psq_lx mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF0, "psq_lx frt");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR3, "psq_lx base");
    check_eq(insn.operands[1].mem.index, ember::Reg::PpcR0, "psq_lx index");
    check_eq(insn.operands[1].mem.size, std::uint8_t{4}, "psq_lx size");
    check_eq(insn.operands[2].imm.value, std::int64_t{1}, "psq_lx w");
    check_eq(insn.operands[3].imm.value, std::int64_t{5}, "psq_lx quant");

    insn = must_decode(0x13E1000E);  // psq_stx f31, r1, r0, 0, 0
    check_eq(insn.mnemonic, ember::Mnemonic::PsqStx, "psq_stx mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF31, "psq_stx frs");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR1, "psq_stx base");

    insn = must_decode(0x10200090);  // ps_mr f1, f0
    check_eq(insn.mnemonic, ember::Mnemonic::PsMr, "ps_mr mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF1, "ps_mr frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF0, "ps_mr frb");

    struct FixedCase {
        std::uint32_t xo;
        ember::Mnemonic mnemonic;
        std::uint8_t operands;
    };
    constexpr FixedCase fixed_cases[] = {
        {0, ember::Mnemonic::PsCmpu0, 3},
        {32, ember::Mnemonic::PsCmpo0, 3},
        {64, ember::Mnemonic::PsCmpu1, 3},
        {96, ember::Mnemonic::PsCmpo1, 3},
        {40, ember::Mnemonic::PsNeg, 2},
        {72, ember::Mnemonic::PsMr, 2},
        {136, ember::Mnemonic::PsNabs, 2},
        {264, ember::Mnemonic::PsAbs, 2},
        {528, ember::Mnemonic::PsMerge00, 3},
        {560, ember::Mnemonic::PsMerge01, 3},
        {592, ember::Mnemonic::PsMerge10, 3},
        {624, ember::Mnemonic::PsMerge11, 3},
    };
    for (const auto& c : fixed_cases) {
        const bool compare = c.xo == 0 || c.xo == 32 || c.xo == 64 || c.xo == 96;
        insn = must_decode(compare ? ps_compare_word(2, 4, 5, c.xo)
                                   : ps_x_word(3, 4, 5, c.xo));
        check_eq(insn.mnemonic, c.mnemonic, "paired-single fixed mnemonic");
        check_eq(insn.num_operands, c.operands, "paired-single fixed operands");
    }

    struct ArithmeticCase {
        std::uint32_t xo;
        ember::Mnemonic mnemonic;
        std::uint8_t operands;
    };
    constexpr ArithmeticCase arithmetic_cases[] = {
        {10, ember::Mnemonic::PsSum0, 4},
        {11, ember::Mnemonic::PsSum1, 4},
        {12, ember::Mnemonic::PsMuls0, 3},
        {13, ember::Mnemonic::PsMuls1, 3},
        {14, ember::Mnemonic::PsMadds0, 4},
        {15, ember::Mnemonic::PsMadds1, 4},
        {18, ember::Mnemonic::PsDiv, 3},
        {20, ember::Mnemonic::PsSub, 3},
        {21, ember::Mnemonic::PsAdd, 3},
        {23, ember::Mnemonic::PsSel, 4},
        {24, ember::Mnemonic::PsRes, 2},
        {25, ember::Mnemonic::PsMul, 3},
        {26, ember::Mnemonic::PsRsqrte, 2},
        {28, ember::Mnemonic::PsMsub, 4},
        {29, ember::Mnemonic::PsMadd, 4},
        {30, ember::Mnemonic::PsNmsub, 4},
        {31, ember::Mnemonic::PsNmadd, 4},
    };
    for (const auto& c : arithmetic_cases) {
        insn = must_decode(ps_a_word(3, 4, 5, 6, c.xo));
        check_eq(insn.mnemonic, c.mnemonic, "paired-single arithmetic mnemonic");
        check_eq(insn.num_operands, c.operands, "paired-single arithmetic operands");
    }

    insn = must_decode(ps_a_word(3, 4, 5, 6, 25));
    check_eq(ember::format_instruction(insn), std::string{"ps_mul f3, f4, f6"},
             "ps_mul format");
    insn = must_decode(ps_a_word(3, 4, 5, 6, 29));
    check_eq(ember::format_instruction(insn), std::string{"ps_madd f3, f4, f6, f5"},
             "ps_madd format");
    insn = must_decode(ps_compare_word(2, 4, 5, 96));
    check_eq(ember::format_instruction(insn), std::string{"ps_cmpo1 0x2, f4, f5"},
             "ps_cmpo1 format");

    insn = must_decode(ps_x_word(0, 3, 4, 1014));
    check_eq(insn.mnemonic, ember::Mnemonic::DcbzL, "dcbz_l mnemonic");
    check_eq(insn.operands[0].mem.base, ember::Reg::PpcR3, "dcbz_l base");
    check_eq(insn.operands[0].mem.index, ember::Reg::PpcR4, "dcbz_l index");

    insn = must_decode(0x10000002);
    check_eq(insn.mnemonic, ember::Mnemonic::PsOp4, "ps op4 mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{0x10000002}, "ps op4 raw");

    insn = must_decode(0xFC000836);
    check_eq(insn.mnemonic, ember::Mnemonic::FpOp, "fp op placeholder mnemonic");
}

void test_paired_single_lifter_forms() {
    auto ir = lift_one(0xF3E10058);  // psq_st f31, 0x58(r1), 0, 0
    bool saw_psq_store_address = false;
    bool saw_spurious_psq_load = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_spurious_psq_load |= inst.op == ember::IrOp::Load;
        saw_psq_store_address |= inst.op == ember::IrOp::Store &&
                                 inst.src_count == 2 &&
                                 inst.srcs[0].kind == ember::IrValueKind::Temp &&
                                 inst.srcs[1].kind == ember::IrValueKind::Reg &&
                                 inst.srcs[1].reg == ember::Reg::PpcF31 &&
                                 inst.srcs[1].type == ember::IrType::V2F32;
    }
    check_eq(saw_psq_store_address && !saw_spurious_psq_load, true,
             "unquantized psq_st becomes a typed float2 store");

    ir = lift_one(0xE0230008);  // psq_l f1, 8(r3), 0, 0
    bool saw_psq_pair_load = false;
    bool saw_psq_pair_assign = false;
    bool saw_psq_pair_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_psq_pair_load |= inst.op == ember::IrOp::Load &&
                             inst.dst.type == ember::IrType::V2F32;
        saw_psq_pair_assign |= inst.op == ember::IrOp::Assign &&
                               inst.dst.kind == ember::IrValueKind::Reg &&
                               inst.dst.reg == ember::Reg::PpcF1 &&
                               inst.dst.type == ember::IrType::V2F32;
        saw_psq_pair_intrinsic |= inst.op == ember::IrOp::Intrinsic &&
                                  inst.name == "ppc.psq_l";
    }
    check_eq(saw_psq_pair_load && saw_psq_pair_assign &&
             !saw_psq_pair_intrinsic, true,
             "unquantized psq_l becomes a typed float2 load");

    ir = lift_one(0xE483F234);  // psq_lu f4, 0x234(r3), 1, 7
    bool saw_psq_load_config = false;
    bool saw_psq_base_update = false;
    bool saw_gqr_type_mask = false;
    bool saw_signed_gqr_scale = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_psq_load_config |= inst.op == ember::IrOp::Intrinsic &&
                               inst.name == "ppc.psq_load_quantized_w1" &&
                               inst.dst.reg == ember::Reg::PpcF4 &&
                               inst.dst.type == ember::IrType::V2F32 &&
                               inst.src_count == 3;
        saw_gqr_type_mask |= inst.op == ember::IrOp::And &&
                             inst.src_count == 2 &&
                             inst.srcs[1].kind == ember::IrValueKind::Imm &&
                             inst.srcs[1].imm == 7;
        saw_signed_gqr_scale |= inst.op == ember::IrOp::Ashr &&
                                inst.src_count == 2 &&
                                inst.srcs[1].kind == ember::IrValueKind::Imm &&
                                inst.srcs[1].imm == 26;
        saw_psq_base_update |= inst.op == ember::IrOp::Assign &&
                               inst.dst.reg == ember::Reg::PpcR3;
    }
    check_eq(saw_psq_load_config && saw_gqr_type_mask &&
             saw_signed_gqr_scale && saw_psq_base_update, true,
             "psq_lu decodes GQR load type/scale and updates base");

    ir = lift_one(0xE0238008);  // psq_l f1, 8(r3), 1, 0
    bool saw_single_float_load = false;
    bool saw_lane_one_build = false;
    bool saw_opaque_single_load = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_single_float_load |= inst.op == ember::IrOp::Load &&
                                 inst.dst.type == ember::IrType::F32;
        saw_lane_one_build |= inst.op == ember::IrOp::Intrinsic &&
                              inst.name == "ppc.ps_build_pair_one" &&
                              inst.dst.type == ember::IrType::V2F32;
        saw_opaque_single_load |= inst.op == ember::IrOp::Intrinsic &&
                                  inst.name.starts_with("ppc.psq_load");
    }
    check_eq(saw_single_float_load && saw_lane_one_build &&
             !saw_opaque_single_load, true,
             "W=1 GQR0 load uses one float and synthesizes lane 1");

    ir = lift_one(0xF3E18058);  // psq_st f31, 0x58(r1), 1, 0
    bool saw_lane_zero_extract = false;
    bool saw_single_float_store = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_lane_zero_extract |= inst.op == ember::IrOp::Intrinsic &&
                                 inst.name == "ppc.ps_lane0" &&
                                 inst.dst.type == ember::IrType::F32;
        saw_single_float_store |= inst.op == ember::IrOp::Store &&
                                  inst.src_count == 2 &&
                                  inst.srcs[1].type == ember::IrType::F32;
    }
    check_eq(saw_lane_zero_extract && saw_single_float_store, true,
             "W=1 GQR0 store writes only paired-single lane 0");

    ir = lift_one(0xF3E17058);  // psq_st f31, 0x58(r1), 0, 7
    bool saw_quantized_store = false;
    bool saw_store_scale_shift = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_quantized_store |= inst.op == ember::IrOp::Intrinsic &&
                               inst.name == "ppc.psq_store_quantized_w0" &&
                               inst.src_count == 4;
        saw_store_scale_shift |= inst.op == ember::IrOp::Lshr &&
                                 inst.src_count == 2 &&
                                 inst.srcs[1].kind == ember::IrValueKind::Imm &&
                                 inst.srcs[1].imm == 8;
    }
    check_eq(saw_quantized_store && saw_store_scale_shift, true,
             "quantized psq_st decodes the GQR store half");

    ir = lift_one(0x10200090);  // ps_mr f1, f0
    bool saw_ps_move = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_ps_move |= inst.op == ember::IrOp::Assign &&
                       inst.dst.kind == ember::IrValueKind::Reg &&
                       inst.dst.reg == ember::Reg::PpcF1 &&
                       inst.src_count == 1 &&
                       inst.srcs[0].kind == ember::IrValueKind::Reg &&
                       inst.srcs[0].reg == ember::Reg::PpcF0;
    }
    check_eq(saw_ps_move, true, "ps_mr lifts as register assignment");

    ir = lift_one(ps_a_word(3, 4, 5, 6, 21));  // ps_add f3, f4, f5
    bool saw_ps_add = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_ps_add |= inst.op == ember::IrOp::Add &&
                      inst.dst.kind == ember::IrValueKind::Temp &&
                      inst.dst.type == ember::IrType::V2F32 && inst.src_count == 2 &&
                      inst.srcs[0].reg == ember::Reg::PpcF4 &&
                      inst.srcs[1].reg == ember::Reg::PpcF5;
    }
    check_eq(saw_ps_add, true, "ps_add keeps named paired-single dataflow in IR");

    ir = lift_one(ps_a_word(3, 4, 5, 6, 29));  // ps_madd f3, f4, f6, f5
    bool saw_ps_madd_mul = false;
    bool saw_ps_madd_add = false;
    bool saw_ps_madd_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_ps_madd_mul |= inst.op == ember::IrOp::Mul &&
                           inst.dst.type == ember::IrType::V2F32 &&
                           inst.srcs[0].reg == ember::Reg::PpcF4 &&
                           inst.srcs[1].reg == ember::Reg::PpcF6;
        saw_ps_madd_add |= inst.op == ember::IrOp::Add &&
                           inst.dst.type == ember::IrType::V2F32 &&
                           inst.srcs[1].reg == ember::Reg::PpcF5;
        saw_ps_madd_intrinsic |= inst.op == ember::IrOp::Intrinsic &&
                                 inst.name == "ppc.ps_madd";
    }
    check_eq(saw_ps_madd_mul && saw_ps_madd_add && !saw_ps_madd_intrinsic,
             true, "ps_madd lifts to typed paired multiply-add dataflow");

    ir = lift_one(ps_a_word(3, 4, 5, 6, 30));  // ps_nmsub f3, f4, f6, f5
    bool saw_ps_nmsub_sub = false;
    bool saw_ps_nmsub_neg = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_ps_nmsub_sub |= inst.op == ember::IrOp::Sub &&
                            inst.dst.type == ember::IrType::V2F32;
        saw_ps_nmsub_neg |= inst.op == ember::IrOp::Neg &&
                            inst.dst.type == ember::IrType::V2F32;
    }
    check_eq(saw_ps_nmsub_sub && saw_ps_nmsub_neg, true,
             "ps_nmsub exposes paired subtract and final negation");

}

void run_paired_single_tests() {
    test_paired_single_quantized_forms();
    test_paired_single_op4_placeholder();
    test_paired_single_lifter_forms();
}

}  // namespace ppc_decoder_test
