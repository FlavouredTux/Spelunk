#include "ppc_decoder_test_support.hpp"

namespace ppc_decoder_test {

void test_bclr_forms() {
    auto insn = must_decode(0x4E800020);  // blr
    check_eq(insn.mnemonic, ember::Mnemonic::Ret, "blr ret mnemonic");

    insn = must_decode(0x4D820020);  // beqlr-style conditional bclr
    check_eq(insn.mnemonic, ember::Mnemonic::Bclr, "conditional bclr mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{12}, "bclr bo");
    check_eq(insn.operands[1].imm.value, std::int64_t{2}, "bclr bi");
    check_eq(insn.ppc_bo, std::uint8_t{12}, "bclr metadata bo");
    check_eq(insn.ppc_bi, std::uint8_t{2}, "bclr metadata bi");

    insn = must_decode(0x4E800021);  // bclrl
    check_eq(insn.mnemonic, ember::Mnemonic::Call, "bclrl call mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcLr, "bclrl lr target");

    insn = must_decode((19u << 26) | (12u << 21) | (6u << 16) | (528u << 1));
    check_eq(insn.mnemonic, ember::Mnemonic::Bcctr, "conditional bcctr mnemonic");
    check_eq(insn.ppc_bo, std::uint8_t{12}, "bcctr metadata bo");
    check_eq(insn.ppc_bi, std::uint8_t{6}, "bcctr metadata bi");
}

void test_cr_fields_and_wii_sprs() {
    auto insn = must_decode((11u << 26) | (3u << 23) | (4u << 16) | 7u);
    check_eq(insn.mnemonic, ember::Mnemonic::Cmp, "cmpwi cr3 mnemonic");
    check_eq(insn.ppc_cr_field, std::uint8_t{3}, "cmpwi keeps CR field");

    insn = must_decode(spr_word(5, 915, 467));  // mtspr GQR3, r5
    check_eq(insn.mnemonic, ember::Mnemonic::Mov, "mtspr GQR3 becomes move");
    check_eq(insn.operands[0].reg, ember::Reg::PpcGqr3, "mtspr GQR3 destination");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR5, "mtspr GQR3 source");

    insn = must_decode(spr_word(6, 919, 339));  // mfspr r6, GQR7
    check_eq(insn.mnemonic, ember::Mnemonic::Mov, "mfspr GQR7 becomes move");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR6, "mfspr GQR7 destination");
    check_eq(insn.operands[1].reg, ember::Reg::PpcGqr7, "mfspr GQR7 source");

    insn = must_decode(spr_word(7, 26, 339));  // mfspr r7, SRR0
    check_eq(ember::format_instruction(insn), std::string{"mfspr r7, srr0"},
             "known Wii SPR has a symbolic name");

    auto ir = lift_conditional_pair(
        (11u << 26) | (1u << 23) | (3u << 16),
        (16u << 26) | (12u << 21) | (6u << 16) | 8u);  // beq cr1
    bool wrote_cr1_eq = false;
    bool branched_on_cr1_eq = false;
    for (const auto& inst : ir.blocks[0].insts) {
        wrote_cr1_eq |= inst.op == ember::IrOp::Assign &&
                        inst.dst.kind == ember::IrValueKind::Flag &&
                        inst.dst.flag == ember::Flag::Cr1Eq;
        branched_on_cr1_eq |= inst.op == ember::IrOp::CondBranch &&
                              inst.src_count == 1 &&
                              inst.srcs[0].kind == ember::IrValueKind::Flag &&
                              inst.srcs[0].flag == ember::Flag::Cr1Eq;
    }
    check_eq(wrote_cr1_eq && branched_on_cr1_eq, true,
             "non-CR0 compare and branch share the selected CR field");

    ir = lift_conditional_pair(
        (11u << 26) | (1u << 23) | (3u << 16),
        (16u << 26) | (0u << 21) | (6u << 16) | 8u);  // CTR!=0 && !CR1.eq
    bool decremented_ctr = false;
    bool combined_predicates = false;
    for (const auto& inst : ir.blocks[0].insts) {
        decremented_ctr |= inst.op == ember::IrOp::Assign &&
                           inst.dst.kind == ember::IrValueKind::Reg &&
                           inst.dst.reg == ember::Reg::PpcCtr;
        combined_predicates |= inst.op == ember::IrOp::And &&
                               inst.dst.type == ember::IrType::I1;
    }
    check_eq(decremented_ctr && combined_predicates, true,
             "generic BO form combines CTR and CR predicates");
}

void test_cr_logical_forms() {
    struct Case {
        std::uint32_t xo;
        ember::Mnemonic mnemonic;
        const char* name;
    };
    const Case cases[] = {
        {33, ember::Mnemonic::Crnor, "crnor"},
        {129, ember::Mnemonic::Crandc, "crandc"},
        {193, ember::Mnemonic::Crxor, "crxor"},
        {225, ember::Mnemonic::Crnand, "crnand"},
        {257, ember::Mnemonic::Crand, "crand"},
        {289, ember::Mnemonic::Creqv, "creqv"},
        {417, ember::Mnemonic::Crorc, "crorc"},
        {449, ember::Mnemonic::Cror, "cror"},
    };
    for (const auto& c : cases) {
        auto insn = must_decode(cr_logical_word(6, 7, 8, c.xo));
        check_eq(insn.mnemonic, c.mnemonic, c.name);
        check_eq(insn.num_operands, std::uint8_t{3}, "cr logical nargs");
        check_eq(insn.operands[0].imm.value, std::int64_t{6}, "cr logical bt");
        check_eq(insn.operands[1].imm.value, std::int64_t{7}, "cr logical ba");
        check_eq(insn.operands[2].imm.value, std::int64_t{8}, "cr logical bb");
    }
}

void test_call_abi_lifter_forms() {
    check_eq(ember::fp_return_reg(ember::Abi::Ppc32Sysv),
             ember::Reg::PpcF1,
             "PPC32 SysV floating return lane is f1");
    auto call_ir = lift_one(0x48000001);  // bl .
    bool saw_fp_args = false;
    bool saw_f0_clobber = false;
    bool saw_f13_clobber = false;
    bool saw_f1_return_source = false;
    for (const auto& inst : call_ir.blocks[0].insts) {
        saw_fp_args |= inst.op == ember::IrOp::Intrinsic &&
                       inst.name == "call.fp_args.1" && inst.src_count == 3 &&
                       inst.srcs[0].reg == ember::Reg::PpcF1 &&
                       inst.srcs[2].reg == ember::Reg::PpcF3;
        saw_f0_clobber |= inst.op == ember::IrOp::Clobber &&
                          inst.dst.reg == ember::Reg::PpcF0;
        saw_f13_clobber |= inst.op == ember::IrOp::Clobber &&
                           inst.dst.reg == ember::Reg::PpcF13;
        if (inst.op == ember::IrOp::Return) {
            for (ember::u8 i = 0; i < inst.src_count; ++i) {
                saw_f1_return_source |=
                    inst.srcs[i].kind == ember::IrValueKind::Reg &&
                    inst.srcs[i].reg == ember::Reg::PpcF1;
            }
        }
    }
    check_eq(saw_fp_args && saw_f0_clobber && saw_f13_clobber &&
             saw_f1_return_source, true,
             "PPC calls snapshot FP args, clobber FPRs, and preserve f1 returns");

}

void run_control_flow_tests() {
    test_bclr_forms();
    test_cr_fields_and_wii_sprs();
    test_cr_logical_forms();
    test_call_abi_lifter_forms();
}

}  // namespace ppc_decoder_test
