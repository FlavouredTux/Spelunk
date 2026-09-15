#include "ppc_decoder_test_support.hpp"

namespace ppc_decoder_test {

void test_unsigned_compare_forms() {
    auto insn = must_decode(0x2803FFFF);  // cmplwi r3, 0xffff
    check_eq(insn.mnemonic, spelunk::Mnemonic::Cmpl, "cmplwi mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR3, "cmplwi ra");
    check_eq(insn.operands[1].imm.value, std::int64_t{0xffff}, "cmplwi imm");
    check_eq(insn.operands[1].imm.is_signed, false, "cmplwi unsigned imm");

    insn = must_decode(0x7C032040);  // cmplw r3, r4
    check_eq(insn.mnemonic, spelunk::Mnemonic::Cmpl, "cmplw mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR3, "cmplw ra");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR4, "cmplw rb");
}

void test_common_immediates() {
    auto insn = must_decode(0x20830020);  // subfic r4, r3, 0x20
    check_eq(insn.mnemonic, spelunk::Mnemonic::Sub, "subfic mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR4, "subfic rt");
    check_eq(insn.operands[1].imm.value, std::int64_t{0x20}, "subfic imm");
    check_eq(insn.operands[2].reg, spelunk::Reg::PpcR3, "subfic ra");

    insn = must_decode(0x74641234);  // andis. r4, r3, 0x1234
    check_eq(insn.mnemonic, spelunk::Mnemonic::And, "andis mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR4, "andis ra");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR3, "andis rs");
    check_eq(insn.operands[2].imm.value, std::int64_t{0x12340000}, "andis imm");
}

void test_scalar_unary_forms() {
    auto insn = must_decode(xo_word(3, 4, 954));  // extsb r4, r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Extsb, "extsb mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR4, "extsb ra");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR3, "extsb rs");

    insn = must_decode(xo_word(5, 6, 922));  // extsh r6, r5
    check_eq(insn.mnemonic, spelunk::Mnemonic::Extsh, "extsh mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR6, "extsh ra");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR5, "extsh rs");

    insn = must_decode(xo_word(7, 8, 26));  // cntlzw r8, r7
    check_eq(insn.mnemonic, spelunk::Mnemonic::Cntlzw, "cntlzw mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR8, "cntlzw ra");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR7, "cntlzw rs");
}

void test_multiword_forms() {
    auto insn = must_decode(0xBB61000C);  // lmw r27, 0xc(r1)
    check_eq(insn.mnemonic, spelunk::Mnemonic::Lmw, "lmw mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR27, "lmw rt");
    check_eq(insn.operands[1].mem.base, spelunk::Reg::PpcR1, "lmw base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0xc}, "lmw disp");
    check_eq(insn.operands[1].mem.size, std::uint8_t{20}, "lmw size");

    insn = must_decode(0xBF61000C);  // stmw r27, 0xc(r1)
    check_eq(insn.mnemonic, spelunk::Mnemonic::Stmw, "stmw mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR27, "stmw rs");
    check_eq(insn.operands[1].mem.base, spelunk::Reg::PpcR1, "stmw base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0xc}, "stmw disp");
}

void test_integer_and_system_forms() {
    auto insn = must_decode(0x3403FFFF);  // addic. r0, r3, -1
    check_eq(insn.mnemonic, spelunk::Mnemonic::Add, "addic mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR0, "addic rt");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR3, "addic ra");
    check_eq(insn.operands[2].imm.value, std::int64_t{-1}, "addic imm");

    insn = must_decode(0x7C030016);  // mulhwu r0, r3, r0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mulhwu, "mulhwu mnemonic");

    insn = must_decode(0x7C001810);  // subfc r0, r0, r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Subfc, "subfc mnemonic");

    insn = must_decode(0x7C852014);  // addc r4, r5, r4
    check_eq(insn.mnemonic, spelunk::Mnemonic::Addc, "addc mnemonic");

    insn = must_decode(0x7C601914);  // adde r3, r0, r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Adde, "adde mnemonic");

    insn = must_decode(0x7C002078);  // andc r0, r0, r4
    check_eq(insn.mnemonic, spelunk::Mnemonic::Andc, "andc mnemonic");

    insn = must_decode(0x7CA420F8);  // nor r4, r5, r4
    check_eq(insn.mnemonic, spelunk::Mnemonic::Nor, "nor mnemonic");

    insn = must_decode(0x7CA53338);  // orc r5, r5, r6
    check_eq(insn.mnemonic, spelunk::Mnemonic::Orc, "orc mnemonic");

    insn = must_decode(0x7C630190);  // subfze r3, r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Subfze, "subfze mnemonic");

    insn = must_decode(0x7CC83BD6);  // divw r6, r8, r7
    check_eq(insn.mnemonic, spelunk::Mnemonic::Divw, "divw mnemonic");

    insn = must_decode(0x4C00012C);  // isync
    check_eq(insn.mnemonic, spelunk::Mnemonic::Isync, "isync mnemonic");

    insn = must_decode(0x7C0004AC);  // sync
    check_eq(insn.mnemonic, spelunk::Mnemonic::Sync, "sync mnemonic");

    insn = must_decode(0x4C000064);  // rfi
    check_eq(insn.mnemonic, spelunk::Mnemonic::Rfi, "rfi mnemonic");

    insn = must_decode(0x44000002);  // sc
    check_eq(insn.mnemonic, spelunk::Mnemonic::Sc, "sc mnemonic");

    insn = must_decode(0x0FE00000);  // twi 31, r0, 0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Twi, "twi mnemonic");

    insn = must_decode(0x7C6000A6);  // mfmsr r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mfmsr, "mfmsr mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR3, "mfmsr rt");

    insn = must_decode(0x7C600124);  // mtmsr r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtmsr, "mtmsr mnemonic");

    insn = must_decode(0x7C4FF120);  // mtcrf 0xff, r2
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtcrf, "mtcrf mnemonic");

    insn = must_decode(0x7C0018AC);  // dcbf r0, r3
    check_eq(insn.mnemonic, spelunk::Mnemonic::Dcbf, "dcbf mnemonic");

    insn = must_decode(0x7C002FAC);  // icbi r0, r5
    check_eq(insn.mnemonic, spelunk::Mnemonic::Icbi, "icbi mnemonic");

    insn = must_decode(0x7D4C42E6);  // mftb r10, ...
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mftb, "mftb mnemonic");

    insn = must_decode(0x7E0004A6);  // mfsr r16, 0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mfsr, "mfsr mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR16, "mfsr rt");
    check_eq(insn.operands[1].imm.value, std::int64_t{0}, "mfsr sr");

    insn = must_decode(0x7FEF01A4);  // mtsr 15, r31
    check_eq(insn.mnemonic, spelunk::Mnemonic::Mtsr, "mtsr mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{15}, "mtsr sr");
    check_eq(insn.operands[1].reg, spelunk::Reg::PpcR31, "mtsr rs");

    insn = must_decode(0x7E40D72C);  // sthbrx r18, r0, r26
    check_eq(insn.mnemonic, spelunk::Mnemonic::Sthbrx, "sthbrx mnemonic");
    check_eq(insn.operands[0].reg, spelunk::Reg::PpcR18, "sthbrx rs");
    check_eq(insn.operands[1].mem.base, spelunk::Reg::None, "sthbrx zero base");
    check_eq(insn.operands[1].mem.index, spelunk::Reg::PpcR26, "sthbrx index");
    check_eq(insn.operands[1].mem.size, std::uint8_t{2}, "sthbrx size");
}

void test_indexed_update_and_rotate_forms() {
    auto insn = must_decode(0x7C04026E);  // lhzux r0, r4, r0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Lhzux, "lhzux mnemonic");
    check_eq(insn.operands[1].mem.base, spelunk::Reg::PpcR4, "lhzux base");

    insn = must_decode(0x7C03042E);  // lfsx f0, r3, r0
    check_eq(insn.mnemonic, spelunk::Mnemonic::Lfsx, "lfsx mnemonic");

    insn = must_decode(0x7CE95D2E);  // stfsx f7, r9, r11
    check_eq(insn.mnemonic, spelunk::Mnemonic::Stfsx, "stfsx mnemonic");

    insn = must_decode(0x50C31F7E);  // rlwimi r3, r6, 3, 29, 31
    check_eq(insn.mnemonic, spelunk::Mnemonic::Rlwimi, "rlwimi mnemonic");

    insn = must_decode(0xD4030060);  // stfsu f0, 0x60(r3)
    check_eq(insn.mnemonic, spelunk::Mnemonic::Stfsu, "stfsu mnemonic");
}

void test_integer_lifter_forms() {
    auto ir = lift_one(0x7E40D72C);  // sthbrx r18, r0, r26
    bool saw_shl = false;
    bool saw_lshr = false;
    bool saw_i16_store = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_shl |= inst.op == spelunk::IrOp::Shl && inst.dst.type == spelunk::IrType::I16;
        saw_lshr |= inst.op == spelunk::IrOp::Lshr && inst.dst.type == spelunk::IrType::I16;
        saw_i16_store |= inst.op == spelunk::IrOp::Store &&
                         inst.src_count == 2 && inst.srcs[1].type == spelunk::IrType::I16;
    }
    check_eq(saw_shl && saw_lshr && saw_i16_store, true,
             "sthbrx lifts byte reversal and halfword store");

    ir = lift_one(xo_word(7, 8, 26));  // cntlzw r8, r7
    bool saw_clz = false;
    bool saw_cntlzw_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_clz |= inst.op == spelunk::IrOp::Clz &&
                   inst.dst.type == spelunk::IrType::I32 && inst.src_count == 1 &&
                   inst.srcs[0].reg == spelunk::Reg::PpcR7;
        saw_cntlzw_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                                inst.name == "ppc.cntlzw";
    }
    check_eq(saw_clz && !saw_cntlzw_intrinsic, true,
             "cntlzw lifts as generic leading-zero dataflow");

    ir = lift_one(0x7C030016);  // mulhwu r0, r3, r0
    bool saw_wide_multiply = false;
    bool saw_high_shift = false;
    bool saw_mulhw_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_wide_multiply |= inst.op == spelunk::IrOp::Mul &&
                             inst.dst.type == spelunk::IrType::I64;
        saw_high_shift |= inst.op == spelunk::IrOp::Lshr &&
                          inst.dst.type == spelunk::IrType::I64;
        saw_mulhw_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                               inst.name == "ppc.mulhwu";
    }
    check_eq(saw_wide_multiply && saw_high_shift && !saw_mulhw_intrinsic, true,
             "mulhwu lifts as widened multiply and high-word shift");

    ir = lift_one((31u << 26) | (3u << 21) | (4u << 16) |
                  (5u << 11) | (75u << 1));  // mulhw r3, r4, r5
    bool saw_signed_high_shift = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_signed_high_shift |= inst.op == spelunk::IrOp::Ashr &&
                                 inst.dst.type == spelunk::IrType::I64;
    }
    check_eq(saw_signed_high_shift, true,
             "mulhw uses an arithmetic high-word shift");

    ir = lift_one(0x7C852014);  // addc r4, r5, r4
    bool saw_addc_sum = false;
    bool saw_add_carry = false;
    bool saw_ca_write = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_addc_sum |= inst.op == spelunk::IrOp::Add &&
                        inst.dst.type == spelunk::IrType::I32;
        saw_add_carry |= inst.op == spelunk::IrOp::AddCarry;
        saw_ca_write |= inst.op == spelunk::IrOp::Assign &&
                        inst.dst.kind == spelunk::IrValueKind::Flag &&
                        inst.dst.flag == spelunk::Flag::PpcCa;
    }
    check_eq(saw_addc_sum && saw_add_carry && saw_ca_write, true,
             "addc lifts sum and PPC carry dataflow");

    ir = lift_one(0x7C601914);  // adde r3, r0, r3
    unsigned adde_adds = 0;
    unsigned adde_carries = 0;
    bool saw_adde_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        adde_adds += inst.op == spelunk::IrOp::Add;
        adde_carries += inst.op == spelunk::IrOp::AddCarry;
        saw_adde_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                              inst.name == "ppc.adde";
    }
    check_eq(adde_adds >= 2 && adde_carries >= 2 && !saw_adde_intrinsic, true,
             "adde includes carry-in and recomputes carry-out");

    for (const auto& [word, label] : std::array{
             std::pair{xo_word(3, 4, 202), "addze"},
             std::pair{xo_word(3, 4, 200), "subfze"},
             std::pair{(31u << 26) | (3u << 21) | (4u << 16) |
                           (5u << 11) | (136u << 1), "subfe"}}) {
        ir = lift_one(word);
        bool saw_carry_flow = false;
        bool saw_opaque = false;
        for (const auto& inst : ir.blocks[0].insts) {
            saw_carry_flow |= inst.op == spelunk::IrOp::AddCarry;
            saw_opaque |= inst.op == spelunk::IrOp::Intrinsic &&
                          inst.name == std::string("ppc.") + label;
        }
        check_eq(saw_carry_flow && !saw_opaque, true,
                 "extended carry instruction lifts as generic dataflow");
    }

    ir = lift_one(0x7C001810);  // subfc r0, r0, r3
    bool saw_subfc_sub = false;
    bool saw_subfc_borrow = false;
    bool saw_subfc_invert = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_subfc_sub |= inst.op == spelunk::IrOp::Sub;
        saw_subfc_borrow |= inst.op == spelunk::IrOp::SubBorrow;
        saw_subfc_invert |= inst.op == spelunk::IrOp::Not &&
                            inst.dst.type == spelunk::IrType::I1;
    }
    check_eq(saw_subfc_sub && saw_subfc_borrow && saw_subfc_invert, true,
             "subfc models PPC no-borrow carry semantics");

    for (const auto& [word, op, label] : std::array{
             std::tuple{0x7C002078u, spelunk::IrOp::And, "andc"},
             std::tuple{0x7CA420F8u, spelunk::IrOp::Or, "nor"},
             std::tuple{0x7CA53338u, spelunk::IrOp::Or, "orc"}}) {
        ir = lift_one(word);
        bool saw_logic = false;
        bool saw_not = false;
        bool saw_opaque = false;
        for (const auto& inst : ir.blocks[0].insts) {
            saw_logic |= inst.op == op;
            saw_not |= inst.op == spelunk::IrOp::Not;
            saw_opaque |= inst.op == spelunk::IrOp::Intrinsic &&
                          inst.name == std::string("ppc.") + label;
        }
        check_eq(saw_logic && saw_not && !saw_opaque, true,
                 "complemented logical op lifts as generic dataflow");
    }

    ir = lift_one(0x50C31F7E);  // rlwimi r3, r6, 3, 29, 31
    bool saw_insert_mask = false;
    bool saw_keep_mask = false;
    bool saw_rlwimi_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        if (inst.op == spelunk::IrOp::And && inst.src_count == 2 &&
            inst.srcs[1].kind == spelunk::IrValueKind::Imm) {
            saw_insert_mask |= inst.srcs[1].imm == 7;
            saw_keep_mask |= inst.srcs[1].imm == static_cast<std::int64_t>(~7u);
        }
        saw_rlwimi_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                                inst.name == "ppc.rlwimi";
    }
    check_eq(saw_insert_mask && saw_keep_mask && !saw_rlwimi_intrinsic, true,
             "rlwimi lifts as rotate-and-masked-insert dataflow");

    ir = lift_one(0xBB61000C);  // lmw r27, 0xc(r1)
    unsigned lmw_loads = 0;
    unsigned lmw_assigns = 0;
    bool saw_lmw_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        lmw_loads += inst.op == spelunk::IrOp::Load &&
                     inst.dst.type == spelunk::IrType::I32;
        lmw_assigns += inst.op == spelunk::IrOp::Assign &&
                       inst.dst.kind == spelunk::IrValueKind::Reg &&
                       inst.dst.reg >= spelunk::Reg::PpcR27 &&
                       inst.dst.reg <= spelunk::Reg::PpcR31;
        saw_lmw_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                             inst.name == "ppc.lmw";
    }
    check_eq(lmw_loads == 5 && lmw_assigns == 5 && !saw_lmw_intrinsic, true,
             "lmw expands into five typed register loads");

    ir = lift_one(0xBF61000C);  // stmw r27, 0xc(r1)
    unsigned stmw_stores = 0;
    bool saw_stmw_intrinsic = false;
    for (const auto& inst : ir.blocks[0].insts) {
        stmw_stores += inst.op == spelunk::IrOp::Store &&
                       inst.src_count == 2 &&
                       inst.srcs[1].type == spelunk::IrType::I32 &&
                       inst.srcs[1].kind == spelunk::IrValueKind::Reg &&
                       inst.srcs[1].reg >= spelunk::Reg::PpcR27 &&
                       inst.srcs[1].reg <= spelunk::Reg::PpcR31;
        saw_stmw_intrinsic |= inst.op == spelunk::IrOp::Intrinsic &&
                              inst.name == "ppc.stmw";
    }
    check_eq(stmw_stores == 5 && !saw_stmw_intrinsic, true,
             "stmw expands into five typed register stores");

    ir = lift_one(0x7E0004A6);  // mfsr r16, 0
    bool saw_mfsr = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_mfsr |= inst.op == spelunk::IrOp::Intrinsic && inst.name == "ppc.mfsr" &&
                    inst.dst.kind == spelunk::IrValueKind::Reg &&
                    inst.dst.reg == spelunk::Reg::PpcR16;
    }
    check_eq(saw_mfsr, true, "mfsr preserves destination in IR");

}

void run_integer_tests() {
    test_unsigned_compare_forms();
    test_common_immediates();
    test_scalar_unary_forms();
    test_multiword_forms();
    test_integer_and_system_forms();
    test_indexed_update_and_rotate_forms();
    test_integer_lifter_forms();
}

}  // namespace ppc_decoder_test
