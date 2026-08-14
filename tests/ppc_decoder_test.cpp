#include <ember/disasm/instruction.hpp>
#include <ember/disasm/ppc_decoder.hpp>
#include <ember/ir/ppc_lifter.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

std::array<std::byte, 4> be32(std::uint32_t v) {
    return {
        static_cast<std::byte>((v >> 24) & 0xff),
        static_cast<std::byte>((v >> 16) & 0xff),
        static_cast<std::byte>((v >> 8) & 0xff),
        static_cast<std::byte>(v & 0xff),
    };
}

ember::Instruction must_decode(std::uint32_t raw) {
    auto bytes = be32(raw);
    const ember::PpcDecoder dec(ember::Endian::Big);
    auto insn = dec.decode(std::span<const std::byte>(bytes.data(), bytes.size()), 0x80003100);
    if (!insn) {
        std::fprintf(stderr, "FAIL: ppc decode %#010x: %s\n",
                     raw, insn.error().message.c_str());
        ++fails;
        return {};
    }
    return *insn;
}

ember::IrFunction lift_one(std::uint32_t raw) {
    ember::Function fn;
    fn.start = 0x80003100;
    fn.end = fn.start + 4;
    ember::BasicBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = ember::BlockKind::Return;
    bb.instructions.push_back(must_decode(raw));
    fn.blocks.push_back(std::move(bb));
    ember::PpcLifter lifter(ember::Abi::Ppc32Sysv);
    auto ir = lifter.lift(fn);
    if (!ir) {
        std::fprintf(stderr, "FAIL: ppc lift %#010x: %s\n",
                     raw, ir.error().message.c_str());
        ++fails;
        return {};
    }
    return std::move(*ir);
}

ember::IrFunction lift_conditional_pair(std::uint32_t first, std::uint32_t branch) {
    ember::Function fn;
    fn.start = 0x80003100;
    fn.end = fn.start + 16;

    ember::BasicBlock entry;
    entry.start = fn.start;
    entry.end = fn.start + 8;
    entry.kind = ember::BlockKind::Conditional;
    entry.instructions.push_back(must_decode(first));
    auto branch_insn = must_decode(branch);
    branch_insn.address = fn.start + 4;
    entry.instructions.push_back(std::move(branch_insn));
    entry.successors = {fn.start + 12, fn.start + 8};

    ember::BasicBlock fallthrough;
    fallthrough.start = fn.start + 8;
    fallthrough.end = fn.start + 12;
    fallthrough.kind = ember::BlockKind::Return;
    fallthrough.predecessors = {fn.start};

    ember::BasicBlock taken;
    taken.start = fn.start + 12;
    taken.end = fn.start + 16;
    taken.kind = ember::BlockKind::Return;
    taken.predecessors = {fn.start};

    fn.blocks.push_back(std::move(entry));
    fn.blocks.push_back(std::move(fallthrough));
    fn.blocks.push_back(std::move(taken));
    ember::PpcLifter lifter(ember::Abi::Ppc32Sysv);
    auto ir = lifter.lift(fn);
    if (!ir) {
        std::fprintf(stderr, "FAIL: conditional PPC lift: %s\n", ir.error().message.c_str());
        ++fails;
        return {};
    }
    return std::move(*ir);
}

std::uint32_t cr_logical_word(std::uint32_t bt, std::uint32_t ba,
                              std::uint32_t bb, std::uint32_t xo) {
    return (19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (xo << 1);
}

std::uint32_t xo_word(std::uint32_t rs, std::uint32_t ra, std::uint32_t xo) {
    return (31u << 26) | (rs << 21) | (ra << 16) | (xo << 1);
}

std::uint32_t spr_word(std::uint32_t rt, std::uint32_t spr, std::uint32_t xo) {
    return (31u << 26) | (rt << 21) | ((spr & 0x1fu) << 16) |
           (((spr >> 5) & 0x1fu) << 11) | (xo << 1);
}

std::uint32_t ps_x_word(std::uint32_t fd, std::uint32_t fa,
                        std::uint32_t fb, std::uint32_t xo) {
    return (4u << 26) | (fd << 21) | (fa << 16) | (fb << 11) | (xo << 1);
}

std::uint32_t ps_a_word(std::uint32_t fd, std::uint32_t fa, std::uint32_t fb,
                        std::uint32_t fc, std::uint32_t xo) {
    return (4u << 26) | (fd << 21) | (fa << 16) | (fb << 11) |
           (fc << 6) | (xo << 1);
}

std::uint32_t ps_compare_word(std::uint32_t crfd, std::uint32_t fa,
                              std::uint32_t fb, std::uint32_t xo) {
    return (4u << 26) | (crfd << 23) | (fa << 16) | (fb << 11) | (xo << 1);
}

void test_unsigned_compare_forms() {
    auto insn = must_decode(0x2803FFFF);  // cmplwi r3, 0xffff
    check_eq(insn.mnemonic, ember::Mnemonic::Cmpl, "cmplwi mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR3, "cmplwi ra");
    check_eq(insn.operands[1].imm.value, std::int64_t{0xffff}, "cmplwi imm");
    check_eq(insn.operands[1].imm.is_signed, false, "cmplwi unsigned imm");

    insn = must_decode(0x7C032040);  // cmplw r3, r4
    check_eq(insn.mnemonic, ember::Mnemonic::Cmpl, "cmplw mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR3, "cmplw ra");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR4, "cmplw rb");
}

void test_common_immediates() {
    auto insn = must_decode(0x20830020);  // subfic r4, r3, 0x20
    check_eq(insn.mnemonic, ember::Mnemonic::Sub, "subfic mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR4, "subfic rt");
    check_eq(insn.operands[1].imm.value, std::int64_t{0x20}, "subfic imm");
    check_eq(insn.operands[2].reg, ember::Reg::PpcR3, "subfic ra");

    insn = must_decode(0x74641234);  // andis. r4, r3, 0x1234
    check_eq(insn.mnemonic, ember::Mnemonic::And, "andis mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR4, "andis ra");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR3, "andis rs");
    check_eq(insn.operands[2].imm.value, std::int64_t{0x12340000}, "andis imm");
}

void test_scalar_unary_forms() {
    auto insn = must_decode(xo_word(3, 4, 954));  // extsb r4, r3
    check_eq(insn.mnemonic, ember::Mnemonic::Extsb, "extsb mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR4, "extsb ra");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR3, "extsb rs");

    insn = must_decode(xo_word(5, 6, 922));  // extsh r6, r5
    check_eq(insn.mnemonic, ember::Mnemonic::Extsh, "extsh mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR6, "extsh ra");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR5, "extsh rs");

    insn = must_decode(xo_word(7, 8, 26));  // cntlzw r8, r7
    check_eq(insn.mnemonic, ember::Mnemonic::Cntlzw, "cntlzw mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR8, "cntlzw ra");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR7, "cntlzw rs");
}

std::uint32_t fp_unary_word(std::uint32_t frt, std::uint32_t frb, std::uint32_t xo) {
    return (63u << 26) | (frt << 21) | (frb << 11) | (xo << 1);
}

std::uint32_t fp_a_word(std::uint32_t op, std::uint32_t frt, std::uint32_t fra,
                        std::uint32_t frb, std::uint32_t frc, std::uint32_t xo) {
    return (op << 26) | (frt << 21) | (fra << 16) | (frb << 11) |
           (frc << 6) | (xo << 1);
}

void test_fp_unary_forms() {
    auto insn = must_decode(fp_unary_word(1, 2, 12));  // frsp f1, f2
    check_eq(insn.mnemonic, ember::Mnemonic::Frsp, "frsp mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF1, "frsp frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF2, "frsp frb");

    insn = must_decode(fp_unary_word(3, 4, 14));  // fctiw f3, f4
    check_eq(insn.mnemonic, ember::Mnemonic::Fctiw, "fctiw mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF3, "fctiw frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF4, "fctiw frb");

    insn = must_decode(fp_unary_word(5, 6, 15));  // fctiwz f5, f6
    check_eq(insn.mnemonic, ember::Mnemonic::Fctiwz, "fctiwz mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF5, "fctiwz frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF6, "fctiwz frb");

    insn = must_decode(fp_a_word(59, 7, 0, 8, 0, 24));  // fres f7, f8
    check_eq(insn.mnemonic, ember::Mnemonic::Fres, "fres mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF7, "fres frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF8, "fres frb");

    insn = must_decode(fp_a_word(63, 9, 0, 10, 0, 26));  // frsqrte f9, f10
    check_eq(insn.mnemonic, ember::Mnemonic::Frsqrte, "frsqrte mnemonic");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF10, "frsqrte frb");

    insn = must_decode(fp_unary_word(11, 12, 136));  // fnabs f11, f12
    check_eq(insn.mnemonic, ember::Mnemonic::Fnabs, "fnabs mnemonic");

    insn = must_decode(fp_unary_word(13, 0, 583));  // mffs f13
    check_eq(insn.mnemonic, ember::Mnemonic::Mffs, "mffs mnemonic");
    check_eq(insn.num_operands, std::uint8_t{1}, "mffs operands");
}

void test_fp_fused_forms() {
    auto insn = must_decode(0xEC0100BA);  // fmadds f0, f1, f2, f0
    check_eq(insn.mnemonic, ember::Mnemonic::Fmadds, "fmadds mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcF0, "fmadds frt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF1, "fmadds fra");
    check_eq(insn.operands[2].reg, ember::Reg::PpcF2, "fmadds frc");
    check_eq(insn.operands[3].reg, ember::Reg::PpcF0, "fmadds frb");

    insn = must_decode(0xFC0110BA);  // fmadd f0, f1, f2, f2
    check_eq(insn.mnemonic, ember::Mnemonic::Fmadd, "fmadd mnemonic");

    insn = must_decode(fp_a_word(63, 3, 4, 5, 6, 23));  // fsel f3, f4, f6, f5
    check_eq(insn.mnemonic, ember::Mnemonic::Fsel, "fsel mnemonic");
    check_eq(ember::format_instruction(insn), std::string{"fsel f3, f4, f6, f5"},
             "fsel operand order");
}

void test_fp_status_forms() {
    auto insn = must_decode((63u << 26) | (3u << 23) | (5u << 18) | (64u << 1));
    check_eq(insn.mnemonic, ember::Mnemonic::Mcrfs, "mcrfs mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{3}, "mcrfs crfd");
    check_eq(insn.operands[1].imm.value, std::int64_t{5}, "mcrfs crfs");

    insn = must_decode((63u << 26) | (17u << 21) | (38u << 1));
    check_eq(insn.mnemonic, ember::Mnemonic::Mtfsb1, "mtfsb1 mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{17}, "mtfsb1 bit");

    insn = must_decode((63u << 26) | (2u << 23) | (0xau << 12) | (134u << 1));
    check_eq(insn.mnemonic, ember::Mnemonic::Mtfsfi, "mtfsfi mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{2}, "mtfsfi crfd");
    check_eq(insn.operands[1].imm.value, std::int64_t{0xa}, "mtfsfi imm");

    insn = must_decode((63u << 26) | (0xa5u << 17) | (14u << 11) | (711u << 1));
    check_eq(insn.mnemonic, ember::Mnemonic::Mtfsf, "mtfsf mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{0xa5}, "mtfsf mask");
    check_eq(insn.operands[1].reg, ember::Reg::PpcF14, "mtfsf frb");
}

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

void test_multiword_forms() {
    auto insn = must_decode(0xBB61000C);  // lmw r27, 0xc(r1)
    check_eq(insn.mnemonic, ember::Mnemonic::Lmw, "lmw mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR27, "lmw rt");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR1, "lmw base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0xc}, "lmw disp");
    check_eq(insn.operands[1].mem.size, std::uint8_t{20}, "lmw size");

    insn = must_decode(0xBF61000C);  // stmw r27, 0xc(r1)
    check_eq(insn.mnemonic, ember::Mnemonic::Stmw, "stmw mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR27, "stmw rs");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR1, "stmw base");
    check_eq(insn.operands[1].mem.disp, std::int64_t{0xc}, "stmw disp");
}

void test_integer_and_system_forms() {
    auto insn = must_decode(0x3403FFFF);  // addic. r0, r3, -1
    check_eq(insn.mnemonic, ember::Mnemonic::Add, "addic mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR0, "addic rt");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR3, "addic ra");
    check_eq(insn.operands[2].imm.value, std::int64_t{-1}, "addic imm");

    insn = must_decode(0x7C030016);  // mulhwu r0, r3, r0
    check_eq(insn.mnemonic, ember::Mnemonic::Mulhwu, "mulhwu mnemonic");

    insn = must_decode(0x7C001810);  // subfc r0, r0, r3
    check_eq(insn.mnemonic, ember::Mnemonic::Subfc, "subfc mnemonic");

    insn = must_decode(0x7C852014);  // addc r4, r5, r4
    check_eq(insn.mnemonic, ember::Mnemonic::Addc, "addc mnemonic");

    insn = must_decode(0x7C601914);  // adde r3, r0, r3
    check_eq(insn.mnemonic, ember::Mnemonic::Adde, "adde mnemonic");

    insn = must_decode(0x7C002078);  // andc r0, r0, r4
    check_eq(insn.mnemonic, ember::Mnemonic::Andc, "andc mnemonic");

    insn = must_decode(0x7CA420F8);  // nor r4, r5, r4
    check_eq(insn.mnemonic, ember::Mnemonic::Nor, "nor mnemonic");

    insn = must_decode(0x7CA53338);  // orc r5, r5, r6
    check_eq(insn.mnemonic, ember::Mnemonic::Orc, "orc mnemonic");

    insn = must_decode(0x7C630190);  // subfze r3, r3
    check_eq(insn.mnemonic, ember::Mnemonic::Subfze, "subfze mnemonic");

    insn = must_decode(0x7CC83BD6);  // divw r6, r8, r7
    check_eq(insn.mnemonic, ember::Mnemonic::Divw, "divw mnemonic");

    insn = must_decode(0x4C00012C);  // isync
    check_eq(insn.mnemonic, ember::Mnemonic::Isync, "isync mnemonic");

    insn = must_decode(0x7C0004AC);  // sync
    check_eq(insn.mnemonic, ember::Mnemonic::Sync, "sync mnemonic");

    insn = must_decode(0x4C000064);  // rfi
    check_eq(insn.mnemonic, ember::Mnemonic::Rfi, "rfi mnemonic");

    insn = must_decode(0x44000002);  // sc
    check_eq(insn.mnemonic, ember::Mnemonic::Sc, "sc mnemonic");

    insn = must_decode(0x0FE00000);  // twi 31, r0, 0
    check_eq(insn.mnemonic, ember::Mnemonic::Twi, "twi mnemonic");

    insn = must_decode(0x7C6000A6);  // mfmsr r3
    check_eq(insn.mnemonic, ember::Mnemonic::Mfmsr, "mfmsr mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR3, "mfmsr rt");

    insn = must_decode(0x7C600124);  // mtmsr r3
    check_eq(insn.mnemonic, ember::Mnemonic::Mtmsr, "mtmsr mnemonic");

    insn = must_decode(0x7C4FF120);  // mtcrf 0xff, r2
    check_eq(insn.mnemonic, ember::Mnemonic::Mtcrf, "mtcrf mnemonic");

    insn = must_decode(0x7C0018AC);  // dcbf r0, r3
    check_eq(insn.mnemonic, ember::Mnemonic::Dcbf, "dcbf mnemonic");

    insn = must_decode(0x7C002FAC);  // icbi r0, r5
    check_eq(insn.mnemonic, ember::Mnemonic::Icbi, "icbi mnemonic");

    insn = must_decode(0x7D4C42E6);  // mftb r10, ...
    check_eq(insn.mnemonic, ember::Mnemonic::Mftb, "mftb mnemonic");

    insn = must_decode(0x7E0004A6);  // mfsr r16, 0
    check_eq(insn.mnemonic, ember::Mnemonic::Mfsr, "mfsr mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR16, "mfsr rt");
    check_eq(insn.operands[1].imm.value, std::int64_t{0}, "mfsr sr");

    insn = must_decode(0x7FEF01A4);  // mtsr 15, r31
    check_eq(insn.mnemonic, ember::Mnemonic::Mtsr, "mtsr mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{15}, "mtsr sr");
    check_eq(insn.operands[1].reg, ember::Reg::PpcR31, "mtsr rs");

    insn = must_decode(0x7E40D72C);  // sthbrx r18, r0, r26
    check_eq(insn.mnemonic, ember::Mnemonic::Sthbrx, "sthbrx mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcR18, "sthbrx rs");
    check_eq(insn.operands[1].mem.base, ember::Reg::None, "sthbrx zero base");
    check_eq(insn.operands[1].mem.index, ember::Reg::PpcR26, "sthbrx index");
    check_eq(insn.operands[1].mem.size, std::uint8_t{2}, "sthbrx size");
}

void test_indexed_update_and_rotate_forms() {
    auto insn = must_decode(0x7C04026E);  // lhzux r0, r4, r0
    check_eq(insn.mnemonic, ember::Mnemonic::Lhzux, "lhzux mnemonic");
    check_eq(insn.operands[1].mem.base, ember::Reg::PpcR4, "lhzux base");

    insn = must_decode(0x7C03042E);  // lfsx f0, r3, r0
    check_eq(insn.mnemonic, ember::Mnemonic::Lfsx, "lfsx mnemonic");

    insn = must_decode(0x7CE95D2E);  // stfsx f7, r9, r11
    check_eq(insn.mnemonic, ember::Mnemonic::Stfsx, "stfsx mnemonic");

    insn = must_decode(0x50C31F7E);  // rlwimi r3, r6, 3, 29, 31
    check_eq(insn.mnemonic, ember::Mnemonic::Rlwimi, "rlwimi mnemonic");

    insn = must_decode(0xD4030060);  // stfsu f0, 0x60(r3)
    check_eq(insn.mnemonic, ember::Mnemonic::Stfsu, "stfsu mnemonic");
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

void test_wii_lifter_forms() {
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

    auto ir = lift_one(0xF3E10058);  // psq_st f31, 0x58(r1), 0, 0
    bool saw_psq_store_address = false;
    bool saw_spurious_psq_load = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_spurious_psq_load |= inst.op == ember::IrOp::Load;
        saw_psq_store_address |= inst.op == ember::IrOp::Intrinsic &&
                                 inst.name == "ppc.psq_st" && inst.src_count == 4 &&
                                 inst.srcs[0].reg == ember::Reg::PpcF31 &&
                                 inst.srcs[1].kind == ember::IrValueKind::Temp &&
                                 inst.srcs[2].kind == ember::IrValueKind::Imm &&
                                 inst.srcs[2].imm == 0 &&
                                 inst.srcs[3].kind == ember::IrValueKind::Reg &&
                                 inst.srcs[3].reg == ember::Reg::PpcGqr0;
    }
    check_eq(saw_psq_store_address && !saw_spurious_psq_load, true,
             "psq_st passes effective address without loading it");

    ir = lift_one(0xE483F234);  // psq_lu f4, 0x234(r3), 1, 7
    bool saw_psq_load_config = false;
    bool saw_psq_base_update = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_psq_load_config |= inst.op == ember::IrOp::Intrinsic &&
                               inst.name == "ppc.psq_lu" &&
                               inst.dst.reg == ember::Reg::PpcF4 &&
                               inst.dst.type == ember::IrType::V2F32 &&
                               inst.src_count == 3 && inst.srcs[1].imm == 1 &&
                               inst.srcs[2].kind == ember::IrValueKind::Reg &&
                               inst.srcs[2].reg == ember::Reg::PpcGqr7;
        saw_psq_base_update |= inst.op == ember::IrOp::Assign &&
                               inst.dst.reg == ember::Reg::PpcR3;
    }
    check_eq(saw_psq_load_config && saw_psq_base_update, true,
             "psq_lu keeps quantization config and updates base");

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

    ir = lift_one(0x7E40D72C);  // sthbrx r18, r0, r26
    bool saw_shl = false;
    bool saw_lshr = false;
    bool saw_i16_store = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_shl |= inst.op == ember::IrOp::Shl && inst.dst.type == ember::IrType::I16;
        saw_lshr |= inst.op == ember::IrOp::Lshr && inst.dst.type == ember::IrType::I16;
        saw_i16_store |= inst.op == ember::IrOp::Store &&
                         inst.src_count == 2 && inst.srcs[1].type == ember::IrType::I16;
    }
    check_eq(saw_shl && saw_lshr && saw_i16_store, true,
             "sthbrx lifts byte reversal and halfword store");

    ir = lift_one(0x7E0004A6);  // mfsr r16, 0
    bool saw_mfsr = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_mfsr |= inst.op == ember::IrOp::Intrinsic && inst.name == "ppc.mfsr" &&
                    inst.dst.kind == ember::IrValueKind::Reg &&
                    inst.dst.reg == ember::Reg::PpcR16;
    }
    check_eq(saw_mfsr, true, "mfsr preserves destination in IR");

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
    bool saw_ps_madd = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_ps_madd |= inst.op == ember::IrOp::Intrinsic && inst.name == "ppc.ps_madd" &&
                       inst.dst.kind == ember::IrValueKind::Reg &&
                       inst.dst.reg == ember::Reg::PpcF3 && inst.src_count == 3;
    }
    check_eq(saw_ps_madd, true, "ps_madd keeps all three sources in IR");

    ir = lift_one(fp_a_word(63, 3, 4, 5, 6, 23));
    bool saw_fsel = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_fsel |= inst.op == ember::IrOp::Intrinsic && inst.name == "ppc.fsel" &&
                    inst.dst.kind == ember::IrValueKind::Reg &&
                    inst.dst.reg == ember::Reg::PpcF3 && inst.src_count == 3 &&
                    inst.srcs[0].reg == ember::Reg::PpcF4 &&
                    inst.srcs[1].reg == ember::Reg::PpcF6 &&
                    inst.srcs[2].reg == ember::Reg::PpcF5;
    }
    check_eq(saw_fsel, true, "fsel keeps named floating-point dataflow in IR");
}

}  // namespace

int main() {
    test_unsigned_compare_forms();
    test_common_immediates();
    test_scalar_unary_forms();
    test_fp_unary_forms();
    test_fp_fused_forms();
    test_fp_status_forms();
    test_bclr_forms();
    test_cr_fields_and_wii_sprs();
    test_paired_single_quantized_forms();
    test_multiword_forms();
    test_integer_and_system_forms();
    test_indexed_update_and_rotate_forms();
    test_paired_single_op4_placeholder();
    test_cr_logical_forms();
    test_wii_lifter_forms();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
