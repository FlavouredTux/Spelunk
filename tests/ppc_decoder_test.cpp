#include <ember/disasm/instruction.hpp>
#include <ember/disasm/ppc_decoder.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>

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

std::uint32_t cr_logical_word(std::uint32_t bt, std::uint32_t ba,
                              std::uint32_t bb, std::uint32_t xo) {
    return (19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (xo << 1);
}

std::uint32_t xo_word(std::uint32_t rs, std::uint32_t ra, std::uint32_t xo) {
    return (31u << 26) | (rs << 21) | (ra << 16) | (xo << 1);
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
}

void test_bclr_forms() {
    auto insn = must_decode(0x4E800020);  // blr
    check_eq(insn.mnemonic, ember::Mnemonic::Ret, "blr ret mnemonic");

    insn = must_decode(0x4D820020);  // beqlr-style conditional bclr
    check_eq(insn.mnemonic, ember::Mnemonic::Bclr, "conditional bclr mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{12}, "bclr bo");
    check_eq(insn.operands[1].imm.value, std::int64_t{2}, "bclr bi");

    insn = must_decode(0x4E800021);  // bclrl
    check_eq(insn.mnemonic, ember::Mnemonic::Call, "bclrl call mnemonic");
    check_eq(insn.operands[0].reg, ember::Reg::PpcLr, "bclrl lr target");
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
    auto insn = must_decode(0x1003068C);
    check_eq(insn.mnemonic, ember::Mnemonic::PsOp4, "ps op4 mnemonic");
    check_eq(insn.operands[0].imm.value, std::int64_t{0x1003068C}, "ps op4 raw");

    insn = must_decode(0xFC000834);
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

}  // namespace

int main() {
    test_unsigned_compare_forms();
    test_common_immediates();
    test_scalar_unary_forms();
    test_fp_unary_forms();
    test_fp_fused_forms();
    test_bclr_forms();
    test_paired_single_quantized_forms();
    test_multiword_forms();
    test_integer_and_system_forms();
    test_indexed_update_and_rotate_forms();
    test_paired_single_op4_placeholder();
    test_cr_logical_forms();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
