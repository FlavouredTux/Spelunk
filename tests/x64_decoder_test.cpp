#include <ember/disasm/x64_decoder.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void test_popcnt_f3_0f_b8() {
    const std::array<std::byte, 5> code = {
        std::byte{0xF3}, std::byte{0x48}, std::byte{0x0F},
        std::byte{0xB8}, std::byte{0xC2},
    };
    const ember::X64Decoder dec;
    auto insn = dec.decode(code, 0x69e92e5);
    if (!insn) {
        std::fprintf(stderr, "FAIL: popcnt decode failed: %s\n",
                     insn.error().message.c_str());
        ++fails;
        return;
    }
    check_eq(insn->mnemonic, ember::Mnemonic::Popcnt, "popcnt mnemonic");
    check_eq(insn->length, static_cast<ember::u8>(5), "popcnt length");
    check_eq(insn->num_operands, static_cast<ember::u8>(2), "popcnt operands");
    check_eq(insn->operands[0].kind, ember::Operand::Kind::Register, "dst reg");
    check_eq(insn->operands[0].reg, ember::Reg::Rax, "dst rax");
    check_eq(insn->operands[1].kind, ember::Operand::Kind::Register, "src reg");
    check_eq(insn->operands[1].reg, ember::Reg::Rdx, "src rdx");
}

void test_flag_control_one_byte_opcodes() {
    struct Case {
        std::byte byte;
        ember::Mnemonic mnemonic;
        const char* name;
    };
    constexpr std::array<Case, 11> cases{{
        {std::byte{0x9C}, ember::Mnemonic::Pushf,  "pushf"},
        {std::byte{0x9D}, ember::Mnemonic::Popf,   "popf"},
        {std::byte{0x9E}, ember::Mnemonic::Sahf,   "sahf"},
        {std::byte{0x9F}, ember::Mnemonic::Lahf,   "lahf"},
        {std::byte{0xF5}, ember::Mnemonic::Cmc,    "cmc"},
        {std::byte{0xF8}, ember::Mnemonic::Clc,    "clc"},
        {std::byte{0xF9}, ember::Mnemonic::Stc,    "stc"},
        {std::byte{0xFA}, ember::Mnemonic::Cli,    "cli"},
        {std::byte{0xFB}, ember::Mnemonic::Sti,    "sti"},
        {std::byte{0xFC}, ember::Mnemonic::Cld,    "cld"},
        {std::byte{0xFD}, ember::Mnemonic::StdDir, "std"},
    }};

    const ember::X64Decoder dec;
    for (const auto& c : cases) {
        const std::array<std::byte, 1> code{c.byte};
        auto insn = dec.decode(code, 0x401000);
        if (!insn) {
            std::fprintf(stderr, "FAIL: %s decode failed: %s\n",
                         c.name, insn.error().message.c_str());
            ++fails;
            continue;
        }
        check_eq(insn->mnemonic, c.mnemonic, c.name);
        check_eq(insn->length, static_cast<ember::u8>(1), c.name);
        check_eq(insn->num_operands, static_cast<ember::u8>(0), c.name);
    }
}

void test_rotate_through_carry_group2() {
    const ember::X64Decoder dec;

    {
        const std::array<std::byte, 2> code = {
            std::byte{0xD1}, std::byte{0xD0},
        };
        auto insn = dec.decode(code, 0x401000);
        if (!insn) {
            std::fprintf(stderr, "FAIL: rcl decode failed: %s\n",
                         insn.error().message.c_str());
            ++fails;
        } else {
            check_eq(insn->mnemonic, ember::Mnemonic::Rcl, "rcl mnemonic");
            check_eq(insn->length, static_cast<ember::u8>(2), "rcl length");
            check_eq(insn->num_operands, static_cast<ember::u8>(2), "rcl operands");
            check_eq(insn->operands[0].kind, ember::Operand::Kind::Register, "rcl dst kind");
            check_eq(insn->operands[0].reg, ember::Reg::Eax, "rcl dst eax");
            check_eq(insn->operands[1].kind, ember::Operand::Kind::Immediate, "rcl count kind");
            check_eq(insn->operands[1].imm.value, static_cast<ember::i64>(1), "rcl count");
        }
    }

    {
        const std::array<std::byte, 3> code = {
            std::byte{0xC1}, std::byte{0xD8}, std::byte{0x02},
        };
        auto insn = dec.decode(code, 0x401000);
        if (!insn) {
            std::fprintf(stderr, "FAIL: rcr decode failed: %s\n",
                         insn.error().message.c_str());
            ++fails;
        } else {
            check_eq(insn->mnemonic, ember::Mnemonic::Rcr, "rcr mnemonic");
            check_eq(insn->length, static_cast<ember::u8>(3), "rcr length");
            check_eq(insn->num_operands, static_cast<ember::u8>(2), "rcr operands");
            check_eq(insn->operands[0].kind, ember::Operand::Kind::Register, "rcr dst kind");
            check_eq(insn->operands[0].reg, ember::Reg::Eax, "rcr dst eax");
            check_eq(insn->operands[1].kind, ember::Operand::Kind::Immediate, "rcr count kind");
            check_eq(insn->operands[1].imm.value, static_cast<ember::i64>(2), "rcr count");
        }
    }
}

}  // namespace

int main() {
    test_popcnt_f3_0f_b8();
    test_flag_control_one_byte_opcodes();
    test_rotate_through_carry_group2();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
