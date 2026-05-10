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

}  // namespace

int main() {
    test_popcnt_f3_0f_b8();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
