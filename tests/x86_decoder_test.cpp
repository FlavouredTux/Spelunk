// 32-bit x86 decoding: protected mode shares the long-mode opcode tables but
// differs in exactly the places this test pins - 0x40..0x4f is INC/DEC rather
// than a REX prefix, VEX/EVEX escapes must not swallow LDS/BOUND encodings,
// ARPL has no long-mode counterpart, address size defaults to 32 bits with a
// 16-bit override, and x87 stack operands report their slot.

#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/x64_decoder.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <span>
#include <string>

namespace {

int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s (got %lld, want %lld)\n", ctx,
                     static_cast<long long>(got), static_cast<long long>(want));
        ++fails;
    }
}

std::span<const std::byte> bytes(std::initializer_list<unsigned> values) {
    static std::array<std::byte, 16> storage;
    std::size_t n = 0;
    for (unsigned value : values) storage[n++] = static_cast<std::byte>(value);
    return {storage.data(), n};
}

void test_inc_dec_are_opcodes_not_rex() {
    const spelunk::X64Decoder dec(false);
    auto inc = dec.decode(bytes({0x41}), 0x401000);  // inc ecx
    check_eq(inc.has_value(), true, "41 decodes in 32-bit mode");
    if (inc) {
        check_eq(inc->mnemonic, spelunk::Mnemonic::Inc, "41 is inc");
        check_eq(inc->length, static_cast<spelunk::u8>(1), "41 length");
        check_eq(inc->num_operands, static_cast<spelunk::u8>(1), "41 operands");
        check_eq(inc->operands[0].kind, spelunk::Operand::Kind::Register, "41 dst kind");
        check_eq(inc->operands[0].reg, spelunk::Reg::Ecx, "41 dst ecx");
    }
    auto decrement = dec.decode(bytes({0x4F}), 0x401001);  // dec edi
    check_eq(decrement.has_value(), true, "4f decodes in 32-bit mode");
    if (decrement) {
        check_eq(decrement->mnemonic, spelunk::Mnemonic::Dec, "4f is dec");
        check_eq(decrement->operands[0].reg, spelunk::Reg::Edi, "4f dst edi");
    }
    // Long mode reads the same byte as a REX.B prefix and has no INC r32.
    const spelunk::X64Decoder wide;
    auto rex = wide.decode(bytes({0x41, 0x90}), 0x401002);
    check_eq(rex.has_value(), true, "41 90 decodes in 64-bit mode");
    if (rex) {
        check_eq(rex->mnemonic, spelunk::Mnemonic::Nop, "41 90 is rex-prefixed nop");
        check_eq(rex->length, static_cast<spelunk::u8>(2), "41 90 length");
    }
}

void test_arpl_is_reported_not_implemented() {
    const spelunk::X64Decoder dec(false);
    auto arpl = dec.decode(bytes({0x63, 0xC8}), 0x401000);  // arpl eax, ecx
    check_eq(arpl.has_value(), false, "arpl rejected");
    if (!arpl) {
        check_eq(arpl.error().message.find("ARPL") != std::string::npos, true,
                 "arpl error names the opcode");
    }
}

void test_lds_is_not_a_vex_prefix() {
    // 0xC5 is LDS in 32-bit mode. Only a following byte with both top bits
    // set can be a two-byte VEX prefix (avoiding a real LDS with mod=11).
    const spelunk::X64Decoder dec(false);
    auto lds = dec.decode(bytes({0xC5, 0x00, 0x00}), 0x401000);
    check_eq(lds.has_value(), false, "c5 00 rejected as unimplemented LDS");
    if (!lds) {
        check_eq(lds.error().message.find("VEX") == std::string::npos, true,
                 "c5 00 is not treated as VEX");
    }
    // A VEX-shaped follow-up still decodes as a vector instruction.
    auto vex = dec.decode(bytes({0xC5, 0xF8, 0x77}), 0x401003);  // vzeroupper
    check_eq(vex.has_value(), true, "c5 f8 77 decodes as vex");
    if (vex) check_eq(vex->mnemonic, spelunk::Mnemonic::Vzeroupper, "c5 f8 77 vzeroupper");
}

void test_address_size_defaults_and_override() {
    const spelunk::X64Decoder dec(false);
    auto plain = dec.decode(bytes({0x8B, 0x44, 0x24, 0x04}), 0x401000);
    check_eq(plain.has_value(), true, "mov eax,[esp+4] decodes");
    if (plain) {
        check_eq(plain->operands[1].kind, spelunk::Operand::Kind::Memory, "src is memory");
        check_eq(plain->operands[1].mem.address_size, static_cast<spelunk::u8>(4),
                 "default address size is 32-bit");
        check_eq(plain->operands[1].mem.base, spelunk::Reg::Esp, "base esp");
        check_eq(plain->operands[1].mem.disp, static_cast<spelunk::i64>(4), "disp 4");
    }
    // 0x67 selects 16-bit addressing: mod=01, rm=000 -> [bx+si+disp8].
    auto narrow = dec.decode(bytes({0x67, 0x8B, 0x40, 0x04}), 0x401004);
    check_eq(narrow.has_value(), true, "address-size override decodes");
    if (narrow) {
        check_eq(narrow->length, static_cast<spelunk::u8>(4), "addrsize prefix length");
        check_eq(narrow->operands[1].mem.address_size, static_cast<spelunk::u8>(2),
                 "address size is 16-bit");
        check_eq(narrow->operands[1].mem.base, spelunk::Reg::Bx, "base bx");
        check_eq(narrow->operands[1].mem.index, spelunk::Reg::Si, "index si");
        check_eq(narrow->operands[1].mem.disp, static_cast<spelunk::i64>(4), "disp 4");
    }
}

void test_x87_stack_slots_and_ret_immediate() {
    const spelunk::X64Decoder dec(false);
    // fadd st(1), st
    auto fadd = dec.decode(bytes({0xD8, 0xC1}), 0x401000);
    check_eq(fadd.has_value(), true, "d8 c1 decodes");
    if (fadd) {
        check_eq(fadd->mnemonic, spelunk::Mnemonic::X87Fadd, "d8 c1 is fadd");
        check_eq(fadd->operands[0].x87_stack, static_cast<spelunk::u8>(1), "first st slot");
        check_eq(fadd->operands[1].x87_stack, static_cast<spelunk::u8>(0), "second st slot");
    }
    // ret 8: stdcall callee pops two stack arguments.
    auto ret = dec.decode(bytes({0xC2, 0x08, 0x00}), 0x401002);
    check_eq(ret.has_value(), true, "c2 08 00 decodes");
    if (ret) {
        check_eq(ret->mnemonic, spelunk::Mnemonic::Ret, "c2 is ret");
        check_eq(ret->length, static_cast<spelunk::u8>(3), "ret imm16 length");
        check_eq(ret->num_operands, static_cast<spelunk::u8>(1), "ret imm16 operand count");
        check_eq(ret->operands[0].imm.value, static_cast<spelunk::i64>(8), "ret pops 8");
    }
}

}  // namespace

int main() {
    test_inc_dec_are_opcodes_not_rex();
    test_arpl_is_reported_not_implemented();
    test_lds_is_not_a_vex_prefix();
    test_address_size_defaults_and_override();
    test_x87_stack_slots_and_ret_immediate();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
