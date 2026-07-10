#include <ember/disasm/x64_decoder.hpp>
#include <ember/ir/x64_lifter.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <utility>
#include <vector>

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

void test_long_mode_prefix_edge_cases() {
    const ember::X64Decoder dec;
    {
        const std::array<std::byte, 8> code{
            std::byte{0x67}, std::byte{0x48}, std::byte{0x8b}, std::byte{0x05},
            std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        };
        auto i = dec.decode(code, 0x1000);
        check_eq(i.has_value(), true, "addr32 absolute decode");
        if (i) {
            check_eq(i->operands[1].mem.base, ember::Reg::None,
                     "addr32 mod00/rm5 is not RIP-relative");
            check_eq(i->operands[1].mem.address_size, static_cast<ember::u8>(4),
                     "addr32 memory address width");
            check_eq(i->operands[1].mem.disp, static_cast<ember::i64>(0x12345678),
                     "addr32 absolute displacement");
        }
    }
    {
        const std::array<std::byte, 6> code{
            std::byte{0x66}, std::byte{0xe8}, std::byte{0x01},
            std::byte{0x02}, std::byte{0x03}, std::byte{0x04},
        };
        auto i = dec.decode(code, 0x1000);
        check_eq(i.has_value(), true, "prefixed near call decode");
        if (i) {
            check_eq(i->length, static_cast<ember::u8>(6),
                     "prefixed near call keeps rel32");
            check_eq(i->operands[0].rel.size, static_cast<ember::u8>(4),
                     "prefixed near call displacement width");
        }
    }
}

ember::IrFunction lift_one(std::span<const std::byte> code) {
    const ember::X64Decoder dec;
    auto decoded = dec.decode(code, 0x1000);
    if (!decoded) {
        std::fprintf(stderr, "FAIL: x64 lift decode: %s\n",
                     decoded.error().message.c_str());
        ++fails;
        return {};
    }
    ember::Function fn;
    fn.start = 0x1000;
    fn.end = 0x1000 + decoded->length;
    ember::BasicBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = ember::BlockKind::Return;
    bb.instructions.push_back(*decoded);
    fn.blocks.push_back(std::move(bb));
    ember::X64Lifter lifter;
    auto ir = lifter.lift(fn);
    if (!ir) {
        std::fprintf(stderr, "FAIL: x64 lift: %s\n", ir.error().message.c_str());
        ++fails;
        return {};
    }
    return std::move(*ir);
}

void test_word_push_pop_width() {
    const std::array<std::byte, 2> push{std::byte{0x66}, std::byte{0x50}};
    auto ir = lift_one(push);
    bool store_i16 = false, sub_two = false;
    for (const auto& i : ir.blocks[0].insts) {
        store_i16 |= i.op == ember::IrOp::Store &&
                     i.srcs[1].type == ember::IrType::I16;
        sub_two |= i.op == ember::IrOp::Sub && i.src_count == 2 &&
                   i.srcs[1].kind == ember::IrValueKind::Imm &&
                   i.srcs[1].imm == 2;
    }
    check_eq(store_i16 && sub_two, true, "pushw uses a two-byte stack slot");

    const std::array<std::byte, 2> pop{std::byte{0x66}, std::byte{0x58}};
    ir = lift_one(pop);
    bool load_i16 = false, add_two = false;
    for (const auto& i : ir.blocks[0].insts) {
        load_i16 |= i.op == ember::IrOp::Load && i.dst.type == ember::IrType::I16;
        add_two |= i.op == ember::IrOp::Add && i.src_count == 2 &&
                   i.srcs[1].kind == ember::IrValueKind::Imm &&
                   i.srcs[1].imm == 2;
    }
    check_eq(load_i16 && add_two, true, "popw uses a two-byte stack slot");
}

}  // namespace

int main() {
    test_popcnt_f3_0f_b8();
    test_flag_control_one_byte_opcodes();
    test_rotate_through_carry_group2();
    test_long_mode_prefix_edge_cases();
    test_word_push_pop_width();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
