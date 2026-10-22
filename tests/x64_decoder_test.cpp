#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/ir/x64_lifter.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <tuple>
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
    const spelunk::X64Decoder dec;
    auto insn = dec.decode(code, 0x69e92e5);
    if (!insn) {
        std::fprintf(stderr, "FAIL: popcnt decode failed: %s\n",
                     insn.error().message.c_str());
        ++fails;
        return;
    }
    check_eq(insn->mnemonic, spelunk::Mnemonic::Popcnt, "popcnt mnemonic");
    check_eq(insn->length, static_cast<spelunk::u8>(5), "popcnt length");
    check_eq(insn->num_operands, static_cast<spelunk::u8>(2), "popcnt operands");
    check_eq(insn->operands[0].kind, spelunk::Operand::Kind::Register, "dst reg");
    check_eq(insn->operands[0].reg, spelunk::Reg::Rax, "dst rax");
    check_eq(insn->operands[1].kind, spelunk::Operand::Kind::Register, "src reg");
    check_eq(insn->operands[1].reg, spelunk::Reg::Rdx, "src rdx");
}

void test_flag_control_one_byte_opcodes() {
    struct Case {
        std::byte byte;
        spelunk::Mnemonic mnemonic;
        const char* name;
    };
    constexpr std::array<Case, 11> cases{{
        {std::byte{0x9C}, spelunk::Mnemonic::Pushf,  "pushf"},
        {std::byte{0x9D}, spelunk::Mnemonic::Popf,   "popf"},
        {std::byte{0x9E}, spelunk::Mnemonic::Sahf,   "sahf"},
        {std::byte{0x9F}, spelunk::Mnemonic::Lahf,   "lahf"},
        {std::byte{0xF5}, spelunk::Mnemonic::Cmc,    "cmc"},
        {std::byte{0xF8}, spelunk::Mnemonic::Clc,    "clc"},
        {std::byte{0xF9}, spelunk::Mnemonic::Stc,    "stc"},
        {std::byte{0xFA}, spelunk::Mnemonic::Cli,    "cli"},
        {std::byte{0xFB}, spelunk::Mnemonic::Sti,    "sti"},
        {std::byte{0xFC}, spelunk::Mnemonic::Cld,    "cld"},
        {std::byte{0xFD}, spelunk::Mnemonic::StdDir, "std"},
    }};

    const spelunk::X64Decoder dec;
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
        check_eq(insn->length, static_cast<spelunk::u8>(1), c.name);
        check_eq(insn->num_operands, static_cast<spelunk::u8>(0), c.name);
    }
}

void test_rotate_through_carry_group2() {
    const spelunk::X64Decoder dec;

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
            check_eq(insn->mnemonic, spelunk::Mnemonic::Rcl, "rcl mnemonic");
            check_eq(insn->length, static_cast<spelunk::u8>(2), "rcl length");
            check_eq(insn->num_operands, static_cast<spelunk::u8>(2), "rcl operands");
            check_eq(insn->operands[0].kind, spelunk::Operand::Kind::Register, "rcl dst kind");
            check_eq(insn->operands[0].reg, spelunk::Reg::Eax, "rcl dst eax");
            check_eq(insn->operands[1].kind, spelunk::Operand::Kind::Immediate, "rcl count kind");
            check_eq(insn->operands[1].imm.value, static_cast<spelunk::i64>(1), "rcl count");
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
            check_eq(insn->mnemonic, spelunk::Mnemonic::Rcr, "rcr mnemonic");
            check_eq(insn->length, static_cast<spelunk::u8>(3), "rcr length");
            check_eq(insn->num_operands, static_cast<spelunk::u8>(2), "rcr operands");
            check_eq(insn->operands[0].kind, spelunk::Operand::Kind::Register, "rcr dst kind");
            check_eq(insn->operands[0].reg, spelunk::Reg::Eax, "rcr dst eax");
            check_eq(insn->operands[1].kind, spelunk::Operand::Kind::Immediate, "rcr count kind");
            check_eq(insn->operands[1].imm.value, static_cast<spelunk::i64>(2), "rcr count");
        }
    }
}

void test_long_mode_prefix_edge_cases() {
    const spelunk::X64Decoder dec;
    {
        const std::array<std::byte, 8> code{
            std::byte{0x67}, std::byte{0x48}, std::byte{0x8b}, std::byte{0x05},
            std::byte{0x78}, std::byte{0x56}, std::byte{0x34}, std::byte{0x12},
        };
        auto i = dec.decode(code, 0x1000);
        check_eq(i.has_value(), true, "addr32 absolute decode");
        if (i) {
            check_eq(i->operands[1].mem.base, spelunk::Reg::None,
                     "addr32 mod00/rm5 is not RIP-relative");
            check_eq(i->operands[1].mem.address_size, static_cast<spelunk::u8>(4),
                     "addr32 memory address width");
            check_eq(i->operands[1].mem.disp, static_cast<spelunk::i64>(0x12345678),
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
            check_eq(i->length, static_cast<spelunk::u8>(6),
                     "prefixed near call keeps rel32");
            check_eq(i->operands[0].rel.size, static_cast<spelunk::u8>(4),
                     "prefixed near call displacement width");
        }
    }
}

spelunk::IrFunction lift_one(std::span<const std::byte> code,
                           spelunk::Abi abi = spelunk::Abi::SysVAmd64) {
    const spelunk::X64Decoder dec;
    auto decoded = dec.decode(code, 0x1000);
    if (!decoded) {
        std::fprintf(stderr, "FAIL: x64 lift decode: %s\n",
                     decoded.error().message.c_str());
        ++fails;
        return {};
    }
    spelunk::Function fn;
    fn.start = 0x1000;
    fn.end = 0x1000 + decoded->length;
    spelunk::BasicBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = spelunk::BlockKind::Return;
    bb.instructions.push_back(*decoded);
    fn.blocks.push_back(std::move(bb));
    spelunk::X64Lifter lifter{abi};
    auto ir = lifter.lift(fn);
    if (!ir) {
        std::fprintf(stderr, "FAIL: x64 lift: %s\n", ir.error().message.c_str());
        ++fails;
        return {};
    }
    return std::move(*ir);
}

void test_vex_evex_and_bmi_decode() {
    const spelunk::X64Decoder decoder;
    {
        const std::array<std::byte, 4> code{
            std::byte{0xC5}, std::byte{0xF4}, std::byte{0x58}, std::byte{0xC2}};
        auto instruction = decoder.decode(code, 0x1000);
        check_eq(instruction.has_value(), true, "VEX vaddps decode");
        if (instruction) {
            check_eq(instruction->mnemonic, spelunk::Mnemonic::Addps,
                     "VEX vaddps mnemonic");
            check_eq(instruction->num_operands, static_cast<spelunk::u8>(3),
                     "VEX vaddps operand count");
            check_eq(instruction->operands[0].reg, spelunk::Reg::Ymm0,
                     "VEX vaddps destination");
            check_eq(instruction->operands[1].reg, spelunk::Reg::Ymm1,
                     "VEX vaddps first source");
            check_eq(instruction->operands[2].reg, spelunk::Reg::Ymm2,
                     "VEX vaddps second source");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("vaddps ymm0, ymm1, ymm2"),
                     "VEX vaddps formatting");
        }
    }
    {
        const std::array<std::byte, 6> code{
            std::byte{0x62}, std::byte{0xF1}, std::byte{0x74},
            std::byte{0x48}, std::byte{0x58}, std::byte{0xC2}};
        auto instruction = decoder.decode(code, 0x2000);
        check_eq(instruction.has_value(), true, "EVEX vaddps decode");
        if (instruction) {
            check_eq(instruction->operands[0].reg, spelunk::Reg::Zmm0,
                     "EVEX destination width");
            check_eq(instruction->operands[1].reg, spelunk::Reg::Zmm1,
                     "EVEX first source width");
            check_eq(instruction->operands[2].reg, spelunk::Reg::Zmm2,
                     "EVEX second source width");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("vaddps zmm0, zmm1, zmm2"),
                     "EVEX vaddps formatting");
        }
    }
    {
        const std::array<std::byte, 6> code{
            std::byte{0x62}, std::byte{0xF1}, std::byte{0x74},
            std::byte{0xC9}, std::byte{0x58}, std::byte{0xC2}};
        auto instruction = decoder.decode(code, 0x2800);
        check_eq(instruction.has_value(), true, "masked EVEX vaddps decode");
        if (instruction) {
            check_eq(instruction->x86_mask, static_cast<spelunk::u8>(1),
                     "EVEX mask register");
            check_eq(instruction->x86_zeroing, true, "EVEX zeroing mode");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("vaddps zmm0 {k1} {z}, zmm1, zmm2"),
                     "masked EVEX formatting");
        }
    }
    {
        const std::array<std::byte, 5> code{
            std::byte{0xC4}, std::byte{0xE2}, std::byte{0xF0},
            std::byte{0xF2}, std::byte{0xC2}};
        auto instruction = decoder.decode(code, 0x3000);
        check_eq(instruction.has_value(), true, "BMI andn decode");
        if (instruction) {
            check_eq(instruction->mnemonic, spelunk::Mnemonic::Andn,
                     "BMI andn mnemonic");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("andn rax, rcx, rdx"),
                     "BMI andn formatting");
        }
    }
    {
        const std::array<std::byte, 5> code{
            std::byte{0xC4}, std::byte{0xE2}, std::byte{0x75},
            std::byte{0x98}, std::byte{0xC2}};
        auto instruction = decoder.decode(code, 0x3800);
        check_eq(instruction.has_value(), true, "FMA vfmadd132ps decode");
        if (instruction) {
            check_eq(instruction->mnemonic, spelunk::Mnemonic::Vfmadd132ps,
                     "FMA mnemonic");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("vfmadd132ps ymm0, ymm1, ymm2"),
                     "FMA formatting");
        }
    }
    {
        const std::array<std::byte, 3> code{
            std::byte{0xC5}, std::byte{0xF8}, std::byte{0x77}};
        auto instruction = decoder.decode(code, 0x4000);
        check_eq(instruction.has_value(), true, "vzeroupper decode");
        if (instruction) {
            check_eq(instruction->mnemonic, spelunk::Mnemonic::Vzeroupper,
                     "vzeroupper mnemonic");
            check_eq(spelunk::format_instruction(*instruction),
                     std::string("vzeroupper"), "vzeroupper formatting");
        }
    }
}

void test_vex_map2_opcode_tables() {
    struct Case {
        std::byte vex;
        std::byte opcode;
        spelunk::Mnemonic mnemonic;
        const char* text;
    };
    constexpr std::array<Case, 9> cases{{
        {std::byte{0xF0}, std::byte{0xF5}, spelunk::Mnemonic::Bzhi,
         "bzhi rax, rdx, rcx"},
        {std::byte{0xF1}, std::byte{0xF7}, spelunk::Mnemonic::Shlx,
         "shlx rax, rdx, rcx"},
        {std::byte{0xF2}, std::byte{0xF5}, spelunk::Mnemonic::Pext,
         "pext rax, rcx, rdx"},
        {std::byte{0xF2}, std::byte{0xF7}, spelunk::Mnemonic::Sarx,
         "sarx rax, rdx, rcx"},
        {std::byte{0xF3}, std::byte{0xF5}, spelunk::Mnemonic::Pdep,
         "pdep rax, rcx, rdx"},
        {std::byte{0xF3}, std::byte{0xF6}, spelunk::Mnemonic::Mulx,
         "mulx rax, rcx, rdx"},
        {std::byte{0xF3}, std::byte{0xF7}, spelunk::Mnemonic::Shrx,
         "shrx rax, rdx, rcx"},
        {std::byte{0xF5}, std::byte{0xA8}, spelunk::Mnemonic::Vfmadd213pd,
         "vfmadd213pd ymm0, ymm1, ymm2"},
        {std::byte{0xF1}, std::byte{0xB9}, spelunk::Mnemonic::Vfmadd231sd,
         "vfmadd231sd xmm0, xmm1, xmm2"},
    }};

    const spelunk::X64Decoder decoder;
    for (const auto& c : cases) {
        const std::array<std::byte, 5> code{
            std::byte{0xC4}, std::byte{0xE2}, c.vex, c.opcode,
            std::byte{0xC2},
        };
        auto instruction = decoder.decode(code, 0x4800);
        if (!instruction) {
            std::fprintf(stderr, "FAIL: %s decode failed: %s\n", c.text,
                         instruction.error().message.c_str());
            ++fails;
            continue;
        }
        check_eq(instruction->mnemonic, c.mnemonic, c.text);
        check_eq(instruction->length, static_cast<spelunk::u8>(code.size()),
                 c.text);
        check_eq(instruction->num_operands, static_cast<spelunk::u8>(3),
                 c.text);
        check_eq(instruction->x86_vex, true, c.text);
        for (spelunk::u8 i = 0; i < instruction->num_operands; ++i) {
            check_eq(instruction->operands[i].kind,
                     spelunk::Operand::Kind::Register, c.text);
        }
        check_eq(spelunk::format_instruction(*instruction), std::string(c.text),
                 c.text);
    }
}

void test_x64_fp_call_lanes_and_vex_lift() {
    const std::array<std::byte, 5> call{
        std::byte{0xE8}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
    for (const auto& [abi, expected_args, expected_clobbers] :
         std::array{
             std::tuple{spelunk::Abi::SysVAmd64, 8u, 16u},
             std::tuple{spelunk::Abi::Win64, 4u, 6u}}) {
        auto ir = lift_one(call, abi);
        unsigned fp_args = 0;
        unsigned fp_clobbers = 0;
        for (const auto& instruction : ir.blocks[0].insts) {
            if (instruction.op == spelunk::IrOp::Intrinsic &&
                instruction.name.starts_with("call.fp_args.")) {
                fp_args += instruction.src_count;
            }
            if (instruction.op == spelunk::IrOp::Clobber &&
                instruction.dst.kind == spelunk::IrValueKind::Reg &&
                spelunk::is_xmm(instruction.dst.reg)) {
                ++fp_clobbers;
            }
        }
        check_eq(fp_args, expected_args, "x64 FP call argument lanes");
        check_eq(fp_clobbers, expected_clobbers, "x64 FP call clobbers");
    }

    const std::array<std::byte, 4> vaddps{
        std::byte{0xC5}, std::byte{0xF4}, std::byte{0x58}, std::byte{0xC2}};
    auto ir = lift_one(vaddps);
    bool saw_avx_intrinsic = false;
    bool wrote_ymm0 = false;
    for (const auto& instruction : ir.blocks[0].insts) {
        saw_avx_intrinsic |= instruction.op == spelunk::IrOp::Intrinsic &&
            instruction.name == "_mm256_add_ps" &&
            instruction.dst.type == spelunk::IrType::I256 &&
            instruction.src_count == 2 &&
            instruction.srcs[0].reg == spelunk::Reg::Ymm1 &&
            instruction.srcs[1].reg == spelunk::Reg::Ymm2;
        wrote_ymm0 |= instruction.op == spelunk::IrOp::Assign &&
            instruction.dst.kind == spelunk::IrValueKind::Reg &&
            instruction.dst.reg == spelunk::Reg::Ymm0;
    }
    check_eq(saw_avx_intrinsic && wrote_ymm0, true,
             "VEX non-destructive AVX lift");

    const std::array<std::byte, 6> masked_avx512{
        std::byte{0x62}, std::byte{0xF1}, std::byte{0x74},
        std::byte{0xC9}, std::byte{0x58}, std::byte{0xC2}};
    ir = lift_one(masked_avx512);
    bool preserved_mask = false;
    for (const auto& instruction : ir.blocks[0].insts) {
        preserved_mask |= instruction.op == spelunk::IrOp::Intrinsic &&
            instruction.name == "avx512.maskz._mm512_add_ps" &&
            instruction.dst.type == spelunk::IrType::I512 &&
            instruction.src_count == 3 &&
            instruction.srcs[2].reg == spelunk::Reg::K1;
    }
    check_eq(preserved_mask, true, "EVEX mask semantics remain explicit in IR");

    const std::array<std::byte, 5> fma{
        std::byte{0xC4}, std::byte{0xE2}, std::byte{0x75},
        std::byte{0x98}, std::byte{0xC2}};
    ir = lift_one(fma);
    // vfmadd132ps ymm0, ymm1, ymm2 computes ymm0 * ymm2 + ymm1.
    bool saw_fma = false;
    for (const auto& instruction : ir.blocks[0].insts) {
        saw_fma |= instruction.op == spelunk::IrOp::Intrinsic &&
            instruction.name == "_mm256_fmadd_ps" &&
            instruction.dst.type == spelunk::IrType::I256 &&
            instruction.src_count == 3 &&
            instruction.srcs[0].reg == spelunk::Reg::Ymm0 &&
            instruction.srcs[1].reg == spelunk::Reg::Ymm2 &&
            instruction.srcs[2].reg == spelunk::Reg::Ymm1;
    }
    check_eq(saw_fma, true, "FMA3 operand ordering remains explicit in IR");
}

void test_word_push_pop_width() {
    const std::array<std::byte, 2> push{std::byte{0x66}, std::byte{0x50}};
    auto ir = lift_one(push);
    bool store_i16 = false, sub_two = false;
    for (const auto& i : ir.blocks[0].insts) {
        store_i16 |= i.op == spelunk::IrOp::Store &&
                     i.srcs[1].type == spelunk::IrType::I16;
        sub_two |= i.op == spelunk::IrOp::Sub && i.src_count == 2 &&
                   i.srcs[1].kind == spelunk::IrValueKind::Imm &&
                   i.srcs[1].imm == 2;
    }
    check_eq(store_i16 && sub_two, true, "pushw uses a two-byte stack slot");

    const std::array<std::byte, 2> pop{std::byte{0x66}, std::byte{0x58}};
    ir = lift_one(pop);
    bool load_i16 = false, add_two = false;
    for (const auto& i : ir.blocks[0].insts) {
        load_i16 |= i.op == spelunk::IrOp::Load && i.dst.type == spelunk::IrType::I16;
        add_two |= i.op == spelunk::IrOp::Add && i.src_count == 2 &&
                   i.srcs[1].kind == spelunk::IrValueKind::Imm &&
                   i.srcs[1].imm == 2;
    }
    check_eq(load_i16 && add_two, true, "popw uses a two-byte stack slot");
}

using M = spelunk::Mnemonic;

// ---- x87 FPU escapes (D8-DF) ---------------------------------------------
// Hand-packed byte arrays. Every positive case asserts mnemonic, length and
// the full rendered text so operand order/shape regressions cannot slip
// through; negative cases assert the unsupported-error path, and reserved
// rows must additionally embed the instruction address in the message.

template <typename... Bs>
std::vector<std::byte> xb(Bs... bs) {
    return {std::byte{static_cast<unsigned char>(bs)}...};
}

struct X87Case {
    std::vector<std::byte> code;
    spelunk::Mnemonic m;
    const char* text;
};

void test_cmpss() {
    const spelunk::X64Decoder decoder;
    for (unsigned predicate = 0; predicate < 8; ++predicate) {
        const auto code = xb(0xF3, 0x0F, 0xC2, 0xCA, predicate);
        const auto insn = decoder.decode(code, 0x401000);
        check_eq(insn.has_value(), true, "cmpss register decode");
        if (!insn) continue;
        check_eq(insn->mnemonic, M::Cmpss, "cmpss mnemonic");
        check_eq(insn->length, 5, "cmpss length includes immediate");
        check_eq(insn->num_operands, 3, "cmpss operand count");
        check_eq(insn->operands[0].reg, spelunk::Reg::Xmm1, "cmpss destination");
        check_eq(insn->operands[1].reg, spelunk::Reg::Xmm2, "cmpss source");
        check_eq(insn->operands[2].imm.value, predicate, "cmpss predicate");
        check_eq(insn->prefixes.rep, false, "cmpss consumes F3 prefix");
        const auto ir = lift_one(code);
        bool mask = false;
        for (const auto& i : ir.blocks[0].insts) {
            mask |= i.op == spelunk::IrOp::Intrinsic && i.dst.type == spelunk::IrType::I128 &&
                    i.src_count == 2 && i.srcs[0].type == spelunk::IrType::I128 &&
                    i.srcs[1].type == spelunk::IrType::F32;
            check_eq(i.dst.kind == spelunk::IrValueKind::Flag, false, "cmpss leaves flags intact");
        }
        check_eq(mask, true, "cmpss retains upper lanes in mask result");
    }
    const auto memory = xb(0xF3, 0x44, 0x0F, 0xC2, 0x05, 0x10, 0, 0, 0, 0x07);
    const auto insn = decoder.decode(memory, 0x401000);
    check_eq(insn.has_value(), true, "cmpss RIP-relative decode");
    if (insn) {
        check_eq(insn->length, 10, "cmpss memory length");
        check_eq(insn->operands[0].reg, spelunk::Reg::Xmm8, "cmpss extended register");
        check_eq(insn->operands[1].mem.size, 4, "cmpss memory width");
    }
    const auto ir = lift_one(memory);
    bool scalar_load = false;
    for (const auto& i : ir.blocks[0].insts)
        scalar_load |= i.op == spelunk::IrOp::Load && i.dst.type == spelunk::IrType::F32;
    check_eq(scalar_load, true, "cmpss memory reads only four bytes");
    for (std::size_t n = 0; n < memory.size(); ++n)
        check_eq(decoder.decode(std::span(memory).first(n), 0x401000).has_value(), false,
                 "truncated cmpss rejected");
    for (const auto& code : {xb(0xC5, 0xF2, 0xC2, 0xC2, 0x01),
                            xb(0x62, 0xF1, 0x76, 0x08, 0xC2, 0xC2, 0x01)})
        check_eq(decoder.decode(code, 0x401000).has_value(), false,
                 "VCMPSS does not inherit legacy predicate or destination semantics");
}

struct X87Bad {
    std::vector<std::byte> code;
    const char* what;
};

void run_x87(const std::vector<X87Case>& pos, const std::vector<X87Bad>& neg,
             bool neg_want_addr) {
    const spelunk::X64Decoder dec;
    for (const auto& c : pos) {
        auto insn = dec.decode(c.code, 0x401000);
        if (!insn) {
            std::fprintf(stderr, "FAIL: x87 %s decode failed: %s\n", c.text,
                         insn.error().message.c_str());
            ++fails;
            continue;
        }
        check_eq(insn->mnemonic, c.m, c.text);
        check_eq(insn->length,
                 static_cast<spelunk::u8>(c.code.size()), c.text);
        check_eq(spelunk::format_instruction(*insn), std::string(c.text),
                 c.text);
    }
    for (const auto& b : neg) {
        auto insn = dec.decode(b.code, 0x401000);
        if (insn) {
            std::fprintf(stderr, "FAIL: %s should hit the unsupported path\n",
                         b.what);
            ++fails;
            continue;
        }
        if (neg_want_addr) {
            check_eq(insn.error().message.find("401000") != std::string::npos,
                     true, b.what);
        }
    }
}

void test_x87_d8_d9_memory_register_state() {
    run_x87(
        {
            // D8: /N selects the op over m32 real; st(i), st(0) reg forms.
            {{xb(0xD8, 0x00)}, M::X87Fadd, "fadd dword ptr [rax]"},
            {{xb(0xD8, 0x4B, 0x10)}, M::X87Fmul, "fmul dword ptr [rbx + 0x10]"},
            {{xb(0xD8, 0x15, 0x78, 0x56, 0x34, 0x12)},
             M::X87Fcom, "fcom dword ptr [0x1274667e]"},
            {{xb(0xD8, 0x1D, 0x78, 0x56, 0x34, 0x12)},
             M::X87Fcomp, "fcomp dword ptr [0x1274667e]"},
            {{xb(0xD8, 0x61, 0x08)}, M::X87Fsub, "fsub dword ptr [rcx + 0x8]"},
            {{xb(0xD8, 0x6A, 0xF4)}, M::X87Fsubr, "fsubr dword ptr [rdx - 0xc]"},
            {{xb(0xD8, 0x30)}, M::X87Fdiv, "fdiv dword ptr [rax]"},
            {{xb(0xD8, 0x39)}, M::X87Fdivr, "fdivr dword ptr [rcx]"},
            {{xb(0xD8, 0xC1)}, M::X87Fadd, "fadd st(1), st(0)"},
            {{xb(0xD8, 0xCA)}, M::X87Fmul, "fmul st(2), st(0)"},
            {{xb(0xD8, 0xD3)}, M::X87Fcom, "fcom st(3)"},
            {{xb(0xD8, 0xDC)}, M::X87Fcomp, "fcomp st(4)"},
            {{xb(0xD8, 0xE5)}, M::X87Fsub, "fsub st(5), st(0)"},
            {{xb(0xD8, 0xEE)}, M::X87Fsubr, "fsubr st(6), st(0)"},
            {{xb(0xD8, 0xF7)}, M::X87Fdiv, "fdiv st(7), st(0)"},
            {{xb(0xD8, 0xF9)}, M::X87Fdivr, "fdivr st(1), st(0)"},
            // D9: m32 transfers, control/status word, stack + state ops.
            {{xb(0xD9, 0x00)}, M::X87Fld, "fld dword ptr [rax]"},
            {{xb(0xD9, 0x11)}, M::X87Fst, "fst dword ptr [rcx]"},
            {{xb(0xD9, 0x1C, 0x24)}, M::X87Fstp, "fstp dword ptr [rsp]"},
            {{xb(0xD9, 0xC3)}, M::X87Fld, "fld st(3)"},
            {{xb(0xD9, 0xCA)}, M::X87Fxch, "fxch st(2)"},
            {{xb(0xD9, 0xE0)}, M::X87Fchs, "fchs"},
            {{xb(0xD9, 0xE1)}, M::X87Fabs, "fabs"},
            {{xb(0xD9, 0xFA)}, M::X87Fsqrt, "fsqrt"},
            // /4-/7 are fldenv, fldcw, fnstenv, fnstcw (Intel SDM D9).
            {{xb(0xD9, 0x20)}, M::X87Fldenv, "fldenv [rax]"},
            {{xb(0xD9, 0x28)}, M::X87Fldcw, "fldcw word ptr [rax]"},
            {{xb(0xD9, 0x30)}, M::X87Fnstenv, "fnstenv [rax]"},
            {{xb(0xD9, 0x38)}, M::X87Fnstcw, "fnstcw word ptr [rax]"},
            {{xb(0xD9, 0x68, 0x02)}, M::X87Fldcw, "fldcw word ptr [rax + 0x2]"},
            {{xb(0xD9, 0xD0)}, M::X87Fnop, "fnop"},
            {{xb(0xD9, 0xE4)}, M::X87Ftst, "ftst"},
            {{xb(0xD9, 0xE5)}, M::X87Fxam, "fxam"},
            {{xb(0xD9, 0xE8)}, M::X87Fld1, "fld1"},
            {{xb(0xD9, 0xEB)}, M::X87Fldpi, "fldpi"},
            {{xb(0xD9, 0xEE)}, M::X87Fldz, "fldz"},
            {{xb(0xD9, 0xF3)}, M::X87Fpatan, "fpatan"},
            {{xb(0xD9, 0xFB)}, M::X87Fsincos, "fsincos"},
            {{xb(0xD9, 0xFC)}, M::X87Frndint, "frndint"},
            {{xb(0xD9, 0xFF)}, M::X87Fcos, "fcos"},
            // DA: m32 integer arithmetic, fcmov, fucompp.
            {{xb(0xDA, 0x00)}, M::X87Fiadd, "fiadd dword ptr [rax]"},
            {{xb(0xDA, 0x3B)}, M::X87Fidivr, "fidivr dword ptr [rbx]"},
            {{xb(0xDA, 0xC1)}, M::X87Fcmovb, "fcmovb st(0), st(1)"},
            {{xb(0xDA, 0xDA)}, M::X87Fcmovu, "fcmovu st(0), st(2)"},
            {{xb(0xDA, 0xE9)}, M::X87Fucompp, "fucompp"},
        },
        {
            // Truncated disp32 errors out instead of misdecoding.
            {{xb(0xD8, 0xA0)}, "truncated x87 m32 disp32"},
            // Reserved/not-modeled rows land on not_implemented with addr.
            {{xb(0xD9, 0x08)}, "reserved D9 /1"},
            {{xb(0xD9, 0xD1)}, "reserved D9 D1"},
            {{xb(0xD9, 0xE2)}, "reserved D9 E2"},
            {{xb(0xDA, 0xE8)}, "reserved DA E8"},
        },
        false);
}

void test_x87_dc_dd_m64_and_fucom() {
    run_x87(
        {
            // DC: same /N rows as D8 but over m64 real.
            {{xb(0xDC, 0x00)}, M::X87Fadd, "fadd qword ptr [rax]"},
            {{xb(0xDC, 0x48, 0xF0)}, M::X87Fmul, "fmul qword ptr [rax - 0x10]"},
            {{xb(0xDC, 0x10)}, M::X87Fcom, "fcom qword ptr [rax]"},
            {{xb(0xDC, 0x19)}, M::X87Fcomp, "fcomp qword ptr [rcx]"},
            {{xb(0xDC, 0x20)}, M::X87Fsub, "fsub qword ptr [rax]"},
            {{xb(0xDC, 0x2B)}, M::X87Fsubr, "fsubr qword ptr [rbx]"},
            {{xb(0xDC, 0x32)}, M::X87Fdiv, "fdiv qword ptr [rdx]"},
            {{xb(0xDC, 0x3B)}, M::X87Fdivr, "fdivr qword ptr [rbx]"},
            // DC register rows write st(0) and swap sub/div vs D8:
            // E8 is fsub (not fsubr!), F8 fdiv, E0/F0 the R forms.
            {{xb(0xDC, 0xC1)}, M::X87Fadd, "fadd st(0), st(1)"},
            {{xb(0xDC, 0xCA)}, M::X87Fmul, "fmul st(0), st(2)"},
            {{xb(0xDC, 0xE1)}, M::X87Fsubr, "fsubr st(0), st(1)"},
            {{xb(0xDC, 0xEA)}, M::X87Fsub, "fsub st(0), st(2)"},
            {{xb(0xDC, 0xF3)}, M::X87Fdivr, "fdivr st(0), st(3)"},
            {{xb(0xDC, 0xFC)}, M::X87Fdiv, "fdiv st(0), st(4)"},
            // DD: m64 transfers, fnstsw m16, fucom/fucomp st(i).
            {{xb(0xDD, 0x00)}, M::X87Fld, "fld qword ptr [rax]"},
            {{xb(0xDD, 0x10)}, M::X87Fst, "fst qword ptr [rax]"},
            {{xb(0xDD, 0x1C, 0x24)}, M::X87Fstp, "fstp qword ptr [rsp]"},
            {{xb(0xDD, 0x3C, 0x24)}, M::X87Fnstsw, "fnstsw word ptr [rsp]"},
            {{xb(0xDD, 0xD1)}, M::X87Fst, "fst st(1)"},
            {{xb(0xDD, 0xDA)}, M::X87Fstp, "fstp st(2)"},
            {{xb(0xDD, 0xE3)}, M::X87Fucom, "fucom st(3)"},
            {{xb(0xDD, 0xEC)}, M::X87Fucomp, "fucomp st(4)"},
            {{xb(0xDD, 0x08)}, M::X87Fisttp, "fisttp qword ptr [rax]"},
            {{xb(0xDD, 0x20)}, M::X87Frstor, "frstor [rax]"},
            {{xb(0xDD, 0x30)}, M::X87Fnsave, "fnsave [rax]"},
            {{xb(0xDD, 0xC1)}, M::X87Ffree, "ffree st(1)"},
        },
        {
            {{xb(0xDC, 0xD1)}, "reserved DC D1"},
            {{xb(0xDC, 0xDA)}, "reserved DC DA"},
            {{xb(0xDD, 0x28)}, "reserved DD /5"},
            {{xb(0xDD, 0xF1)}, "reserved DD F1"},
        },
        true);
}

void test_x87_db_de_df_integer_pop_fini() {
    run_x87(
        {
            // DB: m32 integer and m80 transfers, fcmovn*, fucomi/fcomi,
            // fnclex and finit. The popping compares live in DF.
            {{xb(0xDB, 0x00)}, M::X87Fild, "fild dword ptr [rax]"},
            {{xb(0xDB, 0x08)}, M::X87Fisttp, "fisttp dword ptr [rax]"},
            {{xb(0xDB, 0x11)}, M::X87Fist, "fist dword ptr [rcx]"},
            {{xb(0xDB, 0x5C, 0x24, 0x40)}, M::X87Fistp, "fistp dword ptr [rsp + 0x40]"},
            {{xb(0xDB, 0x28)}, M::X87Fld, "fld tbyte ptr [rax]"},
            {{xb(0xDB, 0x38)}, M::X87Fstp, "fstp tbyte ptr [rax]"},
            {{xb(0xDB, 0xC9)}, M::X87Fcmovne, "fcmovne st(0), st(1)"},
            {{xb(0xDB, 0xE9)}, M::X87Fucomi, "fucomi st(1)"},
            {{xb(0xDB, 0xF3)}, M::X87Fcomi, "fcomi st(3)"},
            {{xb(0xDB, 0xE2)}, M::X87Fnclex, "fnclex"},
            {{xb(0xDB, 0xE3)}, M::X87Finit, "finit"},
            // DE: pop variants write st(i) then pop; D9 lone fcompp.
            {{xb(0xDE, 0xC1)}, M::X87Faddp, "faddp st(1), st(0)"},
            {{xb(0xDE, 0xCA)}, M::X87Fmulp, "fmulp st(2), st(0)"},
            {{xb(0xDE, 0xE3)}, M::X87Fsubrp, "fsubrp st(3), st(0)"},
            {{xb(0xDE, 0xEC)}, M::X87Fsubp, "fsubp st(4), st(0)"},
            {{xb(0xDE, 0xF5)}, M::X87Fdivrp, "fdivrp st(5), st(0)"},
            {{xb(0xDE, 0xFE)}, M::X87Fdivp, "fdivp st(6), st(0)"},
            {{xb(0xDE, 0xD9)}, M::X87Fcompp, "fcompp"},
            {{xb(0xDE, 0x00)}, M::X87Fiadd, "fiadd word ptr [rax]"},
            {{xb(0xDE, 0x29)}, M::X87Fisubr, "fisubr word ptr [rcx]"},
            // DF: m16/m64 integer transfers; E0 stores status to AX.
            {{xb(0xDF, 0x00)}, M::X87Fild, "fild word ptr [rax]"},
            {{xb(0xDF, 0x10)}, M::X87Fist, "fist word ptr [rax]"},
            {{xb(0xDF, 0x1C, 0x24)}, M::X87Fistp, "fistp word ptr [rsp]"},
            {{xb(0xDF, 0x28)}, M::X87Fild, "fild qword ptr [rax]"},
            {{xb(0xDF, 0x39)}, M::X87Fistp, "fistp qword ptr [rcx]"},
            {{xb(0xDF, 0xE0)}, M::X87Fnstsw, "fnstsw ax"},
            {{xb(0xDF, 0xE9)}, M::X87Fucomip, "fucomip st(1)"},
            {{xb(0xDF, 0xF2)}, M::X87Fcomip, "fcomip st(2)"},
            {{xb(0xDF, 0x08)}, M::X87Fisttp, "fisttp word ptr [rax]"},
            {{xb(0xDF, 0x20)}, M::X87Fbld, "fbld tbyte ptr [rax]"},
            {{xb(0xDF, 0x30)}, M::X87Fbstp, "fbstp tbyte ptr [rax]"},
            {{xb(0xDF, 0xC4)}, M::X87Ffreep, "ffreep st(4)"},
        },
        {
            {{xb(0xDB, 0x20)}, "reserved DB /4"},
            {{xb(0xDB, 0xE1)}, "reserved DB E1"},
            {{xb(0xDE, 0xD1)}, "reserved DE D1"},
            {{xb(0xDE, 0xDA)}, "reserved DE DA"},
            {{xb(0xDF, 0xF9)}, "reserved DF F9"},
        },
        true);

    // Segment override must flow through to x87 memory operands.
    const spelunk::X64Decoder dec;
    auto insn =
        dec.decode(xb(0x64, 0xD8, 0x05, 0x78, 0x56, 0x34, 0x12),
                   0x401000);
    check_eq(insn.has_value(), true, "fs-prefixed x87 decode");
    if (insn) {
        check_eq(insn->operands[0].mem.segment, spelunk::Reg::Fs,
                 "segment override on x87 memory operand");
        check_eq(insn->length, static_cast<spelunk::u8>(7),
                 "prefix counted in x87 length");
    }
}

// cvtsd2si / cvtss2si round with MXCSR, unlike the truncating 2C forms;
// F3 REX.W 0F AE /5 is CET's incsspq.
void test_rounding_conversions_and_incssp() {
    const spelunk::X64Decoder decoder;
    struct Case {
        std::vector<std::byte> code;
        M mnemonic;
        const char* text;
        const char* intrinsic;
    };
    const std::array<Case, 4> cases{{
        {xb(0xF2, 0x48, 0x0F, 0x2D, 0xC0), M::Cvtsd2si, "cvtsd2si rax, xmm0", "cvtsd2si"},
        {xb(0xF3, 0x0F, 0x2D, 0xC1), M::Cvtss2si, "cvtss2si eax, xmm1", "cvtss2si"},
        {xb(0xC5, 0xFB, 0x2D, 0xC0), M::Cvtsd2si, "vcvtsd2si eax, xmm0", "cvtsd2si"},
        {xb(0xF3, 0x48, 0x0F, 0xAE, 0xEE), M::Incssp, "incssp rsi", "_incsspq"},
    }};
    for (const auto& c : cases) {
        const auto insn = decoder.decode(c.code, 0x401000);
        check_eq(insn.has_value(), true, c.text);
        if (!insn) continue;
        check_eq(insn->mnemonic, c.mnemonic, c.text);
        check_eq(insn->length, static_cast<spelunk::u8>(c.code.size()), c.text);
        check_eq(spelunk::format_instruction(*insn), std::string(c.text), c.text);
        bool lifted = false;
        for (const auto& i : lift_one(c.code).blocks[0].insts)
            lifted |= i.op == spelunk::IrOp::Intrinsic && i.name == c.intrinsic;
        check_eq(lifted, true, c.intrinsic);
    }
}

}  // namespace

int main() {
    test_cmpss();
    test_popcnt_f3_0f_b8();
    test_flag_control_one_byte_opcodes();
    test_rotate_through_carry_group2();
    test_long_mode_prefix_edge_cases();
    test_word_push_pop_width();
    test_vex_evex_and_bmi_decode();
    test_vex_map2_opcode_tables();
    test_x64_fp_call_lanes_and_vex_lift();
    test_x87_d8_d9_memory_register_state();
    test_x87_dc_dd_m64_and_fucom();
    test_x87_db_de_df_integer_pop_fini();
    test_rounding_conversions_and_incssp();
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
