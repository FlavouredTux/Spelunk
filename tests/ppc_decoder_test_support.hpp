#pragma once

#include <ember/disasm/instruction.hpp>
#include <ember/disasm/ppc_decoder.hpp>
#include <ember/ir/ppc_lifter.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <span>
#include <string>
#include <tuple>
#include <utility>

namespace ppc_decoder_test {

inline int fails = 0;

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

inline std::array<std::byte, 4> be32(std::uint32_t v) {
    return {
        static_cast<std::byte>((v >> 24) & 0xff),
        static_cast<std::byte>((v >> 16) & 0xff),
        static_cast<std::byte>((v >> 8) & 0xff),
        static_cast<std::byte>(v & 0xff),
    };
}

inline ember::Instruction must_decode(std::uint32_t raw) {
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

inline ember::IrFunction lift_one(std::uint32_t raw) {
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

inline ember::IrFunction lift_words(std::initializer_list<std::uint32_t> words) {
    ember::Function fn;
    fn.start = 0x80003100;
    fn.end = fn.start + words.size() * 4;
    ember::BasicBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = ember::BlockKind::Return;
    ember::addr_t address = fn.start;
    for (std::uint32_t raw : words) {
        auto instruction = must_decode(raw);
        instruction.address = address;
        bb.instructions.push_back(std::move(instruction));
        address += 4;
    }
    fn.blocks.push_back(std::move(bb));
    ember::PpcLifter lifter(ember::Abi::Ppc32Sysv);
    auto ir = lifter.lift(fn);
    if (!ir) {
        std::fprintf(stderr, "FAIL: multi-word PPC lift: %s\n",
                     ir.error().message.c_str());
        ++fails;
        return {};
    }
    return std::move(*ir);
}

inline ember::IrFunction lift_conditional_pair(std::uint32_t first, std::uint32_t branch) {
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

inline std::uint32_t cr_logical_word(std::uint32_t bt, std::uint32_t ba,
                              std::uint32_t bb, std::uint32_t xo) {
    return (19u << 26) | (bt << 21) | (ba << 16) | (bb << 11) | (xo << 1);
}

inline std::uint32_t xo_word(std::uint32_t rs, std::uint32_t ra, std::uint32_t xo) {
    return (31u << 26) | (rs << 21) | (ra << 16) | (xo << 1);
}

inline std::uint32_t spr_word(std::uint32_t rt, std::uint32_t spr, std::uint32_t xo) {
    return (31u << 26) | (rt << 21) | ((spr & 0x1fu) << 16) |
           (((spr >> 5) & 0x1fu) << 11) | (xo << 1);
}

inline std::uint32_t ps_x_word(std::uint32_t fd, std::uint32_t fa,
                        std::uint32_t fb, std::uint32_t xo) {
    return (4u << 26) | (fd << 21) | (fa << 16) | (fb << 11) | (xo << 1);
}

inline std::uint32_t ps_a_word(std::uint32_t fd, std::uint32_t fa, std::uint32_t fb,
                        std::uint32_t fc, std::uint32_t xo) {
    return (4u << 26) | (fd << 21) | (fa << 16) | (fb << 11) |
           (fc << 6) | (xo << 1);
}

inline std::uint32_t ps_compare_word(std::uint32_t crfd, std::uint32_t fa,
                              std::uint32_t fb, std::uint32_t xo) {
    return (4u << 26) | (crfd << 23) | (fa << 16) | (fb << 11) | (xo << 1);
}

inline std::uint32_t fp_unary_word(std::uint32_t frt, std::uint32_t frb, std::uint32_t xo) {
    return (63u << 26) | (frt << 21) | (frb << 11) | (xo << 1);
}

inline std::uint32_t fp_a_word(std::uint32_t op, std::uint32_t frt, std::uint32_t fra,
                        std::uint32_t frb, std::uint32_t frc, std::uint32_t xo) {
    return (op << 26) | (frt << 21) | (fra << 16) | (frb << 11) |
           (frc << 6) | (xo << 1);
}

void run_integer_tests();
void run_floating_point_tests();
void run_control_flow_tests();
void run_paired_single_tests();

}  // namespace ppc_decoder_test
