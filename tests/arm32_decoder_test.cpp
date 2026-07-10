// Unit tests for the ARM (A32 / ARMv7) decoder.
//
// Hand-encoded 32-bit little-endian words (assembled from the ARM ARM) fed
// through the decoder; each check pins a mnemonic + operand shape, plus the
// A32-specific carriers arm_cond / arm_setflags / operand barrel-shift.
#include <ember/disasm/arm32_decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/ir/arm32_lifter.hpp>

#include <array>
#include <cstdio>
#include <span>
#include <string>

using namespace ember;

namespace {

int fails = 0;

void fail(const char* ctx) {
    std::fprintf(stderr, "FAIL: %s\n", ctx);
    ++fails;
}

template <typename A, typename B>
void check_eq(const A& got, const B& want, const char* ctx) {
    if (!(got == want)) fail(ctx);
}

std::array<std::byte, 4> le32(std::uint32_t v) {
    return {
        static_cast<std::byte>(v & 0xff),
        static_cast<std::byte>((v >> 8) & 0xff),
        static_cast<std::byte>((v >> 16) & 0xff),
        static_cast<std::byte>((v >> 24) & 0xff),
    };
}

Instruction must_decode(std::uint32_t raw, addr_t addr = 0x1000) {
    auto bytes = le32(raw);
    Arm32Decoder d;
    auto r = d.decode(std::span<const std::byte>(bytes.data(), 4), addr);
    if (!r) {
        std::fprintf(stderr, "FAIL: decode of %#010x: %s\n", raw,
                     r.error().message.c_str());
        ++fails;
        return {};
    }
    return *r;
}

void test_dp_immediate() {
    auto i = must_decode(0xE2810010);  // add r0, r1, #16
    check_eq(i.mnemonic, Mnemonic::A32Add, "add imm: mnemonic");
    check_eq(i.num_operands, std::uint8_t{3}, "add imm: nargs");
    check_eq(i.operands[0].reg, Reg::ArmR0, "add imm: rd");
    check_eq(i.operands[1].reg, Reg::ArmR1, "add imm: rn");
    check_eq(i.operands[2].imm.value, std::int64_t{16}, "add imm: imm");
    check_eq(i.arm_setflags, false, "add imm: S clear");
    check_eq(i.arm_cond, kArmCondAL, "add imm: cond AL");

    i = must_decode(0xE2432001);  // sub r2, r3, #1
    check_eq(i.mnemonic, Mnemonic::A32Sub, "sub imm: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR2, "sub imm: rd");
    check_eq(i.operands[2].imm.value, std::int64_t{1}, "sub imm: imm");

    i = must_decode(0xE3500001);  // cmp r0, #1
    check_eq(i.mnemonic, Mnemonic::A32Cmp, "cmp imm: mnemonic");
    check_eq(i.num_operands, std::uint8_t{2}, "cmp imm: nargs (no rd)");
    check_eq(i.operands[0].reg, Reg::ArmR0, "cmp imm: rn");
    check_eq(i.arm_setflags, false, "cmp imm: no visible S suffix");
}

void test_dp_register_and_shift() {
    auto i = must_decode(0xE1B00001);  // movs r0, r1
    check_eq(i.mnemonic, Mnemonic::A32Mov, "movs: mnemonic");
    check_eq(i.arm_setflags, true, "movs: S set");
    check_eq(i.operands[1].reg, Reg::ArmR1, "movs: rm");

    i = must_decode(0xE1A00101);  // mov r0, r1, lsl #2  → lsl r0, r1, #2
    check_eq(i.mnemonic, Mnemonic::A32Lsl, "lsl alias: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR0, "lsl alias: rd");
    check_eq(i.operands[1].reg, Reg::ArmR1, "lsl alias: rm");
    check_eq(i.operands[2].imm.value, std::int64_t{2}, "lsl alias: amt");

    i = must_decode(0xE0810182);  // add r0, r1, r2, lsl #3
    check_eq(i.mnemonic, Mnemonic::A32Add, "add shifted: mnemonic");
    check_eq(i.operands[2].reg, Reg::ArmR2, "add shifted: rm");
    check_eq(i.operands[2].arm_shift, ArmShift::Lsl, "add shifted: shift type");
    check_eq(i.operands[2].arm_shift_amt, std::uint8_t{3}, "add shifted: shift amt");

    i = must_decode(0xE0810312);  // add r0, r1, r2, lsl r3
    check_eq(i.operands[2].arm_shift_reg, Reg::ArmR3,
             "add register-shifted: shift register");
    check_eq(format_instruction(i), std::string{"add r0, r1, r2, lsl r3"},
             "add register-shifted: format");

    i = must_decode(0x12910001);  // addsne r0, r1, #1
    check_eq(format_instruction(i), std::string{"addnes r0, r1, 0x1"},
             "conditional S suffix order");
}

void test_multiply_and_media() {
    auto i = must_decode(0xE0000291);  // mul r0, r1, r2
    check_eq(i.mnemonic, Mnemonic::A32Mul, "mul: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR0, "mul: rd");
    check_eq(i.operands[1].reg, Reg::ArmR1, "mul: rm");
    check_eq(i.operands[2].reg, Reg::ArmR2, "mul: rs");

    i = must_decode(0xE730F211);  // udiv r0, r1, r2
    check_eq(i.mnemonic, Mnemonic::A32Udiv, "udiv: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR0, "udiv: rd");
    check_eq(i.operands[1].reg, Reg::ArmR1, "udiv: rn");
    check_eq(i.operands[2].reg, Reg::ArmR2, "udiv: rm");

    i = must_decode(0xE3010234);  // movw r0, #0x1234
    check_eq(i.mnemonic, Mnemonic::A32Movw, "movw: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR0, "movw: rd");
    check_eq(i.operands[1].imm.value, std::int64_t{0x1234}, "movw: imm");
}

void test_loads_stores() {
    auto i = must_decode(0xE5910004);  // ldr r0, [r1, #4]
    check_eq(i.mnemonic, Mnemonic::A32Ldr, "ldr: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR0, "ldr: rt");
    check_eq(i.operands[1].mem.base, Reg::ArmR1, "ldr: base");
    check_eq(i.operands[1].mem.disp, std::int64_t{4}, "ldr: disp");
    check_eq(i.operands[1].mem.size, std::uint8_t{4}, "ldr: size");

    i = must_decode(0xE50D2008);  // str r2, [sp, #-8]
    check_eq(i.mnemonic, Mnemonic::A32Str, "str: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR2, "str: rt");
    check_eq(i.operands[1].mem.base, Reg::Asp, "str: base sp");
    check_eq(i.operands[1].mem.disp, std::int64_t{-8}, "str: neg disp");

    i = must_decode(0xE7110002);  // ldr r0, [r1, -r2] (not representable by Mem)
    check_eq(i.mnemonic, Mnemonic::A32Undef,
             "negative register offset is not misdecoded as addition");
}

void test_block_transfer() {
    auto i = must_decode(0xE92D4010);  // push {r4, lr}
    check_eq(i.mnemonic, Mnemonic::A32Push, "push: mnemonic");
    check_eq(i.operands[1].imm.value, std::int64_t{0x4010}, "push: reglist");

    i = must_decode(0xE8BD8010);  // pop {r4, pc}  → return
    check_eq(i.mnemonic, Mnemonic::A32Ret, "pop-pc: return mnemonic");
    check_eq(i.operands[1].imm.value, std::int64_t{0x8010}, "pop-pc: reglist");

    i = must_decode(0xE8B08000);  // ldmia r0!, {pc} → indirect branch, not return
    check_eq(i.mnemonic, Mnemonic::A32LdmPc, "ldm-pc: indirect branch mnemonic");
}

void test_branches() {
    auto i = must_decode(0xEB00000E, 0x1000);  // bl 0x1040
    check_eq(i.mnemonic, Mnemonic::A32Bl, "bl: mnemonic");
    check_eq(i.operands[0].rel.target, addr_t{0x1040}, "bl: target");

    i = must_decode(0xEA0003FE, 0x1000);  // b 0x2000 (unconditional)
    check_eq(i.mnemonic, Mnemonic::A32B, "b: mnemonic");
    check_eq(i.operands[0].rel.target, addr_t{0x2000}, "b: target");

    i = must_decode(0x1A000002, 0x1000);  // bne 0x1010
    check_eq(i.mnemonic, Mnemonic::A32Bcc, "bne: mnemonic");
    check_eq(i.arm_cond, std::uint8_t{0x1}, "bne: cond NE");
    check_eq(i.operands[0].rel.target, addr_t{0x1010}, "bne: target");

    i = must_decode(0xE12FFF1E);  // bx lr → return
    check_eq(i.mnemonic, Mnemonic::A32Ret, "bx lr: return mnemonic");
    check_eq(i.operands[0].reg, Reg::Alr, "bx lr: reg");

    i = must_decode(0xE12FFF13);  // bx r3 → indirect
    check_eq(i.mnemonic, Mnemonic::A32Bx, "bx reg: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR3, "bx reg: reg");

    i = must_decode(0xE12FFF32);  // blx r2 → indirect call
    check_eq(i.mnemonic, Mnemonic::A32Blx, "blx reg: mnemonic");
    check_eq(i.operands[0].reg, Reg::ArmR2, "blx reg: reg");

    i = must_decode(0x1B00000E, 0x1000);  // blne 0x1040
    check_eq(i.mnemonic, Mnemonic::A32Bl, "blne: mnemonic");
    check_eq(i.arm_cond, std::uint8_t{1}, "blne: condition preserved");
}

IrFunction lift_one(std::uint32_t raw) {
    Function fn;
    fn.start = 0x1000; fn.end = 0x1004;
    BasicBlock bb;
    bb.start = fn.start; bb.end = fn.end; bb.kind = BlockKind::Return;
    bb.instructions.push_back(must_decode(raw));
    fn.blocks.push_back(std::move(bb));
    Arm32Lifter lifter(Abi::AapcsArm32);
    auto ir = lifter.lift(fn);
    if (!ir) { fail("arm32 lift failed"); return {}; }
    return std::move(*ir);
}

void test_lifter_regressions() {
    auto ir = lift_one(0xE1500001);  // cmp r0, r1
    bool saw_borrow = false, saw_invert = false;
    for (const auto& inst : ir.blocks[0].insts) {
        saw_borrow |= inst.op == IrOp::SubBorrow;
        saw_invert |= inst.op == IrOp::Not && inst.dst.type == IrType::I1;
    }
    check_eq(saw_borrow && saw_invert, true, "cmp: carry is inverted borrow");

    ir = lift_one(0xE0A10002);  // adc r0, r1, r2
    unsigned adds = 0;
    for (const auto& inst : ir.blocks[0].insts) adds += inst.op == IrOp::Add;
    check_eq(adds >= 2, true, "adc: includes carry-in addition");

    ir = lift_one(0x15810000);  // strne r0, [r1]
    bool guarded = false, plain_store = false;
    for (const auto& inst : ir.blocks[0].insts) {
        guarded |= inst.op == IrOp::Intrinsic && inst.name == "arm.store_if";
        plain_store |= inst.op == IrOp::Store;
    }
    check_eq(guarded && !plain_store, true, "strne: guarded side effect");
}

void test_system() {
    auto i = must_decode(0xEF000000);  // svc #0
    check_eq(i.mnemonic, Mnemonic::A32Svc, "svc: mnemonic");

    i = must_decode(0xE320F000);  // nop
    check_eq(i.mnemonic, Mnemonic::A32Nop, "nop: mnemonic");

    // A well-formed but unmodelled coprocessor word decodes shape-only and
    // keeps a length of 4 so the linear sweep does not derail.
    i = must_decode(0xEE070F58);  // mcr p15, ... (coprocessor)
    check_eq(i.mnemonic, Mnemonic::A32Undef, "coproc: shape-only udf");
    check_eq(i.length, std::uint8_t{4}, "coproc: length 4");
}

}  // namespace

int main() {
    test_dp_immediate();
    test_dp_register_and_shift();
    test_multiply_and_media();
    test_loads_stores();
    test_block_transfer();
    test_branches();
    test_system();
    test_lifter_regressions();

    if (fails == 0) {
        std::fprintf(stderr, "arm32_decoder_test: ok\n");
        return 0;
    }
    return 1;
}
