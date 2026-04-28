// Unit tests for the AArch64 decoder.
//
// We feed hand-encoded 32-bit instructions (assembled by hand from the
// ARMv8 reference manual; the constants are chosen so a reader can spot
// them in a one-line `xxd` of a real binary) and check that each one
// decodes to the right mnemonic + operand shape.
#include <ember/disasm/arm64_decoder.hpp>
#include <ember/disasm/instruction.hpp>

#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

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
    Arm64Decoder d;
    auto r = d.decode(std::span<const std::byte>(bytes.data(), 4), addr);
    if (!r) {
        std::fprintf(stderr, "FAIL: decode of %#010x at %#llx: %s\n",
                     raw, static_cast<unsigned long long>(addr),
                     r.error().message.c_str());
        ++fails;
        return {};
    }
    return *r;
}

// ===== Tests =====

void test_alu_imm() {
    // add x0, x1, #0x10
    auto i = must_decode(0x91004020);
    check_eq(i.mnemonic, Mnemonic::A64Add, "add imm: mnemonic");
    check_eq(i.num_operands, std::uint8_t{3}, "add imm: nargs");
    check_eq(i.operands[0].reg, Reg::X0, "add imm: rd");
    check_eq(i.operands[1].reg, Reg::X1, "add imm: rn");
    check_eq(i.operands[2].imm.value, std::int64_t{0x10}, "add imm: imm");

    // sub w2, w3, #0x100
    i = must_decode(0x51040062);
    check_eq(i.mnemonic, Mnemonic::A64Sub, "sub imm: mnemonic");
    check_eq(i.operands[0].reg, Reg::W2, "sub imm: rd");
    check_eq(i.operands[1].reg, Reg::W3, "sub imm: rn");
    check_eq(i.operands[2].imm.value, std::int64_t{0x100}, "sub imm: imm");

    // cmp x0, #1   (== subs xzr, x0, #1)
    i = must_decode(0xf100041f);
    check_eq(i.mnemonic, Mnemonic::Cmp, "cmp imm: mnemonic");
}

void test_movz_movk() {
    // movz x0, #0x1234
    auto i = must_decode(0xd2824680);
    check_eq(i.mnemonic, Mnemonic::A64Movz, "movz: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "movz: rd");
    check_eq(i.operands[1].imm.value, std::int64_t{0x1234}, "movz: imm value");

    // movk x0, #0xabcd, lsl #16
    i = must_decode(0xf2b579a0);
    check_eq(i.mnemonic, Mnemonic::A64Movk, "movk: mnemonic");
    check_eq(i.operands[2].imm.value, std::int64_t{16}, "movk: shift");
}

void test_branches() {
    // b 0x2000 from 0x1000: imm26 = (0x2000-0x1000)/4 = 0x400 = 1024
    // encoded: 00010100 00000000 00000100 00000000 -> 0x14000400
    auto i = must_decode(0x14000400, 0x1000);
    check_eq(i.mnemonic, Mnemonic::A64B, "b: mnemonic");
    check_eq(i.operands[0].rel.target, addr_t{0x2000}, "b: target");

    // bl <forward>
    i = must_decode(0x94000010, 0x1000);
    check_eq(i.mnemonic, Mnemonic::A64Bl, "bl: mnemonic");
    check_eq(i.operands[0].rel.target, addr_t{0x1040}, "bl: target");

    // ret (== ret x30)
    i = must_decode(0xd65f03c0);
    check_eq(i.mnemonic, Mnemonic::A64Ret, "ret: mnemonic");
    check_eq(i.operands[0].reg, Reg::X30, "ret: rn");

    // br x16
    i = must_decode(0xd61f0200);
    check_eq(i.mnemonic, Mnemonic::A64Br, "br: mnemonic");
    check_eq(i.operands[0].reg, Reg::X16, "br: rn");

    // cbz x0, +0x10
    i = must_decode(0xb4000080, 0x1000);
    check_eq(i.mnemonic, Mnemonic::A64Cbz, "cbz: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "cbz: rt");
    check_eq(i.operands[1].rel.target, addr_t{0x1010}, "cbz: target");

    // b.eq 0x1010 from 0x1000: imm19 = 4 = 0x4
    i = must_decode(0x54000080, 0x1000);
    check_eq(i.mnemonic, Mnemonic::A64Bcc, "b.cond: mnemonic");
    check_eq(i.operands[0].imm.value, std::int64_t{0}, "b.cond: cond=eq");
    check_eq(i.operands[1].rel.target, addr_t{0x1010}, "b.cond: target");
}

void test_loads_stores() {
    // ldr x0, [sp, #16]   — unsigned offset, scale 8 → imm12=2
    auto i = must_decode(0xf94007e0);
    check_eq(i.mnemonic, Mnemonic::A64Ldr, "ldr unsigned: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "ldr unsigned: rt");
    check_eq(i.operands[1].mem.base, Reg::Xsp, "ldr unsigned: base");
    check_eq(i.operands[1].mem.disp, std::int64_t{8}, "ldr unsigned: disp");
    check_eq(i.operands[1].mem.size, std::uint8_t{8}, "ldr unsigned: size");

    // str w1, [x0]   — unsigned offset, imm12=0
    i = must_decode(0xb9000001);
    check_eq(i.mnemonic, Mnemonic::A64Str, "str unsigned: mnemonic");
    check_eq(i.operands[0].reg, Reg::W1, "str unsigned: rt");

    // ldp x29, x30, [sp, #-16]!     — pre-indexed, imm7 = -1, scale 8
    // Bits: 1010 1001 0110 1111 1111 1111 1011 1111 1101  ... actually
    // let me just encode the most common LDP signed-offset variant:
    // ldp x29, x30, [sp, #16]   bits: 0xa9417bfd
    i = must_decode(0xa9417bfd);
    check_eq(i.mnemonic, Mnemonic::A64Ldp, "ldp: mnemonic");
    check_eq(i.operands[0].reg, Reg::X29, "ldp: rt");
    check_eq(i.operands[1].reg, Reg::X30, "ldp: rt2");
    check_eq(i.operands[2].mem.disp, std::int64_t{16}, "ldp: disp");
}

void test_dp_reg() {
    // mov x0, x1   == orr x0, xzr, x1
    auto i = must_decode(0xaa0103e0);
    check_eq(i.mnemonic, Mnemonic::A64Mov, "mov reg: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "mov reg: rd");
    check_eq(i.operands[1].reg, Reg::X1, "mov reg: rm");

    // mul x0, x1, x2  == madd x0, x1, x2, xzr
    i = must_decode(0x9b027c20);
    check_eq(i.mnemonic, Mnemonic::A64Mul, "mul: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "mul: rd");
    check_eq(i.operands[1].reg, Reg::X1, "mul: rn");
    check_eq(i.operands[2].reg, Reg::X2, "mul: rm");

    // udiv x0, x1, x2
    i = must_decode(0x9ac20820);
    check_eq(i.mnemonic, Mnemonic::A64Udiv, "udiv: mnemonic");
}

void test_pcrel() {
    // adrp x0, +0x10000     — at addr 0x1000, target = 0x11000
    // ADRP encoding: bit 31=1, bits 30:29=immlo, bits 28:24=10000,
    // bits 23:5=immhi, bits 4:0=Rd. immlo:immhi as a single 21-bit
    // imm. For target page 0x11000 from page 0x1000, imm = 0x10.
    // Encoded: 0x90000080.
    auto i = must_decode(0x90000080, 0x1000);
    check_eq(i.mnemonic, Mnemonic::A64Adrp, "adrp: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "adrp: rd");
    check_eq(i.operands[1].rel.target, addr_t{0x11000}, "adrp: target");
}

void test_misc() {
    // nop (hint #0)
    auto i = must_decode(0xd503201f);
    check_eq(i.mnemonic, Mnemonic::A64Nop, "nop: mnemonic");

    // brk #0x1234   bits 31:21 = 1101_0100_001, imm16 in bits 20:5
    i = must_decode(0xd4224680);
    check_eq(i.mnemonic, Mnemonic::A64Brk, "brk: mnemonic");
    check_eq(i.operands[0].imm.value, std::int64_t{0x1234}, "brk: imm");

    // svc #0
    i = must_decode(0xd4000001);
    check_eq(i.mnemonic, Mnemonic::A64Svc, "svc: mnemonic");
}

}  // namespace

int main() {
    test_alu_imm();
    test_movz_movk();
    test_branches();
    test_loads_stores();
    test_dp_reg();
    test_pcrel();
    test_misc();

    if (fails == 0) {
        std::fprintf(stderr, "arm64_decoder_test: ok\n");
        return 0;
    }
    return 1;
}
