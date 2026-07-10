// Unit tests for the AArch64 decoder.
//
// We feed hand-encoded 32-bit instructions (assembled by hand from the
// ARMv8 reference manual; the constants are chosen so a reader can spot
// them in a one-line `xxd` of a real binary) and check that each one
// decodes to the right mnemonic + operand shape.
#include <ember/disasm/arm64_decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/ir/arm64_lifter.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>
#include <utility>

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

IrFunction lift_one(std::uint32_t raw) {
    Function fn;
    fn.start = 0x1000;
    fn.end = 0x1004;
    BasicBlock bb;
    bb.start = fn.start;
    bb.end = fn.end;
    bb.kind = BlockKind::Return;
    bb.instructions.push_back(must_decode(raw));
    fn.blocks.push_back(std::move(bb));
    Arm64Lifter lifter(Abi::Aapcs64);
    auto ir = lifter.lift(fn);
    if (!ir) {
        fail("arm64 lift failed");
        return {};
    }
    return std::move(*ir);
}

void test_lifter_regressions() {
    auto decoded = must_decode(0x8b020c20);  // add x0, x1, x2, lsl #3
    check_eq(decoded.operands[2].arm_shift, ArmShift::Lsl,
             "shifted add: shift kind");
    check_eq(decoded.operands[2].arm_shift_amt, std::uint8_t{3},
             "shifted add: shift amount");
    auto ir = lift_one(0x8b020c20);
    bool saw_shl = false, saw_add = false;
    for (const auto& i : ir.blocks[0].insts) {
        saw_shl |= i.op == IrOp::Shl;
        saw_add |= i.op == IrOp::Add;
    }
    check_eq(saw_shl && saw_add, true, "shifted add: shift survives lifting");

    ir = lift_one(0xeb01001f);  // cmp x0, x1
    bool saw_borrow = false, saw_invert = false;
    for (const auto& i : ir.blocks[0].insts) {
        saw_borrow |= i.op == IrOp::SubBorrow;
        saw_invert |= i.op == IrOp::Not && i.dst.type == IrType::I1;
    }
    check_eq(saw_borrow && saw_invert, true, "cmp: C flag is no-borrow");

    ir = lift_one(0xb9000001);  // str w1, [x0]
    bool store_i32 = false;
    for (const auto& i : ir.blocks[0].insts) {
        store_i32 |= i.op == IrOp::Store && i.srcs[1].type == IrType::I32;
    }
    check_eq(store_i32, true, "str w: 32-bit memory store");

    ir = lift_one(0xb9400001);  // ldr w1, [x0]
    bool load_i32 = false;
    for (const auto& i : ir.blocks[0].insts) {
        load_i32 |= i.op == IrOp::Load && i.dst.type == IrType::I32;
    }
    check_eq(load_i32, true, "ldr w: 32-bit memory load");

    ir = lift_one(0x69420402);  // ldpsw x2, x1, [x0, #16]
    unsigned sexts = 0;
    for (const auto& i : ir.blocks[0].insts) {
        sexts += i.op == IrOp::SExt && i.dst.type == IrType::I64;
    }
    check_eq(sexts >= 2, true, "ldpsw: both lanes sign-extend");

    ir = lift_one(0xf2b579a0);  // movk x0, #0xabcd, lsl #16
    bool correct_insert = false;
    for (const auto& i : ir.blocks[0].insts) {
        if (i.op == IrOp::Or && i.src_count == 2 &&
            i.srcs[1].kind == IrValueKind::Imm &&
            static_cast<u64>(i.srcs[1].imm) == 0x00000000abcd0000ull) {
            correct_insert = true;
        }
    }
    check_eq(correct_insert, true, "movk: immediate is shifted once");

    decoded = must_decode(0x9a9f17e0);  // cset x0, eq
    check_eq(decoded.mnemonic, Mnemonic::A64Cset, "cset: alias mnemonic");
    check_eq(decoded.operands[1].imm.value, std::int64_t{0},
             "cset: alias condition is inverted from CSINC encoding");

    ir = lift_one(0x94000001);  // bl +4
    bool saw_args = false, saw_clobber = false;
    for (const auto& i : ir.blocks[0].insts) {
        saw_args |= i.op == IrOp::Intrinsic && i.name == "call.args.1";
        saw_clobber |= i.op == IrOp::Clobber && i.dst.reg == Reg::X0;
    }
    check_eq(saw_args && saw_clobber, true, "bl: ABI barriers and clobbers");

    ir = lift_one(0xf80107e0);  // str x0, [sp], #16
    std::size_t store_pos = ir.blocks[0].insts.size();
    std::size_t sp_write_pos = ir.blocks[0].insts.size();
    for (std::size_t n = 0; n < ir.blocks[0].insts.size(); ++n) {
        const auto& i = ir.blocks[0].insts[n];
        if (i.op == IrOp::Store) store_pos = std::min(store_pos, n);
        if (i.op == IrOp::Assign && i.dst.kind == IrValueKind::Reg &&
            i.dst.reg == Reg::Xsp) sp_write_pos = std::min(sp_write_pos, n);
    }
    check_eq(store_pos < sp_write_pos, true,
             "post-index: memory access precedes base writeback");

    ir = lift_one(0x9ac22c20);  // rorv x0, x1, x2
    unsigned masked_counts = 0;
    bool saw_lshr = false, saw_rotate_shl = false, saw_rotate_or = false;
    for (const auto& i : ir.blocks[0].insts) {
        if (i.op == IrOp::And && i.src_count == 2 &&
            i.srcs[1].kind == IrValueKind::Imm && i.srcs[1].imm == 63) {
            ++masked_counts;
        }
        saw_lshr |= i.op == IrOp::Lshr;
        saw_rotate_shl |= i.op == IrOp::Shl;
        saw_rotate_or |= i.op == IrOp::Or;
    }
    check_eq(masked_counts >= 2 && saw_lshr && saw_rotate_shl && saw_rotate_or,
             true, "rorv: masked rotate rather than plain right shift");

    ir = lift_one(0x1ac52083);  // lslv w3, w4, w5
    bool saw_w_mask = false;
    for (const auto& i : ir.blocks[0].insts) {
        saw_w_mask |= i.op == IrOp::And && i.dst.type == IrType::I32 &&
                      i.src_count == 2 &&
                      i.srcs[1].kind == IrValueKind::Imm &&
                      i.srcs[1].imm == 31;
    }
    check_eq(saw_w_mask, true, "lslv w: variable count is masked to 5 bits");
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
    // ldr x0, [sp, #16]   - unsigned offset, scale 8 → imm12=2
    auto i = must_decode(0xf94007e0);
    check_eq(i.mnemonic, Mnemonic::A64Ldr, "ldr unsigned: mnemonic");
    check_eq(i.operands[0].reg, Reg::X0, "ldr unsigned: rt");
    check_eq(i.operands[1].mem.base, Reg::Xsp, "ldr unsigned: base");
    check_eq(i.operands[1].mem.disp, std::int64_t{8}, "ldr unsigned: disp");
    check_eq(i.operands[1].mem.size, std::uint8_t{8}, "ldr unsigned: size");

    i = must_decode(0xf80107e0);  // str x0, [sp], #16
    check_eq(i.operands[1].mem.writeback, Mem::Writeback::PostIndex,
             "str post-index: mode");
    check_eq(i.operands[1].mem.disp, std::int64_t{16},
             "str post-index: delta");

    i = must_decode(0xf8410fe0);  // ldr x0, [sp, #16]!
    check_eq(i.operands[1].mem.writeback, Mem::Writeback::PreIndex,
             "ldr pre-index: mode");

    i = must_decode(0xa9bf7bfd);  // stp x29, x30, [sp, #-16]!
    check_eq(i.operands[2].mem.writeback, Mem::Writeback::PreIndex,
             "stp pre-index: mode");
    check_eq(i.operands[2].mem.disp, std::int64_t{-16},
             "stp pre-index: delta");

    // str w1, [x0]   - unsigned offset, imm12=0
    i = must_decode(0xb9000001);
    check_eq(i.mnemonic, Mnemonic::A64Str, "str unsigned: mnemonic");
    check_eq(i.operands[0].reg, Reg::W1, "str unsigned: rt");

    // ldp x29, x30, [sp, #-16]!     - pre-indexed, imm7 = -1, scale 8
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
    // adrp x0, +0x10000     - at addr 0x1000, target = 0x11000
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

// Reserved / unallocated encodings used to silently masquerade as valid
// instructions in two places. These tests pin the corrected behaviour:
// the decoder should land on A64Udf (the catch-all the validator uses
// for unallocated encodings) rather than reporting a real mnemonic.
void test_reserved_encodings() {
    // DP-1 source, sf=0, opcode=000011 - UNALLOCATED per ARM ARM C4.1.7.
    // sf=1 + same opcode is REV (64-bit). Both branches used to land on
    // A64Rev, so the bit-31 disagreement was lost.
    auto rev_unalloc = must_decode(0x5ac00c00);
    check_eq(rev_unalloc.mnemonic, Mnemonic::A64Udf,
             "rev unallocated (sf=0, opcode=000011): falls through to udf");
    auto rev_valid = must_decode(0xdac00c00);
    check_eq(rev_valid.mnemonic, Mnemonic::A64Rev,
             "rev valid (sf=1, opcode=000011): A64Rev");

    // LDP/STP family, opc=11 - RESERVED per ARM ARM C4.1.4. Used to be
    // accepted as A64Ldpsw because the gate `opc != 0b00 && opc != 0b10`
    // didn't exclude it. Build a representative encoding: opc=11,
    // bits 29:27 = 101, bit 26 = 0, signed-offset variant.
    auto ldp_reserved = must_decode(0xe9400000);
    check_eq(ldp_reserved.mnemonic, Mnemonic::A64Udf,
             "load-pair opc=11: reserved encoding falls through to udf");

    // Valid LDPSW pins the regression so the legitimate opc=01, L=1
    // case keeps decoding correctly through the tightened gate.
    // ldpsw x2, x1, [x0, #16]: opc=01, signed offset, imm7=4 (scale 2).
    auto ldpsw = must_decode(0x69420402);
    check_eq(ldpsw.mnemonic, Mnemonic::A64Ldpsw,
             "ldpsw valid: still A64Ldpsw after gate tightening");
    check_eq(ldpsw.operands[0].reg, Reg::X2, "ldpsw: rt");
    check_eq(ldpsw.operands[1].reg, Reg::X1, "ldpsw: rt2");
    check_eq(ldpsw.operands[2].mem.disp, std::int64_t{16}, "ldpsw: disp");
}

}  // namespace

int main() {
    test_alu_imm();
    test_movz_movk();
    test_lifter_regressions();
    test_branches();
    test_loads_stores();
    test_dp_reg();
    test_pcrel();
    test_misc();
    test_reserved_encodings();

    if (fails == 0) {
        std::fprintf(stderr, "arm64_decoder_test: ok\n");
        return 0;
    }
    return 1;
}
