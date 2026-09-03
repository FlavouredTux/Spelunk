#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <initializer_list>
#include <span>

#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/arm32_decoder.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>

// ARM (A32 / ARMv7-A) instruction decoder.
//
// 4-byte fixed-length little-endian encoding. Top-level dispatch on the
// three op bits [27:25] per ARM ARM A5.1, with the condition field [31:28]
// pulled out onto Instruction::arm_cond and the S bit onto
// Instruction::arm_setflags. The cond == 0b1111 space is the unconditional
// escape (BLX(imm), PLD, barriers) rather than a predicate.
//
// Coverage in this v1 cut (integer + control flow, matching the PPC64 cut):
//   - Data processing, immediate + register + shifted-register operand2
//     (AND/EOR/SUB/RSB/ADD/ADC/SBC/RSC/TST/TEQ/CMP/CMN/ORR/MOV/BIC/MVN),
//     with the shift aliases LSL/LSR/ASR/ROR/RRX peeled off MOV.
//   - MOVW / MOVT (16-bit immediate halves).
//   - Multiply: MUL/MLA/MLS and the 64-bit UMULL/UMLAL/SMULL/SMLAL.
//   - Integer divide UDIV/SDIV; CLZ; REV/REV16; SXTB/SXTH/UXTB/UXTH.
//   - Single load/store LDR/STR{B} and the extra LDRH/STRH/LDRSB/LDRSH and
//     LDRD/STRD, with immediate and register (LSL-scaled) offsets.
//   - Block transfer LDM/STM and the PUSH/POP aliases.
//   - Branches B/BL/BX/BLX and the BX-LR / LDM-with-PC return shapes.
//   - SVC/BKPT/NOP/UDF.
//
// Coprocessor / VFP / NEON encodings decode shape-only (A32Undef, length 4)
// so the linear sweep keeps its footing; the lifter renders them as a named
// intrinsic. Writeback on pre/post-indexed addressing is not modelled (the
// access address is correct; the base-register update is elided) - the same
// simplification the AArch64 cut makes.

namespace ember {

namespace {

[[nodiscard]] inline u32 bits(u32 v, unsigned hi, unsigned lo) noexcept {
    return (v >> lo) & ((1u << (hi - lo + 1)) - 1u);
}

[[nodiscard]] inline u32 bit(u32 v, unsigned n) noexcept { return (v >> n) & 1u; }

[[nodiscard]] inline u32 ror32(u32 v, unsigned r) noexcept {
    r &= 31u;
    return r ? (v >> r) | (v << (32u - r)) : v;
}

// Map a 4-bit ARM register number to its Reg. r13/r14/r15 alias sp/lr/pc.
[[nodiscard]] Reg arm_gpr(unsigned n) noexcept {
    switch (n & 0xf) {
        case 13: return Reg::Asp;
        case 14: return Reg::Alr;
        case 15: return Reg::Apc;
        default: return static_cast<Reg>(
            static_cast<unsigned>(Reg::ArmR0) + (n & 0xf));
    }
}

[[nodiscard]] Operand reg_op(unsigned n) noexcept {
    return Operand::make_reg(arm_gpr(n));
}

[[nodiscard]] Operand imm_op(i64 v, u8 size = 4, bool is_signed = false) noexcept {
    Imm i;
    i.value = v;
    i.size = size;
    i.is_signed = is_signed;
    return Operand::make_imm(i);
}

[[nodiscard]] Operand rel_op(addr_t target) noexcept {
    Rel r;
    r.target = target;
    r.size = 4;
    return Operand::make_rel(r);
}

void set_ops(Instruction& in, std::initializer_list<Operand> ops) noexcept {
    in.num_operands = 0;
    for (const auto& o : ops) {
        if (in.num_operands >= in.operands.size()) break;
        in.operands[in.num_operands++] = o;
    }
}

// Build a shifted register operand2 (I == 0 forms). Returns the operand and,
// when the whole DP op is a MOV, lets the caller peel it into an LSL/LSR/...
// alias. `is_shift_alias` reports a non-trivial shift by immediate.
struct ShiftedReg {
    Operand op;
    bool    shift_by_reg = false;
    ArmShift type        = ArmShift::Lsl;
    unsigned amount       = 0;  // immediate amount, already normalised
    Reg     shift_reg    = Reg::None;
};

[[nodiscard]] ShiftedReg decode_shifted_reg(u32 raw) noexcept {
    ShiftedReg s;
    const unsigned rm = bits(raw, 3, 0);
    s.type = static_cast<ArmShift>(bits(raw, 6, 5));
    Operand o = reg_op(rm);
    if (bit(raw, 4)) {
        // Register-specified shift amount (bits 11:8). Not carried on the
        // operand model; the lifter renders it via intrinsic when needed.
        s.shift_by_reg = true;
        s.shift_reg = arm_gpr(bits(raw, 11, 8));
        o.arm_shift = s.type;
        o.arm_shift_amt = 0;
        o.arm_shift_reg = s.shift_reg;
        s.op = o;
        return s;
    }
    unsigned amt = bits(raw, 11, 7);
    // The "amount 0" special cases: LSR/ASR #0 mean #32, ROR #0 is RRX.
    if (amt == 0) {
        if (s.type == ArmShift::Lsr || s.type == ArmShift::Asr) amt = 32;
        // ROR #0 stays 0 → RRX (rotate through carry), flagged by amt==0.
    }
    s.amount = amt;
    o.arm_shift = s.type;
    o.arm_shift_amt = static_cast<u8>(amt & 0xff);
    s.op = o;
    return s;
}

// ---- Data processing ---------------------------------------------------

constexpr Mnemonic kDpOpc[16] = {
    Mnemonic::A32And, Mnemonic::A32Eor, Mnemonic::A32Sub, Mnemonic::A32Rsb,
    Mnemonic::A32Add, Mnemonic::A32Adc, Mnemonic::A32Sbc, Mnemonic::A32Rsc,
    Mnemonic::A32Tst, Mnemonic::A32Teq, Mnemonic::A32Cmp, Mnemonic::A32Cmn,
    Mnemonic::A32Orr, Mnemonic::A32Mov, Mnemonic::A32Bic, Mnemonic::A32Mvn,
};

// TST/TEQ/CMP/CMN (opcodes 8..11) are compare-class: no Rd, S implicit.
[[nodiscard]] bool dp_is_compare(unsigned opc) noexcept { return opc >= 8 && opc <= 11; }
// MOV/MVN (13/15) take no Rn.
[[nodiscard]] bool dp_is_move(unsigned opc) noexcept { return opc == 13 || opc == 15; }

void decode_dp(u32 raw, Instruction& in, bool imm_form) noexcept {
    const unsigned opc = bits(raw, 24, 21);
    const unsigned s   = bit(raw, 20);
    const unsigned rn  = bits(raw, 19, 16);
    const unsigned rd  = bits(raw, 15, 12);

    Operand op2;
    Mnemonic mn = kDpOpc[opc];
    bool shift_alias = false;

    if (imm_form) {
        const u32 imm8 = bits(raw, 7, 0);
        const u32 rot  = bits(raw, 11, 8);
        op2 = imm_op(static_cast<i32>(ror32(imm8, rot * 2)));
    } else {
        ShiftedReg sr = decode_shifted_reg(raw);
        op2 = sr.op;
        // MOV with a real shift is disassembled as the shift alias.
        if (opc == 13 && !sr.shift_by_reg &&
            !(sr.type == ArmShift::Lsl && sr.amount == 0)) {
            shift_alias = true;
            const bool rrx = (sr.type == ArmShift::Ror && sr.amount == 0);
            mn = rrx ? Mnemonic::A32Rrx
               : sr.type == ArmShift::Lsl ? Mnemonic::A32Lsl
               : sr.type == ArmShift::Lsr ? Mnemonic::A32Lsr
               : sr.type == ArmShift::Asr ? Mnemonic::A32Asr
                                          : Mnemonic::A32Ror;
        } else if (opc == 13 && sr.shift_by_reg) {
            shift_alias = true;
            mn = sr.type == ArmShift::Lsl ? Mnemonic::A32Lsl
               : sr.type == ArmShift::Lsr ? Mnemonic::A32Lsr
               : sr.type == ArmShift::Asr ? Mnemonic::A32Asr
                                          : Mnemonic::A32Ror;
        }
    }

    in.mnemonic = mn;
    in.arm_setflags = s && !dp_is_compare(opc);

    if (shift_alias) {
        // lsl rd, rm, #amt  /  lsl rd, rm, rs  /  rrx rd, rm
        Operand rmbase = Operand::make_reg(op2.reg);
        if (in.mnemonic == Mnemonic::A32Rrx) {
            set_ops(in, {reg_op(rd), rmbase});
        } else if (op2.arm_shift_amt == 0 && !imm_form && bit(raw, 4)) {
            set_ops(in, {reg_op(rd), rmbase, reg_op(bits(raw, 11, 8))});
        } else {
            set_ops(in, {reg_op(rd), rmbase, imm_op(op2.arm_shift_amt)});
        }
        return;
    }

    if (dp_is_compare(opc)) {
        set_ops(in, {reg_op(rn), op2});
    } else if (dp_is_move(opc)) {
        set_ops(in, {reg_op(rd), op2});
    } else {
        set_ops(in, {reg_op(rd), reg_op(rn), op2});
    }
}

// ---- Multiply ----------------------------------------------------------

void decode_multiply(u32 raw, Instruction& in) noexcept {
    const unsigned op   = bits(raw, 23, 21);
    const unsigned s    = bit(raw, 20);
    const unsigned rd   = bits(raw, 19, 16);   // RdHi for long forms
    const unsigned ra   = bits(raw, 15, 12);   // Rn (acc) / RdLo
    const unsigned rs   = bits(raw, 11, 8);    // Rm
    const unsigned rm   = bits(raw, 3, 0);     // Rn
    in.arm_setflags = s != 0;
    switch (op) {
        case 0b000:  // MUL Rd, Rm(=raw3:0), Rs(=raw11:8)
            in.mnemonic = Mnemonic::A32Mul;
            set_ops(in, {reg_op(rd), reg_op(rm), reg_op(rs)});
            break;
        case 0b001:  // MLA Rd, Rm, Rs, Ra
            in.mnemonic = Mnemonic::A32Mla;
            set_ops(in, {reg_op(rd), reg_op(rm), reg_op(rs), reg_op(ra)});
            break;
        case 0b100:  // UMULL RdLo, RdHi, Rm, Rs
            in.mnemonic = Mnemonic::A32Umull;
            set_ops(in, {reg_op(ra), reg_op(rd), reg_op(rm), reg_op(rs)});
            break;
        case 0b101:  // UMLAL
            in.mnemonic = Mnemonic::A32Umlal;
            set_ops(in, {reg_op(ra), reg_op(rd), reg_op(rm), reg_op(rs)});
            break;
        case 0b110:  // SMULL
            in.mnemonic = Mnemonic::A32Smull;
            set_ops(in, {reg_op(ra), reg_op(rd), reg_op(rm), reg_op(rs)});
            break;
        case 0b111:  // SMLAL
            in.mnemonic = Mnemonic::A32Smlal;
            set_ops(in, {reg_op(ra), reg_op(rd), reg_op(rm), reg_op(rs)});
            break;
        default:
            in.mnemonic = Mnemonic::A32Undef;
            break;
    }
}

// ---- Misc (bits 24:23 == 10, S == 0): BX/BLX/CLZ/BKPT/MRS/MSR ----------

void decode_misc(u32 raw, Instruction& in) noexcept {
    if ((raw & 0x0ffffff0u) == 0x012fff10u) {           // BX Rm
        const unsigned rm = bits(raw, 3, 0);
        if (rm == 14) { in.mnemonic = Mnemonic::A32Ret; set_ops(in, {reg_op(rm)}); }
        else          { in.mnemonic = Mnemonic::A32Bx;  set_ops(in, {reg_op(rm)}); }
        return;
    }
    if ((raw & 0x0ffffff0u) == 0x012fff30u) {           // BLX Rm (indirect call)
        in.mnemonic = Mnemonic::A32Blx;
        set_ops(in, {reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0fff0ff0u) == 0x016f0f10u) {           // CLZ Rd, Rm
        in.mnemonic = Mnemonic::A32Clz;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0ff000f0u) == 0x01200070u) {           // BKPT #imm16
        const u32 imm = (bits(raw, 19, 8) << 4) | bits(raw, 3, 0);
        in.mnemonic = Mnemonic::A32Bkpt;
        set_ops(in, {imm_op(static_cast<i64>(imm))});
        return;
    }
    // MRS / MSR and the saturating/DSP ops: shape-only for this cut.
    in.mnemonic = Mnemonic::A32Undef;
    set_ops(in, {imm_op(static_cast<i64>(raw))});
}

// ---- Extra load/store (LDRH/STRH/LDRSB/LDRSH/LDRD/STRD) ----------------

void decode_extra_ls(u32 raw, Instruction& in) noexcept {
    const unsigned p    = bit(raw, 24);
    const unsigned u    = bit(raw, 23);
    const unsigned immf = bit(raw, 22);
    const unsigned l    = bit(raw, 20);
    const unsigned rn   = bits(raw, 19, 16);
    const unsigned rd   = bits(raw, 15, 12);
    const unsigned sh   = bits(raw, 6, 5);

    Mem m{};
    m.base = arm_gpr(rn);
    if (immf) {
        const i64 off = static_cast<i64>((bits(raw, 11, 8) << 4) | bits(raw, 3, 0));
        m.disp = p ? (u ? off : -off) : 0;
        m.has_disp = true;
    } else {
        if (p) {
            m.index = arm_gpr(bits(raw, 3, 0));
            m.scale = 1;
            m.subtract_index = !u;
        }
    }

    Mnemonic mn = Mnemonic::A32Undef;
    u8 size = 2;
    if (sh == 0b01) { mn = l ? Mnemonic::A32Ldrh : Mnemonic::A32Strh; size = 2; }
    else if (sh == 0b10) {
        if (l) { mn = Mnemonic::A32Ldrsb; size = 1; }
        else   { mn = Mnemonic::A32Ldrd;  size = 8; }
    } else if (sh == 0b11) {
        if (l) { mn = Mnemonic::A32Ldrsh; size = 2; }
        else   { mn = Mnemonic::A32Strd;  size = 8; }
    }
    m.size = size;
    in.mnemonic = mn;
    set_ops(in, {reg_op(rd), Operand::make_mem(m)});
}

// ---- Single load/store (LDR/STR/LDRB/STRB) -----------------------------

void decode_single_ls(u32 raw, Instruction& in) noexcept {
    const unsigned regoff = bit(raw, 25);  // in this space, 1 == register
    const unsigned p      = bit(raw, 24);
    const unsigned u      = bit(raw, 23);
    const unsigned b      = bit(raw, 22);
    const unsigned l      = bit(raw, 20);
    const unsigned rn     = bits(raw, 19, 16);
    const unsigned rd     = bits(raw, 15, 12);

    Mem m{};
    m.base = arm_gpr(rn);
    m.size = b ? 1 : 4;

    if (!regoff) {
        const i64 imm12 = static_cast<i64>(bits(raw, 11, 0));
        const i64 off = u ? imm12 : -imm12;
        m.disp = p ? off : 0;   // post-index writeback elided; access at [Rn]
        m.has_disp = true;
    } else {
        const unsigned rm  = bits(raw, 3, 0);
        const ArmShift st  = static_cast<ArmShift>(bits(raw, 6, 5));
        const unsigned amt = bits(raw, 11, 7);
        m.index = arm_gpr(rm);
        // Mem represents an optionally-subtracted, power-of-two LSL index.
        // Other barrel shifts still require richer address metadata.
        if (st != ArmShift::Lsl || amt >= 8) {
            in.mnemonic = Mnemonic::A32Undef;
            set_ops(in, {imm_op(static_cast<i64>(raw))});
            return;
        }
        m.scale = static_cast<u8>(1u << amt);
        m.subtract_index = !u;
    }

    // ldr into PC is an indirect branch / return.
    if (l && rd == 15) {
        in.mnemonic = Mnemonic::A32Bx;
        set_ops(in, {Operand::make_mem(m)});
        return;
    }
    in.mnemonic = l ? (b ? Mnemonic::A32Ldrb : Mnemonic::A32Ldr)
                    : (b ? Mnemonic::A32Strb : Mnemonic::A32Str);
    set_ops(in, {reg_op(rd), Operand::make_mem(m)});
}

// ---- Media (bits 27:25 == 011, bit4 == 1) ------------------------------

void decode_media(u32 raw, Instruction& in) noexcept {
    if ((raw & 0x0ff0f0f0u) == 0x0710f010u) {  // SDIV Rd, Rn, Rm
        in.mnemonic = Mnemonic::A32Sdiv;
        set_ops(in, {reg_op(bits(raw, 19, 16)), reg_op(bits(raw, 3, 0)),
                     reg_op(bits(raw, 11, 8))});
        return;
    }
    if ((raw & 0x0ff0f0f0u) == 0x0730f010u) {  // UDIV Rd, Rn, Rm
        in.mnemonic = Mnemonic::A32Udiv;
        set_ops(in, {reg_op(bits(raw, 19, 16)), reg_op(bits(raw, 3, 0)),
                     reg_op(bits(raw, 11, 8))});
        return;
    }
    if ((raw & 0x0fff0ff0u) == 0x06bf0f30u) {  // REV Rd, Rm
        in.mnemonic = Mnemonic::A32Rev;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0fff0ff0u) == 0x06bf0fb0u) {  // REV16 Rd, Rm
        in.mnemonic = Mnemonic::A32Rev16;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    // SXTB/SXTH/UXTB/UXTH: Rn field == 1111 (no add), rotate in bits 11:10.
    if ((raw & 0x0fff03f0u) == 0x06af0070u) {  // SXTB Rd, Rm
        in.mnemonic = Mnemonic::A32Sxtb;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0fff03f0u) == 0x06bf0070u) {  // SXTH Rd, Rm
        in.mnemonic = Mnemonic::A32Sxth;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0fff03f0u) == 0x06ef0070u) {  // UXTB Rd, Rm
        in.mnemonic = Mnemonic::A32Uxtb;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    if ((raw & 0x0fff03f0u) == 0x06ff0070u) {  // UXTH Rd, Rm
        in.mnemonic = Mnemonic::A32Uxth;
        set_ops(in, {reg_op(bits(raw, 15, 12)), reg_op(bits(raw, 3, 0))});
        return;
    }
    in.mnemonic = Mnemonic::A32Undef;
    set_ops(in, {imm_op(static_cast<i64>(raw))});
}

// ---- Block data transfer (LDM/STM/PUSH/POP) ----------------------------

void decode_block(u32 raw, Instruction& in) noexcept {
    const unsigned p    = bit(raw, 24);
    const unsigned u    = bit(raw, 23);
    const unsigned w    = bit(raw, 21);
    const unsigned l    = bit(raw, 20);
    const unsigned rn   = bits(raw, 19, 16);
    const u32      list = bits(raw, 15, 0);
    // Pack P/U/W/L so the lifter can reconstruct the addressing mode.
    const i64 flags = (i64{p} << 3) | (i64{u} << 2) | (i64{w} << 1) | i64{l};

    // POP {...,pc} is the conventional return shape. Other LDM-to-PC forms
    // are general indirect branches and must not terminate the whole function.
    if (l && (list & 0x8000u) && rn == 13 && w && u && !p) {
        in.mnemonic = Mnemonic::A32Ret;
        set_ops(in, {reg_op(rn), imm_op(static_cast<i64>(list)), imm_op(flags)});
        return;
    }
    if (l && (list & 0x8000u)) {
        in.mnemonic = Mnemonic::A32LdmPc;
        set_ops(in, {reg_op(rn), imm_op(static_cast<i64>(list)), imm_op(flags)});
        return;
    }
    // PUSH == STMDB sp!, POP == LDMIA sp!.
    if (rn == 13 && w) {
        if (!l && !u && p) { in.mnemonic = Mnemonic::A32Push;
            set_ops(in, {reg_op(rn), imm_op(static_cast<i64>(list)), imm_op(flags)});
            return; }
        if (l && u && !p) { in.mnemonic = Mnemonic::A32Pop;
            set_ops(in, {reg_op(rn), imm_op(static_cast<i64>(list)), imm_op(flags)});
            return; }
    }
    in.mnemonic = l ? Mnemonic::A32Ldm : Mnemonic::A32Stm;
    set_ops(in, {reg_op(rn), imm_op(static_cast<i64>(list)), imm_op(flags)});
}

// ---- Branch (B / BL) ---------------------------------------------------

void decode_branch(u32 raw, addr_t addr, Instruction& in) noexcept {
    const unsigned link = bit(raw, 24);
    i32 imm24 = static_cast<i32>(bits(raw, 23, 0));
    imm24 = (imm24 << 8) >> 8;                       // sign-extend 24→32
    const addr_t target =
        addr + 8 + static_cast<addr_t>(static_cast<i64>(imm24) << 2);
    if (link) {
        in.mnemonic = Mnemonic::A32Bl;
        set_ops(in, {rel_op(target)});
    } else if (in.arm_cond == kArmCondAL) {
        in.mnemonic = Mnemonic::A32B;
        set_ops(in, {rel_op(target)});
    } else {
        in.mnemonic = Mnemonic::A32Bcc;
        set_ops(in, {rel_op(target)});
    }
}

}  // namespace

Result<Instruction>
Arm32Decoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.size() < 4) {
        return std::unexpected(Error::truncated(std::format(
            "arm32: truncated insn at {:#x}", addr)));
    }
    Instruction in;
    in.address = addr;
    in.length  = 4;
    in.mnemonic = Mnemonic::Invalid;
    std::memcpy(in.raw_bytes.data(), code.data(), 4);

    const u32 raw  = read_le_at<u32>(code.data());
    const unsigned cond = bits(raw, 31, 28);
    in.arm_cond = static_cast<u8>(cond);

    // Unconditional (cond == 0b1111) escape space.
    if (cond == 0xf) {
        in.arm_cond = kArmCondAL;
        if ((raw & 0xfe000000u) == 0xfa000000u) {    // BLX (immediate)
            const unsigned h = bit(raw, 24);
            i32 imm24 = static_cast<i32>(bits(raw, 23, 0));
            imm24 = (imm24 << 8) >> 8;
            const addr_t target =
                addr + 8 + static_cast<addr_t>((static_cast<i64>(imm24) << 2)) +
                (h << 1);
            in.mnemonic = Mnemonic::A32Bl;           // direct call to Thumb
            set_ops(in, {rel_op(target)});
        } else {
            in.mnemonic = Mnemonic::A32Undef;        // PLD, barriers, ...
            set_ops(in, {imm_op(static_cast<i64>(raw))});
        }
        return in;
    }

    const unsigned op1 = bits(raw, 27, 25);
    switch (op1) {
        case 0b000: {
            const bool b7 = bit(raw, 7);
            const bool b4 = bit(raw, 4);
            if (b7 && b4) {
                if (bits(raw, 6, 5) == 0) {
                    // Multiply / multiply-long (24:23 select within class).
                    if (bits(raw, 24, 23) <= 0b01) decode_multiply(raw, in);
                    else { in.mnemonic = Mnemonic::A32Undef;  // SWP etc.
                           set_ops(in, {imm_op(static_cast<i64>(raw))}); }
                } else {
                    decode_extra_ls(raw, in);
                }
            } else if (bits(raw, 24, 23) == 0b10 && bit(raw, 20) == 0) {
                decode_misc(raw, in);
            } else {
                decode_dp(raw, in, /*imm_form=*/false);
            }
            break;
        }
        case 0b001: {
            if ((raw & 0x0ff00000u) == 0x03000000u) {          // MOVW
                in.mnemonic = Mnemonic::A32Movw;
                set_ops(in, {reg_op(bits(raw, 15, 12)),
                             imm_op((bits(raw, 19, 16) << 12) | bits(raw, 11, 0))});
            } else if ((raw & 0x0ff00000u) == 0x03400000u) {   // MOVT
                in.mnemonic = Mnemonic::A32Movt;
                set_ops(in, {reg_op(bits(raw, 15, 12)),
                             imm_op((bits(raw, 19, 16) << 12) | bits(raw, 11, 0))});
            } else if ((raw & 0x0fb00000u) == 0x03200000u) {   // MSR imm / hints
                in.mnemonic = Mnemonic::A32Nop;                // NOP-class hint
            } else {
                decode_dp(raw, in, /*imm_form=*/true);
            }
            break;
        }
        case 0b010:
            decode_single_ls(raw, in);
            break;
        case 0b011:
            if (bit(raw, 4)) decode_media(raw, in);
            else             decode_single_ls(raw, in);
            break;
        case 0b100:
            decode_block(raw, in);
            break;
        case 0b101:
            decode_branch(raw, addr, in);
            break;
        case 0b110:   // coprocessor / VFP load-store
            in.mnemonic = Mnemonic::A32Undef;
            set_ops(in, {imm_op(static_cast<i64>(raw))});
            break;
        case 0b111:
            if (bit(raw, 24)) {                                // SVC
                in.mnemonic = Mnemonic::A32Svc;
                set_ops(in, {imm_op(static_cast<i64>(bits(raw, 23, 0)))});
            } else {                                           // coprocessor
                in.mnemonic = Mnemonic::A32Undef;
                set_ops(in, {imm_op(static_cast<i64>(raw))});
            }
            break;
    }

    if (in.mnemonic == Mnemonic::Invalid) {
        in.mnemonic = Mnemonic::A32Undef;
        set_ops(in, {imm_op(static_cast<i64>(raw))});
    }
    return in;
}

}  // namespace ember
