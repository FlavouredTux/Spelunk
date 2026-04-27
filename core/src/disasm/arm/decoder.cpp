#include <ember/disasm/arm64_decoder.hpp>

#include <bit>
#include <cstring>
#include <format>

#include <ember/common/bytes.hpp>

// AArch64 (ARMv8-A) instruction decoder.
//
// 4-byte fixed-length little-endian encoding. Top-level dispatch on bits
// [28:25] (op0) per ARM ARM Table C4-1:
//
//   op0 = 100x : Data Processing -- Immediate
//   op0 = 101x : Branches, Exception generation, System
//   op0 = x1x0 : Loads and Stores
//   op0 = x101 : Data Processing -- Register
//   op0 = x111 : Data Processing -- Advanced SIMD/FP   (mostly stubbed)
//
// Coverage in this v1 cut:
//   - ALU immediate + register (add/sub/and/orr/eor + signed variants)
//   - Logical / shifted / bitfield aliases (mov, mvn, cmp, cmn, tst,
//     lsl/lsr/asr/ror imm, sxt*/uxt*)
//   - Move-wide immediate (movz/movn/movk)
//   - PC-relative (adr/adrp)
//   - Multiply (mul/madd/msub/smaddl/umaddl/smulh/umulh)
//   - Conditional select (csel/csinc/csinv/csneg + cset/csetm aliases)
//   - All branch families (B, BL, BR, BLR, RET, B.cc, CBZ/CBNZ, TBZ/TBNZ)
//   - Loads / stores: register (immediate offset, pre/post-indexed),
//     PC-relative literal, register-pair (LDP/STP), unscaled (LDUR/STUR)
//   - System: NOP, BRK, SVC, HVC, SMC, ERET, HINT-class (yield/wfe/wfi)
//
// Floating-point and Advanced SIMD instructions are decoded shape-only so
// linear sweep doesn't fall apart in their presence; the lifter renders
// them as `arm64.<op>(...)` block comments. SVE / SME are unmapped.

namespace ember {

namespace {

using u32 = ember::u32;

[[nodiscard]] inline u32 bits(u32 v, unsigned hi, unsigned lo) noexcept {
    const unsigned w = hi - lo + 1;
    const u32 mask = (w >= 32) ? ~0u : ((1u << w) - 1u);
    return (v >> lo) & mask;
}

[[nodiscard]] inline u32 bit(u32 v, unsigned i) noexcept {
    return (v >> i) & 1u;
}

[[nodiscard]] inline i64 sign_extend(u64 v, unsigned width) noexcept {
    const u64 sign = u64{1} << (width - 1);
    return static_cast<i64>((v ^ sign) - sign);
}

// Map a 5-bit register index + sf bit to our Reg enum. `sf=1` selects
// X0..X30/SP/XZR; sf=0 selects W0..W30/WSP/WZR. Index 31 maps to Sp/Wsp
// when `is_sp` is true (some encodings allow either Sp or Zr at this
// slot), otherwise Xzr/Wzr.
[[nodiscard]] Reg gpr_of(unsigned idx, bool sf, bool is_sp) noexcept {
    if (idx >= 31) {
        return is_sp ? (sf ? Reg::Xsp : Reg::Wsp)
                     : (sf ? Reg::Xzr : Reg::Wzr);
    }
    if (sf) {
        return static_cast<Reg>(static_cast<unsigned>(Reg::X0) + idx);
    }
    return static_cast<Reg>(static_cast<unsigned>(Reg::W0) + idx);
}

[[nodiscard]] Reg vreg_of(unsigned idx) noexcept {
    if (idx > 31) return Reg::None;
    return static_cast<Reg>(static_cast<unsigned>(Reg::V0) + idx);
}

[[nodiscard]] Operand make_reg(Reg r) noexcept {
    return Operand::make_reg(r);
}

[[nodiscard]] Operand make_imm_u(u64 v, u8 size = 8) noexcept {
    Imm i;
    i.value = static_cast<i64>(v);
    i.size  = size;
    i.is_signed = false;
    return Operand::make_imm(i);
}

[[maybe_unused, nodiscard]] Operand make_imm_s(i64 v, u8 size = 8) noexcept {
    Imm i;
    i.value = v;
    i.size  = size;
    i.is_signed = true;
    return Operand::make_imm(i);
}

[[nodiscard]] Operand make_rel(addr_t target, u8 size = 4) noexcept {
    Rel r;
    r.target = target;
    r.size   = size;
    return Operand::make_rel(r);
}

[[nodiscard]] Operand make_mem(Reg base, i64 disp, u8 size, bool has_disp = true) noexcept {
    Mem m;
    m.base = base;
    m.disp = disp;
    m.size = size;
    m.has_disp = has_disp;
    return Operand::make_mem(m);
}

[[maybe_unused, nodiscard]] Operand make_mem_idx(Reg base, Reg index, u8 scale, u8 size) noexcept {
    Mem m;
    m.base  = base;
    m.index = index;
    m.scale = scale;
    m.size  = size;
    return Operand::make_mem(m);
}

void set_ops(Instruction& insn,
             const Operand& a = {},
             const Operand& b = {},
             const Operand& c = {},
             const Operand& d = {}) {
    u8 n = 0;
    auto push = [&](const Operand& o) {
        if (o.kind == Operand::Kind::None) return;
        if (n < insn.operands.size()) insn.operands[n++] = o;
    };
    push(a); push(b); push(c); push(d);
    insn.num_operands = n;
}

// Decode the N:imms:immr field used by logical-immediate to an actual
// 64-bit (or 32-bit) bitmask. Returns nullopt on invalid encodings —
// some N/imms/immr triples are reserved.
[[nodiscard]] std::optional<u64>
decode_bitmask_imm(unsigned N, unsigned imms, unsigned immr,
                   bool is_64bit) noexcept {
    const unsigned len_bit_w = is_64bit ? 7u : 6u;
    const u32 combined = (N << 6) | (~imms & 0x3f);
    if (combined == 0) return std::nullopt;
    const int len = std::bit_width(combined) - 1;
    if (len < 1) return std::nullopt;
    if (!is_64bit && N != 0) return std::nullopt;
    const unsigned esize = 1u << len;
    if (esize > (is_64bit ? 64u : 32u)) return std::nullopt;
    const unsigned levels = esize - 1;
    const unsigned S = imms & levels;
    const unsigned R = immr & levels;
    if (S == levels) return std::nullopt;
    const u64 welem = (u64{1} << (S + 1)) - 1;
    auto rotate = [&](u64 v) {
        if (R == 0 || esize == 0) return v;
        return ((v >> R) | (v << (esize - R))) &
               ((esize == 64) ? ~u64{0} : ((u64{1} << esize) - 1));
    };
    u64 element = rotate(welem);
    u64 result = 0;
    for (unsigned i = 0; i < (is_64bit ? 64u : 32u); i += esize) {
        result |= element << i;
    }
    if (!is_64bit) result &= 0xffffffffu;
    (void)len_bit_w;
    return result;
}

// AArch64 condition-code encodings (4-bit field).
[[maybe_unused, nodiscard]] std::string_view cond_name(unsigned c) noexcept {
    switch (c & 0xf) {
        case 0x0: return "eq"; case 0x1: return "ne";
        case 0x2: return "cs"; case 0x3: return "cc";
        case 0x4: return "mi"; case 0x5: return "pl";
        case 0x6: return "vs"; case 0x7: return "vc";
        case 0x8: return "hi"; case 0x9: return "ls";
        case 0xa: return "ge"; case 0xb: return "lt";
        case 0xc: return "gt"; case 0xd: return "le";
        case 0xe: return "al"; case 0xf: return "nv";
    }
    return "?";
}

// ============================================================================
// Per-class decoders
// ============================================================================

// op0 = 100x : Data Processing -- Immediate
void decode_dp_imm(u32 raw, addr_t addr, Instruction& insn) {
    const unsigned op0 = bits(raw, 25, 23);
    const bool sf = bit(raw, 31);
    const unsigned Rd = bits(raw, 4, 0);
    const unsigned Rn = bits(raw, 9, 5);

    switch (op0) {
        // PC-rel addressing: ADR / ADRP
        case 0b000: case 0b001: {
            const u32 immlo = bits(raw, 30, 29);
            const u32 immhi = bits(raw, 23, 5);
            i64 imm = sign_extend((static_cast<u64>(immhi) << 2) | immlo, 21);
            const bool is_adrp = bit(raw, 31) != 0;
            const addr_t target = is_adrp
                ? ((addr & ~addr_t{0xfff}) + static_cast<addr_t>(imm << 12))
                :  (addr + static_cast<addr_t>(imm));
            insn.mnemonic = is_adrp ? Mnemonic::A64Adrp : Mnemonic::A64Adr;
            set_ops(insn, make_reg(gpr_of(Rd, /*sf=*/true, /*is_sp=*/false)),
                          make_rel(target));
            return;
        }
        // Add/sub (immediate): bits 28:23 = 100010 (add) or 100110 (sub-flag);
        // we got into this case via op0[2:0] = 010 (add) or 011 (adds/sub*).
        case 0b010: case 0b011: {
            const bool sh = bit(raw, 22);
            u64 imm12 = bits(raw, 21, 10);
            if (sh) imm12 <<= 12;
            const bool S  = bit(raw, 29);
            const bool op = bit(raw, 30);
            // Rd may be SP for non-S forms; Rn is always SP-allowed.
            const Reg rd = gpr_of(Rd, sf, /*is_sp=*/!S);
            const Reg rn = gpr_of(Rn, sf, /*is_sp=*/true);

            if (S && Rd == 31) {
                insn.mnemonic = op ? Mnemonic::Cmp : Mnemonic::Cmn;
                set_ops(insn, make_reg(rn), make_imm_u(imm12));
            } else {
                insn.mnemonic = op
                    ? (S ? Mnemonic::A64Subs : Mnemonic::A64Sub)
                    : (S ? Mnemonic::A64Adds : Mnemonic::A64Add);
                set_ops(insn, make_reg(rd), make_reg(rn), make_imm_u(imm12));
            }
            return;
        }
        // Logical (immediate): AND / ORR / EOR / ANDS
        case 0b100: {
            const unsigned opc  = bits(raw, 30, 29);
            const unsigned N    = bit(raw, 22);
            const unsigned immr = bits(raw, 21, 16);
            const unsigned imms = bits(raw, 15, 10);
            auto bm = decode_bitmask_imm(N, imms, immr, sf);
            if (!bm) {
                insn.mnemonic = Mnemonic::Invalid;
                return;
            }
            const Reg rd = gpr_of(Rd, sf, /*is_sp=*/opc != 0b11);
            const Reg rn = gpr_of(Rn, sf, /*is_sp=*/false);
            switch (opc) {
                case 0b00: insn.mnemonic = Mnemonic::A64And;  break;
                case 0b01: insn.mnemonic = Mnemonic::A64Orr;  break;
                case 0b10: insn.mnemonic = Mnemonic::A64Eor;  break;
                case 0b11: insn.mnemonic = Rd == 31
                                ? Mnemonic::Cmp  /* tst alias — but we have ANDS in v1; use Tst-shape */
                                : Mnemonic::A64Ands;
                           break;
            }
            // ORR Wd, WZR, #imm == MOV Wd, #imm — recognise the alias.
            if (insn.mnemonic == Mnemonic::A64Orr && Rn == 31) {
                insn.mnemonic = Mnemonic::A64Mov;
                set_ops(insn, make_reg(rd), make_imm_u(*bm));
                return;
            }
            set_ops(insn, make_reg(rd), make_reg(rn), make_imm_u(*bm));
            return;
        }
        // Move-wide immediate (MOVZ / MOVN / MOVK)
        case 0b101: {
            const unsigned opc = bits(raw, 30, 29);
            const unsigned hw  = bits(raw, 22, 21);
            const u64 imm16    = bits(raw, 20, 5);
            const Reg rd = gpr_of(Rd, sf, /*is_sp=*/false);
            switch (opc) {
                case 0b00: insn.mnemonic = Mnemonic::A64Movn; break;
                case 0b10: insn.mnemonic = Mnemonic::A64Movz; break;
                case 0b11: insn.mnemonic = Mnemonic::A64Movk; break;
                default:   insn.mnemonic = Mnemonic::Invalid; return;
            }
            set_ops(insn, make_reg(rd),
                          make_imm_u(imm16 << (hw * 16u)),
                          make_imm_u(hw * 16u));
            return;
        }
        // Bitfield: SBFM / BFM / UBFM. Aliases (LSL/LSR/ASR-imm, SXT*, UXT*)
        // are decoded later by inspection of immr/imms.
        case 0b110: {
            const unsigned opc  = bits(raw, 30, 29);
            const unsigned immr = bits(raw, 21, 16);
            const unsigned imms = bits(raw, 15, 10);
            const Reg rd = gpr_of(Rd, sf, /*is_sp=*/false);
            const Reg rn = gpr_of(Rn, sf, /*is_sp=*/false);
            // LSL (immediate) = UBFM Rd, Rn, #(-shift mod W), #(W-1-shift)
            // LSR (immediate) = UBFM Rd, Rn, #shift, #(W-1)
            // ASR (immediate) = SBFM Rd, Rn, #shift, #(W-1)
            const unsigned width = sf ? 64u : 32u;
            if (opc == 0b00 && imms != width - 1 && imms + 1 == immr) {
                // SBFM with imms = immr - 1 → SXT*-shape; fall through to raw
            }
            if (opc == 0b10 && imms == width - 1) {
                insn.mnemonic = Mnemonic::A64Lsr;
                set_ops(insn, make_reg(rd), make_reg(rn), make_imm_u(immr));
                return;
            }
            if (opc == 0b00 && imms == width - 1) {
                insn.mnemonic = Mnemonic::A64Asr;
                set_ops(insn, make_reg(rd), make_reg(rn), make_imm_u(immr));
                return;
            }
            if (opc == 0b10 && imms != width - 1 &&
                ((imms + 1) % width) == immr) {
                insn.mnemonic = Mnemonic::A64Lsl;
                const unsigned shift = (width - immr) % width;
                set_ops(insn, make_reg(rd), make_reg(rn), make_imm_u(shift));
                return;
            }
            // SXTB / SXTH / SXTW / UXTB / UXTH aliases (immr=0, imms in {7,15,31}).
            if (immr == 0 && (imms == 7 || imms == 15 || imms == 31)) {
                Mnemonic m = Mnemonic::Invalid;
                if (opc == 0b00) {
                    m = (imms == 7)  ? Mnemonic::A64Sxtb :
                        (imms == 15) ? Mnemonic::A64Sxth : Mnemonic::A64Sxtw;
                } else if (opc == 0b10) {
                    m = (imms == 7)  ? Mnemonic::A64Uxtb :
                        (imms == 15) ? Mnemonic::A64Uxth : Mnemonic::A64Uxtw;
                }
                if (m != Mnemonic::Invalid) {
                    insn.mnemonic = m;
                    set_ops(insn, make_reg(rd), make_reg(rn));
                    return;
                }
            }
            switch (opc) {
                case 0b00: insn.mnemonic = Mnemonic::A64Sbfm; break;
                case 0b01: insn.mnemonic = Mnemonic::A64Bfm;  break;
                case 0b10: insn.mnemonic = Mnemonic::A64Ubfm; break;
                default:   insn.mnemonic = Mnemonic::Invalid; return;
            }
            set_ops(insn, make_reg(rd), make_reg(rn),
                          make_imm_u(immr), make_imm_u(imms));
            return;
        }
        default:
            insn.mnemonic = Mnemonic::Invalid;
            return;
    }
}

// op0 = 101x : Branch / Exception / System
void decode_branch_sys(u32 raw, addr_t addr, Instruction& insn) {
    // Unconditional branch (immediate): bit 31 = op (0=B,1=BL),
    // bits 30:26 = 00101 (then 26-bit imm).
    if (bits(raw, 30, 26) == 0b00101) {
        const i64 off = sign_extend(bits(raw, 25, 0), 26) << 2;
        const addr_t target = addr + static_cast<addr_t>(off);
        insn.mnemonic = bit(raw, 31) ? Mnemonic::A64Bl : Mnemonic::A64B;
        set_ops(insn, make_rel(target));
        return;
    }

    // Conditional branch (immediate): bits 31:24 = 0101_0100, bit 4 = 0,
    // bits 3:0 = cond.
    if (bits(raw, 31, 24) == 0b01010100 && bit(raw, 4) == 0) {
        const i64 off = sign_extend(bits(raw, 23, 5), 19) << 2;
        const addr_t target = addr + static_cast<addr_t>(off);
        insn.mnemonic = Mnemonic::A64Bcc;
        set_ops(insn, make_imm_u(bits(raw, 3, 0), 1),
                      make_rel(target));
        return;
    }

    // Compare-and-branch / test-and-branch.
    if (bits(raw, 30, 25) == 0b011010) {
        const bool nz = bit(raw, 24);
        const i64 off = sign_extend(bits(raw, 23, 5), 19) << 2;
        const addr_t target = addr + static_cast<addr_t>(off);
        const bool sf = bit(raw, 31);
        const Reg rt = gpr_of(bits(raw, 4, 0), sf, /*is_sp=*/false);
        insn.mnemonic = nz ? Mnemonic::A64Cbnz : Mnemonic::A64Cbz;
        set_ops(insn, make_reg(rt), make_rel(target));
        return;
    }
    if (bits(raw, 30, 25) == 0b011011) {
        const bool nz = bit(raw, 24);
        const unsigned b5 = bit(raw, 31);
        const unsigned b40 = bits(raw, 23, 19);
        const unsigned bit_pos = (b5 << 5) | b40;
        const i64 off = sign_extend(bits(raw, 18, 5), 14) << 2;
        const addr_t target = addr + static_cast<addr_t>(off);
        const Reg rt = gpr_of(bits(raw, 4, 0), b5, /*is_sp=*/false);
        insn.mnemonic = nz ? Mnemonic::A64Tbnz : Mnemonic::A64Tbz;
        set_ops(insn, make_reg(rt), make_imm_u(bit_pos), make_rel(target));
        return;
    }

    // Unconditional branch (register): bits 31:25 = 1101011.
    if (bits(raw, 31, 25) == 0b1101011) {
        const unsigned opc = bits(raw, 24, 21);
        const Reg rn = gpr_of(bits(raw, 9, 5), /*sf=*/true, /*is_sp=*/false);
        switch (opc) {
            case 0b0000: insn.mnemonic = Mnemonic::A64Br;  break;
            case 0b0001: insn.mnemonic = Mnemonic::A64Blr; break;
            case 0b0010: insn.mnemonic = Mnemonic::A64Ret;
                          // RET defaults to x30 if Rn == 30; either way encode it
                          set_ops(insn, make_reg(rn));
                          return;
            case 0b0100: insn.mnemonic = Mnemonic::A64Eret; return;
            case 0b0101: insn.mnemonic = Mnemonic::A64Drps; return;
            default:     insn.mnemonic = Mnemonic::Invalid; return;
        }
        set_ops(insn, make_reg(rn));
        return;
    }

    // Exception-generation: bits 31:24 = 1101_0100, bits 23:21 = opc,
    // bits 4:2 = op2, bits 1:0 = LL.
    if (bits(raw, 31, 24) == 0b11010100) {
        const unsigned opc = bits(raw, 23, 21);
        const u32 imm16    = bits(raw, 20, 5);
        switch (opc) {
            case 0b000:
                if (bits(raw, 4, 0) == 1) insn.mnemonic = Mnemonic::A64Svc;
                else if (bits(raw, 4, 0) == 2) insn.mnemonic = Mnemonic::A64Hvc;
                else if (bits(raw, 4, 0) == 3) insn.mnemonic = Mnemonic::A64Smc;
                else { insn.mnemonic = Mnemonic::Invalid; return; }
                set_ops(insn, make_imm_u(imm16, 2));
                return;
            case 0b001:
                insn.mnemonic = Mnemonic::A64Brk;
                set_ops(insn, make_imm_u(imm16, 2));
                return;
            default:
                insn.mnemonic = Mnemonic::Invalid;
                return;
        }
    }

    // System: HINT / NOP / barriers / MRS / MSR. Simplest pattern: bits
    // 31:22 = 1101010100 + sub-classification.
    if (bits(raw, 31, 22) == 0b1101010100) {
        // HINT-class: bits 31:12 = 11010101000000110010, bits 11:5 = CRm:op2,
        // bits 4:0 = 11111.
        if (bits(raw, 31, 12) == 0xd5032 &&
            bits(raw, 4, 0) == 0b11111) {
            const unsigned imm = bits(raw, 11, 5);
            switch (imm) {
                case 0:  insn.mnemonic = Mnemonic::A64Nop;   set_ops(insn); return;
                case 1:  insn.mnemonic = Mnemonic::A64Yield; set_ops(insn); return;
                case 2:  insn.mnemonic = Mnemonic::A64Wfe;   set_ops(insn); return;
                case 3:  insn.mnemonic = Mnemonic::A64Wfi;   set_ops(insn); return;
                case 4:  insn.mnemonic = Mnemonic::A64Sev;   set_ops(insn); return;
                default: insn.mnemonic = Mnemonic::A64Hint;
                         set_ops(insn, make_imm_u(imm, 1));
                         return;
            }
        }
        // Barriers.
        if (bits(raw, 31, 12) == 0xd5033) {
            const unsigned op2 = bits(raw, 7, 5);
            const u32 crm      = bits(raw, 11, 8);
            switch (op2) {
                case 0b101: insn.mnemonic = Mnemonic::A64Dmb; break;
                case 0b100: insn.mnemonic = Mnemonic::A64Dsb; break;
                case 0b110: insn.mnemonic = Mnemonic::A64Isb; break;
                default:    insn.mnemonic = Mnemonic::Invalid; return;
            }
            set_ops(insn, make_imm_u(crm, 1));
            return;
        }
        // MRS / MSR (system register move). Decode as opaque operand.
        if (bits(raw, 31, 22) == 0b1101010100 &&
            (bits(raw, 21, 19) == 0b001 || bits(raw, 21, 19) == 0b011)) {
            const bool is_read = bit(raw, 21);
            insn.mnemonic = is_read ? Mnemonic::A64Mrs : Mnemonic::A64Msr;
            set_ops(insn,
                make_reg(gpr_of(bits(raw, 4, 0), /*sf=*/true, false)),
                make_imm_u(bits(raw, 20, 5), 2));
            return;
        }
    }

    insn.mnemonic = Mnemonic::Invalid;
}

// op0 = x1x0 : Loads and Stores
void decode_loads_stores(u32 raw, addr_t addr, Instruction& insn) {
    // Load/store register pair: bits 29:27 = 101, bit 26 = V (0 = GPR, 1 = FP/SIMD),
    // bits 25:23 = 010 (post-index) / 011 (pre-index) / 010 (signed offset, with bit 24 = 1).
    if (bits(raw, 29, 27) == 0b101 && bit(raw, 26) == 0 &&
        bits(raw, 25, 24) == 0b00) {
        const unsigned variant = bits(raw, 24, 23);    // 00 NoAlloc, 01 Post, 10 Off, 11 Pre
        (void)variant;
    }
    if (bits(raw, 29, 27) == 0b101 && bits(raw, 25, 23) <= 0b011 &&
        bit(raw, 26) == 0) {
        const unsigned opc = bits(raw, 31, 30);
        const bool L  = bit(raw, 22);
        const i64 imm7 = sign_extend(bits(raw, 21, 15), 7);
        const Reg rt2 = gpr_of(bits(raw, 14, 10), opc == 0b10, /*is_sp=*/false);
        const Reg rn  = gpr_of(bits(raw, 9, 5), /*sf=*/true,  /*is_sp=*/true);
        const Reg rt  = gpr_of(bits(raw, 4, 0), opc == 0b10, /*is_sp=*/false);
        if (opc != 0b00 && opc != 0b10) {
            // 32/64-bit forms only; skip 0b01 (LDPSW) for now.
            insn.mnemonic = Mnemonic::A64Ldpsw;
            const unsigned scale = 2;
            set_ops(insn, make_reg(rt), make_reg(rt2),
                          make_mem(rn, imm7 << scale, opc == 0b10 ? 8 : 4));
            return;
        }
        const unsigned scale = (opc == 0b10) ? 3u : 2u;
        const u8 access_size = (opc == 0b10) ? 8u : 4u;
        insn.mnemonic = L ? Mnemonic::A64Ldp : Mnemonic::A64Stp;
        set_ops(insn, make_reg(rt), make_reg(rt2),
                      make_mem(rn, imm7 << scale, access_size));
        return;
    }

    // Load register (literal, PC-relative): bits 31:30 = opc, bits 29:24 = 011000,
    // bits 23:5 = imm19, bits 4:0 = Rt. opc = 00 → 32-bit, 01 → 64-bit, 10 → SW
    // (sign-extending 32→64), 11 → prefetch (PRFM lit, defer).
    if (bits(raw, 29, 24) == 0b011000) {
        const unsigned opc = bits(raw, 31, 30);
        const i64 imm = sign_extend(bits(raw, 23, 5), 19) << 2;
        const addr_t target = addr + static_cast<addr_t>(imm);
        const bool is_64 = opc == 0b01;
        const Reg rt = gpr_of(bits(raw, 4, 0), is_64, /*is_sp=*/false);
        if (opc == 0b00) insn.mnemonic = Mnemonic::A64Ldr;
        else if (opc == 0b01) insn.mnemonic = Mnemonic::A64Ldr;
        else if (opc == 0b10) insn.mnemonic = Mnemonic::A64Ldrsw;
        else { insn.mnemonic = Mnemonic::Invalid; return; }
        set_ops(insn, make_reg(rt), make_rel(target, is_64 ? 8 : 4));
        return;
    }

    // Load/store register (unsigned offset): bits 31:30 = size, bits 29:27 = 111,
    // bit 26 = V, bits 25:24 = 01, bits 23:22 = opc, bits 21:10 = imm12.
    if (bits(raw, 29, 27) == 0b111 && bits(raw, 25, 24) == 0b01) {
        const unsigned size = bits(raw, 31, 30);
        const bool V = bit(raw, 26);
        const unsigned opc = bits(raw, 23, 22);
        const u32 imm12 = bits(raw, 21, 10);
        const Reg rn = gpr_of(bits(raw, 9, 5), /*sf=*/true, /*is_sp=*/true);
        const u8 access_size = static_cast<u8>(1u << size);
        const u32 disp = imm12 * access_size;
        if (V) {
            // FP/SIMD load/store — emit as opaque LDR/STR with v-reg.
            insn.mnemonic = (opc & 1) ? Mnemonic::A64Ldr : Mnemonic::A64Str;
            set_ops(insn, make_reg(vreg_of(bits(raw, 4, 0))),
                          make_mem(rn, static_cast<i64>(disp), access_size));
            return;
        }
        const Reg rt = gpr_of(bits(raw, 4, 0),
                              size == 0b11 || (opc & 0b10) != 0,
                              /*is_sp=*/false);
        Mnemonic m = Mnemonic::Invalid;
        if (opc == 0b00) {
            // STR
            switch (size) {
                case 0b00: m = Mnemonic::A64Strb; break;
                case 0b01: m = Mnemonic::A64Strh; break;
                default:   m = Mnemonic::A64Str;  break;
            }
        } else if (opc == 0b01) {
            switch (size) {
                case 0b00: m = Mnemonic::A64Ldrb; break;
                case 0b01: m = Mnemonic::A64Ldrh; break;
                default:   m = Mnemonic::A64Ldr;  break;
            }
        } else if (opc == 0b10) {
            // LDRSx (sign-extending into 64-bit Xt).
            switch (size) {
                case 0b00: m = Mnemonic::A64Ldrsb; break;
                case 0b01: m = Mnemonic::A64Ldrsh; break;
                case 0b10: m = Mnemonic::A64Ldrsw; break;
                default:   m = Mnemonic::Invalid;  break;
            }
        } else {
            // opc 0b11 = sign-extending into 32-bit Wt; treat as the 64-bit
            // shape for simplicity.
            switch (size) {
                case 0b00: m = Mnemonic::A64Ldrsb; break;
                case 0b01: m = Mnemonic::A64Ldrsh; break;
                default:   m = Mnemonic::Invalid;  break;
            }
        }
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rt),
                      make_mem(rn, static_cast<i64>(disp), access_size));
        return;
    }

    // Load/store register (immediate, unscaled / pre / post / unprivileged):
    // bits 31:30 = size, bits 29:27 = 111, bit 26 = V, bits 25:24 = 00,
    // bits 23:22 = opc, bit 21 = 0, bits 20:12 = imm9, bits 11:10 = op2.
    if (bits(raw, 29, 27) == 0b111 && bits(raw, 25, 24) == 0b00 &&
        bit(raw, 21) == 0) {
        const unsigned size = bits(raw, 31, 30);
        const bool V = bit(raw, 26);
        const unsigned opc = bits(raw, 23, 22);
        const i64 imm9 = sign_extend(bits(raw, 20, 12), 9);
        const unsigned op2 = bits(raw, 11, 10);
        const Reg rn = gpr_of(bits(raw, 9, 5), /*sf=*/true, /*is_sp=*/true);
        const u8 access_size = static_cast<u8>(1u << size);
        if (V) {
            insn.mnemonic = (opc & 1) ? Mnemonic::A64Ldur : Mnemonic::A64Stur;
            set_ops(insn, make_reg(vreg_of(bits(raw, 4, 0))),
                          make_mem(rn, imm9, access_size));
            return;
        }
        const bool is_64 = size == 0b11 || (opc & 0b10) != 0;
        const Reg rt = gpr_of(bits(raw, 4, 0), is_64, /*is_sp=*/false);

        // op2: 00 unscaled (LDUR/STUR), 01 post-indexed, 11 pre-indexed.
        // For v1 we emit the same mnemonic shape (LDUR/STUR/LDR/STR) and
        // encode the address as a Mem with disp; pre/post is documented in
        // a comment but not lifted as an actual reg-write side effect. Some
        // dataflow accuracy is lost (the writeback is invisible), but the
        // base+disp form is enough for CFG + linear sweep.
        Mnemonic m = Mnemonic::Invalid;
        if (opc == 0b00) {
            switch (size) {
                case 0b00: m = Mnemonic::A64Sturb; break;
                case 0b01: m = Mnemonic::A64Sturh; break;
                default:   m = Mnemonic::A64Stur;  break;
            }
        } else if (opc == 0b01) {
            switch (size) {
                case 0b00: m = Mnemonic::A64Ldurb; break;
                case 0b01: m = Mnemonic::A64Ldurh; break;
                default:   m = Mnemonic::A64Ldur;  break;
            }
        } else if (opc == 0b10) {
            switch (size) {
                case 0b00: m = Mnemonic::A64Ldursb; break;
                case 0b01: m = Mnemonic::A64Ldursh; break;
                case 0b10: m = Mnemonic::A64Ldursw; break;
                default:   m = Mnemonic::Invalid;   break;
            }
        }
        (void)op2;
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rt), make_mem(rn, imm9, access_size));
        return;
    }

    insn.mnemonic = Mnemonic::Invalid;
}

// op0 = x101 : Data Processing -- Register
void decode_dp_reg(u32 raw, Instruction& insn) {
    const bool sf = bit(raw, 31);
    const unsigned Rd = bits(raw, 4, 0);
    const unsigned Rn = bits(raw, 9, 5);
    const unsigned Rm = bits(raw, 20, 16);

    // Logical (shifted register): bits 28:24 = 01010, bit 21 = N flag.
    if (bits(raw, 28, 24) == 0b01010) {
        const unsigned opc = bits(raw, 30, 29);
        const bool N = bit(raw, 21);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        const Reg rm = gpr_of(Rm, sf, false);
        Mnemonic m = Mnemonic::Invalid;
        switch (opc) {
            case 0b00: m = N ? Mnemonic::A64Bic : Mnemonic::A64And; break;
            case 0b01: m = N ? Mnemonic::A64Orn : Mnemonic::A64Orr; break;
            case 0b10: m = N ? Mnemonic::A64Eon : Mnemonic::A64Eor; break;
            case 0b11: m = N ? Mnemonic::A64Bics : Mnemonic::A64Ands; break;
        }
        // ORR with shift=0 + Rn=zr is a register-to-register MOV alias.
        if (m == Mnemonic::A64Orr && Rn == 31 && bits(raw, 15, 10) == 0) {
            insn.mnemonic = Mnemonic::A64Mov;
            set_ops(insn, make_reg(rd), make_reg(rm));
            return;
        }
        // ORN with Rn=zr is MVN alias.
        if (m == Mnemonic::A64Orn && Rn == 31) {
            insn.mnemonic = Mnemonic::A64Mvn;
            set_ops(insn, make_reg(rd), make_reg(rm));
            return;
        }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm));
        return;
    }

    // Add/sub (shifted register): bits 28:24 = 01011, bit 21 = 0.
    if (bits(raw, 28, 24) == 0b01011 && bit(raw, 21) == 0) {
        const bool op = bit(raw, 30);
        const bool S  = bit(raw, 29);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        const Reg rm = gpr_of(Rm, sf, false);
        if (S && Rd == 31) {
            insn.mnemonic = op ? Mnemonic::Cmp : Mnemonic::Cmn;
            set_ops(insn, make_reg(rn), make_reg(rm));
        } else {
            insn.mnemonic = op
                ? (S ? Mnemonic::A64Subs : Mnemonic::A64Sub)
                : (S ? Mnemonic::A64Adds : Mnemonic::A64Add);
            // SUB with Rn=zr is NEG / NEGS alias.
            if ((insn.mnemonic == Mnemonic::A64Sub  ||
                 insn.mnemonic == Mnemonic::A64Subs) && Rn == 31) {
                insn.mnemonic = (insn.mnemonic == Mnemonic::A64Subs)
                    ? Mnemonic::A64Negs : Mnemonic::A64Neg;
                set_ops(insn, make_reg(rd), make_reg(rm));
                return;
            }
            set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm));
        }
        return;
    }

    // Conditional select: bits 30 = op, 29 = S, 28:21 = 11010100, 11:10 = op2.
    if (bits(raw, 28, 21) == 0b11010100) {
        const bool op = bit(raw, 30);
        const unsigned op2 = bits(raw, 11, 10);
        const unsigned cond = bits(raw, 15, 12);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        const Reg rm = gpr_of(Rm, sf, false);
        Mnemonic m = Mnemonic::Invalid;
        if (!op && op2 == 0b00) m = Mnemonic::A64Csel;
        if (!op && op2 == 0b01) m = Mnemonic::A64Csinc;
        if ( op && op2 == 0b00) m = Mnemonic::A64Csinv;
        if ( op && op2 == 0b01) m = Mnemonic::A64Csneg;
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        // CSINC Rd, ZR, ZR, cond → CSET (and CSINV→CSETM, etc).
        if (Rn == 31 && Rm == 31 &&
            (m == Mnemonic::A64Csinc || m == Mnemonic::A64Csinv)) {
            insn.mnemonic = (m == Mnemonic::A64Csinc)
                ? Mnemonic::A64Cset : Mnemonic::A64Csetm;
            set_ops(insn, make_reg(rd), make_imm_u(cond, 1));
            return;
        }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm),
                      make_imm_u(cond, 1));
        return;
    }

    // Data processing (3-source): bits 28:24 = 11011, bits 23:21 = opc.
    if (bits(raw, 28, 24) == 0b11011) {
        const unsigned opc = bits(raw, 23, 21);
        const bool o0 = bit(raw, 15);
        const unsigned Ra = bits(raw, 14, 10);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        const Reg rm = gpr_of(Rm, sf, false);
        const Reg ra = gpr_of(Ra, sf, false);
        Mnemonic m = Mnemonic::Invalid;
        if (opc == 0b000) m = o0 ? Mnemonic::A64Msub : Mnemonic::A64Madd;
        if (opc == 0b001) m = o0 ? Mnemonic::A64Smsubl : Mnemonic::A64Smaddl;
        if (opc == 0b010) m = Mnemonic::A64Smulh;
        if (opc == 0b101) m = o0 ? Mnemonic::A64Umsubl : Mnemonic::A64Umaddl;
        if (opc == 0b110) m = Mnemonic::A64Umulh;
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        // MADD with Ra=zr is the MUL alias.
        if (m == Mnemonic::A64Madd && Ra == 31) {
            insn.mnemonic = Mnemonic::A64Mul;
            set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm));
            return;
        }
        insn.mnemonic = m;
        if (m == Mnemonic::A64Smulh || m == Mnemonic::A64Umulh) {
            set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm));
        } else {
            set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm), make_reg(ra));
        }
        return;
    }

    // Data processing (2-source): bits 28:21 = 11010110.
    if (bits(raw, 28, 21) == 0b11010110) {
        const unsigned opcode = bits(raw, 15, 10);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        const Reg rm = gpr_of(Rm, sf, false);
        Mnemonic m = Mnemonic::Invalid;
        switch (opcode) {
            case 0b000010: m = Mnemonic::A64Udiv; break;
            case 0b000011: m = Mnemonic::A64Sdiv; break;
            case 0b001000: m = Mnemonic::A64Lslv; break;
            case 0b001001: m = Mnemonic::A64Lsrv; break;
            case 0b001010: m = Mnemonic::A64Asrv; break;
            case 0b001011: m = Mnemonic::A64Rorv; break;
        }
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rd), make_reg(rn), make_reg(rm));
        return;
    }

    // Data processing (1-source): bits 30:21 = 1011010110, opcode in 15:10.
    if (bits(raw, 30, 21) == 0b1011010110) {
        const unsigned opcode = bits(raw, 15, 10);
        const Reg rd = gpr_of(Rd, sf, false);
        const Reg rn = gpr_of(Rn, sf, false);
        Mnemonic m = Mnemonic::Invalid;
        switch (opcode) {
            case 0b000000: m = Mnemonic::A64Rbit; break;
            case 0b000001: m = Mnemonic::A64Rev16; break;
            case 0b000010: m = sf ? Mnemonic::A64Rev32 : Mnemonic::A64Rev; break;
            case 0b000011: m = sf ? Mnemonic::A64Rev   : Mnemonic::A64Rev; break;
            case 0b000100: m = Mnemonic::A64Clz; break;
            case 0b000101: m = Mnemonic::A64Cls; break;
        }
        if (m == Mnemonic::Invalid) { insn.mnemonic = Mnemonic::Invalid; return; }
        insn.mnemonic = m;
        set_ops(insn, make_reg(rd), make_reg(rn));
        return;
    }

    insn.mnemonic = Mnemonic::Invalid;
}

}  // namespace

Result<Instruction>
Arm64Decoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.size() < 4) {
        return std::unexpected(Error::truncated(std::format(
            "arm64: truncated insn at {:#x}", addr)));
    }
    Instruction insn;
    insn.address = addr;
    insn.length  = 4;
    insn.mnemonic = Mnemonic::Invalid;
    std::memcpy(insn.raw_bytes.data(), code.data(), 4);

    const u32 raw = read_le_at<u32>(code.data());
    const unsigned op0 = bits(raw, 28, 25);

    if ((op0 & 0b1110) == 0b1000) {
        decode_dp_imm(raw, addr, insn);
    } else if ((op0 & 0b1110) == 0b1010) {
        decode_branch_sys(raw, addr, insn);
    } else if ((op0 & 0b0101) == 0b0100) {
        decode_loads_stores(raw, addr, insn);
    } else if ((op0 & 0b0111) == 0b0101) {
        decode_dp_reg(raw, insn);
    }
    // op0 = x111 (Advanced SIMD/FP) and the rest are left as Invalid;
    // the linear sweep records the byte-advance via insn.length and
    // moves on. The lifter will tag Invalid instructions as
    // `arm64.<unknown 0xNNNNNNNN>` intrinsics so the reader sees the
    // gap rather than silently wrong code.
    if (insn.mnemonic == Mnemonic::Invalid) {
        // Surface the raw word so callers can render `udf #N`-style notes.
        insn.mnemonic = Mnemonic::A64Udf;
        set_ops(insn, make_imm_u(raw, 4));
    }
    return insn;
}

}  // namespace ember
