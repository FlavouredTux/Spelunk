#include <algorithm>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <span>
#include <type_traits>
#include <utility>

#include <ember/common/bytes.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>
#include <ember/disasm/register.hpp>
#include <ember/disasm/x64_decoder.hpp>

#include "decoder_internal.hpp"

namespace ember {

namespace {

using x64_decode::OpcodeEntry;
using x64_decode::OpSpec;
using x64_decode::kGroups;
using x64_decode::kPrimary;
using x64_decode::kSecondary;
using x64_decode::kSecondary_66;
using x64_decode::kSecondary_F2;
using x64_decode::kSecondary_F3;
using x64_decode::kVexMap2;
using x64_decode::kVexMap2_66;
using x64_decode::kVexMap2_F2;
using x64_decode::kVexMap2_F3;
using x64_decode::kVzeroupper;

// ============================================================================
// Register lookup tables
// ============================================================================

constexpr Reg kGpr8Legacy[8] = {
    Reg::Al, Reg::Cl, Reg::Dl, Reg::Bl,
    Reg::Ah, Reg::Ch, Reg::Dh, Reg::Bh,
};
constexpr Reg kGpr8Rex[16] = {
    Reg::Al,  Reg::Cl,  Reg::Dl,  Reg::Bl,
    Reg::Spl, Reg::Bpl, Reg::Sil, Reg::Dil,
    Reg::R8b, Reg::R9b, Reg::R10b, Reg::R11b,
    Reg::R12b, Reg::R13b, Reg::R14b, Reg::R15b,
};
constexpr Reg kGpr16[16] = {
    Reg::Ax, Reg::Cx, Reg::Dx, Reg::Bx,
    Reg::Sp, Reg::Bp, Reg::Si, Reg::Di,
    Reg::R8w, Reg::R9w, Reg::R10w, Reg::R11w,
    Reg::R12w, Reg::R13w, Reg::R14w, Reg::R15w,
};
constexpr Reg kGpr32[16] = {
    Reg::Eax, Reg::Ecx, Reg::Edx, Reg::Ebx,
    Reg::Esp, Reg::Ebp, Reg::Esi, Reg::Edi,
    Reg::R8d, Reg::R9d, Reg::R10d, Reg::R11d,
    Reg::R12d, Reg::R13d, Reg::R14d, Reg::R15d,
};
constexpr Reg kGpr64[16] = {
    Reg::Rax, Reg::Rcx, Reg::Rdx, Reg::Rbx,
    Reg::Rsp, Reg::Rbp, Reg::Rsi, Reg::Rdi,
    Reg::R8,  Reg::R9,  Reg::R10, Reg::R11,
    Reg::R12, Reg::R13, Reg::R14, Reg::R15,
};

[[nodiscard]] constexpr Reg gpr(u8 idx, unsigned size, bool rex_present) noexcept {
    idx &= 0xF;
    switch (size) {
        case 1: return rex_present ? kGpr8Rex[idx] : (idx < 8 ? kGpr8Legacy[idx] : Reg::None);
        case 2: return kGpr16[idx];
        case 4: return kGpr32[idx];
        case 8: return kGpr64[idx];
        default: return Reg::None;
    }
}

// ============================================================================
// Decode context
// ============================================================================

struct Context {
    std::span<const std::byte> code{};
    std::size_t pos  = 0;
    addr_t      addr = 0;
    PrefixSet   prefix{};
    bool rex_present = false;
    bool rex_w = false;
    bool rex_r = false;
    bool rex_x = false;
    bool rex_b = false;
    bool vex_r2 = false;
    bool vex_b2 = false;
    bool vex = false;
    bool evex = false;
    u8 vex_map = 0;
    u8 vex_pp = 0;
    u8 vex_vvvv = 0;
    u8 vector_bytes = 16;
    u8 vector_mask = 0;
    bool vector_zeroing = false;
    bool vector_broadcast = false;
    bool default_64 = false;
    u8 opcode = 0;
    u8 opcode_low3 = 0;
    u8 modrm = 0;
    bool have_modrm = false;

    [[nodiscard]] bool eof() const noexcept { return pos >= code.size(); }

    [[nodiscard]] unsigned opsize() const noexcept {
        if (default_64) return prefix.opsize ? 2u : 8u;
        if (rex_w) return 8;
        if (prefix.opsize) return 2;
        return 4;
    }

    [[nodiscard]] Result<u8> read_u8() noexcept {
        if (pos >= code.size()) {
            return std::unexpected(Error::truncated("x64: truncated opcode stream"));
        }
        return static_cast<u8>(code[pos++]);
    }

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] Result<T> read_le() noexcept {
        if (pos > code.size() || code.size() - pos < sizeof(T)) {
            return std::unexpected(Error::truncated(std::format(
                "x64: truncated {}-byte operand at pos {:#x}", sizeof(T), pos)));
        }
        const T v = read_le_at<T>(code.data() + pos);
        pos += sizeof(T);
        return v;
    }
};

[[nodiscard]] constexpr Reg vector_reg(u8 index, u8 bytes) noexcept {
    index &= 31u;
    if (bytes == 64) {
        return static_cast<Reg>(static_cast<unsigned>(Reg::Zmm0) + index);
    }
    if (bytes == 32) {
        return static_cast<Reg>(static_cast<unsigned>(Reg::Ymm0) + index);
    }
    return static_cast<Reg>(static_cast<unsigned>(Reg::Xmm0) + index);
}

// ============================================================================
// Decoding helpers
// ============================================================================

[[nodiscard]] bool parse_legacy_prefix(Context& ctx, u8 b) noexcept {
    switch (b) {
        case 0x26: ctx.prefix.segment  = Reg::Es; return true;
        case 0x2E: ctx.prefix.segment  = Reg::Cs; return true;
        case 0x36: ctx.prefix.segment  = Reg::Ss; return true;
        case 0x3E: ctx.prefix.segment  = Reg::Ds; return true;
        case 0x64: ctx.prefix.segment  = Reg::Fs; return true;
        case 0x65: ctx.prefix.segment  = Reg::Gs; return true;
        case 0x66: ctx.prefix.opsize   = true;    return true;
        case 0x67: ctx.prefix.addrsize = true;    return true;
        case 0xF0: ctx.prefix.lock     = true;    return true;
        case 0xF2: ctx.prefix.repne    = true;    return true;
        case 0xF3: ctx.prefix.rep      = true;    return true;
        default:   return false;
    }
}

[[nodiscard]] Result<Operand>
decode_modrm_rm(Context& ctx, unsigned size, bool mem_only) noexcept {
    const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
    const u8 rm  = static_cast<u8>( ctx.modrm & 7);
    const u8 rm_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | rm);

    if (mod == 3) {
        if (mem_only) {
            return std::unexpected(Error::invalid_format(
                "x64: memory operand required but ModR/M.mod=3"));
        }
        return Operand::make_reg(gpr(rm_ext, size, ctx.rex_present));
    }

    Mem m;
    m.size    = static_cast<u8>(size);
    m.segment = ctx.prefix.segment;
    const unsigned address_size = ctx.prefix.addrsize ? 4u : 8u;
    m.address_size = static_cast<u8>(address_size);

    if (rm == 4) {
        auto sib_r = ctx.read_u8();
        if (!sib_r) return std::unexpected(std::move(sib_r).error());
        const u8 sib         = *sib_r;
        const u8 scale_bits  = static_cast<u8>((sib >> 6) & 3);
        const u8 index_bits  = static_cast<u8>((sib >> 3) & 7);
        const u8 base_bits   = static_cast<u8>( sib & 7);
        const u8 index_ext   = static_cast<u8>((ctx.rex_x ? 8u : 0u) | index_bits);
        const u8 base_ext    = static_cast<u8>((ctx.rex_b ? 8u : 0u) | base_bits);

        if (!(index_bits == 4 && !ctx.rex_x)) {
            m.index = gpr(index_ext, address_size, /*rex_present=*/true);
            m.scale = static_cast<u8>(1u << scale_bits);
        }

        if (mod == 0 && base_bits == 5) {
            auto d = ctx.read_le<u32>();
            if (!d) return std::unexpected(std::move(d).error());
            m.disp = ctx.prefix.addrsize
                ? static_cast<i64>(*d)
                : static_cast<i64>(static_cast<i32>(*d));
            m.has_disp = true;
        } else {
            m.base = gpr(base_ext, address_size, /*rex_present=*/true);
        }
    } else if (mod == 0 && rm == 5) {
        auto d = ctx.read_le<u32>();
        if (!d) return std::unexpected(std::move(d).error());
        m.base = ctx.prefix.addrsize ? Reg::None : Reg::Rip;
        m.disp = ctx.prefix.addrsize
            ? static_cast<i64>(*d)
            : static_cast<i64>(static_cast<i32>(*d));
        m.has_disp = true;
    } else {
        m.base = gpr(rm_ext, address_size, /*rex_present=*/true);
    }

    if (mod == 1) {
        auto d = ctx.read_le<u8>();
        if (!d) return std::unexpected(std::move(d).error());
        m.disp += static_cast<i64>(static_cast<i8>(*d));
        m.has_disp = true;
    } else if (mod == 2) {
        auto d = ctx.read_le<u32>();
        if (!d) return std::unexpected(std::move(d).error());
        m.disp += static_cast<i64>(static_cast<i32>(*d));
        m.has_disp = true;
    }

    return Operand::make_mem(m);
}

[[nodiscard]] Result<Imm>
read_imm(Context& ctx, unsigned size, unsigned sign_ext_to, bool signed_val) noexcept {
    i64 value = 0;
    switch (size) {
        case 1: {
            auto v = ctx.read_le<u8>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i8>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 2: {
            auto v = ctx.read_le<u16>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i16>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 4: {
            auto v = ctx.read_le<u32>();
            if (!v) return std::unexpected(std::move(v).error());
            value = signed_val ? static_cast<i64>(static_cast<i32>(*v))
                               : static_cast<i64>(*v);
            break;
        }
        case 8: {
            auto v = ctx.read_le<u64>();
            if (!v) return std::unexpected(std::move(v).error());
            value = static_cast<i64>(*v);
            break;
        }
        default:
            return std::unexpected(Error::invalid_format("x64: bad immediate size"));
    }
    Imm imm;
    imm.value     = value;
    imm.size      = static_cast<u8>(sign_ext_to != 0 ? sign_ext_to : size);
    imm.is_signed = signed_val;
    return imm;
}

[[nodiscard]] Result<Operand>
decode_rel(Context& ctx, unsigned size, addr_t insn_addr) noexcept {
    i64 off = 0;
    switch (size) {
        case 1: {
            auto v = ctx.read_le<u8>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i8>(*v));
            break;
        }
        case 2: {
            auto v = ctx.read_le<u16>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i16>(*v));
            break;
        }
        case 4: {
            auto v = ctx.read_le<u32>();
            if (!v) return std::unexpected(std::move(v).error());
            off = static_cast<i64>(static_cast<i32>(*v));
            break;
        }
        default:
            return std::unexpected(Error::invalid_format("x64: bad relative size"));
    }
    Rel r;
    r.offset = off;
    r.size   = static_cast<u8>(size);
    r.target = insn_addr + static_cast<u64>(ctx.pos) + static_cast<u64>(off);
    return Operand::make_rel(r);
}

[[nodiscard]] unsigned iz_size(const Context& ctx) noexcept {
    return (ctx.opsize() == 2) ? 2 : 4;
}

[[nodiscard]] Result<Operand>
decode_operand(Context& ctx, OpSpec spec, addr_t insn_addr) noexcept {
    const unsigned os = ctx.opsize();
    switch (spec) {
        case OpSpec::None: return Operand{};

        case OpSpec::Gb: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, 1, ctx.rex_present));
        }
        case OpSpec::Gv: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, os, ctx.rex_present));
        }
        case OpSpec::Gw: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, 2, ctx.rex_present));
        }

        case OpSpec::Eb: return decode_modrm_rm(ctx, 1,  false);
        case OpSpec::Ev: return decode_modrm_rm(ctx, os, false);
        case OpSpec::Ew: return decode_modrm_rm(ctx, 2,  false);
        case OpSpec::Ed: return decode_modrm_rm(ctx, 4,  false);
        case OpSpec::Edq:
            return decode_modrm_rm(ctx, ctx.rex_w ? 8u : 4u, false);
        case OpSpec::M:  return decode_modrm_rm(ctx, os, true);

        case OpSpec::Ib: {
            auto imm = read_imm(ctx, 1, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iw: {
            auto imm = read_imm(ctx, 2, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iz: {
            auto imm = read_imm(ctx, iz_size(ctx), 0, true);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Iv: {
            auto imm = read_imm(ctx, os, 0, false);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }
        case OpSpec::Ibsext: {
            auto imm = read_imm(ctx, 1, os, true);
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_imm(*imm);
        }

        case OpSpec::Jb: return decode_rel(ctx, 1, insn_addr);
        // Near branches in 64-bit mode always carry rel32. 0x66 does not
        // shrink the displacement to rel16.
        case OpSpec::Jz: return decode_rel(ctx, 4, insn_addr);

        case OpSpec::AL:  return Operand::make_reg(Reg::Al);
        case OpSpec::CL:  return Operand::make_reg(Reg::Cl);
        case OpSpec::RAX: {
            const Reg r = (os == 8) ? Reg::Rax : (os == 2 ? Reg::Ax : Reg::Eax);
            return Operand::make_reg(r);
        }

        case OpSpec::One: {
            Imm imm;
            imm.value     = 1;
            imm.size      = 1;
            imm.is_signed = false;
            return Operand::make_imm(imm);
        }

        case OpSpec::Zb: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | ctx.opcode_low3);
            return Operand::make_reg(gpr(reg_ext, 1, ctx.rex_present));
        }
        case OpSpec::Zv: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_b ? 8u : 0u) | ctx.opcode_low3);
            return Operand::make_reg(gpr(reg_ext, os, ctx.rex_present));
        }

        case OpSpec::Vx: {
            // Vector register from ModR/M.reg. VEX extends to 15; EVEX adds
            // the high extension bit for registers 16..31.
            const u8 reg_ext =
                static_cast<u8>((ctx.vex_r2 ? 16u : 0u) |
                                (ctx.rex_r ? 8u : 0u) |
                                ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(vector_reg(reg_ext, ctx.vector_bytes));
        }
        case OpSpec::Hx: {
            return Operand::make_reg(vector_reg(ctx.vex_vvvv, ctx.vector_bytes));
        }
        case OpSpec::Hv: {
            return Operand::make_reg(gpr(ctx.vex_vvvv, os, /*rex_present=*/true));
        }
        case OpSpec::Wx: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.vex_b2 ? 16u : 0u) |
                                    (ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, ctx.vector_bytes));
            }
            return decode_modrm_rm(ctx, ctx.vector_bytes, /*mem_only=*/true);
        }
        case OpSpec::Wss: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            const unsigned scalar_size =
                (ctx.vex || ctx.evex) && ctx.vex_map == 2 && ctx.rex_w ? 8u : 4u;
            return decode_modrm_rm(ctx, scalar_size, /*mem_only=*/true);
        }
        case OpSpec::Wsd: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            return decode_modrm_rm(ctx, /*size=*/8, /*mem_only=*/true);
        }
    }
    return std::unexpected(Error::not_implemented("x64: unhandled operand spec"));
}

// ============================================================================
// x87 FPU escapes (opcodes D8-DF)
//
// These eight bytes are not instructions of their own - the real opcode is
// carried in the ModR/M byte, and the map splits in two on ModR/M.mod:
//
//   mod != 11b ("memory" forms): ModR/M.reg (/0../7) selects the variant and
//       implies a fixed operand width that depends on the escape byte:
//         D8  m32 real  fadd/fmul/fcom/fcomp/fsub/fsubr/fdiv/fdivr
//         D9  mixed     /0 fld m32, /2 fst m32, /3 fstp m32,
//                       /4 fldcw m16, /5 fnstcw m16 (fstcw alias),
//                       /7 fnstsw m16 (fstsw alias)
//         DA  m32 int   fiadd/fimul/ficom/... (not modeled yet)
//         DB  m32 int   /0 fild, /2 fist, /3 fistp (m80 rows /5,/7 n/a)
//         DC  m64 real  same /N rows as D8
//         DD  mixed     /0 fld m64, /2 fst m64, /3 fstp m64, /7 fnstsw m16
//         DE  m16 int   fiadd/... (not modeled yet)
//         DF  m16/m64   /0 fild, /2 fist, /3 fistp, /5 fild m64,
//                       /7 fistp m64
//
//   mod == 11b ("register" forms): the low six bits (C0..FF) select among
//       st(i)-register operations and zero-operand state operations that
//       share nothing with the same-/N memory rows above (D9 E0 fchs sits
//       "under" D9 /4 fldcw). Rows we do not model (f2xm1, fscale, fbld,
//       fnop, ...) and reserved slots fall through to the regular
//       unsupported-opcode error so nothing ever misdecodes silently.
//
// Stack slots st(0)..st(7) ride on Kind::Register operands with
// Operand::x87_stack set. Two-address rows keep SDM operand order: D8 C1 is
// `fadd st(1), st(0)` while DC C1 flips to `fadd st(0), st(1)` - and the
// DC E0/F0 rows are the *reversed* fsubr/fdivr counterparts of D8 E0/F0.
// ============================================================================

enum X87Shape : u8 {
    xs_none,      // zero-operand state op (fchs, fabs, fsqrt, finit, fcompp)
    xs_sti,       // single st(i) operand
    xs_sti_st0,   // st(i), st(0)
    xs_st0_sti,   // st(0), st(i)
    xs_ax,        // implicit AX destination (fnstsw ax)
};

struct X87MemEntry {
    Mnemonic m    = Mnemonic::Invalid;
    u8       size = 0;   // memory operand width; 0 = reserved/not modeled
};

struct X87RegForm {
    Mnemonic m     = Mnemonic::Invalid;
    u8       shape = xs_none;
};

[[nodiscard]] constexpr X87RegForm x87_reg_form(u8 esc, u8 b) noexcept {
    const auto top = static_cast<u8>(b & 0xf8);   // mod==3 + reg field
    switch (esc) {
        case 0xD8:
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fadd,  xs_sti_st0};
                case 0xC8: return {Mnemonic::X87Fmul,  xs_sti_st0};
                case 0xD0: return {Mnemonic::X87Fcom,  xs_sti};
                case 0xD8: return {Mnemonic::X87Fcomp, xs_sti};
                case 0xE0: return {Mnemonic::X87Fsub,  xs_sti_st0};
                case 0xE8: return {Mnemonic::X87Fsubr, xs_sti_st0};
                case 0xF0: return {Mnemonic::X87Fdiv,  xs_sti_st0};
                case 0xF8: return {Mnemonic::X87Fdivr, xs_sti_st0};
                default:   return {};
            }
        case 0xD9:
            if (top == 0xC0) return {Mnemonic::X87Fld,  xs_sti};
            if (top == 0xC8) return {Mnemonic::X87Fxch, xs_sti};
            if (b == 0xE0)   return {Mnemonic::X87Fchs,  xs_none};
            if (b == 0xE1)   return {Mnemonic::X87Fabs,  xs_none};
            if (b == 0xFA)   return {Mnemonic::X87Fsqrt, xs_none};
            return {};
        case 0xDC:
            // Register rows keep st(0) as destination, and the SUB/DIV
            // directions swap relative to D8: DC E0 is fsubr, DC E8 is
            // fsub (mirror of D8 E0/E8 where st(i) is written).
            switch (top) {
                case 0xC0: return {Mnemonic::X87Fadd,  xs_st0_sti};
                case 0xC8: return {Mnemonic::X87Fmul,  xs_st0_sti};
                case 0xE0: return {Mnemonic::X87Fsubr, xs_st0_sti};
                case 0xE8: return {Mnemonic::X87Fsub,  xs_st0_sti};
                case 0xF0: return {Mnemonic::X87Fdivr, xs_st0_sti};
                case 0xF8: return {Mnemonic::X87Fdiv,  xs_st0_sti};
                default:   return {};   // D0-D7 reserved
            }
        case 0xDD:
            switch (top) {
                case 0xD0: return {Mnemonic::X87Fst,    xs_sti};
                case 0xD8: return {Mnemonic::X87Fstp,   xs_sti};
                case 0xE0: return {Mnemonic::X87Fucom,  xs_sti};
                case 0xE8: return {Mnemonic::X87Fucomp, xs_sti};
                default:   return {};   // C0-C7 (ffree) not modeled
            }
        case 0xDE:
            // Pop variants write st(i) then pop; DE D9 is the lone fcompp.
            if (b == 0xD9) return {Mnemonic::X87Fcompp, xs_none};
            switch (top) {
                case 0xC0: return {Mnemonic::X87Faddp,  xs_sti_st0};
                case 0xC8: return {Mnemonic::X87Fmulp,  xs_sti_st0};
                case 0xE0: return {Mnemonic::X87Fsubrp, xs_sti_st0};
                case 0xE8: return {Mnemonic::X87Fsubp,  xs_sti_st0};
                case 0xF0: return {Mnemonic::X87Fdivrp, xs_sti_st0};
                case 0xF8: return {Mnemonic::X87Fdivp,  xs_sti_st0};
                default:   return {};   // D0-D8 minus D9 reserved
            }
        case 0xDB:
            // FUCOMI/FUCOMIP compare into EFLAGS; E3 is the finit reset.
            if (b == 0xE3)   return {Mnemonic::X87Finit, xs_none};
            if (top == 0xE8) return {Mnemonic::X87Fucomi,  xs_sti};
            if (top == 0xF0) return {Mnemonic::X87Fucomip, xs_sti};
            return {};
        case 0xDF:
            if (b == 0xE0) return {Mnemonic::X87Fnstsw, xs_ax};
            return {};
        default:
            return {};   // DA (integer arithmetic) rows are not modeled
    }
}

constexpr X87MemEntry kX87MemD8[8] = {
    {Mnemonic::X87Fadd, 4}, {Mnemonic::X87Fmul, 4},
    {Mnemonic::X87Fcom, 4}, {Mnemonic::X87Fcomp, 4},
    {Mnemonic::X87Fsub, 4}, {Mnemonic::X87Fsubr, 4},
    {Mnemonic::X87Fdiv, 4}, {Mnemonic::X87Fdivr, 4},
};
constexpr X87MemEntry kX87MemD9[8] = {
    {Mnemonic::X87Fld, 4},    {},                    {Mnemonic::X87Fst, 4},
    {Mnemonic::X87Fstp, 4},   {Mnemonic::X87Fldcw, 2},
    {Mnemonic::X87Fnstcw, 2}, {},                    {Mnemonic::X87Fnstsw, 2},
};
constexpr X87MemEntry kX87MemDC[8] = {
    {Mnemonic::X87Fadd, 8}, {Mnemonic::X87Fmul, 8},
    {Mnemonic::X87Fcom, 8}, {Mnemonic::X87Fcomp, 8},
    {Mnemonic::X87Fsub, 8}, {Mnemonic::X87Fsubr, 8},
    {Mnemonic::X87Fdiv, 8}, {Mnemonic::X87Fdivr, 8},
};
constexpr X87MemEntry kX87MemDD[8] = {
    {Mnemonic::X87Fld, 8},  {},                  {Mnemonic::X87Fst, 8},
    {Mnemonic::X87Fstp, 8}, {},                  {},
    {},                     {Mnemonic::X87Fnstsw, 2},
};
constexpr X87MemEntry kX87MemDB[8] = {
    {Mnemonic::X87Fild, 4}, {},                  {Mnemonic::X87Fist, 4},
    {Mnemonic::X87Fistp, 4}, {},                 {},
    {},                      {},
};
constexpr X87MemEntry kX87MemDF[8] = {
    {Mnemonic::X87Fild, 2}, {},                  {Mnemonic::X87Fist, 2},
    {Mnemonic::X87Fistp, 2}, {},                 {Mnemonic::X87Fild, 8},
    {},                      {Mnemonic::X87Fistp, 8},
};

[[nodiscard]] const X87MemEntry& x87_mem_form(u8 esc, u8 reg) noexcept {
    switch (esc) {
        case 0xD8: return kX87MemD8[reg];
        case 0xD9: return kX87MemD9[reg];
        case 0xDB: return kX87MemDB[reg];
        case 0xDC: return kX87MemDC[reg];
        case 0xDD: return kX87MemDD[reg];
        case 0xDF: return kX87MemDF[reg];
        default:   break;
    }
    static constexpr X87MemEntry none{};
    return none;
}

[[nodiscard]] Operand make_stack_reg(u8 i) noexcept {
    Operand o;
    o.kind      = Operand::Kind::Register;
    o.reg       = Reg::None;
    o.x87_stack = static_cast<u8>(i & 7u);
    return o;
}

[[nodiscard]] Result<Instruction>
decode_x87_escape(Context& ctx, addr_t addr) noexcept {
    auto m_r = ctx.read_u8();
    if (!m_r) return std::unexpected(std::move(m_r).error());
    ctx.modrm = *m_r;

    const u8 esc = ctx.opcode;
    const u8 reg = static_cast<u8>((ctx.modrm >> 3) & 7);

    Instruction insn;
    insn.address  = addr;
    insn.prefixes = ctx.prefix;

    if ((ctx.modrm >> 6) != 3) {
        const auto& e = x87_mem_form(esc, reg);
        if (e.m == Mnemonic::Invalid || e.size == 0) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported x87 memory form {:02x} /{} at {:#x}",
                esc, reg, addr)));
        }
        insn.mnemonic = e.m;
        auto op = decode_modrm_rm(ctx, e.size, /*mem_only=*/true);
        if (!op) return std::unexpected(std::move(op).error());
        insn.operands[0]  = *op;
        insn.num_operands = 1;
    } else {
        const auto e = x87_reg_form(esc, ctx.modrm);
        if (e.m == Mnemonic::Invalid) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported x87 register form {:02x} {:02x} at {:#x}",
                esc, ctx.modrm, addr)));
        }
        insn.mnemonic = e.m;
        const u8 i = static_cast<u8>(ctx.modrm & 7);
        switch (e.shape) {
            case xs_sti:
                insn.operands[0]  = make_stack_reg(i);
                insn.num_operands = 1;
                break;
            case xs_sti_st0:
                insn.operands[0]  = make_stack_reg(i);
                insn.operands[1]  = make_stack_reg(0);
                insn.num_operands = 2;
                break;
            case xs_st0_sti:
                insn.operands[0]  = make_stack_reg(0);
                insn.operands[1]  = make_stack_reg(i);
                insn.num_operands = 2;
                break;
            case xs_ax:
                insn.operands[0]  = Operand::make_reg(Reg::Ax);
                insn.num_operands = 1;
                break;
            case xs_none:
            default:
                break;
        }
    }

    insn.length = static_cast<u8>(ctx.pos);
    std::memcpy(insn.raw_bytes.data(), ctx.code.data(),
                std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
    return insn;
}

[[nodiscard]] constexpr bool is_default_64(Mnemonic m) noexcept {
    switch (m) {
        case Mnemonic::Push:
        case Mnemonic::Pop:
        case Mnemonic::Call:
        case Mnemonic::Jmp:
        case Mnemonic::Ret:
        case Mnemonic::Leave:
        case Mnemonic::Jo:  case Mnemonic::Jno: case Mnemonic::Jb:  case Mnemonic::Jae:
        case Mnemonic::Je:  case Mnemonic::Jne: case Mnemonic::Jbe: case Mnemonic::Ja:
        case Mnemonic::Js:  case Mnemonic::Jns: case Mnemonic::Jp:  case Mnemonic::Jnp:
        case Mnemonic::Jl:  case Mnemonic::Jge: case Mnemonic::Jle: case Mnemonic::Jg:
            return true;
        default:
            return false;
    }
}

void promote_size_sensitive_mnemonics(const Context& ctx, Instruction& insn) noexcept {
    if (insn.mnemonic == Mnemonic::Cwde && ctx.opsize() == 8) {
        insn.mnemonic = Mnemonic::Cdqe;
    } else if (insn.mnemonic == Mnemonic::Cdq && ctx.opsize() == 8) {
        insn.mnemonic = Mnemonic::Cqo;
    } else if (insn.mnemonic == Mnemonic::Movd && ctx.rex_w) {
        insn.mnemonic = Mnemonic::MovqGpr;
    } else if (insn.mnemonic == Mnemonic::MovdStore && ctx.rex_w) {
        insn.mnemonic = Mnemonic::MovqGprStore;
    }
    if (ctx.rex_w) {
        switch (insn.mnemonic) {
            case Mnemonic::Vfmadd132ps: insn.mnemonic = Mnemonic::Vfmadd132pd; break;
            case Mnemonic::Vfmadd132ss: insn.mnemonic = Mnemonic::Vfmadd132sd; break;
            case Mnemonic::Vfmadd213ps: insn.mnemonic = Mnemonic::Vfmadd213pd; break;
            case Mnemonic::Vfmadd213ss: insn.mnemonic = Mnemonic::Vfmadd213sd; break;
            case Mnemonic::Vfmadd231ps: insn.mnemonic = Mnemonic::Vfmadd231pd; break;
            case Mnemonic::Vfmadd231ss: insn.mnemonic = Mnemonic::Vfmadd231sd; break;
            default: break;
        }
    }
    // 64-bit promotion for the default-sized string ops (REX.W).
    if (ctx.opsize() == 8) {
        switch (insn.mnemonic) {
            case Mnemonic::Movsd: insn.mnemonic = Mnemonic::Movsq; break;
            case Mnemonic::Cmpsd: insn.mnemonic = Mnemonic::Cmpsq; break;
            case Mnemonic::Stosd: insn.mnemonic = Mnemonic::Stosq; break;
            case Mnemonic::Lodsd: insn.mnemonic = Mnemonic::Lodsq; break;
            case Mnemonic::Scasd: insn.mnemonic = Mnemonic::Scasq; break;
            default: break;
        }
    }
}

[[nodiscard]] constexpr bool vex_has_nondestructive_source(Mnemonic mnemonic) noexcept {
    switch (mnemonic) {
        case Mnemonic::Addss: case Mnemonic::Subss:
        case Mnemonic::Mulss: case Mnemonic::Divss:
        case Mnemonic::Addsd: case Mnemonic::Subsd:
        case Mnemonic::Mulsd: case Mnemonic::Divsd:
        case Mnemonic::Minss: case Mnemonic::Maxss:
        case Mnemonic::Minsd: case Mnemonic::Maxsd:
        case Mnemonic::Sqrtss: case Mnemonic::Sqrtsd:
        case Mnemonic::Cvtsi2ss: case Mnemonic::Cvtsi2sd:
        case Mnemonic::Cvtss2sd: case Mnemonic::Cvtsd2ss:
        case Mnemonic::Andps: case Mnemonic::Andnps:
        case Mnemonic::Orps: case Mnemonic::Xorps:
        case Mnemonic::Addps: case Mnemonic::Mulps:
        case Mnemonic::Subps: case Mnemonic::Divps:
        case Mnemonic::Minps: case Mnemonic::Maxps:
        case Mnemonic::Andpd: case Mnemonic::Andnpd:
        case Mnemonic::Orpd: case Mnemonic::Xorpd:
        case Mnemonic::Addpd: case Mnemonic::Mulpd:
        case Mnemonic::Subpd: case Mnemonic::Divpd:
        case Mnemonic::Minpd: case Mnemonic::Maxpd:
        case Mnemonic::Pxor: case Mnemonic::Pand:
        case Mnemonic::Pandn: case Mnemonic::Por:
        case Mnemonic::Pcmpeqb: case Mnemonic::Pcmpeqw:
        case Mnemonic::Pcmpeqd: case Mnemonic::Pcmpgtb:
        case Mnemonic::Pcmpgtw: case Mnemonic::Pcmpgtd:
        case Mnemonic::Paddb: case Mnemonic::Paddw:
        case Mnemonic::Paddd: case Mnemonic::Paddq:
        case Mnemonic::Psubb: case Mnemonic::Psubw:
        case Mnemonic::Psubd: case Mnemonic::Psubq:
        case Mnemonic::Pmullw: case Mnemonic::Pmulhw:
        case Mnemonic::Pmulhuw: case Mnemonic::Pmuludq:
        case Mnemonic::Pmaddwd: case Mnemonic::Pminub:
        case Mnemonic::Pmaxub: case Mnemonic::Pminsw:
        case Mnemonic::Pmaxsw: case Mnemonic::Pavgb:
        case Mnemonic::Pavgw: case Mnemonic::Psubusb:
        case Mnemonic::Psubusw: case Mnemonic::Paddusb:
        case Mnemonic::Paddusw: case Mnemonic::Psubsb:
        case Mnemonic::Psubsw: case Mnemonic::Paddsb:
        case Mnemonic::Paddsw: case Mnemonic::Punpcklbw:
        case Mnemonic::Punpcklwd: case Mnemonic::Punpckldq:
        case Mnemonic::Punpcklqdq: case Mnemonic::Punpckhbw:
        case Mnemonic::Punpckhwd: case Mnemonic::Punpckhdq:
        case Mnemonic::Punpckhqdq: case Mnemonic::Shufps:
        case Mnemonic::Shufpd:
            return true;
        default:
            return false;
    }
}

}  // anonymous namespace

Result<Instruction>
X64Decoder::decode(std::span<const std::byte> code, addr_t addr) const noexcept {
    if (code.empty()) {
        return std::unexpected(Error::truncated("x64: empty code buffer"));
    }

    Context ctx;
    ctx.code = code;
    ctx.addr = addr;

    while (!ctx.eof()) {
        const u8 b = static_cast<u8>(ctx.code[ctx.pos]);
        if (!parse_legacy_prefix(ctx, b)) break;
        ++ctx.pos;
        if (ctx.pos >= 14) {
            return std::unexpected(Error::invalid_format(
                "x64: more than 14 prefix bytes"));
        }
    }

    if (!ctx.eof()) {
        const u8 b = static_cast<u8>(ctx.code[ctx.pos]);
        if (b == 0xC5) {
            ++ctx.pos;
            auto p1 = ctx.read_u8();
            if (!p1) return std::unexpected(std::move(p1).error());
            ctx.vex = true;
            ctx.vex_map = 1;
            ctx.rex_present = true;
            ctx.rex_r = (*p1 & 0x80u) == 0;
            ctx.vex_vvvv = static_cast<u8>(
                (static_cast<u8>(~*p1) >> 3) & 0x0fu);
            ctx.vector_bytes = (*p1 & 0x04u) ? 32u : 16u;
            ctx.vex_pp = static_cast<u8>(*p1 & 0x03u);
        } else if (b == 0xC4) {
            ++ctx.pos;
            auto p0 = ctx.read_u8();
            auto p1 = ctx.read_u8();
            if (!p0) return std::unexpected(std::move(p0).error());
            if (!p1) return std::unexpected(std::move(p1).error());
            ctx.vex = true;
            ctx.vex_map = static_cast<u8>(*p0 & 0x1fu);
            ctx.rex_present = true;
            ctx.rex_r = (*p0 & 0x80u) == 0;
            ctx.rex_x = (*p0 & 0x40u) == 0;
            ctx.rex_b = (*p0 & 0x20u) == 0;
            ctx.rex_w = (*p1 & 0x80u) != 0;
            ctx.vex_vvvv = static_cast<u8>(
                (static_cast<u8>(~*p1) >> 3) & 0x0fu);
            ctx.vector_bytes = (*p1 & 0x04u) ? 32u : 16u;
            ctx.vex_pp = static_cast<u8>(*p1 & 0x03u);
        } else if (b == 0x62) {
            ++ctx.pos;
            auto p0 = ctx.read_u8();
            auto p1 = ctx.read_u8();
            auto p2 = ctx.read_u8();
            if (!p0) return std::unexpected(std::move(p0).error());
            if (!p1) return std::unexpected(std::move(p1).error());
            if (!p2) return std::unexpected(std::move(p2).error());
            if ((*p1 & 0x04u) == 0) {
                return std::unexpected(Error::invalid_format(
                    "x64: malformed EVEX prefix"));
            }
            ctx.evex = true;
            ctx.vex_map = static_cast<u8>(*p0 & 0x03u);
            ctx.rex_present = true;
            ctx.vex_r2 = (*p0 & 0x80u) == 0;
            ctx.rex_x = (*p0 & 0x40u) == 0;
            ctx.rex_b = (*p0 & 0x20u) == 0;
            ctx.vex_b2 = ctx.rex_x;
            ctx.rex_r = (*p0 & 0x10u) == 0;
            ctx.rex_w = (*p1 & 0x80u) != 0;
            ctx.vex_vvvv = static_cast<u8>(((static_cast<u8>(~*p1) >> 3) & 0x0fu) |
                (((*p2 & 0x08u) == 0 ? 1u : 0u) << 4));
            const u8 length = static_cast<u8>((*p2 >> 5) & 0x03u);
            if (length == 3) {
                return std::unexpected(Error::invalid_format(
                    "x64: reserved EVEX vector length"));
            }
            ctx.vector_bytes = length == 2 ? 64u : (length == 1 ? 32u : 16u);
            ctx.vex_pp = static_cast<u8>(*p1 & 0x03u);
            ctx.vector_mask = static_cast<u8>(*p2 & 0x07u);
            ctx.vector_zeroing = (*p2 & 0x80u) != 0;
            ctx.vector_broadcast = (*p2 & 0x10u) != 0;
        } else if ((b & 0xF0) == 0x40) {
            ctx.rex_present = true;
            ctx.rex_w = (b & 0x8) != 0;
            ctx.rex_r = (b & 0x4) != 0;
            ctx.rex_x = (b & 0x2) != 0;
            ctx.rex_b = (b & 0x1) != 0;
            ++ctx.pos;
        }
    }

    auto op0_r = ctx.read_u8();
    if (!op0_r) return std::unexpected(std::move(op0_r).error());
    u8 opcode = *op0_r;

    const auto has_entry = [](const OpcodeEntry& candidate) {
        return candidate.mnemonic != Mnemonic::Invalid || candidate.group != 0;
    };
    const OpcodeEntry* entry = nullptr;
    if (ctx.vex || ctx.evex) {
        if (ctx.vex_map == 1 && opcode == 0x77 && ctx.vex_pp == 0) {
            entry = &kVzeroupper;
        } else if (ctx.vex_map == 1) {
            switch (ctx.vex_pp) {
                case 0: entry = &kSecondary[opcode]; break;
                case 1: entry = &kSecondary_66[opcode]; break;
                case 2: entry = &kSecondary_F3[opcode]; break;
                case 3: entry = &kSecondary_F2[opcode]; break;
                default: break;
            }
        } else if (ctx.vex_map == 2) {
            switch (ctx.vex_pp) {
                case 0: entry = &kVexMap2[opcode]; break;
                case 1: entry = &kVexMap2_66[opcode]; break;
                case 2: entry = &kVexMap2_F3[opcode]; break;
                case 3: entry = &kVexMap2_F2[opcode]; break;
                default: break;
            }
        } else {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported {} opcode map {} at {:#x}",
                ctx.evex ? "EVEX" : "VEX", ctx.vex_map, addr)));
        }
    } else if (opcode == 0x0F) {
        auto op1_r = ctx.read_u8();
        if (!op1_r) return std::unexpected(std::move(op1_r).error());
        opcode = *op1_r;
        ctx.opcode = opcode;
        ctx.opcode_low3 = static_cast<u8>(opcode & 7);

        if (opcode == 0x1E && ctx.prefix.rep && !ctx.eof()) {
            const u8 m = static_cast<u8>(ctx.code[ctx.pos]);
            if (m == 0xFA || m == 0xFB) {
                ++ctx.pos;
                Instruction insn;
                insn.address  = addr;
                insn.mnemonic = (m == 0xFA) ? Mnemonic::Endbr64 : Mnemonic::Endbr32;
                ctx.prefix.rep = false;
                insn.prefixes = ctx.prefix;
                insn.length   = static_cast<u8>(ctx.pos);
                std::memcpy(insn.raw_bytes.data(), code.data(),
                            std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
                return insn;
            }
        }

        // Mandatory-prefix dispatch: 0x66 / 0xF3 / 0xF2 before 0x0F select
        // SSE secondary tables. Consuming the prefix for dispatch means we
        // shouldn't also interpret it as opsize/rep - clear the bit.
        // Either a real mnemonic OR a group entry (mnemonic=Invalid,
        // group!=0 - opcode-extension dispatch) counts as "the 66 table
        // owns this opcode".
        entry = &kSecondary[opcode];
        if (ctx.prefix.opsize && has_entry(kSecondary_66[opcode])) {
            entry = &kSecondary_66[opcode];
            ctx.prefix.opsize = false;
        } else if (ctx.prefix.rep && has_entry(kSecondary_F3[opcode])) {
            entry = &kSecondary_F3[opcode];
            ctx.prefix.rep = false;
        } else if (ctx.prefix.repne && has_entry(kSecondary_F2[opcode])) {
            entry = &kSecondary_F2[opcode];
            ctx.prefix.repne = false;
        }
    } else {
        ctx.opcode = opcode;
        ctx.opcode_low3 = static_cast<u8>(opcode & 7);
        // x87 escapes D8-DF carry their real opcode in the ModR/M byte and
        // split memory/register maps on mod (see the x87 section above), so
        // they resolve outside the linear opcode-table machinery. Anything
        // unlisted inside them errors out of decode_x87_escape.
        if (opcode >= 0xD8 && opcode <= 0xDF) {
            return decode_x87_escape(ctx, addr);
        }
        entry = &kPrimary[opcode];
    }

    if (!entry || (entry->mnemonic == Mnemonic::Invalid && entry->group == 0)) {
        return std::unexpected(Error::not_implemented(std::format(
            "x64: unsupported opcode {:#04x} at {:#x}", opcode, addr)));
    }
    if ((ctx.vex || ctx.evex) && ctx.vex_map == 1 &&
        entry->group == 0 && entry->mnemonic != Mnemonic::Vzeroupper) {
        const auto vector_spec = [](OpSpec spec) {
            return spec == OpSpec::Vx || spec == OpSpec::Hx ||
                   spec == OpSpec::Wx || spec == OpSpec::Wss ||
                   spec == OpSpec::Wsd;
        };
        if (!vector_spec(entry->op1) && !vector_spec(entry->op2) &&
            !vector_spec(entry->op3) && !vector_spec(entry->op4)) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: unsupported VEX form of {} at {:#x}",
                mnemonic_name(entry->mnemonic), addr)));
        }
    }

    OpcodeEntry vector_entry;
    if ((ctx.vex || ctx.evex) && vex_has_nondestructive_source(entry->mnemonic)) {
        vector_entry = *entry;
        if (entry->op3 == OpSpec::None) {
            vector_entry.op3 = entry->op2;
            vector_entry.op2 = OpSpec::Hx;
        } else {
            vector_entry.op4 = entry->op3;
            vector_entry.op3 = entry->op2;
            vector_entry.op2 = OpSpec::Hx;
        }
        entry = &vector_entry;
    }

    if (entry->modrm) {
        auto m_r = ctx.read_u8();
        if (!m_r) return std::unexpected(std::move(m_r).error());
        ctx.modrm = *m_r;
        ctx.have_modrm = true;
    }

    if (entry->group != 0) {
        const u8 reg = static_cast<u8>((ctx.modrm >> 3) & 7);
        entry = &kGroups[entry->group][reg];
        if (entry->mnemonic == Mnemonic::Invalid) {
            return std::unexpected(Error::not_implemented(std::format(
                "x64: reserved group entry (opcode {:#04x}, /{}) at {:#x}",
                ctx.opcode, reg, addr)));
        }
    }

    Instruction insn;
    insn.address  = addr;
    insn.mnemonic = entry->mnemonic;
    insn.prefixes = ctx.prefix;
    insn.x86_vex = ctx.vex;
    insn.x86_evex = ctx.evex;
    insn.x86_zeroing = ctx.vector_zeroing;
    insn.x86_broadcast = ctx.vector_broadcast;
    insn.x86_mask = ctx.vector_mask;
    insn.x86_vector_bits = ctx.vector_bytes == 64 ? 3u
        : (ctx.vector_bytes == 32 ? 2u : 1u);

    ctx.default_64 = is_default_64(entry->mnemonic);

    const OpSpec specs[4] = {entry->op1, entry->op2, entry->op3, entry->op4};
    for (std::size_t i = 0; i < 4; ++i) {
        if (specs[i] == OpSpec::None) break;
        auto o = decode_operand(ctx, specs[i], addr);
        if (!o) return std::unexpected(std::move(o).error());
        insn.operands[i] = *o;
        insn.num_operands = static_cast<u8>(i + 1);
    }

    promote_size_sensitive_mnemonics(ctx, insn);

    insn.length = static_cast<u8>(ctx.pos);
    std::memcpy(insn.raw_bytes.data(), code.data(),
                std::min<std::size_t>(insn.length, insn.raw_bytes.size()));
    return insn;
}

}  // namespace ember
