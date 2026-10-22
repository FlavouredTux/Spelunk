#include <cstddef>
#include <expected>
#include <format>
#include <utility>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>

#include "decoder_internal.hpp"

namespace spelunk::x64_decode {

namespace {

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

// A widening VEX.256 source reads twice the memory of its VEX.128 form.
[[nodiscard]] unsigned widened(const Context& ctx) noexcept {
    return ctx.widening_source && ctx.vector_bytes == 32 ? 2u : 1u;
}

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

}  // anonymous namespace

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
    const unsigned address_size = ctx.address_size();
    m.address_size = static_cast<u8>(address_size);

    if (address_size == 2) {
        constexpr Reg bases[8] = {Reg::Bx, Reg::Bx, Reg::Bp, Reg::Bp,
                                  Reg::Si, Reg::Di, Reg::Bp, Reg::Bx};
        constexpr Reg indices[8] = {Reg::Si, Reg::Di, Reg::Si, Reg::Di,
                                    Reg::None, Reg::None, Reg::None, Reg::None};
        m.base = bases[rm];
        m.index = indices[rm];
        if (mod == 0 && rm == 6) {
            auto d = ctx.read_le<u16>();
            if (!d) return std::unexpected(std::move(d).error());
            m.base = Reg::None;
            m.disp = *d;
            m.has_disp = true;
        } else if (mod == 1) {
            auto d = ctx.read_u8();
            if (!d) return std::unexpected(std::move(d).error());
            m.disp = static_cast<i8>(*d);
            m.has_disp = true;
        } else if (mod == 2) {
            auto d = ctx.read_le<u16>();
            if (!d) return std::unexpected(std::move(d).error());
            m.disp = static_cast<i16>(*d);
            m.has_disp = true;
        }
        return Operand::make_mem(m);
    }

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
            m.disp = address_size == 4
                ? static_cast<i64>(*d)
                : static_cast<i64>(static_cast<i32>(*d));
            m.has_disp = true;
        } else {
            m.base = gpr(base_ext, address_size, /*rex_present=*/true);
        }
    } else if (mod == 0 && rm == 5) {
        auto d = ctx.read_le<u32>();
        if (!d) return std::unexpected(std::move(d).error());
        m.base = address_size == 4 ? Reg::None : Reg::Rip;
        m.disp = address_size == 4
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

namespace {

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
    if (!ctx.mode64) r.target &= size == 2 ? 0xffffu : 0xffffffffu;
    return Operand::make_rel(r);
}

[[nodiscard]] unsigned iz_size(const Context& ctx) noexcept {
    return (ctx.opsize() == 2) ? 2 : 4;
}

}  // anonymous namespace

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
        case OpSpec::Gdq: {
            const u8 reg_ext = static_cast<u8>((ctx.rex_r ? 8u : 0u) | ((ctx.modrm >> 3) & 7));
            return Operand::make_reg(gpr(reg_ext, ctx.rex_w ? 8u : 4u, ctx.rex_present));
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
        case OpSpec::Jz: return decode_rel(ctx, !ctx.mode64 && ctx.prefix.opsize ? 2u : 4u, insn_addr);

        case OpSpec::Ob:
        case OpSpec::Ov: {
            auto address = read_imm(ctx, ctx.address_size(), 0, false);
            if (!address) return std::unexpected(std::move(address).error());
            Mem m;
            m.size = static_cast<u8>(spec == OpSpec::Ob ? 1u : os);
            m.address_size = static_cast<u8>(ctx.address_size());
            m.segment = ctx.prefix.segment;
            m.disp = address->value;
            m.has_disp = true;
            return Operand::make_mem(m);
        }

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
            return Operand::make_reg(vector_reg(reg_ext,
                ctx.narrowing_destination ? u8{16} : ctx.vector_bytes));
        }
        case OpSpec::Wdq: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.vex_b2 ? 16u : 0u) |
                                    (ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            return decode_modrm_rm(ctx, 16, /*mem_only=*/true);
        }
        case OpSpec::Lx: {
            auto imm = ctx.read_u8();
            if (!imm) return std::unexpected(std::move(imm).error());
            return Operand::make_reg(vector_reg(static_cast<u8>(*imm >> 4), ctx.vector_bytes));
        }
        case OpSpec::Hx: {
            return Operand::make_reg(vector_reg(ctx.vex_vvvv, ctx.vector_bytes));
        }
        case OpSpec::Hv: {
            return Operand::make_reg(gpr(ctx.vex_vvvv, os, /*rex_present=*/true));
        }
        case OpSpec::Wx: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            const u8 bytes = ctx.widening_source ? static_cast<u8>(ctx.vector_bytes / 2)
                                                 : ctx.vector_bytes;
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.vex_b2 ? 16u : 0u) |
                                    (ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, std::max<u8>(bytes, 16)));
            }
            return decode_modrm_rm(ctx, bytes, /*mem_only=*/true);
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
            return decode_modrm_rm(ctx, scalar_size * widened(ctx), /*mem_only=*/true);
        }
        case OpSpec::Wb: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            return decode_modrm_rm(ctx, 1, /*mem_only=*/true);
        }
        case OpSpec::Ww: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            return decode_modrm_rm(ctx, 2u * widened(ctx), /*mem_only=*/true);
        }
        case OpSpec::RdMb:
        case OpSpec::RdMw: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) return decode_modrm_rm(ctx, 4, false);
            return decode_modrm_rm(ctx, spec == OpSpec::RdMb ? 1u : 2u, /*mem_only=*/true);
        }
        case OpSpec::Wsd: {
            const u8 mod = static_cast<u8>((ctx.modrm >> 6) & 3);
            if (mod == 3) {
                const u8 rm_ext =
                    static_cast<u8>((ctx.rex_b ? 8u : 0u) | (ctx.modrm & 7));
                return Operand::make_reg(vector_reg(rm_ext, 16));
            }
            return decode_modrm_rm(ctx, 8u * widened(ctx), /*mem_only=*/true);
        }
    }
    return std::unexpected(Error::not_implemented("x64: unhandled operand spec"));
}

}  // namespace spelunk::x64_decode
