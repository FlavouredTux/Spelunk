#include <algorithm>
#include <cstddef>
#include <cstring>
#include <expected>
#include <format>
#include <span>
#include <utility>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/x64_decoder.hpp>

#include "decoder_internal.hpp"

namespace spelunk {

namespace {

using x64_decode::OpcodeEntry;
using x64_decode::OpSpec;
using x64_decode::kGroups;
using x64_decode::kPrimary;
using x64_decode::kSecondary;
using x64_decode::kSecondary_66;
using x64_decode::kSecondary_F2;
using x64_decode::kSecondary_F3;
using x64_decode::kMap38;
using x64_decode::kMap38_66;
using x64_decode::kMap38_F2;
using x64_decode::kMap3A_66;
using x64_decode::kVexMap2;
using x64_decode::kVexMap2_66;
using x64_decode::kVexMap2_F2;
using x64_decode::kVexMap2_F3;
using x64_decode::kVzeroupper;
using x64_decode::Context;
using x64_decode::decode_operand;
using x64_decode::decode_x87_escape;
using x64_decode::parse_legacy_prefix;

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
    } else if (insn.mnemonic == Mnemonic::Pextrd && ctx.rex_w) {
        insn.mnemonic = Mnemonic::Pextrq;
    } else if (insn.mnemonic == Mnemonic::Pinsrd && ctx.rex_w) {
        insn.mnemonic = Mnemonic::Pinsrq;
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
    ctx.code = code.first(std::min<std::size_t>(code.size(), 15));
    ctx.mode64 = mode64_;

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
        const bool vector_prefix = ctx.mode64 ||
            (ctx.pos + 1 < ctx.code.size() &&
             (static_cast<u8>(ctx.code[ctx.pos + 1]) & 0xc0u) == 0xc0u);
        if (b == 0xC5 && vector_prefix) {
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
        } else if (b == 0xC4 && vector_prefix) {
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
        } else if (b == 0x62 && vector_prefix) {
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
        } else if (ctx.mode64 && (b & 0xF0) == 0x40) {
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
    OpcodeEntry legacy_entry;
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

        // Legacy three-byte maps. F2 (CRC32) outranks 66, which CRC32 uses
        // as its operand-size prefix.
        if (opcode == 0x38 || opcode == 0x3A) {
            auto op2_r = ctx.read_u8();
            if (!op2_r) return std::unexpected(std::move(op2_r).error());
            const u8 escape = opcode;
            opcode = *op2_r;
            ctx.opcode = opcode;
            ctx.opcode_low3 = static_cast<u8>(opcode & 7);
            if (escape == 0x38 && ctx.prefix.repne && has_entry(kMap38_F2[opcode])) {
                entry = &kMap38_F2[opcode];
                ctx.prefix.repne = false;
            } else if (ctx.prefix.opsize &&
                       has_entry(escape == 0x38 ? kMap38_66[opcode] : kMap3A_66[opcode])) {
                entry = escape == 0x38 ? &kMap38_66[opcode] : &kMap3A_66[opcode];
                ctx.prefix.opsize = false;
            } else if (escape == 0x38 && !ctx.prefix.opsize && !ctx.prefix.rep &&
                       !ctx.prefix.repne) {
                entry = &kMap38[opcode];
            }
            if (!entry || !has_entry(*entry)) {
                return std::unexpected(Error::not_implemented(std::format(
                    "x64: unsupported opcode 0f {:02x} {:#04x} at {:#x}", escape, opcode, addr)));
            }
        }
        // Group 15 splits on ModR/M.mod: fences in the register form,
        // MXCSR / FXSAVE / XSAVE / CLFLUSH with memory.
        else if (opcode == 0xAE && !ctx.prefix.opsize && !ctx.prefix.rep &&
                 !ctx.prefix.repne && !ctx.eof()) {
            const u8 modrm = static_cast<u8>(ctx.code[ctx.pos]);
            const u8 reg = static_cast<u8>((modrm >> 3) & 7);
            static constexpr Mnemonic kMemory[8] = {
                Mnemonic::Fxsave, Mnemonic::Fxrstor, Mnemonic::Ldmxcsr, Mnemonic::Stmxcsr,
                Mnemonic::Xsave, Mnemonic::Xrstor, Mnemonic::Xsaveopt, Mnemonic::Clflush};
            static constexpr Mnemonic kRegister[8] = {
                Mnemonic::Invalid, Mnemonic::Invalid, Mnemonic::Invalid, Mnemonic::Invalid,
                Mnemonic::Invalid, Mnemonic::Lfence, Mnemonic::Mfence, Mnemonic::Sfence};
            legacy_entry = OpcodeEntry{};
            legacy_entry.modrm = true;
            if ((modrm >> 6) == 3) {
                legacy_entry.mnemonic = kRegister[reg];
            } else {
                legacy_entry.mnemonic = kMemory[reg];
                legacy_entry.op1 = OpSpec::M;
            }
            entry = &legacy_entry;
        } else {
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
        }
    } else {
        ctx.opcode = opcode;
        ctx.opcode_low3 = static_cast<u8>(opcode & 7);
        // x87 escapes D8-DF carry their real opcode in the ModR/M byte and
        // split memory/register maps on mod (see decoder_x87.cpp), so
        // they resolve outside the linear opcode-table machinery. Anything
        // unlisted inside them errors out of decode_x87_escape.
        if (opcode >= 0xD8 && opcode <= 0xDF) {
            return decode_x87_escape(ctx, addr);
        }
        entry = &kPrimary[opcode];
        if (!ctx.mode64 && opcode >= 0x40 && opcode <= 0x4f) {
            legacy_entry.mnemonic = opcode < 0x48 ? Mnemonic::Inc : Mnemonic::Dec;
            legacy_entry.op1 = OpSpec::Zv;
            entry = &legacy_entry;
        } else if (!ctx.mode64 && opcode == 0x63) {
            return std::unexpected(Error::not_implemented("x86: ARPL is not implemented"));
        }
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
    if ((ctx.vex || ctx.evex) && entry->mnemonic == Mnemonic::Cmpss) {
        return std::unexpected(Error::not_implemented(std::format(
            "x64: unsupported vector-prefix form of cmpss at {:#x}", addr)));
    }
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

    ctx.default_64 = ctx.mode64 && is_default_64(entry->mnemonic);

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

}  // namespace spelunk
