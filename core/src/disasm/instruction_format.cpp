#include <spelunk/disasm/instruction.hpp>

#include <array>
#include <cstddef>
#include <format>
#include <string>
#include <string_view>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>

namespace spelunk {

// ARM condition-code suffix (bits 31:28). AL/NV render empty - callers gate
// on that via kArmCondAL.
[[nodiscard]] std::string_view arm_cond_suffix(u8 cond) noexcept {
    switch (cond & 0xf) {
        case 0x0: return "eq"; case 0x1: return "ne";
        case 0x2: return "cs"; case 0x3: return "cc";
        case 0x4: return "mi"; case 0x5: return "pl";
        case 0x6: return "vs"; case 0x7: return "vc";
        case 0x8: return "hi"; case 0x9: return "ls";
        case 0xa: return "ge"; case 0xb: return "lt";
        case 0xc: return "gt"; case 0xd: return "le";
        default:  return "";   // AL / NV
    }
}

namespace {

[[nodiscard]] constexpr std::string_view ppc_spr_name(u32 spr) noexcept {
    switch (spr) {
        case 18: return "dsisr";
        case 19: return "dar";
        case 22: return "dec";
        case 25: return "sdr1";
        case 26: return "srr0";
        case 27: return "srr1";
        case 268: return "tbl";
        case 269: return "tbu";
        case 272: return "sprg0";
        case 273: return "sprg1";
        case 274: return "sprg2";
        case 275: return "sprg3";
        case 280: return "asr";
        case 282: return "ear";
        case 284: return "tbl_w";
        case 285: return "tbu_w";
        case 287: return "pvr";
        case 920: return "hid2";
        case 921: return "wpar";
        case 922: return "dmau";
        case 923: return "dmal";
        case 924: return "ecid_u";
        case 925: return "ecid_m";
        case 926: return "ecid_l";
        case 936: return "ummcr0";
        case 937: return "upmc1";
        case 938: return "upmc2";
        case 939: return "usia";
        case 940: return "ummcr1";
        case 941: return "upmc3";
        case 942: return "upmc4";
        case 952: return "mmcr0";
        case 953: return "pmc1";
        case 954: return "pmc2";
        case 955: return "sia";
        case 956: return "mmcr1";
        case 957: return "pmc3";
        case 958: return "pmc4";
        case 1008: return "hid0";
        case 1009: return "hid1";
        case 1010: return "iabr";
        case 1011: return "hid4";
        case 1013: return "dabr";
        case 1017: return "l2cr";
        case 1019: return "ictc";
        case 1020: return "thrm1";
        case 1021: return "thrm2";
        case 1022: return "thrm3";
        default: break;
    }
    constexpr std::array<std::string_view, 48> bats = {
        "ibat0u", "ibat0l", "ibat1u", "ibat1l", "ibat2u", "ibat2l", "ibat3u", "ibat3l",
        "dbat0u", "dbat0l", "dbat1u", "dbat1l", "dbat2u", "dbat2l", "dbat3u", "dbat3l",
        "ibat4u", "ibat4l", "ibat5u", "ibat5l", "ibat6u", "ibat6l", "ibat7u", "ibat7l",
        "dbat4u", "dbat4l", "dbat5u", "dbat5l", "dbat6u", "dbat6l", "dbat7u", "dbat7l",
        "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    };
    if (spr >= 528 && spr <= 543) return bats[spr - 528];
    if (spr >= 560 && spr <= 575) return bats[16 + spr - 560];
    return {};
}

[[nodiscard]] std::string_view size_keyword(u8 size) noexcept {
    switch (size) {
        case 1: return "byte ptr ";
        case 2: return "word ptr ";
        case 4: return "dword ptr ";
        case 8: return "qword ptr ";
        default: return "";
    }
}

[[nodiscard]] std::string format_imm_value(const Imm& i) {
    if (i.is_signed && i.value < 0) {
        const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(i.value);
        return std::format("-{:#x}", abs_v);
    }
    return std::format("{:#x}", static_cast<u64>(i.value));
}

[[nodiscard]] std::string format_mem(const Mem& m, bool suppress_size, addr_t end_addr) {
    std::string result;
    if (!suppress_size) {
        result = size_keyword(m.size);
    }
    if (m.segment != Reg::None) {
        result += std::format("{}:", reg_name(m.segment));
    }
    result += "[";

    if (m.base == Reg::Rip && m.index == Reg::None) {
        const u64 target = end_addr + static_cast<u64>(m.disp);
        result += std::format("{:#x}", target);
    } else {
        std::string inside;
        if (m.base != Reg::None) {
            inside += reg_name(m.base);
        }
        if (m.index != Reg::None) {
            if (!inside.empty()) inside += m.subtract_index ? " - " : " + ";
            else if (m.subtract_index) inside += "-";
            inside += reg_name(m.index);
            if (m.scale != 1) {
                inside += std::format("*{}", static_cast<unsigned>(m.scale));
            }
        }
        if (m.writeback != Mem::Writeback::PostIndex &&
            (m.disp != 0 || inside.empty())) {
            if (!inside.empty()) {
                if (m.disp < 0) {
                    const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(m.disp);
                    inside += std::format(" - {:#x}", abs_v);
                } else {
                    inside += std::format(" + {:#x}", static_cast<u64>(m.disp));
                }
            } else {
                if (m.disp < 0) {
                    const u64 abs_v = static_cast<u64>(0) - static_cast<u64>(m.disp);
                    inside += std::format("-{:#x}", abs_v);
                } else {
                    inside += std::format("{:#x}", static_cast<u64>(m.disp));
                }
            }
        }
        result += inside;
    }

    result += "]";
    if (m.writeback == Mem::Writeback::PreIndex) {
        result += "!";
    } else if (m.writeback == Mem::Writeback::PostIndex) {
        result += std::format(", #{}", m.disp);
    }
    return result;
}

}  // namespace

std::string format_operand(const Instruction& insn, const Operand& op) {
    const addr_t end_addr = insn.address + insn.length;
    switch (op.kind) {
        case Operand::Kind::None:
            return "";
        case Operand::Kind::Register: {
            // x87 register-stack operand: st(N), carried outside the Reg
            // enum (see Operand::x87_stack).
            if (op.x87_stack != 0xff) {
                return std::format("st({})",
                                   static_cast<unsigned>(op.x87_stack));
            }
            std::string r(reg_name(op.reg));
            // ARM barrel shift on the register operand.
            if (op.arm_shift_reg != Reg::None) {
                static constexpr std::string_view kShift[4] =
                    {"lsl", "lsr", "asr", "ror"};
                r += std::format(", {} {}",
                                 kShift[static_cast<u8>(op.arm_shift)],
                                 reg_name(op.arm_shift_reg));
            } else if (!(op.arm_shift == ArmShift::Lsl && op.arm_shift_amt == 0)) {
                static constexpr std::string_view kShift[4] =
                    {"lsl", "lsr", "asr", "ror"};
                const bool is_a32 =
                    static_cast<u16>(insn.mnemonic) >=
                    static_cast<u16>(Mnemonic::A32And);
                if (is_a32 && op.arm_shift == ArmShift::Ror &&
                    op.arm_shift_amt == 0) {
                    r += ", rrx";
                } else {
                    r += std::format(", {} #{}",
                                     kShift[static_cast<u8>(op.arm_shift)],
                                     op.arm_shift_amt);
                }
            }
            return r;
        }
        case Operand::Kind::Memory:
            return format_mem(op.mem, insn.mnemonic == Mnemonic::Lea, end_addr);
        case Operand::Kind::Immediate:
            if (insn.mnemonic == Mnemonic::Mfspr || insn.mnemonic == Mnemonic::Mtspr) {
                const auto name = ppc_spr_name(static_cast<u32>(op.imm.value));
                if (!name.empty()) return std::string(name);
            }
            return format_imm_value(op.imm);
        case Operand::Kind::Relative:
            return std::format("{:#x}", op.rel.target);
    }
    return "";
}

std::string format_instruction(const Instruction& insn) {
    std::string s;
    if (insn.prefixes.lock)  s += "lock ";
    if (insn.prefixes.rep)   s += "rep ";
    if (insn.prefixes.repne) s += "repne ";
    const bool bmi_name = insn.mnemonic == Mnemonic::Andn ||
        insn.mnemonic == Mnemonic::Bzhi || insn.mnemonic == Mnemonic::Pext ||
        insn.mnemonic == Mnemonic::Pdep || insn.mnemonic == Mnemonic::Shlx ||
        insn.mnemonic == Mnemonic::Shrx || insn.mnemonic == Mnemonic::Sarx ||
        insn.mnemonic == Mnemonic::Mulx;
    if ((insn.x86_vex || insn.x86_evex) && !bmi_name) s += 'v';
    s += mnemonic_name(insn.mnemonic);
    // ARM: append the S (flag-setting) suffix and the condition-code suffix.
    // Both are inert for other architectures (arm_setflags defaults false,
    // arm_cond defaults to AL).
    if (insn.arm_cond != kArmCondAL && insn.arm_cond != 0xF) {
        s += arm_cond_suffix(insn.arm_cond);
    }
    if (insn.arm_setflags) s += 's';
    // ARM block transfers carry (base, reglist-bitmask, flags); render the
    // list as `{r4, r5, lr}` rather than the raw operands.
    const bool is_block_xfer =
        insn.mnemonic == Mnemonic::A32Push || insn.mnemonic == Mnemonic::A32Pop ||
        insn.mnemonic == Mnemonic::A32Ldm  || insn.mnemonic == Mnemonic::A32LdmPc ||
        insn.mnemonic == Mnemonic::A32Stm ||
        // A returning LDM (`pop {.., pc}` / `ldm rN, {.., pc}`) decodes to
        // A32Ret but still carries the (base, reglist, flags) operand shape.
        (insn.mnemonic == Mnemonic::A32Ret && insn.num_operands >= 2 &&
         insn.operands[1].kind == Operand::Kind::Immediate);
    if (is_block_xfer) {
            const bool has_base = insn.mnemonic == Mnemonic::A32Ldm ||
                                  insn.mnemonic == Mnemonic::A32LdmPc ||
                                  insn.mnemonic == Mnemonic::A32Stm;
            const u32 list = insn.num_operands >= 2
                ? static_cast<u32>(insn.operands[1].imm.value) : 0;
            s += ' ';
            if (has_base && insn.num_operands >= 1) {
                s += reg_name(insn.operands[0].reg);
                s += ", ";
            }
            s += '{';
            bool first = true;
            for (unsigned r = 0; r < 16; ++r) {
                if (!(list & (1u << r))) continue;
                if (!first) s += ", ";
                s += reg_name(r < 13 ? static_cast<Reg>(
                                  static_cast<unsigned>(Reg::ArmR0) + r)
                              : r == 13 ? Reg::Asp
                              : r == 14 ? Reg::Alr : Reg::Apc);
                first = false;
            }
            s += '}';
            return s;
    }
    if (insn.num_operands > 0) {
        s += ' ';
        for (std::size_t i = 0; i < insn.num_operands; ++i) {
            if (i > 0) s += ", ";
            s += format_operand(insn, insn.operands[i]);
            if (i == 0 && insn.x86_evex && insn.x86_mask != 0) {
                s += std::format(" {{k{}}}", insn.x86_mask);
                if (insn.x86_zeroing) s += " {z}";
            }
        }
    }
    return s;
}

}  // namespace spelunk
