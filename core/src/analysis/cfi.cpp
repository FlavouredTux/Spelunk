#include <ember/analysis/cfi.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

#include "eh_frame_internal.hpp"

namespace ember::cfi {

namespace {

using ember::ehfi::Reader;
using ember::ehfi::CieInfo;
using ember::ehfi::read_encoded;
using ember::ehfi::find_eh_frame;
using ember::ehfi::parse_cie;

// DW_CFA_* opcode constants. The "primary" opcodes pack a small
// operand into the low 6 bits of the byte; the high 2 bits select
// advance_loc / offset / restore. The rest are "extended" opcodes
// where the high 2 bits are zero and the low 6 bits select.
enum : u8 {
    kDw_CfaNop                          = 0x00,
    kDw_CfaSetLoc                       = 0x01,
    kDw_CfaAdvanceLoc1                  = 0x02,
    kDw_CfaAdvanceLoc2                  = 0x03,
    kDw_CfaAdvanceLoc4                  = 0x04,
    kDw_CfaOffsetExtended               = 0x05,
    kDw_CfaRestoreExtended              = 0x06,
    kDw_CfaUndefined                    = 0x07,
    kDw_CfaSameValue                    = 0x08,
    kDw_CfaRegister                     = 0x09,
    kDw_CfaRememberState                = 0x0A,
    kDw_CfaRestoreState                 = 0x0B,
    kDw_CfaDefCfa                       = 0x0C,
    kDw_CfaDefCfaRegister               = 0x0D,
    kDw_CfaDefCfaOffset                 = 0x0E,
    kDw_CfaDefCfaExpression             = 0x0F,
    kDw_CfaExpression                   = 0x10,
    kDw_CfaOffsetExtendedSf             = 0x11,
    kDw_CfaDefCfaSf                     = 0x12,
    kDw_CfaDefCfaOffsetSf               = 0x13,
    kDw_CfaValOffset                    = 0x14,
    kDw_CfaValOffsetSf                  = 0x15,
    kDw_CfaValExpression                = 0x16,
    kDw_CfaGnuWindowSave                = 0x2D,
    kDw_CfaGnuArgsSize                  = 0x2E,
    kDw_CfaGnuNegativeOffsetExtended    = 0x2F,
};

struct Vm {
    State              state;
    State              initial_state;     // snapshotted after CIE init runs
    std::vector<State> remember_stack;
    u64                location  = 0;
    u64                code_align = 1;
    i64                data_align = 1;
    bool               failed     = false;
};

void set_offset(Vm& vm, u32 reg, i64 factored) {
    if (reg < State::kNumRegs) {
        vm.state.regs[reg].kind   = RuleKind::Offset;
        vm.state.regs[reg].offset = factored * vm.data_align;
    }
}
void set_val_offset(Vm& vm, u32 reg, i64 factored) {
    if (reg < State::kNumRegs) {
        vm.state.regs[reg].kind   = RuleKind::ValOffset;
        vm.state.regs[reg].offset = factored * vm.data_align;
    }
}
void set_register(Vm& vm, u32 reg, u32 src) {
    if (reg < State::kNumRegs) {
        vm.state.regs[reg].kind = RuleKind::Register;
        vm.state.regs[reg].reg  = src;
    }
}
void set_undef(Vm& vm, u32 reg) {
    if (reg < State::kNumRegs) vm.state.regs[reg].kind = RuleKind::Undefined;
}
void set_same(Vm& vm, u32 reg) {
    if (reg < State::kNumRegs) vm.state.regs[reg].kind = RuleKind::SameValue;
}
void restore_reg(Vm& vm, u32 reg) {
    if (reg < State::kNumRegs) vm.state.regs[reg] = vm.initial_state.regs[reg];
}

// Returns false on a stream that's malformed or uses an unsupported
// opcode. When `target_pc` is non-zero, returns true early as soon
// as the next advance_loc would push location past target_pc — the
// state at that point is the answer for target_pc.
[[nodiscard]] bool run(Vm& vm, std::span<const std::byte> insns,
                       u64 target_pc) {
    Reader r{insns, 0};
    while (!r.eof()) {
        u8 op = 0;
        if (!r.get(op)) return false;
        const u8 high = op & 0xC0;
        const u8 low  = op & 0x3F;

        if (high == 0x40) {
            const u64 new_loc = vm.location + low * vm.code_align;
            if (target_pc != 0 && new_loc > target_pc) return true;
            vm.location = new_loc;
            continue;
        }
        if (high == 0x80) {
            u64 ofs = 0;
            if (!r.get_uleb128(ofs)) return false;
            set_offset(vm, low, static_cast<i64>(ofs));
            continue;
        }
        if (high == 0xC0) {
            restore_reg(vm, low);
            continue;
        }

        // Extended opcode (high bits == 0). low IS the opcode here.
        switch (op) {
            case kDw_CfaNop: break;
            case kDw_CfaSetLoc: {
                u64 v = 0;
                if (!r.get_le(v)) return false;
                if (target_pc != 0 && v > target_pc) return true;
                vm.location = v;
                break;
            }
            case kDw_CfaAdvanceLoc1: {
                u8 d = 0;
                if (!r.get(d)) return false;
                const u64 new_loc = vm.location + d * vm.code_align;
                if (target_pc != 0 && new_loc > target_pc) return true;
                vm.location = new_loc;
                break;
            }
            case kDw_CfaAdvanceLoc2: {
                u16 d = 0;
                if (!r.get_le(d)) return false;
                const u64 new_loc = vm.location + d * vm.code_align;
                if (target_pc != 0 && new_loc > target_pc) return true;
                vm.location = new_loc;
                break;
            }
            case kDw_CfaAdvanceLoc4: {
                u32 d = 0;
                if (!r.get_le(d)) return false;
                const u64 new_loc = vm.location + d * vm.code_align;
                if (target_pc != 0 && new_loc > target_pc) return true;
                vm.location = new_loc;
                break;
            }
            case kDw_CfaOffsetExtended: {
                u64 reg = 0, ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_uleb128(ofs)) return false;
                set_offset(vm, static_cast<u32>(reg), static_cast<i64>(ofs));
                break;
            }
            case kDw_CfaRestoreExtended: {
                u64 reg = 0;
                if (!r.get_uleb128(reg)) return false;
                restore_reg(vm, static_cast<u32>(reg));
                break;
            }
            case kDw_CfaUndefined: {
                u64 reg = 0;
                if (!r.get_uleb128(reg)) return false;
                set_undef(vm, static_cast<u32>(reg));
                break;
            }
            case kDw_CfaSameValue: {
                u64 reg = 0;
                if (!r.get_uleb128(reg)) return false;
                set_same(vm, static_cast<u32>(reg));
                break;
            }
            case kDw_CfaRegister: {
                u64 reg = 0, src = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_uleb128(src)) return false;
                set_register(vm, static_cast<u32>(reg),
                                  static_cast<u32>(src));
                break;
            }
            case kDw_CfaRememberState:
                vm.remember_stack.push_back(vm.state);
                break;
            case kDw_CfaRestoreState:
                if (vm.remember_stack.empty()) return false;
                vm.state = vm.remember_stack.back();
                vm.remember_stack.pop_back();
                break;
            case kDw_CfaDefCfa: {
                u64 reg = 0, ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_uleb128(ofs)) return false;
                vm.state.cfa.kind   = CfaDef::Kind::Register;
                vm.state.cfa.reg    = static_cast<u32>(reg);
                vm.state.cfa.offset = static_cast<i64>(ofs);
                break;
            }
            case kDw_CfaDefCfaRegister: {
                u64 reg = 0;
                if (!r.get_uleb128(reg)) return false;
                vm.state.cfa.reg = static_cast<u32>(reg);
                if (vm.state.cfa.kind != CfaDef::Kind::Register) {
                    vm.state.cfa.kind = CfaDef::Kind::Register;
                }
                break;
            }
            case kDw_CfaDefCfaOffset: {
                u64 ofs = 0;
                if (!r.get_uleb128(ofs)) return false;
                vm.state.cfa.offset = static_cast<i64>(ofs);
                break;
            }
            case kDw_CfaDefCfaExpression:
            case kDw_CfaExpression:
            case kDw_CfaValExpression:
                vm.failed = true;
                return false;
            case kDw_CfaOffsetExtendedSf: {
                u64 reg = 0; i64 ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_sleb128(ofs)) return false;
                set_offset(vm, static_cast<u32>(reg), ofs);
                break;
            }
            case kDw_CfaDefCfaSf: {
                u64 reg = 0; i64 ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_sleb128(ofs)) return false;
                vm.state.cfa.kind   = CfaDef::Kind::Register;
                vm.state.cfa.reg    = static_cast<u32>(reg);
                vm.state.cfa.offset = ofs * vm.data_align;
                break;
            }
            case kDw_CfaDefCfaOffsetSf: {
                i64 ofs = 0;
                if (!r.get_sleb128(ofs)) return false;
                vm.state.cfa.offset = ofs * vm.data_align;
                break;
            }
            case kDw_CfaValOffset: {
                u64 reg = 0, ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_uleb128(ofs)) return false;
                set_val_offset(vm, static_cast<u32>(reg),
                                   static_cast<i64>(ofs));
                break;
            }
            case kDw_CfaValOffsetSf: {
                u64 reg = 0; i64 ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_sleb128(ofs)) return false;
                set_val_offset(vm, static_cast<u32>(reg), ofs);
                break;
            }
            case kDw_CfaGnuArgsSize: {
                u64 ignore = 0;
                if (!r.get_uleb128(ignore)) return false;
                break;
            }
            case kDw_CfaGnuWindowSave:
                // SPARC; treat as no-op on x86-64.
                break;
            case kDw_CfaGnuNegativeOffsetExtended: {
                u64 reg = 0, ofs = 0;
                if (!r.get_uleb128(reg)) return false;
                if (!r.get_uleb128(ofs)) return false;
                set_offset(vm, static_cast<u32>(reg),
                           -static_cast<i64>(ofs));
                break;
            }
            default:
                vm.failed = true;
                return false;
        }
    }
    return true;
}

}  // namespace

std::optional<State> recover(const Binary& b, addr_t target_pc) {
    auto eh = find_eh_frame(b);
    if (!eh) return std::nullopt;

    std::map<std::size_t, CieInfo> cies;
    Reader top{eh->bytes, 0};

    while (top.pos + 4 <= top.buf.size()) {
        const std::size_t entry_off = top.pos;
        u32 length = 0;
        if (!top.get_le(length)) break;
        if (length == 0) break;
        if (length == 0xFFFFFFFFu) break;

        const std::size_t payload_end = top.pos + length;
        if (payload_end > top.buf.size()) break;

        u32 cie_id = 0;
        if (!top.get_le(cie_id)) break;

        std::span<const std::byte> inner(
            eh->bytes.data() + top.pos,
            payload_end - top.pos);
        Reader rd{inner, 0};

        const u64 entry_vaddr = eh->vaddr + entry_off;

        if (cie_id == 0) {
            auto info = parse_cie(rd, entry_vaddr);
            if (info) cies[entry_off] = *info;
            top.pos = payload_end;
            continue;
        }

        const std::size_t cie_ptr_pos = top.pos - 4;
        const std::size_t cie_off = (cie_id <= cie_ptr_pos)
            ? (cie_ptr_pos - cie_id) : 0;
        auto ci_it = cies.find(cie_off);
        if (ci_it == cies.end()) { top.pos = payload_end; continue; }
        const CieInfo& ci = ci_it->second;

        const u64 pc_begin_vaddr = entry_vaddr + 4 + 4 + rd.pos;
        auto pc_begin_v = read_encoded(rd, ci.fde_ptr_enc,
                                       eh->vaddr, pc_begin_vaddr);
        if (!pc_begin_v) { top.pos = payload_end; continue; }
        auto pc_range_v = read_encoded(
            rd, ci.fde_ptr_enc & 0x0F,
            eh->vaddr, entry_vaddr + 4 + 4 + rd.pos);
        if (!pc_range_v) { top.pos = payload_end; continue; }

        if (ci.has_augmentation) {
            u64 fde_aug_len = 0;
            if (!rd.get_uleb128(fde_aug_len)) {
                top.pos = payload_end; continue;
            }
            rd.pos += static_cast<std::size_t>(fde_aug_len);
            if (rd.pos > rd.buf.size()) { top.pos = payload_end; continue; }
        }

        if (target_pc < *pc_begin_v ||
            target_pc >= *pc_begin_v + *pc_range_v) {
            top.pos = payload_end;
            continue;
        }

        // Coverage match — run the FDE.
        Vm vm;
        vm.code_align = ci.code_alignment_factor;
        vm.data_align = ci.data_alignment_factor;
        vm.state.return_address_register =
            static_cast<u32>(ci.return_address_register);

        if (!run(vm, ci.initial_instructions, /*target_pc*/ 0)) {
            return std::nullopt;
        }
        vm.initial_state = vm.state;
        vm.location = *pc_begin_v;

        const std::span<const std::byte> fde_insns =
            rd.buf.subspan(rd.pos);
        if (!run(vm, fde_insns, target_pc) && vm.failed) {
            return std::nullopt;
        }
        return vm.state;
    }

    return std::nullopt;
}

}  // namespace ember::cfi
