// .eh_frame-driven runtime unwinder. Bridges ember::cfi::recover()
// (the static CFI VM, which works against the on-disk binary) to
// the live tracee's registers and memory.
//
// Algorithm:
//   1. Read live regs for the thread.
//   2. For each frame:
//        a. Un-slide RIP to a static PC, ask cfi::recover() for the
//           per-register save rules.
//        b. Compute CFA in live address space from the rule's reg.
//        c. Recover each saved register: [CFA + offset] read from
//           tracee memory, OR a register copy, OR an undefined sink.
//        d. Caller's RSP = CFA. Caller's RIP = the return-address
//           rule (re-slid for the live address space).
//        e. Stop on no-progress, undefined return address, or zero PC.

#include <ember/debug/unwind.hpp>

#include <cstring>

#include <ember/analysis/cfi.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>

namespace ember::debug {

namespace {

// DWARF register-number → live Registers field. x86-64 System V
// mapping: 0..15 = rax/rdx/rcx/rbx/rsi/rdi/rbp/rsp/r8..r15, 16 = RIP.
[[nodiscard]] u64 read_dwarf_reg(const Registers& r, u32 dw_reg) {
    switch (dw_reg) {
        case 0:  return r.rax;
        case 1:  return r.rdx;
        case 2:  return r.rcx;
        case 3:  return r.rbx;
        case 4:  return r.rsi;
        case 5:  return r.rdi;
        case 6:  return r.rbp;
        case 7:  return r.rsp;
        case 8:  return r.r8;
        case 9:  return r.r9;
        case 10: return r.r10;
        case 11: return r.r11;
        case 12: return r.r12;
        case 13: return r.r13;
        case 14: return r.r14;
        case 15: return r.r15;
        case 16: return r.rip;
        default: return 0;
    }
}

void write_dwarf_reg(Registers& r, u32 dw_reg, u64 v) {
    switch (dw_reg) {
        case 0:  r.rax = v; break;
        case 1:  r.rdx = v; break;
        case 2:  r.rcx = v; break;
        case 3:  r.rbx = v; break;
        case 4:  r.rsi = v; break;
        case 5:  r.rdi = v; break;
        case 6:  r.rbp = v; break;
        case 7:  r.rsp = v; break;
        case 8:  r.r8  = v; break;
        case 9:  r.r9  = v; break;
        case 10: r.r10 = v; break;
        case 11: r.r11 = v; break;
        case 12: r.r12 = v; break;
        case 13: r.r13 = v; break;
        case 14: r.r14 = v; break;
        case 15: r.r15 = v; break;
        case 16: r.rip = v; break;
        default: break;
    }
}

[[nodiscard]] bool read_u64(Target& t, addr_t va, u64& out) {
    std::byte buf[8] = {};
    auto rv = t.read_mem(va, buf);
    if (!rv || *rv != sizeof(buf)) return false;
    std::memcpy(&out, buf, sizeof(buf));
    return true;
}

}  // namespace

Result<std::vector<Frame>>
unwind_eh_frame(Target& t, ThreadId tid, const Binary& bin, addr_t slide,
                std::size_t max_frames) {
    std::vector<Frame> out;

    auto regs = t.get_regs(tid);
    if (!regs) return std::unexpected(std::move(regs).error());

    Registers cur = *regs;
    out.push_back({cur.rip, cur.rbp, cur.rsp});

    while (out.size() < max_frames) {
        const addr_t static_pc = cur.rip - slide;
        auto st = cfi::recover(bin, static_pc);
        if (!st) break;
        if (st->cfa.kind != cfi::CfaDef::Kind::Register) break;

        // CFA in live address space.
        const u64 cfa_base = read_dwarf_reg(cur, st->cfa.reg);
        const u64 cfa      = cfa_base + static_cast<u64>(st->cfa.offset);

        // Recover each saved register per its rule. We compute into
        // `next` so SameValue / Register rules read from cur, not
        // partially-updated next.
        Registers next = cur;
        for (u32 i = 0; i < cfi::State::kNumRegs; ++i) {
            const auto& rule = st->regs[i];
            switch (rule.kind) {
                case cfi::RuleKind::Undefined:
                    write_dwarf_reg(next, i, 0);
                    break;
                case cfi::RuleKind::SameValue:
                    write_dwarf_reg(next, i, read_dwarf_reg(cur, i));
                    break;
                case cfi::RuleKind::Offset: {
                    u64 v = 0;
                    if (!read_u64(t, cfa + static_cast<u64>(rule.offset), v)) {
                        return out;
                    }
                    write_dwarf_reg(next, i, v);
                    break;
                }
                case cfi::RuleKind::ValOffset:
                    write_dwarf_reg(next, i, cfa + static_cast<u64>(rule.offset));
                    break;
                case cfi::RuleKind::Register:
                    write_dwarf_reg(next, i, read_dwarf_reg(cur, rule.reg));
                    break;
            }
        }

        // Caller's RSP at the call instruction is, by definition, CFA.
        next.rsp = cfa;

        // Caller's RIP from the return-address rule.
        const u32 raReg = st->return_address_register;
        if (raReg >= cfi::State::kNumRegs) break;
        const auto& raRule = st->regs[raReg];
        if (raRule.kind == cfi::RuleKind::Undefined) break;

        // Recovered values are always runtime addresses: memory reads
        // give us bytes that the CALL instruction pushed (which were
        // runtime PCs to begin with), and register-copy rules pull
        // from live regs. Slide is consumed only on the way *in* to
        // cfi::recover, never re-applied on the way out.
        const u64 caller_rip = read_dwarf_reg(next, raReg);
        if (caller_rip == 0) break;
        if (caller_rip == cur.rip) break;     // no progress

        cur = next;
        cur.rip = caller_rip;
        out.push_back({cur.rip, cur.rbp, cur.rsp});
    }
    return out;
}

}  // namespace ember::debug
