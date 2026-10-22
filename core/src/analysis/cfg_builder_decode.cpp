#include "cfg_builder_internal.hpp"

#include <algorithm>
#include <bit>
#include <optional>
#include <vector>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/section.hpp>
#include <spelunk/common/bytes.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/ir/ssa.hpp>  // canonical_reg

namespace spelunk::cfg_builder_detail {

namespace {

// ---------- Jump-table detection ----------------------------------------------
//
// Recognizes two common x86-64 idioms produced by GCC/Clang:
//
// (A) PIC / RIP-relative offset table:
//       lea     rT, [rip + .Ltable]
//       ...
//       movsxd  rB, dword ptr [rT + rI*4]
//       add     rT, rB
//       jmp     rT
//     Each table entry is a 32-bit signed offset from .Ltable;
//     the case target is .Ltable + *(i32*)&table[idx].
//
// (B) Absolute memory-indirect table:
//       jmp     qword ptr [rip + .Ltable + rI*8]
//     Each entry is a 64-bit absolute target address.
//
// Case-count is derived from a preceding `cmp rI, N` + `ja/jae default` guard
// (GCC's canonical shape). If that guard isn't found, we probe the table
// forward and stop as soon as an entry doesn't land inside an executable
// section - good enough for v1.

[[nodiscard]] const Section*
find_exec_section_for(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (a >= s.vaddr && a - s.vaddr < s.size) return &s;
    }
    return nullptr;
}

[[nodiscard]] bool read_u64_at(const Binary& b, addr_t a, u64& out) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < 8) return false;
    out = b.endian() == Endian::Big
        ? read_be_at<u64>(span.data()) : read_le_at<u64>(span.data());
    return true;
}

// Read one `entry_bytes`-sized slot starting at `a`, returning the value
// sign- or zero-extended to i64 per `is_signed`. Supports {1,2,4}-byte
// entries (8-byte slots go through read_u64_at directly).
[[nodiscard]] bool read_table_entry(const Binary& b, addr_t a,
                                    u8 entry_bytes, bool is_signed,
                                    i64& out) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < entry_bytes) return false;
    if (entry_bytes == 1) {
        u8 raw = static_cast<u8>(span[0]);
        out = is_signed ? static_cast<i64>(static_cast<i8>(raw))
                        : static_cast<i64>(raw);
        return true;
    }
    if (entry_bytes == 2) {
        const u16 raw = b.endian() == Endian::Big
            ? read_be_at<u16>(span.data()) : read_le_at<u16>(span.data());
        out = is_signed ? static_cast<i64>(static_cast<i16>(raw))
                        : static_cast<i64>(raw);
        return true;
    }
    if (entry_bytes == 4) {
        const u32 raw = b.endian() == Endian::Big
            ? read_be_at<u32>(span.data()) : read_le_at<u32>(span.data());
        out = is_signed ? static_cast<i64>(static_cast<i32>(raw))
                        : static_cast<i64>(raw);
        return true;
    }
    return false;
}

// Resolve a `lea rT, [rip + disp]` anywhere in insns_view whose destination
// matches reg. Returns the rip-relative target, or nullopt.
[[nodiscard]] std::optional<addr_t>
find_lea_rip_for(const std::vector<const Instruction*>& insns_view, Reg reg) noexcept {
    const Reg want = canonical_reg(reg);
    for (auto it = insns_view.rbegin(); it != insns_view.rend(); ++it) {
        const Instruction& insn = **it;
        if (insn.mnemonic != Mnemonic::Lea) continue;
        if (insn.num_operands != 2) continue;
        const auto& d = insn.operands[0];
        const auto& s = insn.operands[1];
        if (d.kind != Operand::Kind::Register) continue;
        if (canonical_reg(d.reg) != want) continue;
        if (s.kind != Operand::Kind::Memory) continue;
        if (s.mem.base != Reg::Rip || s.mem.index != Reg::None) continue;
        if (!s.mem.has_disp) continue;
        const i64 base = static_cast<i64>(insn.address + insn.length);
        return static_cast<addr_t>(base + s.mem.disp);
    }
    return std::nullopt;
}

// Try to extract (index_reg, case_count, default_target) from predecessor blocks.
// Looks for a `cmp idx, N` immediately followed by `ja default` (unsigned >),
// which means cases are 0..N.
struct BoundGuess {
    u32                   count       = 0;
    std::optional<addr_t> default_tgt;
    Reg                   index_reg   = Reg::None;
};

[[nodiscard]] std::optional<BoundGuess>
detect_bound(const std::map<addr_t, Instruction>& insns,
             const std::set<addr_t>& leaders,
             addr_t jmp_addr,
             Reg index_reg_hint) {
    auto it = insns.find(jmp_addr);
    if (it == insns.end() || it == insns.begin()) return std::nullopt;

    // `cmp rX, N; jbe table_block` guards from a predecessor anywhere in the
    // function: in range, it branches to the block holding the jump; out of
    // range, it falls through to the default. Match the branch by its
    // target, and the compared register by the table index.
    auto start = it;
    for (int i = 0; i < 16 && !leaders.contains(start->first) && start != insns.begin(); ++i) {
        const auto previous = std::prev(start);
        if (previous->first + previous->second.length != start->first) break;
        start = previous;
    }
    if (leaders.contains(start->first) && index_reg_hint != Reg::None) {
        const Reg want = canonical_reg(index_reg_hint);
        for (auto branch = std::next(insns.begin()); branch != insns.end(); ++branch) {
            const Instruction& jbe = branch->second;
            if ((jbe.mnemonic != Mnemonic::Jbe && jbe.mnemonic != Mnemonic::Jb) ||
                jbe.num_operands < 1 || jbe.operands[0].kind != Operand::Kind::Relative ||
                jbe.operands[0].rel.target != start->first) continue;
            const Instruction& cmp = std::prev(branch)->second;
            if (cmp.mnemonic != Mnemonic::Cmp || cmp.num_operands != 2 ||
                cmp.address + cmp.length != jbe.address ||
                cmp.operands[0].kind != Operand::Kind::Register ||
                cmp.operands[1].kind != Operand::Kind::Immediate ||
                canonical_reg(cmp.operands[0].reg) != want) continue;
            const auto n = static_cast<u32>(cmp.operands[1].imm.value);
            BoundGuess g;
            g.index_reg = cmp.operands[0].reg;
            g.count = jbe.mnemonic == Mnemonic::Jbe ? n + 1 : n;
            g.default_tgt = jbe.address + jbe.length;
            return g;
        }
    }

    // Walk backward from the jmp, scanning up to ~48 instructions (spanning
    // predecessor blocks is fine - we ignore control flow for this heuristic).
    // Match `cmp rX, N` immediately followed by `ja/jae target`; the
    // register name doesn't need to equal the jmp's index register because
    // the compiler often moves it through one or two aliases.

    std::vector<const Instruction*> recent;
    recent.reserve(48);
    auto cur = it;
    for (int i = 0; i < 48 && cur != insns.begin(); ++i) {
        --cur;
        recent.push_back(&cur->second);
    }

    for (std::size_t i = 0; i + 1 < recent.size(); ++i) {
        const Instruction* ja  = recent[i];
        const Instruction* cmp = recent[i + 1];
        const bool x86_bound =
            (ja->mnemonic == Mnemonic::Ja || ja->mnemonic == Mnemonic::Jae) &&
            cmp->mnemonic == Mnemonic::Cmp;
        const bool ppc_bound =
            (ja->mnemonic == Mnemonic::Bgt || ja->mnemonic == Mnemonic::Bge) &&
            (cmp->mnemonic == Mnemonic::Cmpl || cmp->mnemonic == Mnemonic::Cmp);
        if (!x86_bound && !ppc_bound) continue;
        if (cmp->num_operands != 2) continue;
        const auto& a = cmp->operands[0];
        const auto& b = cmp->operands[1];
        if (b.kind != Operand::Kind::Immediate) continue;
        Reg index = a.reg;
        if (a.kind == Operand::Kind::Memory) {
            // `cmp byte ptr [rbx + 0x26d], 5; ja` compares the selector in
            // memory; it is the bound only if that same memory is then
            // loaded into the register the table is indexed with. The reload
            // may go through a copy of the base (`mov r12, rdi`).
            index = Reg::None;
            for (std::size_t j = i; j-- > 0 && index == Reg::None;) {
                const Instruction* load = recent[j];
                if ((load->mnemonic != Mnemonic::Mov && load->mnemonic != Mnemonic::Movzx) ||
                    load->num_operands != 2 ||
                    load->operands[0].kind != Operand::Kind::Register ||
                    load->operands[1].kind != Operand::Kind::Memory) continue;
                const Mem& m = load->operands[1].mem;
                const bool same_base = m.base == a.mem.base ||
                    (index_reg_hint != Reg::None &&
                     canonical_reg(load->operands[0].reg) == canonical_reg(index_reg_hint));
                if (same_base && m.index == a.mem.index && m.scale == a.mem.scale &&
                    m.disp == a.mem.disp && m.size == a.mem.size && m.segment == a.mem.segment &&
                    m.base != Reg::Rip) {
                    index = load->operands[0].reg;
                }
            }
            if (index == Reg::None) continue;
        } else if (a.kind != Operand::Kind::Register) {
            continue;
        }

        BoundGuess g;
        g.index_reg = index;
        const auto n = static_cast<u32>(b.imm.value);
        // ja:  idx > N  → default → valid range 0..N   → count = N+1
        // jae: idx >= N → default → valid range 0..N-1 → count = N
        g.count = (ja->mnemonic == Mnemonic::Ja ||
                   ja->mnemonic == Mnemonic::Bgt) ? (n + 1) : n;
        if (ja->num_operands >= 1 && ja->operands[0].kind == Operand::Kind::Relative) {
            g.default_tgt = ja->operands[0].rel.target;
        }
        return g;
    }

    // `and rX, 7` masks the index into range with no compare at all, as in
    // OpenSSL's tail-byte switches. It bounds the table only if nothing
    // between the mask and the jump writes the register again.
    if (index_reg_hint != Reg::None) {
        const Reg want = canonical_reg(index_reg_hint);
        for (const Instruction* in : recent) {
            if (in->num_operands < 1 || in->operands[0].kind != Operand::Kind::Register ||
                canonical_reg(in->operands[0].reg) != want ||
                in->mnemonic == Mnemonic::Cmp || in->mnemonic == Mnemonic::Test) continue;
            if (in->mnemonic == Mnemonic::And && in->num_operands == 2 &&
                in->operands[1].kind == Operand::Kind::Immediate) {
                const auto mask = static_cast<u64>(in->operands[1].imm.value);
                if (mask > 0 && mask < 4096 && std::has_single_bit(mask + 1)) {
                    BoundGuess g;
                    g.index_reg = in->operands[0].reg;
                    g.count = static_cast<u32>(mask + 1);
                    return g;
                }
            }
            break;
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<u64>
ppc_constant_for_reg(const std::vector<const Instruction*>& recent,
                     Reg want) noexcept;

// CodeWarrior's canonical PPC switch sequence:
//
//   cmplwi  rIDX, max
//   bgt     default
//   lis     rTAB, table@ha
//   slwi    rOFF, rIDX, 2
//   addi    rTAB, rTAB, table@l
//   lwzx    rTGT, rTAB, rOFF
//   mtctr   rTGT
//   bctr
//
// DOL tables contain absolute big-endian 32-bit code addresses. The bound
// supplies both the exact case count and the source selector register, while
// the table address is recovered from the lis/addi chain as it existed before
// lwzx overwrote rTGT (CodeWarrior commonly reuses rTAB as rTGT).
[[nodiscard]] std::optional<JumpTable>
detect_ppc_ctr_jump_table(const Binary& b, const WalkState& ws,
                          addr_t jmp_addr,
                          const std::vector<const Instruction*>& recent) {
    if (b.arch() != Arch::Ppc32) return std::nullopt;
    auto jit = ws.insns.find(jmp_addr);
    if (jit == ws.insns.end()) return std::nullopt;
    const Instruction& jump = jit->second;
    if (jump.mnemonic != Mnemonic::Jmp || jump.num_operands != 1 ||
        jump.operands[0].kind != Operand::Kind::Register ||
        canonical_reg(jump.operands[0].reg) != Reg::PpcCtr) {
        return std::nullopt;
    }

    std::optional<Reg> target_reg;
    const Instruction* load = nullptr;
    for (const Instruction* in : recent) {
        if (!target_reg && in->mnemonic == Mnemonic::Mov &&
            in->num_operands == 2 &&
            in->operands[0].kind == Operand::Kind::Register &&
            canonical_reg(in->operands[0].reg) == Reg::PpcCtr &&
            in->operands[1].kind == Operand::Kind::Register) {
            target_reg = canonical_reg(in->operands[1].reg);
            continue;
        }
        if (!target_reg || in->mnemonic != Mnemonic::Lwzx ||
            in->num_operands != 2 ||
            in->operands[0].kind != Operand::Kind::Register ||
            canonical_reg(in->operands[0].reg) != *target_reg ||
            in->operands[1].kind != Operand::Kind::Memory) {
            continue;
        }
        const Mem& mem = in->operands[1].mem;
        if (mem.base == Reg::None || mem.index == Reg::None || mem.size != 4) {
            continue;
        }
        load = in;
        break;
    }
    if (!target_reg || !load) return std::nullopt;

    const Mem& table_mem = load->operands[1].mem;
    std::vector<const Instruction*> before_load;
    before_load.reserve(recent.size());
    for (const Instruction* in : recent) {
        if (in->address < load->address) before_load.push_back(in);
    }
    auto table_value = ppc_constant_for_reg(before_load, table_mem.base);
    if (!table_value) return std::nullopt;
    const addr_t table = static_cast<addr_t>(*table_value & 0xffffffffULL);

    auto bound = detect_bound(ws.insns, ws.leaders, jmp_addr, table_mem.index);
    constexpr u32 kJumpTableMax = 4096;
    const u32 max_count =
        std::min(bound ? bound->count : 256u, kJumpTableMax);

    JumpTable jt;
    jt.index_reg = bound ? canonical_reg(bound->index_reg)
                         : canonical_reg(table_mem.index);
    if (bound) jt.default_tgt = bound->default_tgt;

    constexpr unsigned kMaxConsecBadProbes = 1;
    unsigned consec_bad = 0;
    for (u32 k = 0; k < max_count; ++k) {
        i64 entry = 0;
        if (!read_table_entry(b, table + static_cast<addr_t>(k) * 4u,
                              4, false, entry)) {
            break;
        }
        const addr_t target = static_cast<addr_t>(
            static_cast<u64>(entry) & 0xffffffffULL);
        if (!find_exec_section_for(b, target)) {
            if (!bound) {
                if (++consec_bad > kMaxConsecBadProbes) break;
            }
            continue;
        }
        consec_bad = 0;
        jt.targets.push_back(target);
        jt.values.push_back(static_cast<i64>(k));
    }
    if (jt.targets.empty()) return std::nullopt;
    return jt;
}

// MSVC two-table indexed switches:
//
//   movzx/movsx  rIDX, byte/dword ptr [rip + .index_table + rOUTER*S1]
//   jmp qword ptr [rip + .jump_table + rIDX*8]
//
// The outer index table holds dense slot numbers into the (compressed) jump
// table - many outer values can map to the same target. Returns true and
// populates `index_table_va`/`entry_bytes`/`outer_reg` if a load-from-rip
// for `rIDX` is found in the recent instruction window.
struct OuterTable {
    addr_t va          = 0;
    u8     entry_bytes = 0;
    bool   is_signed   = false;
    Reg    outer_reg   = Reg::None;
};

[[nodiscard]] std::optional<OuterTable>
find_outer_index_table(const std::vector<const Instruction*>& recent, Reg idx_reg) noexcept {
    const Reg want = canonical_reg(idx_reg);
    for (const Instruction* in : recent) {
        const Mnemonic mn = in->mnemonic;
        if (mn != Mnemonic::Movzx && mn != Mnemonic::Movsx &&
            mn != Mnemonic::Movsxd && mn != Mnemonic::Mov) continue;
        if (in->num_operands != 2) continue;
        const auto& d = in->operands[0];
        const auto& s = in->operands[1];
        if (d.kind != Operand::Kind::Register) continue;
        if (canonical_reg(d.reg) != want) continue;
        if (s.kind != Operand::Kind::Memory) continue;
        if (s.mem.index == Reg::None) continue;
        // The memory access size names the table-entry width.
        const u8 sz = s.mem.size;
        if (sz != 1 && sz != 2 && sz != 4) continue;
        if (s.mem.scale != sz) continue;

        addr_t base_va = 0;
        if (s.mem.base == Reg::Rip) {
            // Direct rip-rel form: [rip + disp + idx*sz]. Note: x86-64 doesn't
            // actually allow rip-rel addressing with a SIB index, so this
            // path is mostly defensive - the lea-then-load form below is
            // what real compilers emit.
            if (!s.mem.has_disp) continue;
            base_va = static_cast<addr_t>(in->address + in->length) +
                      static_cast<addr_t>(s.mem.disp);
        } else {
            // [rTAB + rIDX*sz (+ disp)] where rTAB came from a prior
            // `lea rTAB, [rip + .table]` strictly preceding this load.
            // (Two distinct switch tables can both use rdx, so we must
            // not pick up a later `lea rdx, ...` for a different table.)
            std::vector<const Instruction*> before;
            for (const Instruction* p : recent) {
                if (p->address < in->address) before.push_back(p);
            }
            std::vector<const Instruction*> forward(before.rbegin(), before.rend());
            auto t = find_lea_rip_for(forward, s.mem.base);
            if (!t) continue;
            base_va = *t;
            if (s.mem.has_disp) base_va += static_cast<addr_t>(s.mem.disp);
        }
        OuterTable t;
        t.va          = base_va;
        t.entry_bytes = sz;
        t.is_signed   = (mn == Mnemonic::Movsx || mn == Mnemonic::Movsxd);
        t.outer_reg   = s.mem.index;
        return t;
    }
    return std::nullopt;
}

}  // namespace

[[nodiscard]] std::optional<JumpTable>
detect_jump_table(const Binary& b, const WalkState& ws, addr_t jmp_addr) {
    auto it = ws.insns.find(jmp_addr);
    if (it == ws.insns.end()) return std::nullopt;
    const Instruction& jmp = it->second;
    if (jmp.mnemonic != Mnemonic::Jmp || jmp.num_operands != 1) return std::nullopt;

    const Operand& jop = jmp.operands[0];

    // Collect a window of recent instructions for back-pattern matching.
    std::vector<const Instruction*> recent;  // reverse-chronological
    {
        auto cur = it;
        for (int i = 0; i < 12 && cur != ws.insns.begin(); ++i) {
            --cur;
            recent.push_back(&cur->second);
        }
    }

    if (auto ppc = detect_ppc_ctr_jump_table(b, ws, jmp_addr, recent); ppc) {
        return ppc;
    }

    // -------- Pattern (B): absolute / lea-then-indexed 8-byte table --------
    // Accepted forms (x86-64 doesn't actually allow rip+SIB-index, so the
    // RIP-relative variant only exists defensively):
    //   jmp qword ptr [disp32 + idx*8]                ; absolute (mod=00 base=5)
    //   jmp qword ptr [rTAB   + idx*8 (+disp)]        ; rTAB ← lea [rip+.]
    //   jmp qword ptr [rip + disp + idx*8]            ; theoretical
    if (jop.kind == Operand::Kind::Memory &&
        jop.mem.index != Reg::None &&
        jop.mem.scale == 8) {
        std::optional<addr_t> table_opt;
        if (jop.mem.base == Reg::Rip && jop.mem.has_disp) {
            table_opt = jmp.address + jmp.length +
                        static_cast<addr_t>(jop.mem.disp);
        } else if (jop.mem.base == Reg::None && jop.mem.has_disp) {
            table_opt = static_cast<addr_t>(jop.mem.disp);
        } else if (jop.mem.base != Reg::None && jop.mem.base != Reg::Rip) {
            std::vector<const Instruction*> forward(recent.rbegin(), recent.rend());
            if (auto t = find_lea_rip_for(forward, jop.mem.base); t) {
                table_opt = *t + (jop.mem.has_disp
                                  ? static_cast<addr_t>(jop.mem.disp) : 0);
            }
        }
        if (table_opt) {
        const addr_t table = *table_opt;
        const Reg idx_reg = jop.mem.index;

        // ---- Pattern (D): MSVC two-table indexed switch --------------
        // If `idx_reg` was just loaded from a small index table indexed by
        // some outer register, expand to per-outer-value cases. This is
        // MSVC's bread-and-butter for dense switches with non-contiguous
        // case values (see find_outer_index_table above).
        if (auto outer = find_outer_index_table(recent, idx_reg); outer) {
            auto bound = detect_bound(ws.insns, ws.leaders, jmp_addr, outer->outer_reg);
            constexpr u32 kJumpTableMax = 4096;
            const u32 max_count =
                std::min(bound ? bound->count : 256u, kJumpTableMax);

            JumpTable jt;
            jt.index_reg = bound ? canonical_reg(bound->index_reg)
                                 : canonical_reg(outer->outer_reg);
            if (bound) jt.default_tgt = bound->default_tgt;
            // In probe mode (no decoded bound) we tolerate one consecutive
            // bad entry before giving up - handles rare compiler-emitted
            // unreachable-default slots without becoming a junk-data probe.
            constexpr unsigned kMaxConsecBadProbes = 1;
            unsigned consec_bad = 0;
            for (u32 k = 0; k < max_count; ++k) {
                i64 slot = 0;
                if (!read_table_entry(b, outer->va + k * outer->entry_bytes,
                                      outer->entry_bytes, outer->is_signed,
                                      slot)) {
                    break;
                }
                if (slot < 0) {
                    if (!bound) break;
                    continue;
                }
                u64 entry = 0;
                if (!read_u64_at(b, table + static_cast<u64>(slot) * 8u,
                                 entry)) {
                    break;
                }
                const addr_t tgt = static_cast<addr_t>(entry);
                if (!find_exec_section_for(b, tgt)) {
                    if (!bound) {
                        if (++consec_bad > kMaxConsecBadProbes) break;
                        continue;
                    }
                    continue;
                }
                consec_bad = 0;
                jt.targets.push_back(tgt);
                jt.values.push_back(static_cast<i64>(k));
            }
            if (!jt.targets.empty()) return jt;
        }

        auto bound = detect_bound(ws.insns, ws.leaders, jmp_addr, idx_reg);
        // Hard cap regardless of the decoded `cmp; ja` bound - a corrupt
        // immediate in that guard could otherwise drive a billions-wide loop.
        // Real compilers fall back to other codegen well below this.
        constexpr u32 kJumpTableMax = 4096;
        const u32 max_count =
            std::min(bound ? bound->count : 256u, kJumpTableMax);

        JumpTable jt;
        jt.index_reg = bound ? canonical_reg(bound->index_reg) : canonical_reg(idx_reg);
        if (bound) jt.default_tgt = bound->default_tgt;
        // Tolerate one consecutive bad entry in probe mode; see the outer-
        // table loop above for rationale.
        constexpr unsigned kMaxConsecBadProbes = 1;
        unsigned consec_bad = 0;
        for (u32 k = 0; k < max_count; ++k) {
            u64 entry = 0;
            if (!read_u64_at(b, table + k * 8u, entry)) break;
            const addr_t tgt = static_cast<addr_t>(entry);
            if (!find_exec_section_for(b, tgt)) {
                if (!bound) {
                    if (++consec_bad > kMaxConsecBadProbes) break;
                    continue;
                }
                // With a known bound, trust it even if a single entry looks odd.
                continue;
            }
            consec_bad = 0;
            jt.targets.push_back(tgt);
            jt.values.push_back(static_cast<i64>(k));
        }
        if (jt.targets.empty()) return std::nullopt;
        return jt;
        }  // table_opt
    }

    // -------- Pattern (A): PIC / rip-relative offset table --------
    if (jop.kind != Operand::Kind::Register) return std::nullopt;
    const Reg jmp_reg = canonical_reg(jop.reg);

    // -------- Pattern (C): mov rJmp, [rip + table + idx*8]; jmp rJmp ----
    for (const Instruction* in : recent) {
        if (in->mnemonic != Mnemonic::Mov) continue;
        if (in->num_operands != 2) continue;
        const auto& d = in->operands[0];
        const auto& s = in->operands[1];
        if (d.kind != Operand::Kind::Register) continue;
        if (canonical_reg(d.reg) != jmp_reg) continue;
        if (s.kind != Operand::Kind::Memory) continue;
        if (s.mem.base != Reg::Rip || s.mem.index == Reg::None ||
            s.mem.scale != 8 || !s.mem.has_disp) {
            continue;
        }
        const addr_t table = in->address + in->length +
                             static_cast<addr_t>(s.mem.disp);
        const Reg idx_reg = s.mem.index;
        auto bound = detect_bound(ws.insns, ws.leaders, jmp_addr, idx_reg);
        constexpr u32 kJumpTableMax = 4096;
        const u32 max_count =
            std::min(bound ? bound->count : 256u, kJumpTableMax);

        JumpTable jt;
        jt.index_reg = bound ? canonical_reg(bound->index_reg) : canonical_reg(idx_reg);
        if (bound) jt.default_tgt = bound->default_tgt;
        constexpr unsigned kMaxConsecBadProbes = 1;
        unsigned consec_bad = 0;
        for (u32 k = 0; k < max_count; ++k) {
            u64 entry = 0;
            if (!read_u64_at(b, table + k * 8u, entry)) break;
            const addr_t tgt = static_cast<addr_t>(entry);
            if (!find_exec_section_for(b, tgt)) {
                if (!bound) {
                    if (++consec_bad > kMaxConsecBadProbes) break;
                    continue;
                }
                continue;
            }
            consec_bad = 0;
            jt.targets.push_back(tgt);
            jt.values.push_back(static_cast<i64>(k));
        }
        if (!jt.targets.empty()) return jt;
    }

    // Also gather forward order for lea-lookup helper.
    std::vector<const Instruction*> forward(recent.rbegin(), recent.rend());

    // Pattern:
    //   lea  rTAB, [rip + .table]
    //   movsxd rOFF, [rTAB + rIDX*4]
    //   add  rJMP, rTAB   ; OR  add rTAB, rOFF  (GCC vs. Clang flavor)
    //   jmp  rJMP
    // Where rJMP == dst of the `add` and holds `rTAB + rOFF`, i.e. the final
    // case target. rTAB has a preceding `lea rTAB, [rip+disp]`; rOFF is
    // whichever of {add.dst, add.src} isn't rTAB.
    const Instruction* add_insn = nullptr;
    Reg                add_other = Reg::None;
    for (std::size_t i = 0; i < recent.size(); ++i) {
        const Instruction* in = recent[i];
        if (in->mnemonic != Mnemonic::Add || in->num_operands != 2) continue;
        const auto& d = in->operands[0];
        const auto& s = in->operands[1];
        if (d.kind != Operand::Kind::Register) continue;
        if (s.kind != Operand::Kind::Register) continue;
        if (canonical_reg(d.reg) != jmp_reg) continue;
        add_insn  = in;
        add_other = canonical_reg(s.reg);
        break;
    }
    if (!add_insn) return std::nullopt;

    // Try both (rTAB, rOFF) orderings.
    struct Cand { Reg tab; Reg off; };
    const Cand cands[] = {
        { add_other, jmp_reg },      // GCC: add rJMP, rTAB → rTAB=add.src
        { jmp_reg,  add_other },     // Clang: add rTAB, rOFF → rTAB=add.dst
    };

    addr_t table       = 0;
    Reg    idx_reg     = Reg::None;
    bool   matched     = false;
    u8     entry_bytes = 4;
    bool   entry_signed = true;

    for (const auto& c : cands) {
        // Need a movsxd/movzx/movsx/mov whose dst is rOFF and whose mem
        // base is rTAB. Accepts {1,2,4}-byte entries - Pattern (A) uses
        // 4-byte signed offsets (movsxd); Pattern (E) uses 2-byte or
        // 1-byte entries (movzx/movsx) for dense small-offset switches.
        const Instruction* off_insn = nullptr;
        for (std::size_t i = 0; i < recent.size(); ++i) {
            const Instruction* in = recent[i];
            const Mnemonic mn = in->mnemonic;
            if (mn != Mnemonic::Movsxd && mn != Mnemonic::Mov &&
                mn != Mnemonic::Movzx  && mn != Mnemonic::Movsx) continue;
            if (in->num_operands != 2) continue;
            const auto& d = in->operands[0];
            const auto& s = in->operands[1];
            if (d.kind != Operand::Kind::Register) continue;
            if (canonical_reg(d.reg) != c.off) continue;
            if (s.kind != Operand::Kind::Memory) continue;
            if (s.mem.index == Reg::None) continue;
            const u8 sz = s.mem.size;
            if (sz != 1 && sz != 2 && sz != 4) continue;
            if (s.mem.scale != sz) continue;
            if (canonical_reg(s.mem.base) != c.tab) continue;
            off_insn     = in;
            entry_bytes  = sz;
            entry_signed = (mn == Mnemonic::Movsxd ||
                            mn == Mnemonic::Movsx  ||
                            (mn == Mnemonic::Mov && sz == 4));
            break;
        }
        if (!off_insn) continue;

        auto t = find_lea_rip_for(forward, c.tab);
        if (!t) continue;

        table   = *t;
        idx_reg = off_insn->operands[1].mem.index;
        matched = true;
        break;
    }
    if (!matched) return std::nullopt;

    auto bound = detect_bound(ws.insns, ws.leaders, jmp_addr, idx_reg);
    constexpr u32 kJumpTableMax = 4096;
    const u32 max_count =
        std::min(bound ? bound->count : 256u, kJumpTableMax);

    JumpTable jt;
    jt.index_reg = bound ? canonical_reg(bound->index_reg) : canonical_reg(idx_reg);
    if (bound) jt.default_tgt = bound->default_tgt;

    constexpr unsigned kMaxConsecBadProbes = 1;
    unsigned consec_bad = 0;
    for (u32 k = 0; k < max_count; ++k) {
        i64 entry = 0;
        if (!read_table_entry(b, table + k * entry_bytes,
                              entry_bytes, entry_signed, entry)) {
            break;
        }
        const addr_t tgt = table + static_cast<addr_t>(entry);
        if (!find_exec_section_for(b, tgt)) {
            if (!bound) {
                if (++consec_bad > kMaxConsecBadProbes) break;
                continue;
            }
            continue;
        }
        consec_bad = 0;
        jt.targets.push_back(tgt);
        jt.values.push_back(static_cast<i64>(k));
    }
    if (jt.targets.empty()) return std::nullopt;
    return jt;
}

namespace {

[[nodiscard]] std::optional<u64>
ppc_constant_for_reg(const std::vector<const Instruction*>& recent, Reg want) noexcept {
    want = canonical_reg(want);
    std::optional<u64> value;
    for (auto it = recent.rbegin(); it != recent.rend(); ++it) {
        const Instruction& in = **it;
        if (in.num_operands == 0 || in.operands[0].kind != Operand::Kind::Register) continue;
        const Reg dst = canonical_reg(in.operands[0].reg);
        if (dst != want) continue;

        if ((in.mnemonic == Mnemonic::Addi || in.mnemonic == Mnemonic::Addis) &&
            in.num_operands == 2 && in.operands[1].kind == Operand::Kind::Immediate) {
            u64 imm = static_cast<u64>(in.operands[1].imm.value);
            if (in.mnemonic == Mnemonic::Addis) imm <<= 16;
            value = imm;
            continue;
        }
        if (in.mnemonic == Mnemonic::Or && in.num_operands == 3 &&
            in.operands[1].kind == Operand::Kind::Register &&
            canonical_reg(in.operands[1].reg) == want &&
            in.operands[2].kind == Operand::Kind::Immediate && value) {
            value = *value | static_cast<u64>(in.operands[2].imm.value);
            continue;
        }
        if (in.mnemonic == Mnemonic::Addi && in.num_operands == 3 &&
            in.operands[1].kind == Operand::Kind::Register &&
            canonical_reg(in.operands[1].reg) == want &&
            in.operands[2].kind == Operand::Kind::Immediate && value) {
            value = *value + static_cast<u64>(in.operands[2].imm.value);
            continue;
        }
        value.reset();
    }
    return value;
}

}  // namespace

[[nodiscard]] std::optional<addr_t>
resolve_ppc_ctr_target(const Binary& b, const WalkState& ws, addr_t branch_addr) {
    if (b.arch() != Arch::Ppc32 && b.arch() != Arch::Ppc64) return std::nullopt;
    auto bit = ws.insns.find(branch_addr);
    if (bit == ws.insns.end()) return std::nullopt;
    const Instruction& br = bit->second;
    if (br.num_operands != 1 || br.operands[0].kind != Operand::Kind::Register ||
        canonical_reg(br.operands[0].reg) != Reg::PpcCtr) {
        return std::nullopt;
    }

    std::vector<const Instruction*> recent;
    for (auto it = bit; it != ws.insns.begin() && recent.size() < 8;) {
        --it;
        recent.push_back(&it->second);
        if (it->second.mnemonic == Mnemonic::Call || is_unconditional_jmp(it->second.mnemonic) ||
            is_return_like(it->second.mnemonic)) {
            break;
        }
    }

    std::optional<Reg> ctr_source;
    for (const Instruction* in : recent) {
        if (in->mnemonic != Mnemonic::Mov || in->num_operands != 2) continue;
        if (in->operands[0].kind != Operand::Kind::Register ||
            canonical_reg(in->operands[0].reg) != Reg::PpcCtr) continue;
        if (in->operands[1].kind != Operand::Kind::Register) continue;
        ctr_source = canonical_reg(in->operands[1].reg);
        break;
    }
    if (!ctr_source) return std::nullopt;
    auto value = ppc_constant_for_reg(recent, *ctr_source);
    if (!value) return std::nullopt;
    const u64 mask = b.arch() == Arch::Ppc32 ? 0xffffffffULL : ~0ULL;
    const addr_t target = static_cast<addr_t>(*value & mask);
    return find_exec_section_for(b, target) ? std::optional<addr_t>(target) : std::nullopt;
}

}  // namespace spelunk::cfg_builder_detail
