#include <ember/analysis/cfg_builder.hpp>

#include <ember/analysis/eh_frame.hpp>
#include <ember/analysis/pe_unwind.hpp>
#include <ember/ir/ssa.hpp>  // canonical_reg

#include <algorithm>
#include <cstring>
#include <deque>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <unordered_set>
#include <utility>

namespace ember {

namespace {

struct JumpTable {
    std::vector<addr_t> targets;
    std::vector<i64>    values;          // parallel to targets (0, 1, 2, …)
    std::optional<addr_t> default_tgt;
    Reg                 index_reg = Reg::None;
};

struct WalkState {
    std::map<addr_t, Instruction> insns;
    std::set<addr_t>              leaders;
    std::unordered_set<addr_t>    call_seen;
    std::vector<addr_t>           calls;
    // Switch tables, keyed by the address of the indirect jmp that reads them.
    std::map<addr_t, JumpTable>   tables;
    // Addresses of `jmp`s that are tail calls (target is a known function
    // entry or PLT stub). Partition converts these into TailCall blocks.
    std::set<addr_t>              tail_calls;
};

// A jmp is a tail call if its target is the entry of some function — either
// a defined non-import function symbol, or a PLT stub for an imported one.
// Self-recursive tail calls (target == current function's entry) also count.
[[nodiscard]] bool is_tail_call_target(const Binary& b, addr_t target) noexcept {
    if (const Symbol* s = b.defined_object_at(target);
        s && s->kind == SymbolKind::Function && s->addr == target) {
        return true;
    }
    if (b.import_at_plt(target) != nullptr) return true;
    return false;
}

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
// section — good enough for v1.

[[nodiscard]] const Section*
find_exec_section_for(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (a >= s.vaddr && a < s.vaddr + s.size) return &s;
    }
    return nullptr;
}

[[nodiscard]] bool read_u64_at(const Binary& b, addr_t a, u64& out) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < 8) return false;
    std::memcpy(&out, span.data(), 8);
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
        u16 raw;
        std::memcpy(&raw, span.data(), 2);
        out = is_signed ? static_cast<i64>(static_cast<i16>(raw))
                        : static_cast<i64>(raw);
        return true;
    }
    if (entry_bytes == 4) {
        u32 raw;
        std::memcpy(&raw, span.data(), 4);
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
             Reg /*index_reg_hint*/) {
    // Walk backward from the jmp, scanning up to ~48 instructions (spanning
    // predecessor blocks is fine — we ignore control flow for this heuristic).
    // Match `cmp rX, N` immediately followed by `ja/jae target`; the
    // register name doesn't need to equal the jmp's index register because
    // the compiler often moves it through one or two aliases.
    auto it = insns.find(jmp_addr);
    if (it == insns.end() || it == insns.begin()) return std::nullopt;

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
        if (ja->mnemonic != Mnemonic::Ja && ja->mnemonic != Mnemonic::Jae) continue;
        if (cmp->mnemonic != Mnemonic::Cmp) continue;
        if (cmp->num_operands != 2) continue;
        const auto& a = cmp->operands[0];
        const auto& b = cmp->operands[1];
        if (a.kind != Operand::Kind::Register) continue;
        if (b.kind != Operand::Kind::Immediate) continue;

        BoundGuess g;
        g.index_reg = a.reg;
        const auto n = static_cast<u32>(b.imm.value);
        // ja:  idx > N  → default → valid range 0..N   → count = N+1
        // jae: idx >= N → default → valid range 0..N-1 → count = N
        g.count = (ja->mnemonic == Mnemonic::Ja) ? (n + 1) : n;
        if (ja->num_operands >= 1 && ja->operands[0].kind == Operand::Kind::Relative) {
            g.default_tgt = ja->operands[0].rel.target;
        }
        (void)leaders;
        return g;
    }
    return std::nullopt;
}

// MSVC two-table indexed switches:
//
//   movzx/movsx  rIDX, byte/dword ptr [rip + .index_table + rOUTER*S1]
//   jmp qword ptr [rip + .jump_table + rIDX*8]
//
// The outer index table holds dense slot numbers into the (compressed) jump
// table — many outer values can map to the same target. Returns true and
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
            // path is mostly defensive — the lea-then-load form below is
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
            // bad entry before giving up — handles rare compiler-emitted
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
        // Hard cap regardless of the decoded `cmp; ja` bound — a corrupt
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
        // base is rTAB. Accepts {1,2,4}-byte entries — Pattern (A) uses
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

void walk_from(const Binary& b, const Decoder& dec, WalkState& ws, addr_t entry) {
    std::deque<addr_t> wl;
    wl.push_back(entry);
    ws.leaders.insert(entry);

    while (!wl.empty()) {
        addr_t ip = wl.front();
        wl.pop_front();

        while (true) {
            if (ws.insns.contains(ip)) break;
            // LC_DATA_IN_CODE / analogous: the linker flagged these bytes
            // as non-code (jump tables, ARM switch constants, etc.). Don't
            // try to decode them as instructions.
            if (b.is_data_in_code(ip)) break;

            const auto bytes = b.bytes_at(ip);
            if (bytes.empty()) break;

            auto decoded = dec.decode(bytes, ip);
            if (!decoded) break;

            auto [it, _] = ws.insns.emplace(ip, std::move(*decoded));
            const Instruction& insn = it->second;
            const addr_t fallthrough = ip + insn.length;
            const Mnemonic mn = insn.mnemonic;

            if (is_return_like(mn)) break;

            if (is_call(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (ws.call_seen.insert(*t).second) {
                        ws.calls.push_back(*t);
                    }
                }
                ip = fallthrough;
                continue;
            }
            if (is_conditional_branch(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (ws.leaders.insert(*t).second) wl.push_back(*t);
                }
                if (ws.leaders.insert(fallthrough).second) wl.push_back(fallthrough);
                break;
            }
            if (is_unconditional_jmp(mn)) {
                if (auto t = branch_target(insn); t) {
                    if (is_tail_call_target(b, *t)) {
                        // Tail call: don't walk into the target; record the
                        // call for xrefs and mark this jmp so partition()
                        // can materialize a TailCall block.
                        if (ws.call_seen.insert(*t).second) {
                            ws.calls.push_back(*t);
                        }
                        ws.tail_calls.insert(ip);
                    } else if (ws.leaders.insert(*t).second) {
                        wl.push_back(*t);
                    }
                }
                break;
            }

            ip = fallthrough;
        }
    }
}

void partition(const Binary& b, const WalkState& ws, Function& fn) {
    for (addr_t leader : ws.leaders) {
        auto it = ws.insns.find(leader);
        if (it == ws.insns.end()) continue;

        BasicBlock bb;
        bb.start = leader;

        while (it != ws.insns.end()) {
            const Instruction& insn = it->second;
            const addr_t addr = it->first;
            const addr_t next = addr + insn.length;

            bb.instructions.push_back(insn);
            bb.end = next;

            const Mnemonic mn = insn.mnemonic;
            if (ends_basic_block(mn)) {
                if (is_return_like(mn)) {
                    bb.kind = BlockKind::Return;
                } else if (is_conditional_branch(mn)) {
                    bb.kind = BlockKind::Conditional;
                    if (auto t = branch_target(insn); t) {
                        bb.successors.push_back(*t);
                    }
                    bb.successors.push_back(next);
                } else if (is_unconditional_jmp(mn)) {
                    auto ti = ws.tables.find(addr);
                    if (ti != ws.tables.end()) {
                        const JumpTable& jt = ti->second;
                        bb.kind = BlockKind::Switch;
                        bb.successors   = jt.targets;
                        bb.case_values  = jt.values;
                        bb.switch_index = jt.index_reg;
                        if (jt.default_tgt) {
                            bb.successors.push_back(*jt.default_tgt);
                            bb.has_default = true;
                        }
                    } else if (ws.tail_calls.contains(addr)) {
                        // Record the target as the single successor so later
                        // stages (lifter, emitter) can recover `return fn(...);`.
                        bb.kind = BlockKind::TailCall;
                        if (auto t = branch_target(insn); t) {
                            bb.successors.push_back(*t);
                        }
                    } else if (auto t = branch_target(insn); t) {
                        bb.kind = BlockKind::Unconditional;
                        bb.successors.push_back(*t);
                    } else if (auto edges = b.indirect_edges_from(addr);
                               !edges.empty()) {
                        // Oracle-resolved indirect jmp. Render as a
                        // Switch-like block so the structurer sees the
                        // full successor set; case_values stay empty
                        // because we have no opcode-to-target mapping
                        // yet (the CLI flag carries pairs only).
                        bb.kind = BlockKind::Switch;
                        bb.successors.assign(edges.begin(), edges.end());
                    } else {
                        bb.kind = BlockKind::IndirectJmp;
                    }
                }
                break;
            }

            if (ws.leaders.contains(next) && next != leader) {
                bb.kind = BlockKind::Fallthrough;
                bb.successors.push_back(next);
                break;
            }

            auto next_it = ws.insns.find(next);
            if (next_it == ws.insns.end()) {
                bb.kind = BlockKind::Fallthrough;
                bb.successors.push_back(next);
                break;
            }
            it = next_it;
        }

        fn.block_at[bb.start] = fn.blocks.size();
        fn.blocks.push_back(std::move(bb));
    }

    for (const auto& blk : fn.blocks) {
        if (blk.end > fn.end) fn.end = blk.end;
    }
}

void compute_predecessors(Function& fn) {
    for (const auto& bb : fn.blocks) {
        for (addr_t succ : bb.successors) {
            auto it = fn.block_at.find(succ);
            if (it != fn.block_at.end()) {
                fn.blocks[it->second].predecessors.push_back(bb.start);
            }
        }
    }
    for (auto& bb : fn.blocks) {
        std::ranges::sort(bb.predecessors);
        const auto dup = std::ranges::unique(bb.predecessors);
        bb.predecessors.erase(dup.begin(), dup.end());
    }
}

}  // namespace

void CfgBuilder::ensure_unwind_ranges_() const {
    if (unwind_ranges_init_) return;
    unwind_ranges_init_ = true;

    auto note = [&](addr_t begin, u64 len) {
        if (len == 0) return;
        auto [it, inserted] = unwind_ranges_.try_emplace(begin, len);
        if (!inserted && len > it->second) it->second = len;
    };
    for (const auto& e : enumerate_fde_extents(binary_)) {
        note(e.pc_begin, e.pc_range);
    }
    for (const auto& e : parse_pe_pdata(binary_)) {
        if (e.end > e.begin) note(e.begin, e.end - e.begin);
    }
}

Result<Function>
CfgBuilder::build(addr_t entry, std::string name) const {
    if (binary_.bytes_at(entry).empty()) {
        return std::unexpected(Error::out_of_bounds(std::format(
            "cfg: no mapped bytes at entry {:#x}", entry)));
    }

    WalkState ws;
    walk_from(binary_, decoder_, ws, entry);

    if (ws.insns.empty()) {
        return std::unexpected(Error::invalid_format(std::format(
            "cfg: failed to decode any instructions at {:#x}", entry)));
    }

    // Iteratively discover jump-table switches: each indirect jmp may reveal
    // case-target blocks that need walking, and those blocks can themselves
    // contain more switches. Bounded to avoid pathological runaway.
    for (int iter = 0; iter < 8; ++iter) {
        bool added_work = false;
        for (const auto& [ip, insn] : ws.insns) {
            if (insn.mnemonic != Mnemonic::Jmp) continue;
            if (ws.tables.contains(ip)) continue;
            if (insn.num_operands != 1) continue;
            const auto& op = insn.operands[0];
            // Only consider "indirect" forms — register or rip-based memory.
            if (op.kind == Operand::Kind::Relative) continue;

            auto table = detect_jump_table(binary_, ws, ip);
            if (!table) continue;

            for (addr_t t : table->targets) {
                if (ws.leaders.insert(t).second) {
                    walk_from(binary_, decoder_, ws, t);
                    added_work = true;
                }
            }
            if (table->default_tgt) {
                if (ws.leaders.insert(*table->default_tgt).second) {
                    walk_from(binary_, decoder_, ws, *table->default_tgt);
                    added_work = true;
                }
            }
            ws.tables.emplace(ip, std::move(*table));
        }
        if (!added_work) break;
    }

    Function fn;
    fn.start        = entry;
    fn.name         = std::move(name);
    fn.call_targets = std::move(ws.calls);

    partition(binary_, ws, fn);
    compute_predecessors(fn);

    // CFG-walk can't reach cleanup/landing-pad tails that the compiler
    // emitted past a noreturn call — there's no branch leading into them
    // from entry. The exception tables know the true function length,
    // so use them to extend fn.end when they report more than we walked.
    ensure_unwind_ranges_();
    if (auto it = unwind_ranges_.find(entry); it != unwind_ranges_.end()) {
        const addr_t fde_end = entry + it->second;
        if (fde_end > fn.end) fn.end = fde_end;
    }

    return fn;
}

}  // namespace ember
