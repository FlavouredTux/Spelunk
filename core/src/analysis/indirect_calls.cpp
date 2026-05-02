#include <ember/analysis/indirect_calls.hpp>

#include <algorithm>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/ir_cache.hpp>
#include <ember/analysis/msvc_rtti.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/rtti.hpp>
#include <ember/binary/symbol.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

// IrCache + lift_cached now live in <ember/analysis/ir_cache.hpp> so this
// pass and the IPA pass can share one cache and amortise the lift cost.

[[nodiscard]] bool addr_in_executable_section(const Binary& b, addr_t a) noexcept {
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (a >= s.vaddr && a < s.vaddr + s.size) return true;
    }
    return false;
}

[[nodiscard]] std::optional<u64> read_u64_le(const Binary& b, addr_t a) noexcept {
    auto span = b.bytes_at(a);
    if (span.size() < 8) return std::nullopt;
    u64 v = 0;
    std::memcpy(&v, span.data(), 8);
    return v;
}

// Trace `v` through trivial Assign and single-distinct-operand Phi chains
// to its rooted definition. Returns the def IrInst* (the producing op,
// e.g. Load/Add/...), or nullptr if the chain leaves the function or hits
// something we can't see through.
[[nodiscard]] const IrInst*
walk_to_def(const std::map<SsaKey, const IrInst*>& defs,
            const IrValue& v, int depth = 0) {
    if (depth > 12) return nullptr;
    auto k = ssa_key(v);
    if (!k) return nullptr;
    auto it = defs.find(*k);
    if (it == defs.end()) return nullptr;
    const IrInst* d = it->second;
    if (d->op == IrOp::Assign && d->src_count == 1) {
        return walk_to_def(defs, d->srcs[0], depth + 1);
    }
    if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
        const IrInst* common = nullptr;
        for (const auto& op : d->phi_operands) {
            auto opk = ssa_key(op);
            if (opk && *opk == *k) continue;  // self-loop; skip
            const IrInst* sub = walk_to_def(defs, op, depth + 1);
            if (!sub) return nullptr;
            if (!common) common = sub;
            else if (common != sub) return nullptr;
        }
        return common;
    }
    return d;
}

// If `v` evaluates to a constant immediate (possibly via Assign/Phi
// chains), return it. Used for trivial constant folding the cleanup
// pass may have left rooted at an Assign instead of inlined.
[[nodiscard]] std::optional<i64>
const_value(const std::map<SsaKey, const IrInst*>& defs,
            const IrValue& v, int depth = 0) {
    if (depth > 12) return std::nullopt;
    if (v.kind == IrValueKind::Imm) return v.imm;
    auto k = ssa_key(v);
    if (!k) return std::nullopt;
    auto it = defs.find(*k);
    if (it == defs.end()) return std::nullopt;
    const IrInst* d = it->second;
    if (d->op == IrOp::Assign && d->src_count == 1) {
        return const_value(defs, d->srcs[0], depth + 1);
    }
    if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
        std::optional<i64> common;
        for (const auto& op : d->phi_operands) {
            auto opk = ssa_key(op);
            if (opk && *opk == *k) continue;
            auto sub = const_value(defs, op, depth + 1);
            if (!sub) return std::nullopt;
            if (!common) common = *sub;
            else if (*common != *sub) return std::nullopt;
        }
        return common;
    }
    return std::nullopt;
}

// If `addr` is `Load(K)` for some constant K, return K.
[[nodiscard]] std::optional<addr_t>
load_of_const(const std::map<SsaKey, const IrInst*>& defs,
              const IrValue& addr) {
    const IrInst* d = walk_to_def(defs, addr);
    if (!d || d->op != IrOp::Load || d->src_count < 1) return std::nullopt;
    auto k = const_value(defs, d->srcs[0]);
    if (!k) return std::nullopt;
    return static_cast<addr_t>(*k);
}

// Decompose an addressing expression into (base_const, offset_const) when
// possible. Handles plain `Imm`, `Add(Imm, Imm)`, and `Add(X, Imm)` where
// X traces to a constant.
[[nodiscard]] std::optional<std::pair<addr_t, i64>>
const_addr_with_offset(const std::map<SsaKey, const IrInst*>& defs,
                       const IrValue& addr) {
    if (auto c = const_value(defs, addr)) {
        return std::pair<addr_t, i64>{static_cast<addr_t>(*c), 0};
    }
    const IrInst* d = walk_to_def(defs, addr);
    if (!d || d->op != IrOp::Add || d->src_count < 2) return std::nullopt;

    auto try_split = [&](const IrValue& a, const IrValue& b)
        -> std::optional<std::pair<addr_t, i64>> {
        auto bc = const_value(defs, b);
        if (!bc) return std::nullopt;
        auto ac = const_value(defs, a);
        if (ac) return std::pair<addr_t, i64>{static_cast<addr_t>(*ac), *bc};
        return std::nullopt;
    };
    if (auto r = try_split(d->srcs[0], d->srcs[1])) return r;
    if (auto r = try_split(d->srcs[1], d->srcs[0])) return r;
    return std::nullopt;
}

// Look up the resolved method at `vtable + offset` in the union vtable
// index. The map keys are the *vptr value the code observes* — the
// address held in an object's vptr slot, which equals `methods[0]`.
//
// For Itanium classes whose `RttiClass::vtable` points at the typeinfo
// slot, the loader stores `vtable + 16` as the vptr (offset_to_top + RTTI
// before methods), so callers index by that value. For MSVC, `vtable`
// already points one past the COL pointer, i.e. at methods[0].
struct VtableEntry {
    const std::vector<addr_t>* methods = nullptr;
};

[[nodiscard]] std::optional<addr_t>
slot_at(const std::map<addr_t, VtableEntry>& idx,
        const Binary& b, addr_t vptr, i64 disp) {
    auto it = idx.find(vptr);
    if (it == idx.end()) return std::nullopt;
    if (disp < 0 || (disp & 7) != 0) return std::nullopt;
    const std::size_t slot = static_cast<std::size_t>(disp) / 8;
    if (slot >= it->second.methods->size()) return std::nullopt;
    const addr_t imp = (*it->second.methods)[slot];
    if (imp == 0 || !addr_in_executable_section(b, imp)) return std::nullopt;
    return imp;
}

// Attempt to resolve a single CallIndirect target. Tries paths in order:
// import GOT, import GOT + small const, vtable dispatch via constant
// vptr load. Returns the resolved target VA or nullopt.
[[nodiscard]] std::optional<addr_t>
resolve_target(const Binary& b,
               const std::map<SsaKey, const IrInst*>& defs,
               const std::map<addr_t, VtableEntry>& vtables,
               const IrValue& target) {
    // The target itself should be a Load(addr).
    const IrInst* td = walk_to_def(defs, target);
    if (!td || td->op != IrOp::Load || td->src_count < 1) return std::nullopt;
    const IrValue& load_addr = td->srcs[0];

    // Path 1+2: Load(K) or Load(K + small) where K is an import GOT.
    if (auto split = const_addr_with_offset(defs, load_addr)) {
        const addr_t base = split->first;
        const i64 off = split->second;
        // Path 1 — exact GOT slot.
        if (off == 0) {
            if (const Symbol* imp = b.import_at_got(base); imp != nullptr) {
                return imp->addr;
            }
        }
        // Path 2 — base + small. Probe the resulting slot.
        if (off >= 0 && off <= 0x10000) {
            const addr_t slot = base + static_cast<addr_t>(off);
            if (const Symbol* imp = b.import_at_got(slot); imp != nullptr) {
                return imp->addr;
            }
            // ...or, if it's a writable function-pointer table whose
            // loaded value is a real code address.
            if (auto v = read_u64_le(b, slot); v) {
                const auto t = static_cast<addr_t>(*v);
                if (t != 0 && addr_in_executable_section(b, t)) return t;
            }
        }
    }

    // Path 3: vtable dispatch.
    //   load_addr = vptr_expr + slot_offset
    //   vptr_expr = Load(receiver_const)         (vptr held in a global)
    //
    // We require the vptr to come from a constant address — the global-
    // object case: `mov rax, [rip+global]; mov rax, [rax]; call [rax+0x18]`.
    auto split = const_addr_with_offset(defs, load_addr);
    // Two shapes feed `load_addr`:
    //   a) Imm + Imm collapsed to a const — handled above already.
    //   b) Add(vptr_expr, slot_imm) — vptr_expr is a non-const SSA value.
    if (split) {
        // Maybe load_addr is itself a constant pointer to a method —
        // very rare but: fall through.
    }
    const IrInst* ad = walk_to_def(defs, load_addr);
    if (!ad || ad->op != IrOp::Add || ad->src_count < 2) return std::nullopt;

    auto try_vtable = [&](const IrValue& vptr_expr, const IrValue& off_expr)
        -> std::optional<addr_t> {
        auto disp = const_value(defs, off_expr);
        if (!disp) return std::nullopt;
        auto vptr = load_of_const(defs, vptr_expr);
        if (!vptr) return std::nullopt;
        return slot_at(vtables, b, *vptr, *disp);
    };
    if (auto r = try_vtable(ad->srcs[0], ad->srcs[1])) return r;
    if (auto r = try_vtable(ad->srcs[1], ad->srcs[0])) return r;

    // Direct vptr load shape: load_addr = vptr_const + 0  (slot 0).
    // (Already handled by the import-path's offset-0 case for the load
    //  base, but when no GOT match and the const is a known vtable, treat
    //  it as slot 0.)
    if (split && split->first != 0) {
        if (auto r = slot_at(vtables, b, split->first, split->second)) return *r;
    }
    return std::nullopt;
}

}  // namespace

std::map<addr_t, addr_t>
resolve_indirect_calls(const Binary& b, IrCache* shared_cache) {
    std::map<addr_t, addr_t> out;

    // Build the vtable index from both Itanium and MSVC parsers. The
    // emitter and pipeline already pay these costs elsewhere; running them
    // again here keeps this resolver self-contained.
    std::vector<RttiClass> itanium;
    std::vector<MsvcRttiClass> msvc;
    if (b.format() == Format::MachO || b.format() == Format::Elf) {
        itanium = parse_itanium_rtti(b);
    }
    if (b.format() == Format::Pe) {
        msvc = parse_msvc_rtti(b);
    }

    std::map<addr_t, VtableEntry> vtables;
    for (const auto& c : itanium) {
        if (c.vtable != 0 && !c.methods.empty()) {
            // Itanium vptr = vtable_addr + 16 (offset_to_top + typeinfo
            // come before methods[0]). pipeline.cpp uses +8 because its
            // RttiClass::vtable already points at the typeinfo slot, not
            // the vtable struct base. Match that convention here.
            vtables.emplace(c.vtable + 8, VtableEntry{&c.methods});
        }
    }
    for (const auto& c : msvc) {
        if (c.vtable != 0 && !c.methods.empty()) {
            vtables.emplace(c.vtable, VtableEntry{&c.methods});
        }
    }

    // Byte-level pre-filter. AArch64 does its indirect calls through
    // BLR/BR (a fixed encoding) but we focus on x86-64 here since the
    // only consumer is the x64 emitter today. The relevant patterns are
    // `FF /2` (call r/m) and `FF /4` (jmp r/m), where the ModR/M reg
    // field selects between 8 sub-opcodes:
    //   call r/m  → reg = 010 → ModR/M byte has middle 3 bits = 010
    //               valid bytes: 0x10..17, 0x50..57, 0x90..97, 0xD0..D7
    //   jmp  r/m  → reg = 100 → middle 3 bits = 100
    //               valid bytes: 0x20..27, 0x60..67, 0xA0..A7, 0xE0..E7
    // A scan that flags any `FF <one of those bytes>` byte position is
    // a superset of indirect calls (false positives in immediate /
    // displacement bytes don't matter — they just cost a lift). For
    // ember itself this collapses 7606 candidate functions down to ~50.
    auto looks_like_indirect_modrm = [](u8 byte) noexcept {
        const u8 mid = (byte >> 3) & 0b111;
        return mid == 0b010 || mid == 0b100;
    };

    std::vector<addr_t> hit_addrs;
    if (b.arch() == Arch::X86_64) {
        for (const auto& sec : b.sections()) {
            if (!sec.flags.executable || sec.data.empty()) continue;
            const auto* p = sec.data.data();
            const std::size_t n = sec.data.size();
            for (std::size_t i = 0; i + 1 < n; ++i) {
                if (p[i] != std::byte{0xFF}) continue;
                if (looks_like_indirect_modrm(static_cast<u8>(p[i + 1]))) {
                    hit_addrs.push_back(sec.vaddr + i);
                }
            }
        }
        std::sort(hit_addrs.begin(), hit_addrs.end());
    }

    std::set<addr_t> fns_with_indirect;
    if (b.arch() == Arch::X86_64 && !hit_addrs.empty()) {
        // Build a sorted [start, end) index over every function entry,
        // then for each hit do an O(log N) lookup of the containing
        // function. Functions with size=0 (sub_<hex> entries) get an end
        // computed as the next function's start (or +4096 for the last
        // entry) so we still catch indirect calls inside them.
        struct Range { addr_t lo, hi, key; };
        std::vector<Range> ranges;
        ranges.reserve(2048);
        for (const auto& d : enumerate_functions(b, EnumerateMode::Full)) {
            if (b.import_at_plt(d.addr) != nullptr) continue;
            ranges.push_back({d.addr, d.addr + d.size, d.addr});
        }
        std::sort(ranges.begin(), ranges.end(),
                  [](const Range& a, const Range& bb) noexcept { return a.lo < bb.lo; });
        for (std::size_t i = 0; i < ranges.size(); ++i) {
            if (ranges[i].hi > ranges[i].lo) continue;
            const addr_t next = (i + 1 < ranges.size())
                ? ranges[i + 1].lo
                : ranges[i].lo + 0x1000;
            ranges[i].hi = next;
        }

        for (addr_t hit : hit_addrs) {
            auto it = std::upper_bound(
                ranges.begin(), ranges.end(), hit,
                [](addr_t a, const Range& r) noexcept { return a < r.lo; });
            if (it == ranges.begin()) continue;
            --it;
            if (hit < it->hi) {
                fns_with_indirect.insert(it->key);
            }
        }
    } else {
        // Architectures we don't have a byte-level filter for fall back
        // to the original full sweep — call-graph callers plus every
        // defined entry — so AArch64 BR/BLR cracking still works.
        for (const auto& cc : compute_call_graph(b)) {
            fns_with_indirect.insert(cc.caller);
        }
        for (const auto& d : enumerate_functions(b, EnumerateMode::Full)) {
            if (b.import_at_plt(d.addr) != nullptr) continue;
            fns_with_indirect.insert(d.addr);
        }
    }
    IrCache local_cache;
    IrCache& cache = shared_cache ? *shared_cache : local_cache;
    for (const addr_t fn : fns_with_indirect) {
        IrFunction* ir = lift_cached(cache, b, fn);
        if (!ir) continue;

        // Index every def in the function for SSA def-walking.
        std::map<SsaKey, const IrInst*> defs;
        for (const auto& bb : ir->blocks) {
            for (const auto& inst : bb.insts) {
                if (auto k = ssa_key(inst.dst); k) defs[*k] = &inst;
            }
        }

        for (const auto& bb : ir->blocks) {
            for (const auto& inst : bb.insts) {
                if (inst.op != IrOp::CallIndirect) continue;
                if (inst.src_count < 1 || inst.source_addr == 0) continue;
                if (auto traced = b.indirect_edges_from(inst.source_addr);
                    !traced.empty()) {
                    const addr_t t = traced.front();
                    if (addr_in_executable_section(b, t) ||
                        b.import_at_plt(t) != nullptr) {
                        out.emplace(inst.source_addr, t);
                        continue;
                    }
                }
                if (auto t = resolve_target(b, defs, vtables, inst.srcs[0]); t) {
                    out.emplace(inst.source_addr, *t);
                }
            }
        }
    }
    return out;
}

}  // namespace ember
