#include <ember/analysis/indirect_calls.hpp>

#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
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

// Per-function memoized lifter+SSA+cleanup. Mirrors IrCache from
// sig_inference.cpp; kept local so neither owns the other's state.
struct IrCache {
    std::map<addr_t, std::unique_ptr<IrFunction>> by_addr;
    std::set<addr_t> failed;
};

IrFunction* get_ir(IrCache& cache, const Binary& b, addr_t fn) {
    if (cache.failed.contains(fn)) return nullptr;
    auto it = cache.by_addr.find(fn);
    if (it != cache.by_addr.end()) return it->second.get();

    auto dec_r = make_decoder(b);
    if (!dec_r) { cache.failed.insert(fn); return nullptr; }
    const CfgBuilder cfg(b, **dec_r);
    auto fn_r = cfg.build(fn, {});
    if (!fn_r) { cache.failed.insert(fn); return nullptr; }
    auto lifter_r = make_lifter(b);
    if (!lifter_r) { cache.failed.insert(fn); return nullptr; }
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) { cache.failed.insert(fn); return nullptr; }
    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) { cache.failed.insert(fn); return nullptr; }
    if (auto rv = run_cleanup(*ir_r);  !rv) { cache.failed.insert(fn); return nullptr; }

    auto out = std::make_unique<IrFunction>(std::move(*ir_r));
    IrFunction* raw = out.get();
    cache.by_addr.emplace(fn, std::move(out));
    return raw;
}

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
resolve_indirect_calls(const Binary& b) {
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

    // Collect candidate functions: anything with at least one indirect
    // call edge in the call graph means there's something to look at.
    // Cheaper than re-lifting every function in the binary.
    std::set<addr_t> fns_with_indirect;
    for (const auto& cc : compute_call_graph(b)) {
        // compute_call_graph emits one edge per (caller, callee) regardless
        // of kind; we don't get the kind here, so just enumerate callers.
        // The IR walk below filters out direct calls naturally.
        fns_with_indirect.insert(cc.caller);
    }
    // Also include every defined function entry — a function with no
    // resolvable callees still might have an indirect call we can crack.
    // Cheap: enumerate_functions is already deduped + sorted.
    for (const auto& d : enumerate_functions(b)) {
        if (b.import_at_plt(d.addr) != nullptr) continue;
        fns_with_indirect.insert(d.addr);
    }

    IrCache cache;
    for (const addr_t fn : fns_with_indirect) {
        IrFunction* ir = get_ir(cache, b, fn);
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
                if (auto t = resolve_target(b, defs, vtables, inst.srcs[0]); t) {
                    out.emplace(inst.source_addr, *t);
                }
            }
        }
    }

    return out;
}

}  // namespace ember
