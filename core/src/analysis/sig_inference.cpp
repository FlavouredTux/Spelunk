#include <spelunk/analysis/sig_inference.hpp>

#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/import_sigs.hpp>
#include <spelunk/analysis/ir_cache.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/type_infer_local.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/decoder.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>
#include <spelunk/ir/ssa.hpp>
#include <spelunk/ir/types.hpp>

namespace spelunk {

namespace {

// IrCache + lift_cached now live in <spelunk/analysis/ir_cache.hpp> so the
// IPA fixed-point and the indirect-call resolver can share one cache and
// only pay each function's lift cost once.

// For an IrValue, trace through Assigns and trivial phis to a version-0
// int-arg register for the given ABI. Returns the 0-based arg slot or
// nullopt.
[[nodiscard]] std::optional<u8>
trace_to_arg_slot(const IrFunction& fn,
                  const std::map<SsaKey, const IrInst*>& defs,
                  Abi abi,
                  const IrValue& v, int depth = 0) {
    if (depth > 8) return std::nullopt;
    const auto args = int_arg_regs(abi);
    IrValue cur = v;
    for (int hop = 0; hop < 8; ++hop) {
        if (cur.kind != IrValueKind::Reg) return std::nullopt;
        const Reg canon = canonical_reg(cur.reg);
        if (cur.version == 0) {
            for (u8 i = 0; i < args.size(); ++i) if (args[i] == canon) return i;
            return std::nullopt;
        }
        auto k = ssa_key(cur);
        if (!k) return std::nullopt;
        auto it = defs.find(*k);
        if (it == defs.end()) return std::nullopt;
        const IrInst* d = it->second;
        if (d->op == IrOp::Assign && d->src_count == 1) {
            cur = d->srcs[0];
            continue;
        }
        if (d->op == IrOp::Phi && !d->phi_operands.empty()) {
            std::optional<u8> common;
            for (const auto& op : d->phi_operands) {
                auto opk = ssa_key(op);
                if (opk && *opk == *k) continue;
                auto slot = trace_to_arg_slot(fn, defs, abi, op, depth + 1);
                if (!slot) return std::nullopt;
                if (!common) common = *slot;
                else if (*common != *slot) return std::nullopt;
            }
            return common;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

// Resolve a call's target to (charp_bitset, typed_params) - combines the
// import-sigs table for known imports and the IPA's running `known` map
// for our own functions. Returns true if we got any usable callee info.
struct CalleeInfo {
    std::array<bool, kMaxAbiIntArgs>    charp{};
    std::array<TypeRef, kMaxAbiIntArgs> param_types{};
    bool                                any = false;
};

[[nodiscard]] CalleeInfo resolve_callee(
    const Binary& b,
    addr_t target,
    const std::map<addr_t, InferredSig>& known,
    TypeArena& arena)
{
    CalleeInfo out;
    if (const Symbol* s = b.import_at_plt(target); s) {
        const std::string_view name = strip_import_name_decorations(s->name);
        if (auto spec = lookup_import_sig(name, arena); spec) {
            for (std::size_t i = 0; i < spec->params.size() &&
                                     i < out.param_types.size(); ++i) {
                out.param_types[i] = spec->params[i];
                if (!spec->params[i].is_top()) out.any = true;
            }
        }
        // Bridge narrow-string metadata for imports not yet covered by the
        // typed signature table. Wide strings do not enter the char* lattice.
        for (u8 k = 0; k < out.charp.size(); ++k) {
            out.charp[k] = import_arg_string_kind(
                name, static_cast<u8>(k + 1)) == ImportStringKind::Narrow;
            if (out.charp[k]) out.any = true;
        }
        return out;
    }
    if (auto it = known.find(target); it != known.end()) {
        out.charp = it->second.charp;
        for (bool v : out.charp) if (v) { out.any = true; break; }
        for (std::size_t i = 0; i < it->second.params.size() &&
                                 i < out.param_types.size(); ++i) {
            out.param_types[i] = it->second.params[i];
            if (!out.param_types[i].is_top()) out.any = true;
        }
    }
    return out;
}

// For one IR function, propagate callee-arg evidence backward into our own
// param slots: each call site contributes both a charp bit (legacy fast-
// path for "this slot is char*") and a refined TypeRef per arg. Both are
// merged via meet so the most refined evidence wins across iterations.
void scan_function(const Binary& b,
                   Abi abi,
                   const IrFunction& fn,
                   const std::map<addr_t, InferredSig>& known,
                   TypeArena& arena,
                   std::array<bool, kMaxAbiIntArgs>& charp,
                   std::array<TypeRef, kMaxAbiIntArgs>& params) {
    // Index defs once per scan.
    std::map<SsaKey, const IrInst*> defs;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst); k) defs[*k] = &inst;
        }
    }

    // Walk each BB, buffering the call-args packing intrinsics so we know
    // which IrValues feed the following Call.
    for (const auto& bb : fn.blocks) {
        std::vector<IrValue> args;
        args.reserve(kMaxAbiIntArgs);
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name == "call.args.1") {
                args.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op == IrOp::Intrinsic &&
                (inst.name == "call.args.2" || inst.name == "call.args.3")) {
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i)
                    args.push_back(inst.srcs[i]);
                continue;
            }
            if (inst.op != IrOp::Call) continue;

            const CalleeInfo info = resolve_callee(b, inst.target1, known, arena);
            if (!info.any) { args.clear(); continue; }

            for (std::size_t i = 0; i < args.size() && i < info.charp.size(); ++i) {
                auto slot = trace_to_arg_slot(fn, defs, abi, args[i]);
                if (!slot || *slot >= charp.size()) continue;
                if (info.charp[i]) charp[*slot] = true;
                if (i < info.param_types.size() && !info.param_types[i].is_top()) {
                    params[*slot] = arena.meet(params[*slot], info.param_types[i]);
                }
            }
            args.clear();
        }
    }
}

// `seed_call_return_types` lives in import_sigs.cpp now so the emitter's
// per-function path can call it too without depending on the IPA module.

// Every function the CFG+call-graph can reach; called once at the top so
// the fixed-point loop can walk a stable set of entries.
std::set<addr_t> collect_entries(const Binary& b) {
    std::set<addr_t> out;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        out.insert(s.addr);
    }
    for (const auto& e : compute_call_graph(b)) {
        if (!b.import_at_plt(e.callee)) out.insert(e.callee);
    }
    return out;
}

// Translate a TypeRef from `src` arena into `dst`. Recurses on Ptr
// pointees; struct/array translation is left as future work - Phase 3 v0
// only flows scalar + pointer types.
[[nodiscard]] TypeRef translate(const TypeArena& src, TypeArena& dst, TypeRef r) {
    if (r.is_top())    return dst.top();
    if (r.is_bottom()) return dst.bottom();
    const TypeNode& n = src.node(r);
    switch (n.kind) {
        case TypeKind::Void:  return dst.void_t();
        case TypeKind::Int:   return dst.int_t(n.i.bits, n.i.sign_known, n.i.is_signed);
        case TypeKind::Float: return dst.float_t(n.f.bits);
        case TypeKind::Ptr:   return dst.ptr_t(translate(src, dst, n.p.pointee), n.p.addr_space);
        default:              return dst.top();   // structs/arrays/funcs not yet
    }
}

struct ReturnTypeValue {
    IrValue value;
    bool    widened_from_narrow = false;
    bool    is_signed           = false;
};

[[nodiscard]] std::map<SsaKey, const IrInst*>
build_defs(const IrFunction& fn) {
    std::map<SsaKey, const IrInst*> out;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (auto k = ssa_key(inst.dst); k) out[*k] = &inst;
        }
    }
    return out;
}

[[nodiscard]] ReturnTypeValue
return_type_value(const std::map<SsaKey, const IrInst*>& defs, IrValue v) {
    ReturnTypeValue out{v};
    for (int depth = 0; depth < 8; ++depth) {
        auto k = ssa_key(v);
        if (!k) break;
        auto it = defs.find(*k);
        if (it == defs.end()) break;

        const IrInst* d = it->second;
        if (d->src_count < 1) break;
        if (d->op == IrOp::Assign) {
            v = d->srcs[0];
            out.value = v;
            continue;
        }
        if ((d->op == IrOp::ZExt || d->op == IrOp::SExt) &&
            type_bits(d->srcs[0].type) <= type_bits(d->dst.type)) {
            v = d->srcs[0];
            out.value = v;
            out.widened_from_narrow = true;
            out.is_signed = d->op == IrOp::SExt;
            continue;
        }
        break;
    }
    return out;
}

[[nodiscard]] bool substantive_return_value(
    const std::map<SsaKey, const IrInst*>& defs, IrValue value,
    std::set<SsaKey>& seen, int depth = 0) {
    if (depth > 12) return false;
    auto key = ssa_key(value);
    if (!key || !seen.insert(*key).second) return false;
    auto found = defs.find(*key);
    if (found == defs.end()) return false;
    const IrInst* definition = found->second;
    if (definition->op == IrOp::Clobber) return false;
    if (definition->op == IrOp::Assign && definition->src_count >= 1) {
        return substantive_return_value(
            defs, definition->srcs[0], seen, depth + 1);
    }
    if (definition->op == IrOp::Phi) {
        bool saw_operand = false;
        for (const IrValue& operand : definition->phi_operands) {
            if (auto operand_key = ssa_key(operand); operand_key && *operand_key == *key) {
                continue;
            }
            std::set<SsaKey> branch_seen = seen;
            if (!substantive_return_value(defs, operand, branch_seen, depth + 1)) {
                return false;
            }
            saw_operand = true;
        }
        return saw_operand;
    }
    return true;
}

[[nodiscard]] TypeRef type_ref_for_ir(TypeArena& arena,
                                      IrType type,
                                      bool is_signed) {
    switch (type) {
        case IrType::I1:  return arena.int_t(1,  false, false);
        case IrType::I8:  return arena.int_t(8,  true,  is_signed);
        case IrType::I16: return arena.int_t(16, true,  is_signed);
        case IrType::I32: return arena.int_t(32, true,  is_signed);
        case IrType::I64: return arena.int_t(64, true,  is_signed);
        case IrType::F32: return arena.float_t(32);
        case IrType::F64: return arena.float_t(64);
        default:          return arena.top();
    }
}

// For one function, harvest typed return + per-arg-slot types from the
// IR's value_types side table (populated by infer_local_types). Meets
// the harvested types into `sig` via the shared `arena`.
void harvest_typed_sig(const IrFunction& fn, Abi abi,
                       TypeArena& arena, InferredSig& sig) {
    // Return type: meet of every Return-instruction's operand type.
    const auto defs = build_defs(fn);
    bool saw_return = false;
    bool saw_substantive_return = false;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Return) continue;
            saw_return = true;
            if (inst.src_count == 0) continue;
            IrValue selected = inst.srcs[0];
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                const IrValue& candidate = inst.srcs[i];
                if (!is_float_type(candidate.type)) continue;
                std::set<SsaKey> seen;
                if (substantive_return_value(defs, candidate, seen)) {
                    selected = candidate;
                    break;
                }
            }
            std::set<SsaKey> selected_seen;
            if (!substantive_return_value(defs, selected, selected_seen)) continue;
            saw_substantive_return = true;
            const ReturnTypeValue ret = return_type_value(defs, selected);
            TypeRef src_t = fn.type_of(ret.value);
            if (src_t.is_top()) {
                const TypeRef fallback = type_ref_for_ir(
                    arena, ret.value.type, ret.is_signed);
                if (!fallback.is_top()) {
                    sig.return_type = arena.meet(sig.return_type, fallback);
                }
                continue;
            }
            const TypeRef dst_t = translate(fn.types, arena, src_t);
            sig.return_type = arena.meet(sig.return_type, dst_t);
        }
    }
    if (saw_return && !saw_substantive_return) {
        sig.return_type = arena.meet(sig.return_type, arena.void_t());
    }
    // Param types: walk SSA defs once; the version-0 read of each int-arg
    // register IS the parameter, so its inferred type is the param type.
    const auto args = int_arg_regs(abi);
    for (u8 i = 0; i < args.size() && i < sig.params.size(); ++i) {
        IrValue probe = IrValue::make_reg(args[i], IrType::I64);
        probe.version = 0;
        const TypeRef src_t = fn.type_of(probe);
        if (src_t.is_top()) continue;
        const TypeRef dst_t = translate(fn.types, arena, src_t);
        sig.params[i] = arena.meet(sig.params[i], dst_t);
    }
}

// Seed the post-call ABI result lane from signatures harvested for internal
// callees. Import returns are handled by seed_call_return_types(); this closes
// the same loop for direct calls inside the binary so pointer/scalar results
// can propagate through wrappers before their caller signature is harvested.
void seed_internal_call_return_types(
    IrFunction& fn, Abi abi,
    const std::map<addr_t, InferredSig>& known,
    const TypeArena& shared_arena) {
    const auto refine = [&](const IrValue& value, TypeRef shared_type) {
        if (shared_type.is_top() || shared_type.is_bottom()) return;
        const TypeRef local_type = translate(shared_arena, fn.types, shared_type);
        if (local_type.is_top()) return;
        const u64 key = value_type_key(value);
        if (key == 0) return;
        auto [it, inserted] = fn.value_types.emplace(key, local_type);
        if (!inserted) it->second = fn.types.meet(it->second, local_type);
    };

    for (const auto& bb : fn.blocks) {
        for (std::size_t i = 0; i < bb.insts.size(); ++i) {
            const IrInst& call = bb.insts[i];
            if (call.op != IrOp::Call) continue;
            auto sig_it = known.find(call.target1);
            if (sig_it == known.end()) continue;
            const TypeRef return_type = sig_it->second.return_type;
            if (return_type.is_top() || return_type.is_bottom()) continue;
            const TypeKind kind = shared_arena.kind(return_type);
            if (kind == TypeKind::Void) continue;
            const Reg lane = kind == TypeKind::Float
                ? fp_return_reg(abi)
                : int_return_reg(abi);
            if (lane == Reg::None) continue;
            for (std::size_t j = i + 1; j < bb.insts.size(); ++j) {
                const IrInst& clobber = bb.insts[j];
                if (clobber.op != IrOp::Clobber) break;
                if (clobber.dst.kind == IrValueKind::Reg &&
                    canonical_reg(clobber.dst.reg) == canonical_reg(lane)) {
                    refine(clobber.dst, return_type);
                    break;
                }
            }
        }
    }
}

}  // namespace

InferenceResult infer_signatures(const Binary& b, IrCache* cache,
                                 std::span<const addr_t> roots) {
    InferenceResult out;
    auto& sigs = out.sigs;
    IrCache local_cache;
    IrCache& ir_cache = cache ? *cache : local_cache;
    std::vector<addr_t> entries;
    const auto all_entries = collect_entries(b);
    if (roots.empty()) {
        entries.assign(all_entries.begin(), all_entries.end());
    } else {
        const std::set<addr_t> allowed(all_entries.begin(), all_entries.end());
        std::set<addr_t> selected;
        std::vector<std::pair<addr_t, u8>> pending;
        pending.reserve(roots.size());
        for (addr_t root : roots) pending.emplace_back(root, 0);
        constexpr std::size_t kMaxScopedFunctions = 256;
        constexpr u8 kMaxScopedDepth = 3;
        while (!pending.empty() && selected.size() < kMaxScopedFunctions) {
            const auto [entry, depth] = pending.back();
            pending.pop_back();
            if (!allowed.contains(entry) || !selected.insert(entry).second) continue;
            IrFunction* ir = lift_cached(ir_cache, b, entry);
            if (!ir) continue;
            if (depth >= kMaxScopedDepth) continue;
            for (const IrBlock& block : ir->blocks) {
                for (const IrInst& inst : block.insts) {
                    if (inst.op == IrOp::Call && allowed.contains(inst.target1) &&
                        !selected.contains(inst.target1)) {
                        pending.emplace_back(inst.target1, static_cast<u8>(depth + 1));
                    }
                }
            }
        }
        entries.assign(selected.begin(), selected.end());
    }
    const Abi abi = abi_for(b.format(), b.arch(), b.endian());

    // Fixed-point: rescan every function until both the charp bitset and
    // the typed-param array stabilize. Practical cases converge in 3-5
    // iterations (call-graph diameter); the guard caps pathological cases.
    bool changed = true;
    int guard = 0;
    while (changed && guard++ < 32) {
        changed = false;
        for (addr_t fn : entries) {
            IrFunction* ir = lift_cached(ir_cache, b, fn);
            if (!ir) continue;
            auto& sig = sigs[fn];
            const auto before_charp  = sig.charp;
            const auto before_params = sig.params;
            scan_function(b, abi, *ir, sigs, out.arena, sig.charp, sig.params);
            if (sig.charp != before_charp || sig.params != before_params) {
                changed = true;
            }
        }
    }

    // Harvest typed return + params after the legacy/char* pass converges.
    // For each function, first seed the post-Call return value type for
    // every call to a known import; then run local inference (which now
    // propagates the seeded types forward), then harvest the typed
    // signature into the shared arena.
    const TypeRef char_ptr = out.arena.ptr_t(out.arena.int_t(8));
    for (addr_t fn : entries) {
        IrFunction* ir = lift_cached(ir_cache, b, fn);
        if (!ir) continue;
        seed_call_return_types(b, *ir);
        infer_local_types(*ir);
        InferredSig& sig = sigs[fn];
        harvest_typed_sig(*ir, abi, out.arena, sig);
        // Bridge legacy charp bits → typed params so the emitter's typed
        // renderer fires uniformly. Doesn't override evidence harvested
        // from local inference (meet preserves the more refined type).
        for (u8 i = 0; i < sig.params.size(); ++i) {
            if (sig.charp[i]) {
                sig.params[i] = out.arena.meet(sig.params[i], char_ptr);
            }
        }
    }

    // Phase 3.5: now that every locally-provable type is in the shared arena,
    // iterate it across the direct call graph. Parameter evidence flows from
    // callee slots back into caller live-ins; return evidence seeds the
    // caller's post-call ABI lane, then local inference and harvesting carry
    // it onward. This is intentionally bounded like the earlier char* pass.
    changed = true;
    guard = 0;
    while (changed && guard++ < 32) {
        changed = false;
        for (addr_t fn : entries) {
            IrFunction* ir = lift_cached(ir_cache, b, fn);
            if (!ir) continue;
            InferredSig& sig = sigs[fn];
            const InferredSig before = sig;
            scan_function(b, abi, *ir, sigs, out.arena,
                          sig.charp, sig.params);
            seed_internal_call_return_types(*ir, abi, sigs, out.arena);
            infer_local_types(*ir);
            harvest_typed_sig(*ir, abi, out.arena, sig);
            for (u8 i = 0; i < sig.params.size(); ++i) {
                if (sig.charp[i]) {
                    sig.params[i] = out.arena.meet(sig.params[i], char_ptr);
                }
            }
            if (sig.charp != before.charp || sig.params != before.params ||
                sig.return_type != before.return_type) {
                changed = true;
            }
        }
    }
    return out;
}

}  // namespace spelunk
