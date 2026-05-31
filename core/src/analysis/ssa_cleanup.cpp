#include <ember/analysis/ssa_cleanup.hpp>

#include <format>
#include <set>
#include <utility>

namespace ember {

std::string_view base_name_for(SsaMergeLocalRole role) noexcept {
    switch (role) {
        case SsaMergeLocalRole::Result:      return "result";
        case SsaMergeLocalRole::Induction:   return "i";
        case SsaMergeLocalRole::Index:       return "idx";
        case SsaMergeLocalRole::Accumulator: return "acc";
        case SsaMergeLocalRole::Pointer:     return "ptr";
        case SsaMergeLocalRole::String:      return "str";
        case SsaMergeLocalRole::Flag:        return "flag";
        case SsaMergeLocalRole::Value:       return "value";
    }
    return "value";
}

namespace {

[[nodiscard]] std::string unique_merge_name(SsaMergeLocalRole role,
                                            std::set<std::string>& used) {
    const std::string base{base_name_for(role)};
    std::string name = base.empty() ? std::string{"value"} : base;
    for (u32 n = 2; used.contains(name); ++n) {
        name = std::format("{}_{}", base, n);
    }
    used.insert(name);
    return name;
}

[[nodiscard]] bool same_literal_or_livein_value(const IrValue& a,
                                                const IrValue& b) {
    if (a.kind != b.kind || a.type != b.type) return false;
    switch (a.kind) {
        case IrValueKind::Imm:
            return a.imm == b.imm;
        case IrValueKind::Reg:
            return canonical_reg(a.reg) == canonical_reg(b.reg) &&
                   a.version == b.version;
        default:
            return false;
    }
}

}  // namespace

SsaMergeLocalRecoveryResult
recover_ssa_merge_locals(const IrFunction& fn,
                         const SsaMergeLocalRecoveryCallbacks& callbacks) {
    SsaMergeLocalRecoveryResult result;
    if (!callbacks.use_count || !callbacks.def_of || !callbacks.type_name ||
        !callbacks.role_for_phi || !callbacks.initializer_candidate) {
        return result;
    }

    std::vector<SsaKey> phi_keys;
    std::map<SsaKey, const IrInst*> phi_defs;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) continue;
            auto k = ssa_key(inst.dst);
            if (!k || callbacks.use_count(*k) == 0) continue;
            phi_defs.emplace(*k, &inst);
            phi_keys.push_back(*k);
        }
    }
    if (phi_keys.empty()) return result;

    std::map<SsaKey, SsaKey> parent;
    for (const auto& k : phi_keys) parent.emplace(k, k);
    auto find_root = [&](const SsaKey& k, auto& self) -> SsaKey {
        auto it = parent.find(k);
        if (it == parent.end() || it->second == k) return k;
        it->second = self(it->second, self);
        return it->second;
    };
    auto unite = [&](const SsaKey& a, const SsaKey& b) {
        auto ra = find_root(a, find_root);
        auto rb = find_root(b, find_root);
        if (ra == rb) return;
        parent[rb] = ra;
    };
    for (const auto& [k, inst] : phi_defs) {
        for (const auto& op : inst->phi_operands) {
            auto ok = ssa_key(op);
            if (!ok || !phi_defs.contains(*ok)) continue;
            const IrInst* od = callbacks.def_of(op);
            if (od && od->op == IrOp::Phi &&
                callbacks.type_name(od->dst) == callbacks.type_name(inst->dst)) {
                unite(k, *ok);
            }
        }
    }

    std::map<SsaKey, std::vector<SsaKey>> groups;
    for (const auto& k : phi_keys) {
        groups[find_root(k, find_root)].push_back(k);
    }

    std::set<std::string> used;
    for (const auto& [_, keys] : groups) {
        const IrInst* best = nullptr;
        for (const auto& k : keys) {
            auto it = phi_defs.find(k);
            if (it == phi_defs.end()) continue;
            best = it->second;
            if (callbacks.role_for_phi(*best) != SsaMergeLocalRole::Value) break;
        }
        if (!best) continue;

        const SsaMergeLocalRole role = callbacks.role_for_phi(*best);
        const std::string name = unique_merge_name(role, used);
        SsaMergeLocal local;
        local.name = name;
        local.role = role;
        local.type_value = best->dst;
        local.keys = keys;

        for (const auto& k : keys) result.value_names.emplace(k, name);
        for (const auto& k : keys) {
            const auto phi_it = phi_defs.find(k);
            const auto* phi = phi_it != phi_defs.end() ? phi_it->second : nullptr;
            if (!phi) continue;
            for (const auto& op : phi->phi_operands) {
                auto ok = ssa_key(op);
                if (!ok || phi_defs.contains(*ok)) continue;
                if (result.value_names.contains(*ok)) continue;
                const IrInst* od = callbacks.def_of(op);
                if (!od || od->op == IrOp::Phi || od->op == IrOp::Clobber) continue;
                if (callbacks.type_name(od->dst) != callbacks.type_name(best->dst)) continue;
                // Only remap pure phi-feeder values. If a value also appears
                // in real emitted code, keeping its original name avoids
                // coalescing two source variables by guess.
                if (callbacks.use_count(*ok) != 1) continue;
                result.value_names.emplace(*ok, name);
                local.keys.push_back(*ok);
            }
        }

        std::optional<IrValue> init;
        bool ambiguous_init = false;
        for (const auto& k : keys) {
            const auto phi_it = phi_defs.find(k);
            const auto* phi = phi_it != phi_defs.end() ? phi_it->second : nullptr;
            if (!phi) continue;
            for (const auto& op : phi->phi_operands) {
                if (auto ok = ssa_key(op);
                    ok && result.value_names.contains(*ok)) {
                    continue;
                }
                auto candidate = callbacks.initializer_candidate(op);
                if (!candidate) continue;
                if (!init) {
                    init = *candidate;
                } else if (!same_literal_or_livein_value(*init, *candidate)) {
                    ambiguous_init = true;
                    break;
                }
            }
            if (ambiguous_init) break;
        }
        if (init && !ambiguous_init) {
            local.initializer = *init;
        }
        result.locals.emplace(name, std::move(local));
    }

    return result;
}

}  // namespace ember
