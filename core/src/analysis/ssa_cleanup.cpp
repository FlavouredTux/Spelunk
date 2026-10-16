#include <spelunk/analysis/ssa_cleanup.hpp>

#include <algorithm>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk {

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
        default: {
            auto ak = ssa_key(a);
            auto bk = ssa_key(b);
            return ak && bk && *ak == *bk;
        }
    }
}

using Position = std::pair<std::size_t, std::size_t>;

// A loop-carried value such as `next = p->next` usually also feeds the loop
// test and the exit path, so it is not a pure Phi feeder. It can still share
// the Phi's local when the two never interfere: once `feeder` is defined, no
// path back to the Phi block reads an old Phi value, and every other read of
// `feeder` happens on such a path. Without this, the back-edge update was
// dropped and `p = p->next` vanished from the loop.
//
// Reads after the feeder may still reach the old value through an earlier,
// inlined definition (`p->key` loaded before the update but consumed after
// it). Loads on that path are added to `snapshot_loads` so the emitter binds
// them where they are defined; any other such dependence rejects the merge.
[[nodiscard]] bool feeder_replaces_dead_phi(const IrFunction& fn, const IrInst& phi,
                                            addr_t phi_block, const SsaKey& feeder,
                                            const std::set<SsaKey>& phi_keys,
                                            const std::map<SsaKey, Position>& definitions,
                                            std::set<SsaKey>& snapshot_loads) {
    const auto feeder_definition = definitions.find(feeder);
    if (feeder_definition == definitions.end()) return false;
    const auto [def_bi, def_ii] = feeder_definition->second;
    // The feeder must arrive over its own block's edge into the Phi block.
    bool own_edge = false;
    for (std::size_t i = 0; i < phi.phi_operands.size() && i < phi.phi_preds.size(); ++i) {
        own_edge |= ssa_key(phi.phi_operands[i]) == feeder &&
                    phi.phi_preds[i] == fn.blocks[def_bi].start;
    }
    if (!own_edge) return false;
    // Only back edges: forward joins keep their existing pure-feeder rule.
    {
        std::set<addr_t> seen;
        std::vector<addr_t> work{phi_block};
        bool loops = false;
        while (!work.empty() && !loops) {
            const addr_t address = work.back();
            work.pop_back();
            if (!seen.insert(address).second) continue;
            const auto found = fn.block_at.find(address);
            if (found == fn.block_at.end()) continue;
            loops = found->second == def_bi;
            const auto& successors = fn.blocks[found->second].successors;
            work.insert(work.end(), successors.begin(), successors.end());
        }
        if (!loops) return false;
    }

    // Everything reachable after the feeder without re-entering the Phi
    // block. Phi operands are read on the incoming edge, so they belong to
    // the region of their predecessor.
    std::set<Position> region;
    std::vector<IrValue> edge_reads;
    std::set<std::size_t> visited;
    std::vector<Position> pending{{def_bi, def_ii + 1}};
    while (!pending.empty()) {
        const auto [bi, first] = pending.back();
        pending.pop_back();
        const auto& block = fn.blocks[bi];
        for (std::size_t ii = first; ii < block.insts.size(); ++ii) {
            if (block.insts[ii].op != IrOp::Phi) region.insert({bi, ii});
        }
        for (addr_t successor : block.successors) {
            const auto found = fn.block_at.find(successor);
            if (found == fn.block_at.end()) continue;  // tail call or exit
            for (const auto& inst : fn.blocks[found->second].insts) {
                if (inst.op != IrOp::Phi || &inst == &phi) continue;
                const auto joined = ssa_key(inst.dst);
                for (std::size_t i = 0; i < inst.phi_operands.size() && i < inst.phi_preds.size(); ++i) {
                    if (inst.phi_preds[i] != block.start) continue;
                    // A Phi of the same local re-established here must take
                    // the feeder, or the local changes under its later reads.
                    if (joined && phi_keys.contains(*joined) &&
                        ssa_key(inst.phi_operands[i]) != feeder) return false;
                    edge_reads.push_back(inst.phi_operands[i]);
                }
            }
            if (successor == phi_block) {
                // Another incoming edge may carry its own assignment.
                if (bi != def_bi) return false;
                continue;
            }
            if (!visited.insert(found->second).second) continue;
            pending.push_back({found->second, 0});
        }
    }

    std::set<SsaKey> captures;
    std::set<SsaKey> checked;
    // True when reading `value` inside the region cannot observe the
    // overwritten Phi value, recording loads that must bind early.
    const auto safe_read = [&](const auto& self, const IrValue& value, int depth) -> bool {
        const auto key = ssa_key(value);
        if (!key || *key == feeder) return true;
        if (phi_keys.contains(*key)) {
            // Only a Phi joined after the feeder holds the current value.
            const auto found = definitions.find(*key);
            return found != definitions.end() && visited.contains(found->second.first);
        }
        if (!checked.insert(*key).second) return true;
        const auto found = definitions.find(*key);
        if (found == definitions.end() || region.contains(found->second)) return true;
        if (depth > 32) return false;
        const IrInst& definition = fn.blocks[found->second.first].insts[found->second.second];
        if (definition.op == IrOp::Phi) return true;  // a different, still-live value
        bool depends = false;
        for (u8 i = 0; i < definition.src_count; ++i) {
            if (definition.op == IrOp::Load) {
                // Only the address matters; the result is captured.
                std::set<SsaKey> saved = checked;
                const bool clean = self(self, definition.srcs[i], depth + 1);
                checked = std::move(saved);
                depends |= !clean;
            } else if (!self(self, definition.srcs[i], depth + 1)) {
                return false;
            }
        }
        if (depends) captures.insert(*key);
        return true;
    };
    std::size_t feeder_reads_in_region = 0;
    for (const auto& [bi, ii] : region) {
        const IrInst& inst = fn.blocks[bi].insts[ii];
        for (u8 i = 0; i < inst.src_count; ++i) {
            feeder_reads_in_region += ssa_key(inst.srcs[i]) == feeder;
            if (!safe_read(safe_read, inst.srcs[i], 0)) return false;
        }
    }
    for (const auto& value : edge_reads) {
        feeder_reads_in_region += ssa_key(value) == feeder;
        if (!safe_read(safe_read, value, 0)) return false;
    }
    std::size_t feeder_reads = 0;
    for (const auto& block : fn.blocks) {
        for (const auto& inst : block.insts) {
            if (&inst == &phi) continue;
            for (u8 i = 0; i < inst.src_count; ++i) feeder_reads += ssa_key(inst.srcs[i]) == feeder;
            for (const auto& value : inst.phi_operands) feeder_reads += ssa_key(value) == feeder;
        }
    }
    if (feeder_reads != feeder_reads_in_region) return false;
    snapshot_loads.insert(captures.begin(), captures.end());
    return true;
}

// Whether `key` (a Phi joined at `home`) can be read once control reaches
// `join` without first passing back through `home`.
[[nodiscard]] bool phi_live_at(const IrFunction& fn, const SsaKey& key,
                               addr_t home, addr_t join) {
    if (home == join) return true;
    std::set<addr_t> seen;
    std::vector<addr_t> work{join};
    while (!work.empty()) {
        const addr_t address = work.back();
        work.pop_back();
        if (address == home || !seen.insert(address).second) continue;
        const auto found = fn.block_at.find(address);
        if (found == fn.block_at.end()) continue;
        const auto& block = fn.blocks[found->second];
        for (const auto& inst : block.insts) {
            for (u8 i = 0; i < inst.src_count; ++i) {
                if (ssa_key(inst.srcs[i]) == key) return true;
            }
        }
        for (addr_t successor : block.successors) {
            const auto next = fn.block_at.find(successor);
            if (next == fn.block_at.end()) continue;
            const auto& phis = fn.blocks[next->second].insts;
            for (const auto& inst : phis) {
                if (inst.op != IrOp::Phi) continue;
                for (std::size_t i = 0; i < inst.phi_operands.size() && i < inst.phi_preds.size(); ++i) {
                    if (inst.phi_preds[i] == address && ssa_key(inst.phi_operands[i]) == key) return true;
                }
            }
            work.push_back(successor);
        }
    }
    return false;
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
    std::map<SsaKey, addr_t> phi_block;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Phi) continue;
            auto k = ssa_key(inst.dst);
            if (!k || callbacks.use_count(*k) == 0) continue;
            phi_defs.emplace(*k, &inst);
            phi_block.emplace(*k, bb.start);
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

    // Phis fed by the same value on different edges (a loop header and its
    // exit join both taking the updated accumulator) are one source variable
    // when neither is read where the other is joined.
    std::map<SsaKey, std::vector<SsaKey>> phis_by_operand;
    for (const auto& [k, inst] : phi_defs) {
        for (const auto& op : inst->phi_operands) {
            auto ok = ssa_key(op);
            const IrInst* od = callbacks.def_of(op);
            if (!ok || phi_defs.contains(*ok) || !od || od->op == IrOp::Phi ||
                od->op == IrOp::Clobber) continue;
            auto& sharing = phis_by_operand[*ok];
            if (std::ranges::find(sharing, k) == sharing.end()) sharing.push_back(k);
        }
    }
    for (const auto& [_, sharing] : phis_by_operand) {
        bool disjoint = sharing.size() > 1;
        for (std::size_t i = 0; i < sharing.size() && disjoint; ++i) {
            for (std::size_t j = i + 1; j < sharing.size() && disjoint; ++j) {
                const auto& a = sharing[i];
                const auto& b = sharing[j];
                disjoint = callbacks.type_name(phi_defs.at(a)->dst) ==
                               callbacks.type_name(phi_defs.at(b)->dst) &&
                           !phi_live_at(fn, a, phi_block.at(a), phi_block.at(b)) &&
                           !phi_live_at(fn, b, phi_block.at(b), phi_block.at(a));
            }
        }
        if (!disjoint) continue;
        for (std::size_t i = 1; i < sharing.size(); ++i) unite(sharing[0], sharing[i]);
    }

    std::map<SsaKey, Position> definitions;
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const auto& insts = fn.blocks[bi].insts;
        for (std::size_t ii = 0; ii < insts.size(); ++ii) {
            if (auto key = ssa_key(insts[ii].dst)) definitions.emplace(*key, Position{bi, ii});
        }
    }

    std::map<SsaKey, std::vector<SsaKey>> groups;
    for (const auto& k : phi_keys) {
        groups[find_root(k, find_root)].push_back(k);
    }

    std::set<std::string> used;
    for (const auto& [_, keys] : groups) {
        std::set<SsaKey> group_keys(keys.begin(), keys.end());
        bool saw_initializer_only_operand = false;
        bool all_operands_same_initializer = true;
        std::optional<IrValue> common_initializer;
        for (const auto& k : keys) {
            const auto phi_it = phi_defs.find(k);
            const auto* phi = phi_it != phi_defs.end() ? phi_it->second : nullptr;
            if (!phi) continue;
            for (const auto& op : phi->phi_operands) {
                if (auto ok = ssa_key(op); ok) {
                    if (group_keys.contains(*ok)) continue;
                    if (phi_defs.contains(*ok)) {
                        all_operands_same_initializer = false;
                        break;
                    }
                }
                auto candidate = callbacks.initializer_candidate(op);
                if (!candidate) {
                    all_operands_same_initializer = false;
                    break;
                }
                saw_initializer_only_operand = true;
                if (!common_initializer) {
                    common_initializer = *candidate;
                } else if (!same_literal_or_livein_value(*common_initializer,
                                                        *candidate)) {
                    all_operands_same_initializer = false;
                    break;
                }
            }
            if (!all_operands_same_initializer) break;
        }
        if (saw_initializer_only_operand && all_operands_same_initializer) {
            continue;
        }

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
                if (callbacks.use_count(*ok) != 1) {
                    // A loop-carried accumulator can also be consumed at an
                    // exit (e.g. store the decoded varint). Coalescing its
                    // update is safe when the old Phi value is read only by
                    // that update, so no use needs the pre-update value.
                    const bool arithmetic = od->op == IrOp::Add || od->op == IrOp::Sub ||
                        od->op == IrOp::Mul || od->op == IrOp::And ||
                        od->op == IrOp::Or || od->op == IrOp::Xor;
                    bool in_place = false;
                    if (arithmetic && keys.size() == 1 && callbacks.use_count(keys[0]) == 1) {
                        for (u8 i = 0; i < od->src_count; ++i)
                            in_place |= ssa_key(od->srcs[i]) == keys[0];
                    }
                    if (!in_place &&
                        !feeder_replaces_dead_phi(fn, *phi, phi_block.at(k), *ok, group_keys,
                                                  definitions, result.snapshot_loads)) continue;
                }
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

}  // namespace spelunk
