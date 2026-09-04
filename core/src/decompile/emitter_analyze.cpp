// Pre-pass over the IR: use counts, merge naming, definite assignment.
#include <algorithm>
#include <cstddef>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <ember/analysis/arity.hpp>
#include <ember/analysis/cfg_util.hpp>
#include <ember/analysis/ssa_cleanup.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

#include "emitter_internal.hpp"

namespace ember::emit {

void Emitter::record_x86_string_intrinsic_extents(const IrInst& inst) {
    if (inst.op != IrOp::Intrinsic || inst.src_count < 3) return;
    const bool copy = inst.name == "rep.movsb" ||
                      inst.name == "rep.movsd" ||
                      inst.name == "rep.movsq";
    const bool fill = inst.name == "rep.stosb" ||
                      inst.name == "rep.stosd" ||
                      inst.name == "rep.stosq";
    if (!copy && !fill) return;
    const u64 element_size = inst.name.ends_with('b') ? 1u
        : (inst.name.ends_with('d') ? 4u : 8u);
    const auto count = resolve_imm(inst.srcs[2]);
    if (!count || *count <= 0 ||
        static_cast<u64>(*count) > (1u << 20) / element_size) return;
    const u32 bytes = static_cast<u32>(
        static_cast<u64>(*count) * element_size);
    const auto record = [&](const IrValue& address) {
        if (auto offset = stack_offset(address); offset) {
            auto& extent = stack_required_extents[*offset];
            extent = std::max(extent, bytes);
        }
    };
    record(inst.srcs[0]);
    if (copy) record(inst.srcs[1]);
}

void Emitter::analyze_msvc_security_cookie_calls() {
    if (!fn || abi != Abi::Win64) return;
    const Reg return_reg = canonical_reg(int_return_reg(abi));
    const auto is_rsp = [&](const IrValue& value) {
        if (value.kind == IrValueKind::Reg &&
            canonical_reg(value.reg) == Reg::Rsp) return true;
        // Optimization forwards the adjusted stack pointer through its
        // defining Sub/Add temp, so the XOR often reads `t5` rather than
        // an architectural `rsp_N` leaf. stack_offset recognizes both.
        const IrInst* definition = def_stripped(value);
        return (!definition || definition->op != IrOp::Load) &&
               stack_offset(value).has_value();
    };
    const auto cookie_stack_load = [&](const IrValue& value)
        -> std::optional<i64> {
        const IrInst* x = def_stripped(value);
        if (!x || x->op != IrOp::Xor || x->src_count < 2) return std::nullopt;
        for (u8 side = 0; side < 2; ++side) {
            if (!is_rsp(x->srcs[1 - side])) continue;
            const IrInst* load = def_stripped(x->srcs[side]);
            if (!load || load->op != IrOp::Load || load->src_count < 1) continue;
            if (auto offset = stack_offset(load->srcs[0]); offset) return offset;
        }
        return std::nullopt;
    };
    for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
        const auto& block = fn->blocks[bi];
        for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
            const IrInst& call = block.insts[ii];
            if (call.op != IrOp::Call || call.source_addr == 0) continue;

            const IrValue* first_arg = nullptr;
            for (std::size_t scan = ii; scan > 0;) {
                const IrInst& previous = block.insts[--scan];
                if (previous.op == IrOp::Intrinsic &&
                    previous.name == "call.args.1" && previous.src_count >= 1) {
                    first_arg = &previous.srcs[0];
                    break;
                }
                if (previous.op == IrOp::Call ||
                    previous.op == IrOp::CallIndirect) break;
            }
            if (!first_arg) continue;
            const auto cookie_offset = cookie_stack_load(*first_arg);
            if (!cookie_offset) continue;

            suppressed_call_positions.insert({bi, ii});
            hidden.insert({bi, ii});

            std::optional<IrValue> preserved;
            for (std::size_t scan = ii; scan > 0;) {
                const IrInst& previous = block.insts[--scan];
                if (previous.dst.kind != IrValueKind::Reg ||
                    canonical_reg(previous.dst.reg) != return_reg) continue;
                if (previous.op != IrOp::Clobber) preserved = previous.dst;
                break;
            }
            for (std::size_t scan = ii + 1; scan < block.insts.size(); ++scan) {
                const IrInst& clobber = block.insts[scan];
                if (clobber.op != IrOp::Clobber) break;
                if (clobber.dst.kind != IrValueKind::Reg ||
                    canonical_reg(clobber.dst.reg) != return_reg) continue;
                if (auto key = ssa_key(clobber.dst); key) {
                    msvc_cookie_return_clobbers.insert(*key);
                    if (preserved) {
                        msvc_cookie_preserved_returns.emplace(*key, *preserved);
                    }
                }
                break;
            }
        }
    }
}

void Emitter::analyze(const IrFunction& f) {
    fn = &f;
    ssa_uses.reset();
    for (std::size_t bi = 0; bi < f.blocks.size(); ++bi) {
        const auto& bb = f.blocks[bi];
        for (std::size_t ii = 0; ii < bb.insts.size(); ++ii) {
            const auto& inst = bb.insts[ii];
            // Some analysis performed here follows definitions. Observe the
            // current instruction afterward so forward definitions remain
            // unavailable, matching the emitter's original scan order.
            record_x86_string_intrinsic_extents(inst);
            ssa_uses.observe(inst, {bi, ii});
        }
    }
    analyze_msvc_security_cookie_calls();
    analyze_abi_noise();
    ssa_uses.scan_visible(f, hidden);
    // Preserve the time at which a load happened. SSA versions registers
    // but not memory, so blindly inlining a load after a call/store can
    // change its meaning. Follow only transparent value aliases; any
    // cross-block use or intervening memory barrier forces a snapshot.
    const auto transparent_alias = [](const IrInst& inst) noexcept {
        return inst.op == IrOp::Assign || inst.op == IrOp::ZExt ||
               inst.op == IrOp::SExt || inst.op == IrOp::Trunc;
    };
    const auto rpo = compute_rpo(f);
    std::unordered_map<addr_t, std::size_t> rpo_index;
    rpo_index.reserve(rpo.size());
    for (std::size_t i = 0; i < rpo.size(); ++i) rpo_index.emplace(rpo[i], i);
    const auto idom = compute_idoms(f, rpo, rpo_index);
    const auto block_dominates = [&](addr_t dominator, addr_t node) {
        for (;;) {
            if (node == dominator) return true;
            auto parent = idom.find(node);
            if (parent == idom.end() || parent->second == node) return false;
            node = parent->second;
        }
    };
    for (u32 def_bi = 0; is_ppc_abi() && def_bi < f.blocks.size(); ++def_bi) {
        const auto& def_bb = f.blocks[def_bi];
        for (u32 def_ii = 0; def_ii < def_bb.insts.size(); ++def_ii) {
            const IrInst& load = def_bb.insts[def_ii];
            if (load.op != IrOp::Load) continue;
            auto load_key = ssa_key(load.dst);
            if (!load_key) continue;
            const auto store_may_alias_load = [&](const IrInst& store) {
                if (store.op != IrOp::Store || store.src_count < 1 ||
                    load.src_count < 1) return false;
                const auto load_stack = stack_offset(load.srcs[0]);
                const auto store_stack = stack_offset(store.srcs[0]);
                const auto load_absolute = try_resolve_imm_addr(load.srcs[0]);
                const auto store_absolute = try_resolve_imm_addr(store.srcs[0]);
                const u32 load_bytes = std::max(1u, type_bits(load.dst.type) / 8u);
                const IrType stored_type = store.src_count >= 2
                    ? store.srcs[1].type : IrType::I8;
                const u32 store_bytes = std::max(1u, type_bits(stored_type) / 8u);
                const auto overlaps = [](i64 a, u32 a_size, i64 b, u32 b_size) {
                    return a < b + static_cast<i64>(b_size) &&
                           b < a + static_cast<i64>(a_size);
                };
                if (load_stack && store_stack) {
                    return overlaps(*load_stack, load_bytes,
                                    *store_stack, store_bytes);
                }
                if (load_absolute && store_absolute) {
                    return overlaps(*load_absolute, load_bytes,
                                    *store_absolute, store_bytes);
                }
                const auto load_access = canonical_struct_access(load.srcs[0]);
                const auto store_access = canonical_struct_access(store.srcs[0]);
                if (load_access && store_access) {
                    const auto load_root = ssa_key(load_access->first);
                    const auto store_root = ssa_key(store_access->first);
                    if (load_root && store_root && *load_root == *store_root) {
                        return overlaps(load_access->second, load_bytes,
                                        store_access->second, store_bytes);
                    }
                }
                // A proven stack address and a proven absolute object
                // cannot alias.
                if ((load_stack && store_absolute) ||
                    (load_absolute && store_stack)) return false;
                // Distinct unresolved pointer roots are not enough to
                // prove an alias. Calls remain conservative barriers;
                // unrelated copy-loop stores should not explode every
                // source load into a one-use scalar temporary.
                return false;
            };
            const auto is_memory_barrier = [&](const IrInst& inst) {
                return inst.op == IrOp::Call || inst.op == IrOp::CallIndirect ||
                       store_may_alias_load(inst);
            };

            std::set<SsaKey> seen;
            std::deque<SsaKey> pending{*load_key};
            bool snapshot = false;
            while (!pending.empty() && !snapshot) {
                const SsaKey key = pending.front();
                pending.pop_front();
                if (!seen.insert(key).second) continue;
                const auto users = ssa_uses.semantic_user_positions(key);
                for (const auto& [use_bi, use_ii] : users) {
                    if (use_bi != def_bi || use_ii <= def_ii) {
                        if (use_bi < f.blocks.size() &&
                            block_dominates(def_bb.start,
                                            f.blocks[use_bi].start)) {
                            snapshot = true;
                            break;
                        }
                        // Across blocks, use machine-address order as a
                        // conservative CodeWarrior snapshot witness. This
                        // catches entry-block saves restored after a later
                        // memset/call without materializing ordinary phi
                        // fallback loads (which have no intervening call).
                        const IrInst& user = f.blocks[use_bi].insts[use_ii];
                        if (load.source_addr != 0 &&
                            user.source_addr > load.source_addr) {
                            for (const auto& candidate_block : f.blocks) {
                                for (const IrInst& candidate : candidate_block.insts) {
                                    if (candidate.source_addr <= load.source_addr ||
                                        candidate.source_addr >= user.source_addr) {
                                        continue;
                                    }
                                    if (candidate.op == IrOp::Call ||
                                        candidate.op == IrOp::CallIndirect ||
                                        store_may_alias_load(candidate)) {
                                        snapshot = true;
                                        break;
                                    }
                                }
                                if (snapshot) break;
                            }
                        }
                        if (snapshot) break;
                        continue;
                    }
                    for (u32 between = def_ii + 1; between < use_ii; ++between) {
                        if (is_memory_barrier(def_bb.insts[between])) {
                            snapshot = true;
                            break;
                        }
                    }
                    if (snapshot) break;
                    const IrInst& user = def_bb.insts[use_ii];
                    if (transparent_alias(user)) {
                        if (auto next = ssa_key(user.dst); next) {
                            pending.push_back(*next);
                        }
                    }
                }
            }
            if (snapshot) memory_snapshot_loads.insert(*load_key);
        }
    }
    // Stack slots that are loaded from somewhere in the function. A
    // store whose address resolves to a slot NOT in this set is a dead
    // spill - at -O0 the compiler routinely emits `mov [rbp-N], reg`
    // for an arg even when the slot is never read, and we want those
    // suppressed in the pseudo-C output. The set is keyed by the slot
    // offset returned by `stack_offset(addr)` so it lines up with the
    // emitter's own naming for `local_<hex>` lvalues.
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Load || inst.src_count < 1) continue;
            if (inst.segment != Reg::None) continue;
            if (auto off = stack_offset(inst.srcs[0]); off) {
                loaded_stack_slots.insert(*off);
            }
        }
    }
    // Init-only slot detection. A slot is "init-only" if it has exactly
    // one Store across the whole function and the stored value is an
    // unmodified arg-reg live-in (version 0). All loads of that slot
    // forward to the live-in name (a1, a2, …) directly, so an -O0
    // `mov [rbp-N], rdi; ... mov reg, [rbp-N]; use reg` collapses to
    // a single use of the parameter - the way the user wrote it.
    //
    // The store's block doesn't have to be the entry: a spill that
    // sits inside the only conditional path that ever reads the slot
    // is just as safe (any path that bypasses the write would be
    // reading uninitialised storage, which is undefined-behaviour
    // territory we don't owe the user a friendly rendering for).
    std::map<i64, int>     slot_write_count;
    std::map<i64, IrValue> slot_first_write_value;
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Store || inst.src_count < 2) continue;
            if (inst.segment != Reg::None) continue;
            auto off = stack_offset(inst.srcs[0]);
            if (!off) continue;
            if (++slot_write_count[*off] == 1) {
                slot_first_write_value[*off] = inst.srcs[1];
            }
        }
    }
    for (const auto& [off, count] : slot_write_count) {
        if (count != 1) continue;
        const IrValue& v = slot_first_write_value[off];
        single_write_slot_value.emplace(off, v);
        // Forward live-in args (rdi/rsi/...) and SSA temps directly:
        // both have a single dominating def that survives unchanged
        // from the store to any later load. Skip clobbers (call-
        // returns) - those represent post-call register state and
        // re-rendering them at every load would duplicate the call
        // expression where the user wrote a single named local.
        const bool is_live_in_arg =
            v.kind == IrValueKind::Reg && v.version == 0;
        const bool is_temp = v.kind == IrValueKind::Temp;
        if (!is_live_in_arg && !is_temp) continue;
        if (is_temp) {
            auto k = ssa_key(v);
            if (!k) continue;
            const IrInst* definition = ssa_uses.definition(*k);
            if (!definition) continue;
            // Forwarding a memory Load through its one-write stack slot
            // loses the time at which the value was captured. A later
            // reload after memset/calls would be printed as a fresh read
            // from the mutated source object. Keep the stack local for
            // Load producers; pure computed temps remain safe to forward.
            if (definition->op == IrOp::Clobber ||
                (is_ppc_abi() && definition->op == IrOp::Load)) continue;
        }
        init_only_slot_value.emplace(off, v);
    }
    // Second scan: after defs/uses are populated (so def_stripped works),
    // collect offsets for every pointer that participates in loads/stores.
    // A base observed at multiple distinct offsets is treated as a struct
    // pointer in format_mem.
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Load && inst.src_count >= 1 &&
                inst.segment == Reg::None) {
                record_struct_access(inst.srcs[0], inst.dst.type);
            } else if (inst.op == IrOp::Store && inst.src_count >= 1 &&
                       inst.segment == Reg::None) {
                const IrType store_type = inst.src_count >= 2
                    ? inst.srcs[1].type
                    : IrType::I64;
                record_struct_access(inst.srcs[0], store_type);
            }
        }
    }
}

bool Emitter::phi_value_feeds_step(const SsaKey& k,
                                   bool* non_unit_accum) const {
    if (non_unit_accum) *non_unit_accum = false;
    const auto users = ssa_uses.visible_user_positions(k);
    bool unit_step = false;
    for (const auto& [bi, ii] : users) {
        if (bi >= fn->blocks.size() || ii >= fn->blocks[bi].insts.size()) continue;
        const IrInst& inst = fn->blocks[bi].insts[ii];
        if (inst.src_count < 2) continue;
        if (inst.op != IrOp::Add && inst.op != IrOp::Sub) continue;
        const auto lhs = ssa_key(inst.srcs[0]);
        const auto rhs = ssa_key(inst.srcs[1]);
        const bool lhs_is_phi = lhs && *lhs == k;
        const bool rhs_is_phi = rhs && *rhs == k;
        if (!lhs_is_phi && !rhs_is_phi) continue;
        const IrValue& other = lhs_is_phi ? inst.srcs[1] : inst.srcs[0];
        if (other.kind == IrValueKind::Imm && (other.imm == 1 || other.imm == -1)) {
            unit_step = true;
        } else if (non_unit_accum) {
            *non_unit_accum = true;
        }
    }
    return unit_step;
}

bool Emitter::value_flows_to_memory_address(const SsaKey& k,
                                            std::set<SsaKey>& seen,
                                            int depth,
                                            bool follow_assigns) const {
    if (depth > 6 || !seen.insert(k).second) return false;
    const auto users = ssa_uses.visible_user_positions(k);
    for (const auto& [bi, ii] : users) {
        if (bi >= fn->blocks.size() || ii >= fn->blocks[bi].insts.size()) continue;
        const IrInst& inst = fn->blocks[bi].insts[ii];
        if ((inst.op == IrOp::Load || inst.op == IrOp::Store) &&
            inst.src_count >= 1 && ssa_key(inst.srcs[0]) == k) {
            return true;
        }
        const bool address_arith =
            inst.op == IrOp::Add || inst.op == IrOp::Sub ||
            inst.op == IrOp::Mul || inst.op == IrOp::Shl ||
            inst.op == IrOp::ZExt || inst.op == IrOp::SExt ||
            (follow_assigns && inst.op == IrOp::Assign);
        if (!address_arith) continue;
        auto dk = ssa_key(inst.dst);
        if (!dk) continue;
        if (value_flows_to_memory_address(*dk, seen, depth + 1,
                                          follow_assigns)) return true;
    }
    return false;
}

bool Emitter::phi_value_feeds_indexing(const SsaKey& k) const {
    std::set<SsaKey> seen;
    return value_flows_to_memory_address(k, seen);
}

SsaMergeLocalRole Emitter::merge_role_for_phi(const IrInst& inst) const {
    auto k = ssa_key(inst.dst);
    bool accumulator = false;
    const bool unit_step = k && phi_value_feeds_step(*k, &accumulator);
    if (unit_step && k && phi_value_feeds_indexing(*k)) {
        return SsaMergeLocalRole::Index;
    }
    if (unit_step) return SsaMergeLocalRole::Induction;
    if (inst.dst.kind == IrValueKind::Reg &&
        canonical_reg(inst.dst.reg) == int_return_reg(abi)) {
        return SsaMergeLocalRole::Result;
    }
    const std::string type_name = c_type_name_for(inst.dst);
    if (type_name == "char*") return SsaMergeLocalRole::String;
    if (!type_name.empty() && type_name.ends_with("*")) return SsaMergeLocalRole::Pointer;
    if (inst.dst.type == IrType::I1) return SsaMergeLocalRole::Flag;
    if (accumulator) return SsaMergeLocalRole::Accumulator;
    return SsaMergeLocalRole::Value;
}

std::optional<IrValue>
Emitter::merge_initializer_candidate(const IrValue& op) const {
    if (op.kind == IrValueKind::Imm) return op;
    if (auto slot = trace_to_self_arg_slot(op); slot) {
        if (*slot < self_arg_layout.size() &&
            self_arg_layout[*slot].reg != Reg::None) {
            return IrValue::make_reg(self_arg_layout[*slot].reg,
                                     self_arg_layout[*slot].type);
        }
    }
    if (stack_offset(op).has_value() || try_resolve_imm_addr(op).has_value()) {
        return op;
    }
    const Reg canonical = op.kind == IrValueKind::Reg
        ? canonical_reg(op.reg) : Reg::None;
    if (canonical >= Reg::PpcF14 && canonical <= Reg::PpcF31) {
        const IrInst* definition = def_stripped(op);
        if (definition && definition->op == IrOp::Load &&
        definition->src_count >= 1 &&
        try_resolve_imm_addr(definition->srcs[0]).has_value()) {
            return op;
        }
    }
    return std::nullopt;
}

void Emitter::name_merge_values() {
    // Build a sink-aware use map for Phi recovery. Raw call.args.* packs
    // contain every ABI register, including stale r8-r10 lanes that the
    // callee does not consume. Counting those as real uses keeps enormous
    // caller-clobber-only Phi webs alive. Count ordinary visible users,
    // add only arguments selected by the callee layout, then retain a Phi
    // web only when it reaches one of those non-Phi sinks.
    std::map<SsaKey, u32> selected_call_arg_uses;
    for (const auto& block : fn->blocks) {
        std::vector<IrValue> int_values;
        std::vector<IrValue> fp_values;
        for (const IrInst& inst : block.insts) {
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.args.")) {
                if (inst.name == "call.args.1") int_values.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    int_values.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op == IrOp::Intrinsic && inst.name.starts_with("call.fp_args.")) {
                if (inst.name == "call.fp_args.1") fp_values.clear();
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    fp_values.push_back(inst.srcs[i]);
                }
                continue;
            }
            if (inst.op != IrOp::Call && inst.op != IrOp::CallIndirect) continue;
            const std::vector<InferredArgument> layout = [&]() -> std::vector<InferredArgument> {
                if (const FunctionSig* signature = call_annotation_signature(inst);
                    signature && !(signature->return_type.empty() &&
                                   signature->params.empty() &&
                                   signature->variadic)) {
                    return abi_layout_for(*signature);
                }
                if (inst.op == IrOp::Call) return cached_argument_layout(inst.target1);
                return {};
            }();
            const auto count_value = [&](const IrValue& value) {
                if (auto key = ssa_key(value); key) {
                    ++selected_call_arg_uses[*key];
                }
            };
            if (layout.empty()) {
                for (const IrValue& value : int_values) count_value(value);
                for (const IrValue& value : fp_values) count_value(value);
            } else {
                const auto int_regs = int_arg_regs(abi);
                const auto fp_regs = fp_arg_regs(abi);
                for (const InferredArgument& argument : layout) {
                    const Reg wanted = canonical_reg(argument.reg);
                    for (std::size_t i = 0; i < int_regs.size() &&
                                            i < int_values.size(); ++i) {
                        if (canonical_reg(int_regs[i]) == wanted) {
                            count_value(int_values[i]);
                        }
                    }
                    for (std::size_t i = 0; i < fp_regs.size() &&
                                            i < fp_values.size(); ++i) {
                        if (canonical_reg(fp_regs[i]) == wanted) {
                            count_value(fp_values[i]);
                        }
                    }
                }
            }
            int_values.clear();
            fp_values.clear();
        }
    }
    const auto non_phi_use_count = [&](const SsaKey& key) {
        const auto selected = selected_call_arg_uses.find(key);
        return ssa_uses.visible_use_count(key) +
               (selected == selected_call_arg_uses.end()
                    ? 0u : selected->second);
    };

    std::map<SsaKey, const IrInst*> phi_defs;
    for (const auto& block : fn->blocks) {
        for (const IrInst& inst : block.insts) {
            if (inst.op != IrOp::Phi) continue;
            if (auto key = ssa_key(inst.dst); key) phi_defs.emplace(*key, &inst);
        }
    }
    std::set<SsaKey> live_phis;
    for (const auto& [key, _] : phi_defs) {
        if (non_phi_use_count(key) != 0) live_phis.insert(key);
    }
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [key, phi] : phi_defs) {
            if (!live_phis.contains(key)) continue;
            for (const IrValue& operand : phi->phi_operands) {
                if (auto operand_key = ssa_key(operand);
                    operand_key && phi_defs.contains(*operand_key) &&
                    live_phis.insert(*operand_key).second) changed = true;
            }
        }
    }
    std::set<SsaKey> dead_phis;
    std::map<SsaKey, u32> live_phi_operand_uses;
    for (const auto& [key, phi] : phi_defs) {
        if (!live_phis.contains(key)) {
            dead_phis.insert(key);
            continue;
        }
        for (const IrValue& operand : phi->phi_operands) {
            if (auto operand_key = ssa_key(operand); operand_key) {
                ++live_phi_operand_uses[*operand_key];
            }
        }
    }

    SsaMergeLocalRecoveryCallbacks callbacks;
    // Call-argument intrinsics are hidden from ordinary statement-use
    // counts, but a Phi consumed only by a call still needs a source
    // local; otherwise the call leaks `r3_14`/`f1_8`.  Include those
    // uses for merge recovery while retaining the lean visible-use map
    // everywhere else.
    callbacks.use_count = [&](const SsaKey& k) {
        if (!is_ppc_abi()) return use_count_by_key(k);
        if (dead_phis.contains(k)) return 0u;
        u32 count = non_phi_use_count(k);
        if (auto found = live_phi_operand_uses.find(k);
            found != live_phi_operand_uses.end()) {
            count += found->second;
        }
        if (live_phis.contains(k)) count = std::max<u32>(count, 1);
        return count;
    };
    callbacks.def_of = [&](const IrValue& v) { return def_of(v); };
    callbacks.type_name = [&](const IrValue& v) { return c_type_name_for(v); };
    callbacks.role_for_phi = [&](const IrInst& inst) {
        return merge_role_for_phi(inst);
    };
    callbacks.initializer_candidate = [&](const IrValue& v) {
        return merge_initializer_candidate(v);
    };
    auto recovered = recover_ssa_merge_locals(*fn, callbacks);
    merge_value_names = std::move(recovered.value_names);
    merge_locals = std::move(recovered.locals);

    // A Win64 bool/byte return often reaches the shared epilogue as a
    // full-width RAX Phi. False arms clear AL with `rax & ~0xff`; true
    // arms zero-extend an i8. The upper carrier bits are not part of the
    // source return value, so type the merge local from the recovered low
    // byte instead of declaring an opaque uint64_t result.
    for (const auto& block : fn->blocks) {
        for (const IrInst& phi : block.insts) {
            if (phi.op != IrOp::Phi || phi.phi_operands.empty()) continue;
            auto key = ssa_key(phi.dst);
            if (!key) continue;
            auto named = merge_value_names.find(*key);
            if (named == merge_value_names.end()) continue;
            std::optional<IrValue> representative;
            bool all_low_bytes = true;
            for (const IrValue& operand : phi.phi_operands) {
                auto payload = low_byte_return_payload(operand);
                if (!payload) {
                    all_low_bytes = false;
                    break;
                }
                if (!representative) representative = *payload;
            }
            if (!all_low_bytes || !representative) continue;
            auto local = merge_locals.find(named->second);
            if (local != merge_locals.end()) {
                local->second.type_value = *representative;
            }
        }
    }

    // Register induction updates commonly feed both the back-edge Phi and
    // the loop comparison (`next = i + 1; cmp next, limit`). Their use
    // count is therefore two, so the generic pure-Phi-feeder rule does not
    // coalesce them. Attach these exact Add/Sub-by-immediate steps to the
    // Phi local so the tail block can emit `i++` and a recognised for-loop
    // can place the update in its header.
    for (const auto& block : fn->blocks) {
        for (const IrInst& phi : block.insts) {
            if (phi.op != IrOp::Phi) continue;
            auto phi_key = ssa_key(phi.dst);
            if (!phi_key) continue;
            auto named = merge_value_names.find(*phi_key);
            if (named == merge_value_names.end()) continue;
            auto local = merge_locals.find(named->second);
            if (local == merge_locals.end() ||
                (local->second.role != SsaMergeLocalRole::Induction &&
                 local->second.role != SsaMergeLocalRole::Index)) continue;
            for (const IrValue& operand : phi.phi_operands) {
                IrValue step_value = operand;
                const IrInst* step = def_of(step_value);
                if (step && step->op == IrOp::Assign && step->src_count == 1) {
                    step_value = step->srcs[0];
                    step = def_of(step_value);
                }
                if (!step || (step->op != IrOp::Add && step->op != IrOp::Sub) ||
                    step->src_count < 2) continue;
                bool uses_local = false;
                bool has_immediate = false;
                for (u8 i = 0; i < 2; ++i) {
                    if (auto key = ssa_key(step->srcs[i]); key) {
                        auto source_name = merge_value_names.find(*key);
                        uses_local |= source_name != merge_value_names.end() &&
                                      source_name->second == named->second;
                    }
                    has_immediate |= step->srcs[i].kind == IrValueKind::Imm;
                }
                if (!uses_local || !has_immediate) continue;
                for (const IrValue& candidate : {operand, step_value, step->dst}) {
                    auto key = ssa_key(candidate);
                    if (!key || merge_value_names.contains(*key)) continue;
                    merge_value_names.emplace(*key, named->second);
                    local->second.keys.push_back(*key);
                }
            }
        }
    }

    // Materialize literal/live-in Phi inputs on unconditional incoming
    // edges. Feeder instructions that were coalesced into the same merge
    // name already emit their own assignment; this fills the missing
    // initialization edges that previously left flags and loop state
    // undefined. Conditional diamond Phis render as ?: and need no local.
    merge_edge_assignments.clear();
    for (const auto& merge_block : fn->blocks) {
        for (const auto& phi : merge_block.insts) {
            if (phi.op != IrOp::Phi || phi.phi_operands.size() != phi.phi_preds.size()) {
                continue;
            }
            auto phi_key = ssa_key(phi.dst);
            if (!phi_key) continue;
            if (!is_ppc_abi() &&
                !structured_return_values.contains(*phi_key)) continue;
            auto named = merge_value_names.find(*phi_key);
            if (named == merge_value_names.end()) continue;
            bool selection_phi = false;
            if (phi.phi_operands.size() == 2 && phi.phi_preds.size() == 2) {
                for (std::size_t direct_i = 0; direct_i < 2 && !selection_phi;
                     ++direct_i) {
                    const addr_t direct_pred = phi.phi_preds[direct_i];
                    const addr_t arm_pred = phi.phi_preds[1 - direct_i];
                    const IrBlock* direct = nullptr;
                    const IrBlock* arm = nullptr;
                    for (const auto& candidate : fn->blocks) {
                        if (candidate.start == direct_pred) direct = &candidate;
                        if (candidate.start == arm_pred) arm = &candidate;
                    }
                    if (!direct || !arm || direct->insts.empty()) continue;
                    const IrInst& branch = direct->insts.back();
                    const bool diamond = branch.op == IrOp::CondBranch &&
                        ((branch.target1 == arm_pred && branch.target2 == merge_block.start) ||
                         (branch.target2 == arm_pred && branch.target1 == merge_block.start));
                    selection_phi = diamond && arm->successors.size() == 1 &&
                        arm->successors[0] == merge_block.start;
                }
            }
            if (selection_phi) continue;
            for (std::size_t i = 0; i < phi.phi_operands.size(); ++i) {
                auto initializer = merge_initializer_candidate(phi.phi_operands[i]);
                if (!initializer && !is_ppc_abi()) {
                    const IrValue& operand = phi.phi_operands[i];
                    const IrInst* definition = def_of(operand);
                    if (operand.kind == IrValueKind::Imm ||
                        (definition && definition->op != IrOp::Clobber &&
                         !renders_raw_arch_reg_name(operand))) {
                        initializer = operand;
                    }
                }
                if (!initializer) continue;
                if (auto operand_key = ssa_key(phi.phi_operands[i]); operand_key) {
                    auto same = merge_value_names.find(*operand_key);
                    if (same != merge_value_names.end() && same->second == named->second) {
                        // Coalesced feeder values normally assign the
                        // merge local through format_merge_assignment.
                        // Return-only Phis deliberately suppress those
                        // feeder statements, so they still need an edge
                        // assignment or the declared `result` is never
                        // initialized.
                        const IrInst* feeder = def_of(phi.phi_operands[i]);
                        if (feeder && merge_assignment_name_for(*feeder)) {
                            continue;
                        }
                    }
                }
                const IrBlock* predecessor = nullptr;
                for (const auto& candidate : fn->blocks) {
                    if (candidate.start == phi.phi_preds[i]) {
                        predecessor = &candidate;
                        break;
                    }
                }
                if (!predecessor || predecessor->successors.size() != 1 ||
                    predecessor->successors[0] != merge_block.start) {
                    continue;
                }
                merge_edge_assignments[predecessor->start].emplace_back(
                    named->second, *initializer);
            }
        }
    }
}

void Emitter::bump_arity_from_merge_initializers() {
    u8 need = self_arity;
    for (const auto& [_, local] : merge_locals) {
        if (!local.initializer) continue;
        bool has_visible_use = false;
        for (const auto& k : local.keys) {
            if (ssa_uses.visible_use_count(k) > 0) {
                has_visible_use = true;
                break;
            }
        }
        if (!has_visible_use) continue;
        if (auto slot = trace_to_self_arg_slot(*local.initializer); slot) {
            if (*slot < self_arg_layout.size() && *slot + 1 > need) {
                need = static_cast<u8>(*slot + 1);
            }
        }
    }
    self_arity = need;
}

void Emitter::analyze_merge_definite_assignment() {
    definitely_assigned_merge_locals.clear();
    if (!fn || merge_locals.empty()) return;

    for (const auto& [name, local] : merge_locals) {
        if (local.initializer) {
            definitely_assigned_merge_locals.insert(name);
            continue;
        }
        const auto local_key = [&](const IrValue& value) -> std::optional<SsaKey> {
            auto key = ssa_key(value);
            if (!key) return std::nullopt;
            auto named = merge_value_names.find(*key);
            if (named == merge_value_names.end() || named->second != name) {
                return std::nullopt;
            }
            return *key;
        };
        const auto assigns_at = [&](std::size_t bi, std::size_t ii,
                                    const IrInst& inst) {
            if (merge_assignment_name_for(inst) == name) return true;
            const std::pair position{bi, ii};
            if (!merge_bound_calls.contains(position)) return false;
            auto bound = bound_call_key.find(position);
            if (bound == bound_call_key.end()) return false;
            auto named = merge_value_names.find(bound->second);
            return named != merge_value_names.end() && named->second == name;
        };

        std::vector<bool> block_assigns(fn->blocks.size(), false);
        std::vector<bool> edge_assigns(fn->blocks.size(), false);
        for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
            const auto& block = fn->blocks[bi];
            for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
                if (assigns_at(bi, ii, block.insts[ii])) {
                    block_assigns[bi] = true;
                }
            }
            if (auto edge = merge_edge_assignments.find(block.start);
                edge != merge_edge_assignments.end()) {
                edge_assigns[bi] = std::ranges::any_of(
                    edge->second, [&](const auto& item) { return item.first == name; });
            }
        }

        std::vector<bool> in(fn->blocks.size(), true);
        std::vector<bool> out(fn->blocks.size(), true);
        if (!in.empty()) in[0] = false;
        bool changed = true;
        for (std::size_t iteration = 0;
             changed && iteration <= fn->blocks.size(); ++iteration) {
            changed = false;
            for (std::size_t bi = 0; bi < fn->blocks.size(); ++bi) {
                bool next_in = false;
                if (bi != 0 && !fn->blocks[bi].predecessors.empty()) {
                    next_in = true;
                    for (addr_t predecessor : fn->blocks[bi].predecessors) {
                        auto found = fn->block_at.find(predecessor);
                        if (found == fn->block_at.end() || !out[found->second]) {
                            next_in = false;
                            break;
                        }
                    }
                }
                const bool next_out = next_in || block_assigns[bi] || edge_assigns[bi];
                if (in[bi] != next_in || out[bi] != next_out) {
                    in[bi] = next_in;
                    out[bi] = next_out;
                    changed = true;
                }
            }
        }

        bool safe = true;
        for (std::size_t bi = 0; bi < fn->blocks.size() && safe; ++bi) {
            bool assigned = in[bi];
            const auto& block = fn->blocks[bi];
            for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
                const IrInst& inst = block.insts[ii];
                if (inst.op != IrOp::Phi) {
                    for (u8 si = 0; si < inst.src_count && si < inst.srcs.size(); ++si) {
                        auto key = local_key(inst.srcs[si]);
                        if (!key) continue;
                        const auto users =
                            ssa_uses.visible_user_positions(*key);
                        const bool visible = std::ranges::find(
                            users, SsaUseIndex::Position{bi, ii}) != users.end();
                        if (visible && !assigned) {
                            safe = false;
                            break;
                        }
                    }
                }
                if (!safe) break;
                assigned |= assigns_at(bi, ii, inst);
            }
        }
        if (safe) definitely_assigned_merge_locals.insert(name);
    }
}

}  // namespace ember::emit
