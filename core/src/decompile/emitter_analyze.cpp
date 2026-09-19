// Pre-pass over the IR: use counts, merge naming, definite assignment.
#include <algorithm>
#include <cstddef>
#include <deque>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <spelunk/analysis/arity.hpp>
#include <spelunk/analysis/ssa_cleanup.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/register.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

#include "emitter_internal.hpp"

namespace spelunk::emit {

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
    // change its meaning. Follow every expression the renderer may defer,
    // including values captured by hidden call-argument packs, and materialize
    // when a call or aliasing store can execute before the eventual use. A
    // cross-block use alone is safe and stays inline.
    for (u32 def_bi = 0; def_bi < f.blocks.size(); ++def_bi) {
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
                const auto overlaps_signed = [](i64 a, u32 a_size,
                                                 i64 b, u32 b_size) {
                    if (a <= b) {
                        return static_cast<u64>(b) - static_cast<u64>(a) <
                               a_size;
                    }
                    return static_cast<u64>(a) - static_cast<u64>(b) <
                           b_size;
                };
                const auto overlaps_unsigned = [](i64 a, u32 a_size,
                                                   i64 b, u32 b_size) {
                    const u64 ua = static_cast<u64>(a);
                    const u64 ub = static_cast<u64>(b);
                    if (ua <= ub) return ub - ua < a_size;
                    return ua - ub < b_size;
                };
                if (load_stack && store_stack) {
                    return overlaps_signed(*load_stack, load_bytes,
                                           *store_stack, store_bytes);
                }
                if (load_absolute && store_absolute) {
                    return overlaps_unsigned(*load_absolute, load_bytes,
                                             *store_absolute, store_bytes);
                }
                const auto load_access = canonical_struct_access(load.srcs[0]);
                const auto store_access = canonical_struct_access(store.srcs[0]);
                if (load_access && store_access) {
                    const auto load_root = ssa_key(load_access->first);
                    const auto store_root = ssa_key(store_access->first);
                    if (load_root && store_root && *load_root == *store_root) {
                        return overlaps_signed(
                            load_access->second, load_bytes,
                            store_access->second, store_bytes);
                    }
                }
                // A proven stack address and a proven absolute object
                // cannot alias.
                if ((load_stack && store_absolute) ||
                    (load_absolute && store_stack)) return false;
                // Different unresolved pointer roots can still alias. Only
                // the concrete stack/absolute/same-root cases above prove
                // that a store cannot change this load's source.
                return true;
            };
            const auto is_memory_barrier = [&](const IrInst& inst) {
                if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect ||
                    store_may_alias_load(inst)) {
                    return true;
                }
                if (inst.op != IrOp::Intrinsic) return false;
                // Argument packs are metadata-only. Every real Intrinsic is
                // conservatively memory-effecting, matching the IR memory
                // passes: a destination does not prove purity (an opaque
                // intrinsic may be an atomic read/modify/write).
                if (SsaUseIndex::is_call_arg_barrier(inst)) return false;
                return true;
            };
            if (ssa_uses.syntactic_use_count(*load_key) == 0) continue;

            // Propagate clean/dirty memory state once for this load. Each CFG
            // block is scanned at most once per incoming state, so all uses of
            // the load and its transparent aliases are constant-time queries.
            // A dirty loop edge can revisit a use that ran clean initially;
            // re-executing the defining Load resets the state to clean.
            std::vector<std::vector<bool>> dirty_before;
            dirty_before.reserve(f.blocks.size());
            for (const IrBlock& block : f.blocks) {
                dirty_before.emplace_back(block.insts.size(), false);
            }
            std::vector<bool> visited_clean(f.blocks.size(), false);
            std::vector<bool> visited_dirty(f.blocks.size(), false);
            std::deque<std::pair<std::size_t, bool>> pending_blocks;
            const auto scan_block = [&](std::size_t block_index,
                                        std::size_t begin,
                                        bool dirty) {
                const auto& instructions = f.blocks[block_index].insts;
                for (std::size_t ii = begin; ii < instructions.size(); ++ii) {
                    if (dirty) dirty_before[block_index][ii] = true;
                    if (block_index == def_bi && ii == def_ii) {
                        dirty = false;
                    } else if (is_memory_barrier(instructions[ii])) {
                        dirty = true;
                    }
                }
                return dirty;
            };
            const auto enqueue_successors = [&](std::size_t block_index,
                                                bool dirty) {
                for (addr_t successor : f.blocks[block_index].successors) {
                    auto found = f.block_at.find(successor);
                    if (found != f.block_at.end()) {
                        pending_blocks.emplace_back(found->second, dirty);
                    }
                }
            };

            const bool suffix_dirty = scan_block(def_bi, def_ii + 1, false);
            enqueue_successors(def_bi, suffix_dirty);
            while (!pending_blocks.empty()) {
                const auto [block_index, incoming_dirty] = pending_blocks.front();
                pending_blocks.pop_front();
                auto& visited = incoming_dirty ? visited_dirty : visited_clean;
                if (visited[block_index]) continue;
                visited[block_index] = true;
                const bool outgoing_dirty = scan_block(
                    block_index, 0, incoming_dirty);
                enqueue_successors(block_index, outgoing_dirty);
            }

            std::set<SsaKey> seen;
            std::deque<SsaKey> pending{*load_key};
            bool snapshot = false;
            while (!pending.empty() && !snapshot) {
                const SsaKey key = pending.front();
                pending.pop_front();
                if (!seen.insert(key).second) continue;
                const auto users = ssa_uses.syntactic_user_positions(key);
                for (const auto& [use_bi, use_ii] : users) {
                    if (use_bi >= f.blocks.size() ||
                        use_ii >= f.blocks[use_bi].insts.size()) {
                        continue;
                    }
                    snapshot = dirty_before[use_bi][use_ii];
                    if (snapshot) break;
                    const IrInst& user = f.blocks[use_bi].insts[use_ii];
                    if (inlinable_op(user.op) || user.op == IrOp::Phi) {
                        if (auto next = ssa_key(user.dst); next) {
                            pending.push_back(*next);
                        }
                    }
                }
            }
            if (snapshot) {
                memory_snapshot_loads.insert(*load_key);
                // ABI-noise propagation hides values used only by call.args.
                // A load that must be captured at its definition is semantic
                // state, not pack noise, so restore that statement here.
                hidden.erase({def_bi, def_ii});
            }
        }
    }
    std::map<i64, int> slot_write_count;
    std::map<i64, IrValue> slot_first_write_value;
    std::map<i64, u32> stored_stack_ranges;
    std::set<std::tuple<i64, u32, IrType>> stack_access_ranges;
    std::set<i64> nonforwardable_stack_slots;
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op == IrOp::Load && inst.src_count >= 1 &&
                inst.segment == Reg::None) {
                if (auto off = stack_offset(inst.srcs[0]); off) {
                    stack_access_ranges.emplace(
                        *off, std::max(1u, type_bits(inst.dst.type) / 8u),
                        inst.dst.type);
                }
            }
            if (inst.op != IrOp::Store || inst.src_count < 2 ||
                inst.segment != Reg::None) {
                continue;
            }
            auto off = stack_offset(inst.srcs[0]);
            if (!off) continue;
            const u32 bytes = std::max(
                1u, type_bits(inst.srcs[1].type) / 8u);
            stack_access_ranges.emplace(*off, bytes, inst.srcs[1].type);
            auto& range_size = stored_stack_ranges[*off];
            range_size = std::max(range_size, bytes);
            if (++slot_write_count[*off] == 1) {
                slot_first_write_value[*off] = inst.srcs[1];
            }
        }
    }

    // A stack-slot store is observable when code either loads the slot or
    // lets its address escape. Seed each stored slot's address provenance,
    // propagate it through pointer-shaped SSA operations, then conservatively
    // treat every non-memory-address consumer as an escape. This includes
    // call.args intrinsics, returns, and storing the pointer somewhere else.
    std::map<SsaKey, std::set<i64>> stack_address_origins;
    const auto range_contains = [](i64 start, u32 size, i64 point) {
        return start <= point &&
               static_cast<u64>(point) - static_cast<u64>(start) < size;
    };
    const auto ranges_overlap = [](i64 a, u32 a_size,
                                   i64 b, u32 b_size) {
        if (a <= b) {
            return static_cast<u64>(b) - static_cast<u64>(a) < a_size;
        }
        return static_cast<u64>(a) - static_cast<u64>(b) < b_size;
    };
    for (auto first = stored_stack_ranges.begin();
         first != stored_stack_ranges.end(); ++first) {
        for (auto second = std::next(first);
             second != stored_stack_ranges.end(); ++second) {
            if (!ranges_overlap(first->first, first->second,
                                second->first, second->second)) {
                continue;
            }
            nonforwardable_stack_slots.insert(first->first);
            nonforwardable_stack_slots.insert(second->first);
        }
    }
    struct StorageComponent {
        i64 start = 0;
        u64 span = 0;
        std::size_t distinct_shapes = 0;
    };
    std::vector<StorageComponent> storage_components;
    for (const auto& access : stack_access_ranges) {
        const i64 start = std::get<0>(access);
        const u32 size = std::get<1>(access);
        if (storage_components.empty()) {
            storage_components.push_back({start, size, 1});
            continue;
        }
        StorageComponent& previous = storage_components.back();
        const u64 distance = static_cast<u64>(start) -
                             static_cast<u64>(previous.start);
        if (distance < previous.span) {
            previous.span = std::max(
                previous.span, distance + static_cast<u64>(size));
            ++previous.distinct_shapes;
        } else {
            storage_components.push_back({start, size, 1});
        }
    }
    stack_storage_ranges.clear();
    stack_byte_storage_ranges.clear();
    for (const StorageComponent& component : storage_components) {
        stack_storage_ranges.emplace(component.start, component.span);
        if (component.distinct_shapes > 1) {
            stack_byte_storage_ranges.emplace(component.start, component.span);
            for (const auto& stored : stored_stack_ranges) {
                const i64 stored_off = stored.first;
                if (stored_off < component.start) continue;
                const u64 displacement = static_cast<u64>(stored_off) -
                                         static_cast<u64>(component.start);
                if (displacement < component.span) {
                    nonforwardable_stack_slots.insert(stored_off);
                }
            }
        }
    }
    const auto seed_stack_address = [&](const IrValue& value) {
        if (value.kind == IrValueKind::Reg &&
            is_stack_base_reg(value.reg)) return;
        auto key = ssa_key(value);
        if (!key) return;
        auto off = stack_offset(value);
        if (!off) return;
        for (const auto& [stored_off, stored_size] : stored_stack_ranges) {
            if (range_contains(stored_off, stored_size, *off)) {
                stack_address_origins[*key].insert(stored_off);
            }
        }
    };
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            seed_stack_address(inst.dst);
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                seed_stack_address(inst.srcs[i]);
            }
            for (const IrValue& operand : inst.phi_operands) {
                seed_stack_address(operand);
            }
        }
    }
    const auto transports_pointer = [](IrOp op) noexcept {
        switch (op) {
            case IrOp::Assign:
            case IrOp::Add:
            case IrOp::Sub:
            case IrOp::And:
            case IrOp::Or:
            case IrOp::Xor:
            case IrOp::Shl:
            case IrOp::Lshr:
            case IrOp::Ashr:
            case IrOp::Select:
            case IrOp::Phi:
            case IrOp::ZExt:
            case IrOp::SExt:
            case IrOp::Trunc:
                return true;
            default:
                return false;
        }
    };
    bool propagated = true;
    while (propagated) {
        propagated = false;
        for (const auto& bb : f.blocks) {
            for (const auto& inst : bb.insts) {
                if (!transports_pointer(inst.op)) continue;
                auto dst = ssa_key(inst.dst);
                if (!dst) continue;
                if (inst.dst.kind == IrValueKind::Reg &&
                    is_stack_base_reg(inst.dst.reg)) continue;
                std::set<i64> incoming;
                const auto collect = [&](const IrValue& value) {
                    auto key = ssa_key(value);
                    if (!key) return;
                    auto found = stack_address_origins.find(*key);
                    if (found != stack_address_origins.end()) {
                        incoming.insert(found->second.begin(), found->second.end());
                    }
                };
                for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                    collect(inst.srcs[i]);
                }
                for (const IrValue& operand : inst.phi_operands) collect(operand);
                if (auto destination_offset = stack_offset(inst.dst);
                    destination_offset) {
                    std::erase_if(incoming, [&](i64 origin) {
                        const i64 base =
                            stack_storage_base(origin).value_or(origin);
                        auto range = stack_storage_ranges.find(base);
                        if (range == stack_storage_ranges.end()) return false;
                        if (*destination_offset < base) return true;
                        const u64 displacement =
                            static_cast<u64>(*destination_offset) -
                            static_cast<u64>(base);
                        // Keep addresses within the object and its legal
                        // one-past position. A large stack-pointer adjustment
                        // (e.g. saved-RSP minus frame size) is not an alias of
                        // the saved slot merely because it flowed through the
                        // same SSA temp.
                        return displacement > range->second;
                    });
                }
                if (incoming.empty()) continue;
                auto& origins = stack_address_origins[*dst];
                const std::size_t old_size = origins.size();
                origins.insert(incoming.begin(), incoming.end());
                propagated |= origins.size() != old_size;
            }
        }
    }

    stack_address_storage_base.clear();
    for (const auto& [key, origins] : stack_address_origins) {
        std::set<i64> canonical_bases;
        for (i64 origin : origins) {
            canonical_bases.insert(
                stack_storage_base(origin).value_or(origin));
        }
        if (canonical_bases.size() == 1) {
            stack_address_storage_base.emplace(key, *canonical_bases.begin());
        }
    }

    std::set<i64> escaped_stack_slots;
    const auto record_escape = [&](const IrValue& value) {
        auto key = ssa_key(value);
        if (!key) return;
        auto found = stack_address_origins.find(*key);
        if (found != stack_address_origins.end()) {
            escaped_stack_slots.insert(found->second.begin(), found->second.end());
        }
        if (auto off = stack_offset(value); off) {
            std::optional<i64> base;
            if (auto provenance = stack_address_storage_base.find(*key);
                provenance != stack_address_storage_base.end()) {
                base = provenance->second;
            } else {
                base = stack_storage_base(*off);
            }
            if (base && *base != *off) {
                auto range = stack_storage_ranges.find(*base);
                if (range != stack_storage_ranges.end()) {
                    stack_byte_storage_ranges[*base] = range->second;
                }
            }
        }
    };
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (transports_pointer(inst.op) && ssa_key(inst.dst)) continue;
            if (inst.op == IrOp::Phi) continue;
            // Recording RSP at a call does not pass a pointer to the callee.
            if (inst.op == IrOp::Intrinsic && inst.name == "call.stack_pointer") continue;
            for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
                const bool memory_address =
                    (inst.op == IrOp::Load || inst.op == IrOp::Store) && i == 0;
                if (!memory_address) record_escape(inst.srcs[i]);
            }
            if (inst.op != IrOp::Load && inst.op != IrOp::Store) {
                for (const IrValue& operand : inst.phi_operands) {
                    record_escape(operand);
                }
            }
        }
    }

    // Keep the existing set as the single format_store query: an explicit
    // load and an escaped address both make the slot's stored value observable.
    for (const auto& bb : f.blocks) {
        for (const auto& inst : bb.insts) {
            if (inst.op != IrOp::Load || inst.src_count < 1) continue;
            if (inst.segment != Reg::None) continue;
            if (auto off = stack_offset(inst.srcs[0]); off) {
                const u32 bytes = std::max(
                    1u, type_bits(inst.dst.type) / 8u);
                for (const auto& [stored_off, stored_size] :
                     stored_stack_ranges) {
                    if (ranges_overlap(stored_off, stored_size, *off, bytes)) {
                        loaded_stack_slots.insert(stored_off);
                        if (stored_off != *off || stored_size != bytes) {
                            nonforwardable_stack_slots.insert(stored_off);
                        }
                    }
                }
            }
        }
    }
    loaded_stack_slots.insert(escaped_stack_slots.begin(),
                              escaped_stack_slots.end());

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
    const auto stable_for_slot_forwarding = [&](const auto& self,
                                                const IrValue& value,
                                                std::set<SsaKey>& seen,
                                                int depth) -> bool {
        if (depth > 32) return false;
        if (value.kind == IrValueKind::Imm) return true;
        if (value.kind == IrValueKind::Reg && value.version == 0) return true;
        auto key = ssa_key(value);
        if (!key || !seen.insert(*key).second) return false;
        const IrInst* definition = ssa_uses.definition(*key);
        if (!definition || definition->op == IrOp::Clobber ||
            (!inlinable_op(definition->op) && definition->op != IrOp::Phi)) {
            return false;
        }
        if (definition->op == IrOp::Load) {
            return memory_snapshot_loads.contains(*key);
        }
        for (u8 i = 0;
             i < definition->src_count && i < definition->srcs.size(); ++i) {
            if (!self(self, definition->srcs[i], seen, depth + 1)) return false;
        }
        for (const IrValue& operand : definition->phi_operands) {
            if (!self(self, operand, seen, depth + 1)) return false;
        }
        return true;
    };
    for (const auto& [off, count] : slot_write_count) {
        if (count != 1) continue;
        const IrValue& v = slot_first_write_value[off];
        if (escaped_stack_slots.contains(off) ||
            nonforwardable_stack_slots.contains(off)) continue;
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
            std::set<SsaKey> seen;
            // A pure-looking Assign/Add can still depend on a Load or
            // clobbered register. Re-expanding that tree at a later slot load
            // would move the original read across intervening side effects.
            if (!stable_for_slot_forwarding(
                    stable_for_slot_forwarding, v, seen, 0)) continue;
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
        // A cloned return can read a phi's incoming value directly. Count
        // that use before coalescing the feeder into the merge local.
        if (!is_ppc_abi()) return use_count_by_key(k) +
            (structured_return_values.contains(k) ? 1u : 0u);
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

    // A computed pointer may feed both a guard and a later call-only Phi.
    // It is not a single-use feeder, but still needs to initialize the merge
    // local before the guard. Coalesce only predecessor-local values with no
    // other-block users: otherwise overwriting the local on the other path
    // could destroy an independently live SSA value.
    if (is_ppc_abi()) {
        for (const auto& block : fn->blocks) {
            for (const auto& phi : block.insts) {
                if (phi.op != IrOp::Phi) continue;
                auto phi_key = ssa_key(phi.dst);
                if (!phi_key) continue;
                auto named = merge_value_names.find(*phi_key);
                if (named == merge_value_names.end()) continue;
                for (std::size_t i = 0; i < phi.phi_operands.size() && i < phi.phi_preds.size(); ++i) {
                    const auto& operand = phi.phi_operands[i];
                    auto key = ssa_key(operand);
                    auto position = key ? ssa_uses.definition_position(*key) : std::nullopt;
                    if (!position || merge_value_names.contains(*key)) continue;
                    const auto [bi, ii] = *position;
                    const auto& predecessor = fn->blocks[bi];
                    const auto& definition = predecessor.insts[ii];
                    if (predecessor.start != phi.phi_preds[i] ||
                        predecessor.start == block.start ||
                        (definition.op != IrOp::Add && definition.op != IrOp::Sub)) continue;
                    bool local_uses = true;
                    for (const auto& [user_bi, user_ii] : ssa_uses.syntactic_user_positions(*key)) {
                        if (user_bi != bi && &fn->blocks[user_bi].insts[user_ii] != &phi) {
                            local_uses = false;
                            break;
                        }
                    }
                    if (!local_uses) continue;
                    merge_value_names.emplace(*key, named->second);
                    merge_locals.at(named->second).keys.push_back(*key);
                }
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

}  // namespace spelunk::emit
