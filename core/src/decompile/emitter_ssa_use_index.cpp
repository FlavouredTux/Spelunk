#include "emitter_ssa_use_index.hpp"

namespace ember::emit {
namespace {

template <typename Visitor>
void for_each_operand(const IrInst& inst, Visitor&& visitor) {
    if (inst.op == IrOp::Phi) {
        for (const IrValue& operand : inst.phi_operands) visitor(operand);
        return;
    }
    for (u8 i = 0; i < inst.src_count && i < inst.srcs.size(); ++i) {
        visitor(inst.srcs[i]);
    }
}

}  // namespace

bool SsaUseIndex::is_call_arg_barrier(const IrInst& inst) noexcept {
    return inst.op == IrOp::Intrinsic &&
           (inst.name.starts_with("call.args.") ||
            inst.name.starts_with("call.fp_args."));
}

void SsaUseIndex::scan(const IrFunction& fn) {
    reset();
    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const IrBlock& block = fn.blocks[bi];
        for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
            observe(block.insts[ii], {bi, ii});
        }
    }
}

void SsaUseIndex::observe(const IrInst& inst, Position position) {
    if (const auto key = ssa_key(inst.dst); key) {
        // Assignment (rather than emplace) intentionally preserves the
        // emitter's historical last-definition-wins behaviour.
        Entry& entry = entries_[*key];
        entry.definition = &inst;
        entry.definition_position = position;
    }

    const bool barrier = is_call_arg_barrier(inst);
    for_each_operand(inst, [&](const IrValue& operand) {
        const auto key = ssa_key(operand);
        if (!key) return;
        Entry& entry = entries_[*key];
        ++entry.syntactic_uses;
        if (barrier) return;
        entry.semantic_user_positions.push_back(position);
    });
}

void SsaUseIndex::scan_visible(const IrFunction& fn,
                               const std::set<Position>& hidden) {
    for (auto& [_, entry] : entries_) {
        entry.visible_flag_assign_uses = 0;
        entry.visible_user_positions.clear();
    }

    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        const IrBlock& block = fn.blocks[bi];
        for (std::size_t ii = 0; ii < block.insts.size(); ++ii) {
            const Position position{bi, ii};
            if (hidden.contains(position)) continue;

            const IrInst& inst = block.insts[ii];
            if (is_call_arg_barrier(inst) || inst.op == IrOp::Phi) continue;

            const bool flag_assign =
                inst.op == IrOp::Assign &&
                inst.dst.kind == IrValueKind::Flag;
            for_each_operand(inst, [&](const IrValue& operand) {
                const auto key = ssa_key(operand);
                if (!key) return;
                Entry& entry = entries_[*key];
                if (flag_assign) ++entry.visible_flag_assign_uses;
                entry.visible_user_positions.push_back(position);
            });
        }
    }
}

void SsaUseIndex::reset() noexcept {
    entries_.clear();
}

const SsaUseIndex::Entry*
SsaUseIndex::find_entry(const SsaKey& key) const noexcept {
    const auto found = entries_.find(key);
    return found == entries_.end() ? nullptr : &found->second;
}

const IrInst* SsaUseIndex::definition(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    return entry ? entry->definition : nullptr;
}

std::optional<SsaUseIndex::Position>
SsaUseIndex::definition_position(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    if (!entry) return std::nullopt;
    return entry->definition_position;
}

u32 SsaUseIndex::syntactic_use_count(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    return entry ? entry->syntactic_uses : 0u;
}

u32 SsaUseIndex::semantic_use_count(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    return entry
        ? static_cast<u32>(entry->semantic_user_positions.size())
        : 0u;
}

u32 SsaUseIndex::visible_use_count(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    return entry
        ? static_cast<u32>(entry->visible_user_positions.size())
        : 0u;
}

bool SsaUseIndex::every_visible_use_is_flag_assign(
    const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    const u32 visible = entry
        ? static_cast<u32>(entry->visible_user_positions.size())
        : 0u;
    return entry && visible != 0u &&
           entry->visible_flag_assign_uses == visible;
}

std::span<const SsaUseIndex::Position>
SsaUseIndex::semantic_user_positions(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    if (!entry) return {};
    return entry->semantic_user_positions;
}

std::span<const SsaUseIndex::Position>
SsaUseIndex::visible_user_positions(const SsaKey& key) const noexcept {
    const Entry* entry = find_entry(key);
    if (!entry) return {};
    return entry->visible_user_positions;
}

}  // namespace ember::emit
