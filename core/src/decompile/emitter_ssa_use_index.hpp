#pragma once

// Private SSA definition/use index for the pseudo-C emitter. The emitter has
// three intentionally different notions of a use; keeping the policy here
// prevents callers from accidentally reaching into one cache when they mean
// another.

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk::emit {

class SsaUseIndex final {
public:
    using Position = std::pair<std::size_t, std::size_t>;

    SsaUseIndex() = default;

    // Phase one records definitions plus syntactic and semantic uses.
    // Syntactic uses include call argument packing intrinsics; semantic uses
    // exclude those barriers but retain Phi operands and users that may later
    // be hidden by the emitter.
    void observe(const IrInst& inst, Position position);

    // Convenience for consumers that do not need the emitter's incremental
    // scan ordering. Clears prior state before visiting the whole function.
    void scan(const IrFunction& fn);

    // Phase two is deliberately separate: ABI/noise analysis discovers the
    // hidden set using the phase-one index. Visible uses exclude those hidden
    // instructions, call-argument barriers, and Phi operands.
    void scan_visible(const IrFunction& fn,
                      const std::set<Position>& hidden);

    void reset() noexcept;

    [[nodiscard]] static bool
    is_call_arg_barrier(const IrInst& inst) noexcept;

    [[nodiscard]] const IrInst*
    definition(const SsaKey& key) const noexcept;

    [[nodiscard]] std::optional<Position>
    definition_position(const SsaKey& key) const noexcept;

    [[nodiscard]] u32
    syntactic_use_count(const SsaKey& key) const noexcept;

    [[nodiscard]] u32
    semantic_use_count(const SsaKey& key) const noexcept;

    [[nodiscard]] u32
    visible_use_count(const SsaKey& key) const noexcept;

    [[nodiscard]] bool
    every_visible_use_is_flag_assign(const SsaKey& key) const noexcept;

    [[nodiscard]] std::span<const Position>
    syntactic_user_positions(const SsaKey& key) const noexcept;

    [[nodiscard]] std::span<const Position>
    semantic_user_positions(const SsaKey& key) const noexcept;

    [[nodiscard]] std::span<const Position>
    visible_user_positions(const SsaKey& key) const noexcept;

    // Definitions are visited in SsaKey order, matching the old std::map
    // iteration order.  Duplicate definitions retain only the last scanned
    // instruction and position.
    template <typename Visitor>
    void for_each_definition(Visitor&& visitor) const {
        for (const auto& [key, entry] : entries_) {
            if (entry.definition) {
                std::invoke(visitor, key, entry.definition);
            }
        }
    }

private:
    struct Entry {
        const IrInst* definition = nullptr;
        std::optional<Position> definition_position;
        u32 syntactic_uses = 0;
        u32 visible_flag_assign_uses = 0;
        std::vector<Position> syntactic_user_positions;
        std::vector<Position> semantic_user_positions;
        std::vector<Position> visible_user_positions;
    };

    [[nodiscard]] const Entry*
    find_entry(const SsaKey& key) const noexcept;
    Entry& entry_for(const SsaKey& key);

    struct KeyHash {
        [[nodiscard]] std::size_t operator()(const SsaKey& k) const noexcept {
            const auto [kind, id, version] = k;
            u64 h = static_cast<u64>(id) * 0x9E3779B97F4A7C15ull;
            h ^= static_cast<u64>(version) * 0xBF58476D1CE4E5B9ull;
            h ^= static_cast<u64>(kind) * 0x94D049BB133111EBull;
            h ^= h >> 30;
            return static_cast<std::size_t>(h);
        }
    };

    // `entries_` keeps SsaKey order for for_each_definition; lookups, which
    // the emitter makes for nearly every value it touches, go through the
    // hash index over its (stable) nodes.
    std::map<SsaKey, Entry> entries_;
    std::unordered_map<SsaKey, Entry*, KeyHash> index_;
};

}  // namespace spelunk::emit
