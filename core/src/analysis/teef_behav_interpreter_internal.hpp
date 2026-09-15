#pragma once

// Private state shared by the behavioural-signature trace driver and its
// instruction evaluator. This is not part of the public fingerprint API.

#include <cstddef>
#include <optional>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;
struct IrFunction;
struct IrInst;
struct IrValue;

namespace teef_behav_detail {

// Minimal flat map for the interpreter's hot path: no erase or iteration.
class FlatMapU64 {
    static constexpr u8 kEmpty    = 0x00;
    static constexpr u8 kOccupied = 0x01;

    struct Slot;

    Slot* slots_ = nullptr;
    u8*   ctrl_  = nullptr;
    u32   cap_   = 0;
    u32   size_  = 0;

    [[nodiscard]] static u32 next_cap(u32 c) noexcept;
    [[nodiscard]] u32 slot_for(u64 key) const noexcept;
    void grow();
    void insert_rehash(u64 key, u64 value) noexcept;

public:
    FlatMapU64() noexcept = default;
    explicit FlatMapU64(u32 reserve_cap);
    ~FlatMapU64();

    FlatMapU64(const FlatMapU64&)            = delete;
    FlatMapU64& operator=(const FlatMapU64&) = delete;

    FlatMapU64(FlatMapU64&& other) noexcept;
    FlatMapU64& operator=(FlatMapU64&& other) noexcept;

    [[nodiscard]] u64* find(u64 key) noexcept;
    [[nodiscard]] const u64* find(u64 key) const noexcept;
    [[nodiscard]] u64& operator[](u64 key);
    void clear() noexcept;
};

struct Memory {
    FlatMapU64 cells;
    u64 salt;

    [[nodiscard]] u64 load(u64 addr, unsigned width_bytes);
    void store(u64 addr, u64 val, unsigned width_bytes);
};

struct Trace {
    const IrFunction& fn;
    const Binary&     bin;

    FlatMapU64       values;
    std::vector<u64> side_effects;
    Memory           mem;
    std::size_t      insns_done = 0;
    std::size_t      loads_done = 0;
    bool             aborted = false;
    addr_t           prev_block = 0;

    Trace(const IrFunction& f, const Binary& b, u64 mem_salt);

    void reset(u64 new_mem_salt);
    [[nodiscard]] std::optional<u64> get(const IrValue& v) noexcept;
    void set(const IrValue& dst, u64 val);
};

[[nodiscard]] u64 value_key(const IrValue& v) noexcept;
[[nodiscard]] bool step(Trace& trace, const IrInst& inst);

}  // namespace teef_behav_detail
}  // namespace spelunk
