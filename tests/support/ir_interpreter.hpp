#pragma once

#include <cstddef>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk::test {

struct MachineInput {
    std::map<SsaKey, u64> values;
    std::vector<u8> memory;
    // Architecture tests may supply explicit semantics for named intrinsics.
    // No callback means every intrinsic remains unsupported.
    std::function<std::expected<u64, std::string>(
        const IrInst&, std::span<const u64>)> intrinsic;
    // Explicit integer ABI oracle: arguments come from projected call.args
    // packs. The callback returns RAX and may mutate bounded target memory.
    std::function<std::expected<u64, std::string>(
        addr_t, std::span<const u64>, std::span<u8>)> call;
};

struct Execution {
    std::optional<u64> returned;
    std::vector<u8> memory;
    std::size_t call_count = 0;
    bool operator==(const Execution&) const = default;
};

// Integer SSA with direct/conditional branches, simultaneous edge-selected
// phis, integer widths 1..64, and bounded little-endian memory.
// Memory is ordinary, nonvolatile storage: compare final bytes, not the number
// of stores (DSE may remove overwritten stores). Direct integer x64 calls
// require an explicit callback; only the immediately following RAX clobber
// receives its result, and other clobbers invalidate their destinations.
// Indirect branches/calls, floating point, and ambiguous signed/unsigned
// Div/Mod are rejected, never skipped.
// Integer carry/borrow/overflow operations are supported. Named intrinsics
// require an explicit MachineInput callback that rejects unknown names.
// Shift counts follow the current scalar IR convention: low 5 bits below
// 64-bit width, low 6 bits at 64-bit width. This is not an ISA emulator.
// Each executed instruction (including phis and branches) consumes one step.
// Exhaustion is an error, not proof of nontermination or equivalence.
[[nodiscard]] std::expected<Execution, std::string>
interpret(const IrFunction& function, const MachineInput& input,
          std::size_t step_limit = 10000);

}  // namespace spelunk::test
