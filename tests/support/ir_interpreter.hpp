#pragma once

#include <cstddef>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

namespace ember::test {

struct MachineInput {
    std::map<SsaKey, u64> values;
    std::vector<u8> memory;
    // Architecture tests may supply explicit semantics for named intrinsics.
    // No callback means every intrinsic remains unsupported.
    std::function<std::expected<u64, std::string>(
        const IrInst&, std::span<const u64>)> intrinsic;
};

struct Execution {
    std::optional<u64> returned;
    std::vector<u8> memory;
    bool operator==(const Execution&) const = default;
};

// Integer SSA with direct/conditional branches, simultaneous edge-selected
// phis, integer widths 1..64, and bounded little-endian memory.
// Memory is ordinary, nonvolatile storage: compare final bytes, not the number
// of stores (DSE may remove overwritten stores). Calls, indirect branches, floating
// point, and ambiguous signed/unsigned Div/Mod are rejected, never skipped.
// Integer carry/borrow/overflow operations are supported. Named intrinsics
// require an explicit MachineInput callback that rejects unknown names.
// Shift counts follow the current scalar IR convention: low 5 bits below
// 64-bit width, low 6 bits at 64-bit width. This is not an ISA emulator.
// Each executed instruction (including phis and branches) consumes one step.
// Exhaustion is an error, not proof of nontermination or equivalence.
[[nodiscard]] std::expected<Execution, std::string>
interpret(const IrFunction& function, const MachineInput& input,
          std::size_t step_limit = 10000);

}  // namespace ember::test
