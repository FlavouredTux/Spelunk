#pragma once

#include <cstddef>
#include <expected>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <ember/ir/ir.hpp>
#include <ember/ir/ssa.hpp>

namespace ember::test {

struct MachineInput {
    std::map<SsaKey, u64> values;
    std::vector<u8> memory;
};

struct Execution {
    std::optional<u64> returned;
    std::vector<u8> memory;
    bool operator==(const Execution&) const = default;
};

// Single-block SSA, integer widths 1..64, and bounded little-endian memory.
// Memory is ordinary, nonvolatile storage: compare final bytes, not the number
// of stores (DSE may remove overwritten stores). Calls, control flow, floating
// point, and ambiguous signed/unsigned Div/Mod are rejected, never skipped.
// Shift counts follow the current scalar IR convention: low 5 bits below
// 64-bit width, low 6 bits at 64-bit width. This is not an ISA emulator.
[[nodiscard]] std::expected<Execution, std::string>
interpret(const IrFunction& function, const MachineInput& input);

}  // namespace ember::test
