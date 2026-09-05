#pragma once

#include "ir_interpreter.hpp"

namespace ember::test {

// Reject malformed CFG/SSA before execution can reuse stale loop values.
// Throws std::runtime_error, translated by interpret into a test failure.
void validate_interpreter_cfg(const IrFunction& function, const MachineInput& input);

}  // namespace ember::test
