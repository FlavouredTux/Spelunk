#pragma once

#include "ir_interpreter.hpp"

namespace spelunk::test {

struct CleanupVerifier {
    std::size_t programs = 0;
    std::size_t executions = 0;

    // Any interpreter error fails the comparison, including exhaustion of the
    // step limit on both sides. Matching errors are not semantic equivalence.
    bool verify(const IrFunction& original, const std::vector<MachineInput>& inputs);
};

}  // namespace spelunk::test
