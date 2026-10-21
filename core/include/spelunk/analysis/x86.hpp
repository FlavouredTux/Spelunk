#pragma once

#include <vector>

#include <spelunk/analysis/arity.hpp>

namespace spelunk {

// x86 Windows conventions are per-function, rather than per-image. Keep
// stack cleanup separate from arity: RET n includes unused stack arguments.
struct X86FunctionInfo {
    Abi abi = Abi::Win32Cdecl;
    u16 callee_pop = 0;
    std::vector<InferredArgument> arguments;
};

[[nodiscard]] X86FunctionInfo
analyze_x86_function(const Binary& binary, addr_t entry);

} // namespace spelunk
