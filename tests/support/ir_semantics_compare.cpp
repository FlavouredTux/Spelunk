#include "ir_semantics_compare.hpp"

#include <cstdio>
#include <format>
#include <ember/ir/passes.hpp>

namespace ember::test {
namespace {

bool compare_execution(const IrFunction& original, const IrFunction& cleaned,
                       const MachineInput& input) {
    const auto before = interpret(original, input);
    const auto after = interpret(cleaned, input);
    if (before && after && *before == *after) return true;
    std::fprintf(stderr, "FAIL: semantic mismatch in %s\n", original.name.c_str());
    for (const auto& [key, value] : input.values) {
        std::fprintf(stderr, "input (%u,%u,%u) = %s\n",
                     static_cast<unsigned>(std::get<0>(key)),
                     std::get<1>(key), std::get<2>(key),
                     std::format("{:#018x}", value).c_str());
    }
    std::fprintf(stderr, "initial memory:");
    for (u8 byte : input.memory) std::fprintf(stderr, " %02x", static_cast<unsigned>(byte));
    std::fprintf(stderr, "\nbefore: %s\nafter: %s\n",
                 before ? (before->returned ? std::format("{:#x}", *before->returned).c_str() : "void") : before.error().c_str(),
                 after ? (after->returned ? std::format("{:#x}", *after->returned).c_str() : "void") : after.error().c_str());
    if (before && after && before->memory != after->memory) {
        for (std::size_t i = 0; i < before->memory.size(); ++i) {
            if (before->memory[i] != after->memory[i]) {
                std::fprintf(stderr, "memory[%zu]: %02x -> %02x\n", i,
                             static_cast<unsigned>(before->memory[i]),
                             static_cast<unsigned>(after->memory[i]));
            }
        }
    }
    std::fprintf(stderr, "Original IR:\n%s\nCleaned IR:\n%s\n",
                 format_ir_function(original).c_str(), format_ir_function(cleaned).c_str());
    return false;
}

}  // namespace

bool CleanupVerifier::verify(const IrFunction& original, const std::vector<MachineInput>& inputs) {
    IrFunction cleaned = original;
    const auto result = run_cleanup(cleaned);
    ++programs;
    if (!result) {
        std::fprintf(stderr, "FAIL: cleanup failed for %s\n", original.name.c_str());
        return false;
    }
    for (const auto& input : inputs) {
        ++executions;
        if (!compare_execution(original, cleaned, input)) return false;
    }
    return true;
}

}  // namespace ember::test
