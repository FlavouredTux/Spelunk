#pragma once

// Document-level assembly and postprocessing for the pseudo-C emitter.
// Kept private so the public emitter API stays focused on whole functions.

#include <map>
#include <set>
#include <string>

#include <spelunk/common/types.hpp>
#include <spelunk/ir/ir.hpp>

namespace spelunk {

class Binary;
struct StructuredFunction;

namespace emit {

struct Emitter;

struct FallbackMaterialization {
    IrValue value;
    std::string initializer;
};

[[nodiscard]] std::string
rtti_alias_comment(const Emitter& emitter, addr_t start);

[[nodiscard]] std::string
structurer_fail_markers(const StructuredFunction& function,
                        const Binary* binary);

[[nodiscard]] std::set<std::string>
matrix_stack_locals(const std::string& body);

void collect_address_taken_functions(Emitter& emitter,
                                     const std::string& body,
                                     const Binary* binary);

[[nodiscard]] std::map<u32, FallbackMaterialization>
fallback_materializations(const Emitter& emitter, const std::string& body);

[[nodiscard]] std::string
file_scope_declarations(const Emitter& emitter,
                        const std::string& declaration_context);

[[nodiscard]] std::string fallback_temp_declarations(
    const Emitter& emitter,
    const std::map<u32, FallbackMaterialization>& fallbacks);

[[nodiscard]] std::string
synthetic_merge_stack_declarations(const Emitter& emitter);

[[nodiscard]] std::string
frame_slot_declarations(const Emitter& emitter, const std::string& body,
                        const std::set<std::string>& matrix_locals);

[[nodiscard]] std::string
merge_local_declarations(const Emitter& emitter, const std::string& body);

[[nodiscard]] std::string
strip_dead_declarations(const Emitter& emitter, const std::string& output,
                        const std::string& header);

void prepend_untyped_pointer_note(std::string& output,
                                  const std::string& header);

}  // namespace emit
}  // namespace spelunk
