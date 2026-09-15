#pragma once

#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <spelunk/analysis/objc.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/common/annotations.hpp>
#include <spelunk/common/types.hpp>

namespace spelunk::emit {

struct Emitter;

// Owns metadata borrowed by the emitter for the duration of one render.
struct EmitterMetadataStorage {
    std::map<addr_t, std::string> local_selrefs;
    std::map<addr_t, std::string> local_classrefs;
    std::vector<ObjcMethod>       local_objc_methods;
    std::vector<ObjcIvar>         local_objc_ivars;
    std::vector<ObjcProperty>     local_objc_properties;
    std::vector<ObjcBlock>        local_objc_blocks;
    std::vector<ObjcStackBlockInvoke> local_objc_stack_blocks;
    std::map<addr_t, std::string> local_rtti_methods;
};

struct SignatureContext {
    bool has_user_sig = false;
    bool has_metadata_sig = false;
    bool has_authoritative_arity = false;
    bool has_authoritative_types = false;
    std::optional<FunctionSig> effective_metadata_signature;
};

[[nodiscard]] bool is_incomplete_decomp_signature(const FunctionSig& signature);

[[nodiscard]] std::string
signature_parameter_name(const ParamSig& parameter, std::size_t index);

void setup_emitter_metadata(Emitter& e,
                            const StructuredFunction& sf,
                            const Binary* binary,
                            EmitterMetadataStorage& storage);

SignatureContext setup_signature_context(Emitter& e,
                                         const StructuredFunction& sf,
                                         const Binary* binary,
                                         const Annotations* annotations);

}  // namespace spelunk::emit
