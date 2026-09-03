#pragma once

// Data models and assembly helpers shared only by the app-surface output
// translation units.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/app_surface.hpp>
#include <ember/common/types.hpp>

namespace ember::cli::builders {

struct SurfaceCategoryRow {
    std::string subsystem;
    std::string category;
    std::size_t evidence_count = 0;
    std::size_t string_count = 0;
    std::size_t artifact_count = 0;
    std::size_t symbol_count = 0;
    std::size_t objc_method_count = 0;
    std::size_t rtti_class_count = 0;
    std::size_t log_category_count = 0;
    std::size_t function_count = 0;
    std::vector<std::string> kinds;
    std::vector<std::string> examples;
};

struct SurfaceArtifactRow {
    std::string path;
    std::size_t match_count = 0;
    std::vector<std::string> subsystems;
    std::vector<std::string> categories;
};

struct SurfaceOwnerRow {
    std::string subsystem;
    std::string owner;
    std::size_t descriptor_count = 0;
    std::size_t bound_function_count = 0;
    std::size_t yield_function_count = 0;
    std::size_t property_count = 0;
    std::size_t event_count = 0;
    std::size_t remote_event_count = 0;
    std::size_t enum_count = 0;
    std::size_t type_count = 0;
    std::size_t other_count = 0;
    std::size_t function_count = 0;
    std::vector<std::string> categories;
    std::vector<std::string> arities;
    std::vector<std::string> examples;
};

struct SurfaceDescriptorRow {
    std::string subsystem;
    std::string owner;
    std::string descriptor_kind;
    std::string category;
    std::string arity;
    std::string signature;
    addr_t addr = 0;
    std::vector<addr_t> xrefs;
    std::vector<addr_t> functions;
    std::string type;
};

struct ReflectionDescriptorFields {
    std::string kind;
    std::string owner;
    std::string arity;
    std::string type;
};

[[nodiscard]] std::optional<ReflectionDescriptorFields>
parse_reflection_descriptor_fields(std::string_view text);

[[nodiscard]] std::vector<SurfaceCategoryRow>
build_surface_category_rows(const std::vector<const AppSurfaceEvidence*>& evidence);

[[nodiscard]] std::vector<SurfaceOwnerRow>
build_surface_owner_rows(const std::vector<const AppSurfaceEvidence*>& evidence);

[[nodiscard]] std::vector<SurfaceDescriptorRow>
build_surface_descriptor_rows(const std::vector<const AppSurfaceEvidence*>& evidence);

[[nodiscard]] std::vector<SurfaceArtifactRow>
build_surface_artifact_rows(const std::vector<const AppSurfaceEvidence*>& evidence);

}  // namespace ember::cli::builders
