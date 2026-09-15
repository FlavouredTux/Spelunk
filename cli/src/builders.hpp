#pragma once

#include <optional>
#include <string>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk { class Binary; }

namespace spelunk::cli {

struct GraphicsOutputFilter {
    std::string backend;
    std::string domain;
    std::string api;
    std::string extension;
    std::string category;
    std::string role;
    std::string row_type;
    std::string function_raw;
    std::optional<addr_t> function;
};

struct SurfaceOutputFilter {
    std::string subsystem;
    std::string kind;
    std::string category;
    std::string owner;
    std::string row_type;
    std::string function_raw;
    std::optional<addr_t> function;
    std::vector<std::string> artifacts;
};

// Per-subcommand output builders. Each returns the full canonical text
// that --SUBCOMMAND would print. Pulled out of main.cpp so the cached-
// output helper (run_cached) can pass them as the compute step without
// mixing dispatch with formatting.

[[nodiscard]] std::string build_strings_output     (const Binary& b);
[[nodiscard]] std::string build_graphics_output    (const Binary& b, bool json,
                                                    const GraphicsOutputFilter& filter = {});
[[nodiscard]] std::string build_surfaces_output    (const Binary& b, bool json,
                                                    const SurfaceOutputFilter& filter = {});
[[nodiscard]] std::string build_surface_artifacts_output(
    const std::vector<std::string>& artifacts, bool json,
    const SurfaceOutputFilter& filter = {});
[[nodiscard]] std::string build_log_categories_output(const Binary& b);
[[nodiscard]] std::string build_xrefs_output       (const Binary& b);
[[nodiscard]] std::string build_data_xrefs_output  (const Binary& b, bool json);
[[nodiscard]] std::string build_arities_output     (const Binary& b);
[[nodiscard]] std::string build_functions_output   (const Binary& b, bool full_analysis);
[[nodiscard]] std::string build_objc_names_output  (const Binary& b);
[[nodiscard]] std::string build_objc_protocols_output(const Binary& b);
[[nodiscard]] std::string build_objc_surfaces_output(const Binary& b);
[[nodiscard]] std::string build_rtti_output        (const Binary& b);
[[nodiscard]] std::string build_vtables_output     (const Binary& b);
[[nodiscard]] std::string build_vtable_at_output   (const Binary& b, spelunk::addr_t va,
                                                    spelunk::u64 limit);
[[nodiscard]] std::string build_int3_resolve_output(const Binary& b);

}  // namespace spelunk::cli
