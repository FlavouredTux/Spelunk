#pragma once

#include <string>
#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;

struct AppSurfaceEvidence {
    std::string         subsystem;
    std::string         kind;
    std::string         category;
    addr_t              addr = 0;
    std::string         text;
    std::vector<addr_t> xrefs;
    std::vector<addr_t> functions;
};

struct AppSurfaceFunction {
    std::string              subsystem;
    addr_t                   function = 0;
    std::size_t              evidence_count = 0;
    std::vector<std::string> categories;
    std::vector<std::string> evidence;
};

struct AppSurfaceSummary {
    std::string              subsystem;
    std::size_t              string_count = 0;
    std::size_t              artifact_count = 0;
    std::size_t              symbol_count = 0;
    std::size_t              objc_method_count = 0;
    std::size_t              rtti_class_count = 0;
    std::size_t              log_category_count = 0;
    std::size_t              function_count = 0;
    std::vector<std::string> categories;
    std::vector<std::string> evidence;
};

struct AppSurfaceAnalysis {
    std::vector<AppSurfaceSummary>  summaries;
    std::vector<AppSurfaceFunction> functions;
    std::vector<AppSurfaceEvidence> evidence;
};

struct AppSurfaceOptions {
    std::vector<std::string> artifact_strings;
    bool artifacts_only = false;
    bool reflection_only = false;
};

[[nodiscard]] AppSurfaceAnalysis analyze_app_surfaces(const Binary& b,
                                                      const AppSurfaceOptions& options = {});
[[nodiscard]] AppSurfaceAnalysis analyze_app_surface_artifacts(
    const std::vector<std::string>& artifacts);

}  // namespace spelunk
