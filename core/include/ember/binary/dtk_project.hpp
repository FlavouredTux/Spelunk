#pragma once

#include <filesystem>
#include <string>
#include <string_view>

#include <ember/common/error.hpp>

namespace ember {

// Resolved main-module inputs for a decomp-toolkit project. DTK paths in
// config.yml are rooted at the project directory, not the version directory.
struct DtkProject {
    std::filesystem::path project_root;
    std::filesystem::path config_path;
    std::filesystem::path object_path;
    std::filesystem::path symbols_path;
    std::string           module_name;
    std::string           version;
};

// `input` may be a project root, config/<version>, or config.yml itself.
// When a project root contains more than one version, `version` is required.
[[nodiscard]] Result<DtkProject>
resolve_dtk_project(const std::filesystem::path& input,
                    std::string_view version = {});

}  // namespace ember
