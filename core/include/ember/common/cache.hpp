#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/error.hpp>

namespace ember::cache {

// Bump when any cached payload's on-disk format changes. Bumped to 3
// when Win64 arity inference landed: --arities now caps at 4 on PE64
// binaries (vs 6 on SysV), so v2 entries are stale.
inline constexpr int kVersion = 3;

std::filesystem::path default_dir();

Result<std::string> key_for(const std::filesystem::path& binary);

std::optional<std::string>
read(const std::filesystem::path& cache_dir,
     std::string_view key, std::string_view tag);

Result<void>
write(const std::filesystem::path& cache_dir,
      std::string_view key, std::string_view tag,
      std::string_view content);

}  // namespace ember::cache
