#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/error.hpp>

namespace ember::cache {

// Bump when any cached payload's on-disk format changes. Bumped to 5
// when --vm-detect switched from one-line TSV to a multi-line per-
// dispatcher block carrying full anatomy (opcode/pc registers, pc
// advance, bytecode VA) — old v4 cache entries are stale.
inline constexpr int kVersion = 5;

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
