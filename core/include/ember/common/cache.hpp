#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/error.hpp>

namespace ember::cache {

// Bump when any cached payload's on-disk format changes. Bumped to 8
// when --vm-detect handler-classification rows grew a kind-specific
// summary detail (arith mnemonic / load+store mem operand / branch
// mnemonic / call target). v7 entries would mis-render.
inline constexpr int kVersion = 8;

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
