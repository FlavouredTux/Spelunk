#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <ember/common/error.hpp>

namespace ember::cache {

// Bump when any cached payload's on-disk format changes. Bumped to 12
// when the vm-detect dispatcher walker grew stack-slot shadow tracking
// (mov [base+disp], reg save / mov reg, [base+disp] restore) — the
// new fixture's VM #6 only shows up under v12.
inline constexpr int kVersion = 12;

std::filesystem::path default_dir();

// `scope_tag`, when non-empty, is folded into the manifest before
// hashing — use it to differentiate cache slots that share the same
// binary but were produced under different analysis scopes
// (e.g. --module restricts enumerate_functions to one DLL of a
// minidump; without folding the scope into the key, switching modules
// silently serves the previous module's cached output). Empty tag
// reproduces the legacy whole-binary key.
Result<std::string>
key_for(const std::filesystem::path& binary, std::string_view scope_tag = {});

std::optional<std::string>
read(const std::filesystem::path& cache_dir,
     std::string_view key, std::string_view tag);

Result<void>
write(const std::filesystem::path& cache_dir,
      std::string_view key, std::string_view tag,
      std::string_view content);

}  // namespace ember::cache
