#pragma once

// Private implementation boundary shared by the TEEF command front ends.

#include <iosfwd>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <spelunk/analysis/teef.hpp>

namespace spelunk::cli {

struct Args;
struct ModuleScope;

namespace teef_internal {

[[nodiscard]] bool
is_compiler_partition_variant(std::string_view name) noexcept;

[[nodiscard]] std::string cache_tag(const Args& args);

[[nodiscard]] std::vector<std::pair<addr_t, TeefFunction>>
parse_tsv(std::string_view tsv);

[[nodiscard]] std::string
build_tsv(const Binary& binary,
          const ModuleScope& scope,
          bool corpus_mode,
          u64 min_fn_bytes,
          u64 max_fn_bytes,
          const TeefComputeOptions& compute_options,
          std::ostream* stream = nullptr);

}  // namespace teef_internal
}  // namespace spelunk::cli
