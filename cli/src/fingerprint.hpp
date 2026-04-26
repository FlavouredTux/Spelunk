#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/pipeline.hpp>

namespace ember { class Binary; }

namespace ember::cli {

struct Args;

// Cache tag for fingerprint TSVs. Includes the fingerprint schema version
// so schema bumps orphan old entries without nuking unrelated caches.
[[nodiscard]] std::string fingerprints_cache_tag();

// Walk the call graph of `b`, fingerprint every function, return the
// canonical TSV: <addr>\t<hash>\t<blocks>\t<insts>\t<calls>\t<dup-count>\t<name>.
[[nodiscard]] std::string build_fingerprints_output(const Binary& b);

// Read cached fingerprint TSV for `binary_path`, or compute and store it.
// Loads `binary_path` only on cache miss. Exits the process on load failure
// (this is run_diff's hot path — it has nothing to fall back to).
[[nodiscard]] std::string fingerprints_cached_or_compute(
    const std::filesystem::path& binary_path,
    const std::filesystem::path& cache_dir,
    bool no_cache);

// Variant for callers that already loaded the binary. Mirrors
// fingerprints_cached_or_compute but takes the Binary by reference, so
// --validate / --collisions don't pay the load cost twice.
[[nodiscard]] std::string fingerprints_tsv_for(const Args& args, const Binary& b);

// Parse the build_fingerprints_output TSV into the row form
// pipeline.cpp's validate_name / collect_collisions consume.
[[nodiscard]] std::vector<FingerprintRow>
fingerprint_rows_from_tsv(std::string_view tsv);

// --diff handler: compare two fingerprint TSVs (computed or read from
// --fingerprint-old/--fingerprint-new) and emit TSV or JSON.
int run_diff(const Args& args);

}  // namespace ember::cli
