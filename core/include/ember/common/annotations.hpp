#pragma once

#include <filesystem>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember {

struct ParamSig {
    std::string type;
    std::string name;
};

struct FunctionSig {
    std::string           return_type;
    std::vector<ParamSig> params;
};

// Where the current annotation file came from. Drives the writeback
// destination (a cache hit round-trips back to the cache, a sidecar
// round-trips back to the sidecar) and the one-line visibility log.
enum class AnnotationSource : u8 {
    None,
    Explicit,   // --annotations PATH or --project PATH
    Sidecar,    // <binary>.ember-annotations
    Cache,      // <cache_dir>/annotations/<path-key>/annotations.db
};

[[nodiscard]] constexpr std::string_view
annotation_source_name(AnnotationSource s) noexcept {
    switch (s) {
        case AnnotationSource::None:     return "none";
        case AnnotationSource::Explicit: return "explicit";
        case AnnotationSource::Sidecar:  return "sidecar";
        case AnnotationSource::Cache:    return "cache";
    }
    return "?";
}

struct AnnotationLocation {
    std::filesystem::path path;
    AnnotationSource      source = AnnotationSource::None;
};

// The sidecar filename ember looks for next to `binary`. Callers that
// don't care about the full resolver can still use this path directly.
[[nodiscard]] std::filesystem::path
sidecar_annotation_path(const std::filesystem::path& binary);

// Cache path for the resolved annotations file. Keyed by
// `basename + '@' + fnv1a_64(parent_abspath)` — deliberately NOT by
// content hash, so annotations survive binary version swaps at the same
// path. `cache_dir` is usually `ember::cache::default_dir()`.
[[nodiscard]] std::filesystem::path
cache_annotation_path(const std::filesystem::path& binary,
                      const std::filesystem::path& cache_dir);

// Resolve which annotation file to read and (symmetrically) write back
// to. Precedence:
//   1. explicit_path (--annotations / --project) — always wins.
//   2. `<binary>.ember-annotations` sidecar — when the file exists.
//   3. Cache path — returned even when the file doesn't exist yet, so
//      the first commit has a destination.
// Returns source=None and an empty path only when both `binary` and
// `explicit_path` are empty.
[[nodiscard]] AnnotationLocation
resolve_annotation_location(const std::filesystem::path& binary,
                            const std::filesystem::path& explicit_path,
                            const std::filesystem::path& cache_dir);

// On-disk format, one record per line:
//
//   rename <hex-addr>  <new-name>
//   sig    <hex-addr>  <return-type>|<param-type>|<param-name>|...
//   note   <hex-addr>  <text>
//   const  <hex-value> <name>
//
// Addresses are hex without a 0x prefix. The `const` record names a
// numeric immediate (width-agnostic) — its primary use is mapping a
// runtime-resolver hash like `0xDEADBEEF` to the API it resolves to,
// e.g. `kernel32!CreateFileW`. Per-version Hyperion-style hash tables
// are dropped in via this record.
//
// Blank lines and lines starting with `#` are ignored. Unknown record
// kinds are skipped.
struct Annotations {
    std::map<addr_t, std::string>  renames;
    std::map<addr_t, FunctionSig>  signatures;
    std::map<addr_t, std::string>  notes;
    std::map<u64,    std::string>  named_constants;

    static Result<Annotations>
    load(const std::filesystem::path& path);

    Result<void>
    save(const std::filesystem::path& path) const;

    // Canonical on-disk text (the same content `save` writes). Exposed
    // so dry-run callers can emit the would-be file to stdout without
    // touching disk.
    [[nodiscard]] std::string to_text() const;

    const std::string* name_for(addr_t a) const noexcept {
        auto it = renames.find(a);
        return it == renames.end() ? nullptr : &it->second;
    }

    const FunctionSig* signature_for(addr_t a) const noexcept {
        auto it = signatures.find(a);
        return it == signatures.end() ? nullptr : &it->second;
    }

    const std::string* note_for(addr_t a) const noexcept {
        auto it = notes.find(a);
        return it == notes.end() ? nullptr : &it->second;
    }

    const std::string* constant_name_for(u64 v) const noexcept {
        auto it = named_constants.find(v);
        return it == named_constants.end() ? nullptr : &it->second;
    }
};

}  // namespace ember
