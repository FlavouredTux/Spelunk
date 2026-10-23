#include <spelunk/common/diagnostic.hpp>
// Whole-binary inventories: xrefs, strings, surfaces, graphics.

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <spelunk/analysis/identify.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/hash.hpp>
#include <spelunk/common/types.hpp>

#include "../args.hpp"
#include "../builders.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"

namespace spelunk::cli {

namespace {

constexpr std::string_view kXrefsCacheTag = "xrefs-v5";

[[nodiscard]] std::vector<std::string>
collect_bundle_artifacts(const std::filesystem::path& binary_path) {
    std::vector<std::string> out;
    std::error_code ec;
    auto path = std::filesystem::weakly_canonical(binary_path, ec);
    if (ec) {
        ec.clear();
        path = binary_path;
    }

    std::filesystem::path app_root;
    for (auto cur = path.parent_path(); !cur.empty(); cur = cur.parent_path()) {
        if (cur.extension() == ".app") {
            app_root = cur;
            break;
        }
        if (cur == cur.root_path()) break;
    }
    if (app_root.empty()) return out;

    constexpr std::size_t kMaxArtifacts = 4096;
    auto opts = std::filesystem::directory_options::skip_permission_denied;
    std::filesystem::recursive_directory_iterator it(app_root, opts, ec);
    std::filesystem::recursive_directory_iterator end;
    if (ec) return out;
    for (; it != end && out.size() < kMaxArtifacts; it.increment(ec)) {
        if (ec) break;
        std::error_code file_ec;
        if (!it->is_regular_file(file_ec) || file_ec) continue;
        auto rel = std::filesystem::relative(it->path(), app_root, file_ec);
        if (file_ec) {
            file_ec.clear();
            rel = it->path().filename();
        }
        out.push_back(rel.generic_string());
    }
    std::ranges::sort(out);
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

[[nodiscard]] u64 hash_artifacts(const std::vector<std::string>& artifacts) {
    std::string manifest;
    for (const auto& artifact : artifacts) {
        manifest += artifact;
        manifest.push_back('\n');
    }
    return fnv1a_64(manifest);
}

[[nodiscard]] bool equals_ascii_ci(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) return false;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        const auto l = static_cast<unsigned char>(lhs[i]);
        const auto r = static_cast<unsigned char>(rhs[i]);
        if (std::tolower(l) != std::tolower(r)) return false;
    }
    return true;
}

[[nodiscard]] bool surface_filter_is_artifacts_only(const SurfaceOutputFilter& filter) {
    if (filter.function) return false;
    if (!filter.owner.empty()) return false;
    if (equals_ascii_ci(filter.row_type, "artifact") &&
        (filter.kind.empty() || equals_ascii_ci(filter.kind, "bundle_file"))) {
        return true;
    }
    return equals_ascii_ci(filter.kind, "bundle_file") &&
           (equals_ascii_ci(filter.row_type, "evidence") ||
            equals_ascii_ci(filter.row_type, "category") ||
            equals_ascii_ci(filter.row_type, "artifact") ||
            equals_ascii_ci(filter.row_type, "all"));
}

[[nodiscard]] std::string surface_cache_tag(const Args& args,
                                            const SurfaceOutputFilter& filter) {
    std::string tag = args.json ? "surfaces-json-v2" : "surfaces-v2";
    if (!filter.subsystem.empty()) tag += "|surface=" + filter.subsystem;
    if (!filter.kind.empty()) tag += "|kind=" + filter.kind;
    if (!filter.category.empty()) tag += "|category=" + filter.category;
    if (!filter.owner.empty()) tag += "|owner=" + filter.owner;
    if (!filter.row_type.empty()) tag += "|row_type=" + filter.row_type;
    if (!filter.function_raw.empty()) tag += "|function=" + filter.function_raw;
    if (!filter.artifacts.empty()) {
        tag += std::format("|bundle={}:{:016x}", filter.artifacts.size(),
                           hash_artifacts(filter.artifacts));
    }
    return tag;
}

[[nodiscard]] std::optional<SurfaceOutputFilter>
make_surface_filter(const Args& args, bool include_artifacts) {
    SurfaceOutputFilter filter{
        .subsystem = args.surface,
        .kind = args.surface_kind,
        .category = args.surface_category,
        .owner = args.surface_owner,
        .row_type = args.surface_row_type,
        .function_raw = args.surface_function,
        .function = std::nullopt,
        .artifacts = include_artifacts ? collect_bundle_artifacts(args.binary)
                                       : std::vector<std::string>{},
    };
    if (!filter.function_raw.empty()) {
        filter.function = parse_cli_addr(filter.function_raw);
        if (!filter.function) {
            spelunk::diagnostic::print("spelunk: --surface-function: bad address '{}'",
                         filter.function_raw);
            return std::nullopt;
        }
    }
    return filter;
}

}  // namespace

int run_xrefs(const Args& args, const Binary& b) {
    return run_cached(args, kXrefsCacheTag, [&] { return build_xrefs_output(b); });
}

int run_data_xrefs(const Args& args, const Binary& b) {
    // TSV and JSON share the compute step but differ in output format,
    // so they cache under distinct tags - otherwise the first form
    // served would silently satisfy the second.
    const std::string_view tag = args.json ? "data-xrefs-json-v2" : "data-xrefs-v2";
    return run_cached(args, tag, [&] { return build_data_xrefs_output(b, args.json); });
}

int run_strings(const Args& args, const Binary& b) {
    // Cache tag bumped to v2 when the scanner started covering executable
    // sections (Mach-O __cstring lives in __TEXT). Old "strings" cache
    // entries from before that change are now orphaned. JSON caches apart,
    // as with --data-xrefs.
    const std::string_view tag = args.json ? "strings-json-v1" : "strings-v2";
    return run_cached(args, tag, [&] { return build_strings_output(b, args.json); });
}

bool surfaces_artifacts_only_requested(const Args& args) {
    if (!args.surfaces) return false;
    const auto filter = make_surface_filter(args, /*include_artifacts=*/false);
    return filter && surface_filter_is_artifacts_only(*filter);
}

int run_surface_artifacts(const Args& args) {
    auto filter = make_surface_filter(args, /*include_artifacts=*/true);
    if (!filter) return 2;
    const auto tag = surface_cache_tag(args, *filter);
    return run_cached(args, tag, [&] {
        return build_surface_artifacts_output(filter->artifacts, args.json, *filter);
    });
}

int run_surfaces(const Args& args, const Binary& b) {
    auto filter = make_surface_filter(args, /*include_artifacts=*/true);
    if (!filter) return 2;
    const auto tag = surface_cache_tag(args, *filter);
    return run_cached(args, tag, [&] {
        return build_surfaces_output(b, args.json, *filter);
    });
}

int run_graphics(const Args& args, const Binary& b) {
    GraphicsOutputFilter filter{
        .backend = args.graphics_backend,
        .domain = args.graphics_domain,
        .api = args.graphics_api,
        .extension = args.graphics_extension,
        .category = args.graphics_category,
        .role = args.graphics_role,
        .row_type = args.graphics_row_type,
        .function_raw = args.graphics_function,
        .function = std::nullopt,
    };
    if (!filter.function_raw.empty()) {
        filter.function = parse_cli_addr(filter.function_raw);
        if (!filter.function) {
            spelunk::diagnostic::print("spelunk: --graphics-function: bad address '{}'",
                         filter.function_raw);
            return 2;
        }
    }
    std::string tag = args.json ? "graphics-json-v13" : "graphics-v13";
    if (!filter.backend.empty()) tag += "|backend=" + filter.backend;
    if (!filter.domain.empty()) tag += "|domain=" + filter.domain;
    if (!filter.api.empty()) tag += "|api=" + filter.api;
    if (!filter.extension.empty()) tag += "|extension=" + filter.extension;
    if (!filter.category.empty()) tag += "|category=" + filter.category;
    if (!filter.role.empty()) tag += "|role=" + filter.role;
    if (!filter.row_type.empty()) tag += "|row_type=" + filter.row_type;
    if (!filter.function_raw.empty()) tag += "|function=" + filter.function_raw;
    return run_cached(args, tag, [&] {
        return build_graphics_output(b, args.json, filter);
    });
}

int run_log_categories(const Args& args, const Binary& b) {
    return run_cached(args, "log-categories-v1",
                      [&] { return build_log_categories_output(b); });
}

}  // namespace spelunk::cli
