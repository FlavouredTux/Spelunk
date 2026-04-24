#include <ember/common/annotations.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;

namespace {

int fails = 0;

void fail(const char* what, const std::string& ctx) {
    std::fprintf(stderr, "FAIL: %s\n  %s\n", what, ctx.c_str());
    ++fails;
}

void check_eq(const std::string& got, const std::string& want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s\n  got:  %s\n  want: %s\n",
                     ctx, got.c_str(), want.c_str());
        ++fails;
    }
}

void check_source(ember::AnnotationSource got, ember::AnnotationSource want,
                  const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s\n  got:  %s\n  want: %s\n",
                     ctx,
                     std::string(ember::annotation_source_name(got)).c_str(),
                     std::string(ember::annotation_source_name(want)).c_str());
        ++fails;
    }
}

fs::path scratch_root() {
    auto p = fs::temp_directory_path() / "ember_resolver_test";
    std::error_code ec;
    fs::remove_all(p, ec);
    fs::create_directories(p);
    return p;
}

fs::path write_stub(const fs::path& p, std::string_view bytes) {
    fs::create_directories(p.parent_path());
    std::ofstream o(p, std::ios::binary);
    o.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    return p;
}

}  // namespace

int main() {
    const auto root = scratch_root();
    const auto cache = root / "cache";

    // Fixture binary with no sidecar: resolver falls through to the
    // cache path (returned even when the file doesn't yet exist so the
    // first commit has a destination).
    const auto bin_a = write_stub(root / "a" / "prog", "v1");
    {
        auto loc = ember::resolve_annotation_location(bin_a, {}, cache);
        check_source(loc.source, ember::AnnotationSource::Cache,
                     "no sidecar → cache");
        if (loc.path.parent_path().parent_path().filename() != "annotations") {
            fail("cache path not under <cache>/annotations/",
                 loc.path.string());
        }
    }

    // Dropping the sidecar flips the resolver from cache to sidecar
    // without any flag change.
    write_stub(ember::sidecar_annotation_path(bin_a), "rename 100 foo\n");
    {
        auto loc = ember::resolve_annotation_location(bin_a, {}, cache);
        check_source(loc.source, ember::AnnotationSource::Sidecar,
                     "sidecar present → sidecar");
        check_eq(loc.path.string(),
                 ember::sidecar_annotation_path(bin_a).string(),
                 "sidecar path");
    }

    // Explicit --annotations path always wins — sidecar and cache are
    // both ignored, the path is returned verbatim regardless of whether
    // it exists yet.
    const auto explicit_path = root / "some" / "file.db";
    {
        auto loc = ember::resolve_annotation_location(
            bin_a, explicit_path, cache);
        check_source(loc.source, ember::AnnotationSource::Explicit,
                     "explicit overrides sidecar");
        check_eq(loc.path.string(), explicit_path.string(),
                 "explicit path preserved");
    }

    // Cache key is stable across content changes at the same path — the
    // whole reason for path-keying over content-hashing. Rewrite the
    // fixture and expect the same cache path back.
    const auto cache_before = ember::cache_annotation_path(bin_a, cache);
    write_stub(bin_a, "v2 — different bytes entirely, longer");
    const auto cache_after = ember::cache_annotation_path(bin_a, cache);
    check_eq(cache_before.string(), cache_after.string(),
             "cache path stable across binary content change");

    // Cache key changes when the binary moves directories — same
    // basename in a different parent must not share annotations.
    const auto bin_b = write_stub(root / "b" / "prog", "v1");
    const auto cache_b = ember::cache_annotation_path(bin_b, cache);
    if (cache_b.string() == cache_after.string()) {
        fail("cache key collides across directories",
             cache_b.string());
    }

    if (fails == 0) std::puts("ok");
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
