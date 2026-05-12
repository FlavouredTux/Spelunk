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

    // Explicit --annotations path always wins - sidecar and cache are
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

    // Cache key is stable across content changes at the same path - the
    // whole reason for path-keying over content-hashing. Rewrite the
    // fixture and expect the same cache path back.
    const auto cache_before = ember::cache_annotation_path(bin_a, cache);
    write_stub(bin_a, "v2 - different bytes entirely, longer");
    const auto cache_after = ember::cache_annotation_path(bin_a, cache);
    check_eq(cache_before.string(), cache_after.string(),
             "cache path stable across binary content change");

    // Cache key changes when the binary moves directories - same
    // basename in a different parent must not share annotations.
    const auto bin_b = write_stub(root / "b" / "prog", "v1");
    const auto cache_b = ember::cache_annotation_path(bin_b, cache);
    if (cache_b.string() == cache_after.string()) {
        fail("cache key collides across directories",
             cache_b.string());
    }

    // ----------------------------------------------------------------
    // meta record round-trip + forward / backward compat.
    //
    // Phase 1 added an `AnnotationMeta` (confidence / evidence / source)
    // attached to renames / notes / signatures via parallel maps and a
    // new `meta <kind> <addr> ...` line. Three properties are
    // load-bearing:
    //   1. round-trip - write a populated Annotations, reload, see
    //      the same metadata,
    //   2. backward compat - files without `meta` lines load with
    //      empty metadata (no crash, no spurious entries),
    //   3. forward compat - files with `meta` lines for unknown
    //      subkinds or unknown keys are silently skipped, and the
    //      primary records remain untouched.
    // ----------------------------------------------------------------
    {
        const auto path = root / "meta_round_trip.ann";
        ember::Annotations a;
        a.renames[0x401000]      = "do_thing";
        a.notes[0x401000]        = "see ticket #42";
        ember::AnnotationMeta rm;
        rm.confidence = 0.875f;
        rm.evidence   = "3-arg, called by 0x3f94380; pipe |, newline\n in ev";
        rm.source     = "agent:namer";
        a.rename_meta[0x401000] = rm;
        a.note_meta[0x401000]   = ember::AnnotationMeta{0.5f, "from doc-comment", "cli"};

        if (auto rv = a.save(path); !rv) {
            fail("save with metadata", "ought to write cleanly");
        }
        auto loaded = ember::Annotations::load(path);
        if (!loaded) {
            fail("load round-trip", "save then load failed");
        } else {
            const auto* m = loaded->meta_for_rename(0x401000);
            if (!m) fail("rename meta missing after round-trip", path.string());
            else {
                if (m->confidence < 0.87f || m->confidence > 0.88f) {
                    fail("rename meta confidence drifted",
                         std::to_string(m->confidence));
                }
                check_eq(m->evidence, rm.evidence,
                         "rename meta evidence survives pipe + newline escapes");
                check_eq(m->source, rm.source, "rename meta source preserved");
            }
            const auto* n = loaded->meta_for_note(0x401000);
            if (!n) fail("note meta missing after round-trip", path.string());
            else check_eq(n->source, std::string{"cli"}, "note meta source preserved");
            // Sanity: the name itself must still be there.
            const auto* name = loaded->name_for(0x401000);
            if (!name || *name != "do_thing") {
                fail("rename text drifted under meta serializer",
                     name ? *name : std::string{"<null>"});
            }
        }
    }

    // Backward compat: a file with no `meta` lines is the existing
    // baseline. Loaders treat absent metadata as nullptr from
    // `meta_for_rename` etc. (different from "metadata recorded with
    // confidence=0", which would still return a valid pointer).
    {
        const auto path = root / "no_meta.ann";
        write_stub(path, "# legacy file\n"
                         "rename 401000 do_thing\n"
                         "note   401000 hand-written; no meta line\n");
        auto loaded = ember::Annotations::load(path);
        if (!loaded) fail("backward compat load", "legacy file rejected");
        else {
            if (loaded->meta_for_rename(0x401000) != nullptr) {
                fail("backward compat: spurious rename meta", path.string());
            }
            if (loaded->meta_for_note(0x401000) != nullptr) {
                fail("backward compat: spurious note meta", path.string());
            }
            const auto* name = loaded->name_for(0x401000);
            if (!name || *name != "do_thing") {
                fail("backward compat: rename lost",
                     name ? *name : std::string{"<null>"});
            }
        }
    }

    // Forward compat: an unknown meta subkind and unknown meta keys
    // must not corrupt the primary records or crash the parser. An
    // older ember reading a file produced by a newer ember should see
    // the names / notes intact and silently drop what it doesn't
    // recognise.
    {
        const auto path = root / "future_meta.ann";
        write_stub(path,
            "# ember annotations\n"
            "rename 401000 do_thing\n"
            "meta rename 401000 conf=0.9|src=cli|future_key=x|ev=ok\n"
            "meta unknown_kind 401000 conf=1|src=mystery\n"
            "rename 402000 other_fn\n");
        auto loaded = ember::Annotations::load(path);
        if (!loaded) fail("forward compat load", "newer-format file rejected");
        else {
            const auto* m = loaded->meta_for_rename(0x401000);
            if (!m) fail("forward compat: known meta dropped", path.string());
            else {
                if (m->confidence < 0.89f || m->confidence > 0.91f) {
                    fail("forward compat: confidence parsing fragile under unknown keys",
                         std::to_string(m->confidence));
                }
                check_eq(m->evidence, std::string{"ok"},
                         "forward compat: known keys survive alongside unknown ones");
            }
            const auto* name = loaded->name_for(0x402000);
            if (!name || *name != "other_fn") {
                fail("forward compat: subsequent records lost after unknown meta",
                     name ? *name : std::string{"<null>"});
            }
        }
    }

    // Confidence clamping: values outside [0,1] would break downstream
    // consumers (sort by conf, threshold filters, etc.). The parser
    // clamps on load, the CLI clamps on write - covered here for the
    // load path.
    {
        const auto path = root / "clamp.ann";
        write_stub(path,
            "rename 401000 too_high\n"
            "meta rename 401000 conf=2.5\n"
            "rename 402000 too_low\n"
            "meta rename 402000 conf=-0.5\n");
        auto loaded = ember::Annotations::load(path);
        if (!loaded) fail("clamp load", "rejected unexpectedly");
        else {
            const auto* hi = loaded->meta_for_rename(0x401000);
            const auto* lo = loaded->meta_for_rename(0x402000);
            if (!hi || hi->confidence != 1.0f) {
                fail("clamp: above-1 not clamped",
                     hi ? std::to_string(hi->confidence) : std::string{"<null>"});
            }
            if (!lo || lo->confidence != 0.0f) {
                fail("clamp: below-0 not clamped",
                     lo ? std::to_string(lo->confidence) : std::string{"<null>"});
            }
        }
    }

    if (fails == 0) std::puts("ok");
    return fails == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
