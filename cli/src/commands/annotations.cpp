#include <spelunk/common/diagnostic.hpp>
// Annotation export, --annotate, and type dumps.

#include <spelunk/common/annotations.hpp>

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <spelunk/analysis/identify.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/types.hpp>

#include "../args.hpp"
#include "../cli_error.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"

namespace spelunk::cli {

int run_dump_types() {
    TypeArena arena;
    std::println("type-lattice self-test");
    std::println("  arena size after seed: {}", arena.size());
    const auto i32a = arena.int_t(32);
    const auto i32b = arena.int_t(32);
    std::println("  i32 interned twice -> same id: {}",
                 i32a == i32b ? "yes" : "no");
    const auto i64t = arena.int_t(64);
    const auto pi32 = arena.ptr_t(i32a);
    const auto pi32b = arena.ptr_t(i32a);
    std::println("  ptr(i32) interned twice -> same id: {}",
                 pi32 == pi32b ? "yes" : "no");
    std::println("  meet(top, i32)            = {}",
                 arena.format(arena.meet(arena.top(), i32a)));
    std::println("  meet(i32, i32)            = {}",
                 arena.format(arena.meet(i32a, i32a)));
    std::println("  meet(i32, i64)            = {}",
                 arena.format(arena.meet(i32a, i64t)));
    const auto si32 = arena.int_t(32, true, true);
    std::println("  meet(i32, s32)            = {}",
                 arena.format(arena.meet(i32a, si32)));
    const auto ptop = arena.ptr_t(arena.top());
    std::println("  meet(ptr(i32), ptr(top))  = {}",
                 arena.format(arena.meet(pi32, ptop)));
    std::println("  meet(ptr(i32), i32)       = {}",
                 arena.format(arena.meet(pi32, i32a)));
    return EXIT_SUCCESS;
}

int run_export_annotations(const Args& args) {
    const std::filesystem::path exp_cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    const auto src = resolve_annotation_location(
        args.binary, args.annotations_path, exp_cache_dir);
    Annotations a;
    std::error_code ec;
    if (src.source != AnnotationSource::None &&
        std::filesystem::exists(src.path, ec) && !ec) {
        auto rv = Annotations::load(src.path);
        if (!rv) return report(rv.error());
        a = std::move(*rv);
    }
    auto sv = a.save(args.export_annotations);
    if (!sv) return report(sv.error());
    if (!args.quiet) {
        const std::size_t n = a.renames.size() + a.signatures.size()
                            + a.notes.size()   + a.named_constants.size();
        spelunk::diagnostic::print("spelunk: exported {} annotation(s) from {} to '{}'",
            n,
            src.source == AnnotationSource::None ? std::string{"<empty>"}
                                                 : src.path.string(),
            args.export_annotations);
    }
    return EXIT_SUCCESS;
}

int run_annotate(const Args& args, const Binary& /*b*/) {
    // One-shot annotation write. Resolves the destination file with the
    // precedence (explicit > sidecar > cache), loads the
    // existing contents, sets whichever record(s) the user asked for,
    // attaches provenance (--confidence / --evidence / --source), and
    // writes back atomically. --dry-run prints the would-be file to
    // stdout instead of touching disk.
    auto va = parse_cli_addr(args.annotate_addr);
    if (!va) {
        spelunk::diagnostic::print("spelunk: --annotate: bad address '{}'", args.annotate_addr);
        return EXIT_FAILURE;
    }

    if (args.annotate_name.empty() && args.annotate_note.empty() &&
        args.annotate_signature.empty()) {
        spelunk::diagnostic::print("spelunk: --annotate: nothing to set "
            "(pass --set-name, --set-note, or --set-signature)");
        return EXIT_FAILURE;
    }

    AnnotationMeta meta;
    if (!args.annotate_conf.empty()) {
        // Clamp to [0,1] to match the annotations parser's clamp on load.
        const auto parsed = parse_cli_double(args.annotate_conf);
        if (!parsed) {
            spelunk::diagnostic::print("spelunk: --confidence: expected a float in [0,1], got '{}'",
                args.annotate_conf);
            return EXIT_FAILURE;
        }
        float v = static_cast<float>(*parsed);
        if (v < 0.0f) v = 0.0f;
        if (v > 1.0f) v = 1.0f;
        meta.confidence = v;
    }
    meta.evidence = args.annotate_evidence;
    meta.source   = args.annotate_source.empty()
        ? std::string{"cli"}
        : args.annotate_source;
    // A user passing --evidence / --source without --confidence still
    // wants the metadata persisted; promote to a tiny non-zero
    // confidence if explicitly empty would suppress it. The serializer
    // omits empty-meta records entirely (confidence==0 + empty
    // evidence + empty source), so we have to keep at least one field
    // populated. `source` is always populated above, so this is fine.

    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};
    if (loc.source == AnnotationSource::None || loc.path.empty()) {
        spelunk::diagnostic::print("spelunk: --annotate: nowhere to write annotations "
            "(no --annotations / sidecar / cache)");
        return EXIT_FAILURE;
    }

    Annotations ann;
    {
        std::error_code ec;
        if (std::filesystem::exists(loc.path, ec) && !ec) {
            auto rv = Annotations::load(loc.path);
            if (!rv) return report(rv.error());
            ann = std::move(*rv);
        }
    }

    // Apply each requested mutation. Provenance attaches to every kind
    // the user set in this invocation - most automated flows set one
    // (typically --set-name) per call, but a human dropping in a known
    // signature might want both --set-name and --set-signature, in
    // which case both meta records get the same evidence.
    if (!args.annotate_name.empty()) {
        ann.renames[*va]      = args.annotate_name;
        ann.rename_meta[*va]  = meta;
    }
    if (!args.annotate_note.empty()) {
        ann.notes[*va]        = args.annotate_note;
        ann.note_meta[*va]    = meta;
    }
    if (!args.annotate_signature.empty()) {
        auto sig = ::spelunk::parse_signature(args.annotate_signature);
        if (!sig) {
            spelunk::diagnostic::print("spelunk: --set-signature: cannot parse '{}'",
                args.annotate_signature);
            return EXIT_FAILURE;
        }
        ann.signatures[*va]       = std::move(*sig);
        ann.signature_meta[*va]   = meta;
    }

    if (args.dry_run) {
        const std::string text = ann.to_text();
        std::fwrite(text.data(), 1, text.size(), stdout);
    } else {
        if (auto sv = ann.save(loc.path); !sv) return report(sv.error());
    }

    if (!args.quiet) {
        const char* tag = args.dry_run ? "--annotate --dry-run" : "--annotate";
        spelunk::diagnostic::print("spelunk: {}: {:#x} -> {} ({})",
            tag, static_cast<u64>(*va),
            loc.path.empty() ? std::string{"<no destination>"} : loc.path.string(),
            annotation_source_name(loc.source));
    }
    return EXIT_SUCCESS;
}

int run_list_annotations(const Args& args, const Binary& /*b*/) {
    // Walk the resolved annotations file and emit every record. Sibling
    // of `--functions --json` for the cases where what the user wrote is
    // a `--set-note` (no rename), which `--functions` can't surface
    // because its TSV row keys off the discovered name. TSV output
    // groups one record per line:
    //
    //   <hex-addr> <kind> <value> [conf=<f> [src=<tag> [ev=<text>]]]
    //
    // where <kind> is `rename` / `note` / `signature`. JSON form
    // returns one object per address with `rename` / `note` /
    // `signature` keys (only those actually set) plus the matching
    // `*_meta` blocks. Both forms emit nothing if the destination file
    // is missing - silence is correct for "no annotations yet".
    const std::filesystem::path cache_dir =
        !args.cache_dir.empty() ? std::filesystem::path{args.cache_dir}
                                : cache::default_dir();
    auto loc = resolve_annotation_location(args.binary, args.annotations_path, cache_dir);
    if (args.no_cache && loc.source == AnnotationSource::Cache) loc = {};

    Annotations ann;
    if (loc.source != AnnotationSource::None && !loc.path.empty()) {
        std::error_code ec;
        if (std::filesystem::exists(loc.path, ec) && !ec) {
            auto rv = Annotations::load(loc.path);
            if (!rv) return report(rv.error());
            ann = std::move(*rv);
        }
    }

    auto sig_to_string = [](const FunctionSig& s) {
        std::string out = s.return_type.empty() ? std::string{"void"} : s.return_type;
        out += '(';
        for (std::size_t i = 0; i < s.params.size(); ++i) {
            if (i) out += ", ";
            out += s.params[i].type;
            if (!s.params[i].name.empty()) {
                out += ' ';
                out += s.params[i].name;
            }
        }
        if (s.params.empty()) out += "void";
        out += ')';
        return out;
    };

    auto append_meta_tsv = [](std::string& row, const AnnotationMeta* m) {
        if (!m) return;
        if (m->confidence > 0.0f) {
            row += std::format("\tconf={:.3g}", m->confidence);
        }
        if (!m->source.empty()) {
            row += std::format("\tsrc={}", m->source);
        }
        if (!m->evidence.empty()) {
            row += std::format("\tev={}", escape_for_line(m->evidence));
        }
    };

    if (args.json) {
        // Build the union of all addresses appearing in any record kind
        // so each address gets one combined object, regardless of which
        // map it shows up in.
        std::set<addr_t> addrs;
        for (const auto& [a, _] : ann.renames)    addrs.insert(a);
        for (const auto& [a, _] : ann.notes)      addrs.insert(a);
        for (const auto& [a, _] : ann.signatures) addrs.insert(a);

        std::string out = "[";
        bool first = true;
        for (addr_t a : addrs) {
            if (!first) out += ',';
            first = false;
            out += std::format("{{\"addr\":\"{:#x}\"", a);
            if (auto it = ann.renames.find(a); it != ann.renames.end()) {
                out += std::format(",\"rename\":\"{}\"", json_escape(it->second));
                if (const auto* m = ann.meta_for_rename(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"rename_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"rename_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"rename_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            if (auto it = ann.notes.find(a); it != ann.notes.end()) {
                out += std::format(",\"note\":\"{}\"", json_escape(it->second));
                if (const auto* m = ann.meta_for_note(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"note_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"note_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"note_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            if (auto it = ann.signatures.find(a); it != ann.signatures.end()) {
                out += std::format(",\"signature\":\"{}\"",
                                   json_escape(sig_to_string(it->second)));
                if (const auto* m = ann.meta_for_signature(a); m) {
                    if (m->confidence > 0.0f)
                        out += std::format(",\"signature_confidence\":{:.3g}", m->confidence);
                    if (!m->source.empty())
                        out += std::format(",\"signature_source\":\"{}\"", json_escape(m->source));
                    if (!m->evidence.empty())
                        out += std::format(",\"signature_evidence\":\"{}\"", json_escape(m->evidence));
                }
            }
            out += '}';
        }
        out += "]\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        return EXIT_SUCCESS;
    }

    // TSV: one record per line. Iteration order is by address, then by
    // kind (rename, note, signature) - stable across runs so diffs read
    // cleanly.
    std::set<addr_t> addrs;
    for (const auto& [a, _] : ann.renames)    addrs.insert(a);
    for (const auto& [a, _] : ann.notes)      addrs.insert(a);
    for (const auto& [a, _] : ann.signatures) addrs.insert(a);
    std::string out;
    for (addr_t a : addrs) {
        if (auto it = ann.renames.find(a); it != ann.renames.end()) {
            std::string row = std::format("{:#x}\trename\t{}", a,
                                          escape_for_line(it->second));
            append_meta_tsv(row, ann.meta_for_rename(a));
            out += row + "\n";
        }
        if (auto it = ann.notes.find(a); it != ann.notes.end()) {
            std::string row = std::format("{:#x}\tnote\t{}", a,
                                          escape_for_line(it->second));
            append_meta_tsv(row, ann.meta_for_note(a));
            out += row + "\n";
        }
        if (auto it = ann.signatures.find(a); it != ann.signatures.end()) {
            std::string row = std::format("{:#x}\tsignature\t{}", a,
                                          escape_for_line(sig_to_string(it->second)));
            append_meta_tsv(row, ann.meta_for_signature(a));
            out += row + "\n";
        }
    }
    std::fwrite(out.data(), 1, out.size(), stdout);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
