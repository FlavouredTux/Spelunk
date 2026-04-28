#include "args.hpp"

#include <array>
#include <filesystem>
#include <format>
#include <string_view>
#include <system_error>

namespace ember::cli {

namespace {

struct BoolFlag {
    std::string_view short_;        // may be empty
    std::string_view long_;
    bool Args::* field;
};

struct ValueFlag {
    std::string_view short_;        // may be empty
    std::string_view long_;
    std::string Args::* field;
};

constexpr auto kBoolFlags = std::to_array<BoolFlag>({
    {"-h", "--help",      &Args::help},
    {"-d", "--disasm",    &Args::disasm},
    {"-c", "--cfg",       &Args::cfg},
    {"-i", "--ir",        &Args::ir},
    {"",   "--ssa",       &Args::ssa},
    {"-O", "--opt",       &Args::opt},
    {"",   "--struct",    &Args::strct},
    {"-p", "--pseudo",    &Args::pseudo},
    {"-X", "--xrefs",     &Args::xrefs},
    {"",   "--data-xrefs", &Args::data_xrefs},
    {"",   "--strings",   &Args::strings},
    {"",   "--arities",   &Args::arities},
    {"",   "--fingerprints", &Args::fingerprints},
    {"",   "--ipa",       &Args::ipa},
    {"",   "--resolve-calls", &Args::resolve_calls},
    {"",   "--eh",        &Args::eh},
    {"",   "--objc-names", &Args::objc_names},
    {"",   "--objc-protocols", &Args::objc_protos},
    {"",   "--rtti",     &Args::rtti},
    {"",   "--vm-detect", &Args::vm_detect},
    {"",   "--cfg-pseudo", &Args::cfg_pseudo},
    {"",   "--functions", &Args::functions},
    {"",   "--collisions", &Args::collisions},
    {"",   "--no-cache",  &Args::no_cache},
    {"",   "--no-pdb",    &Args::no_pdb},
    {"",   "--full-analysis", &Args::full_analysis},
    {"",   "--dump-types", &Args::dump_types},
    {"",   "--labels",    &Args::labels},
    {"",   "--json",      &Args::json},
    {"-q", "--quiet",     &Args::quiet},
    {"",   "--dry-run",   &Args::dry_run},
});

constexpr auto kValueFlags = std::to_array<ValueFlag>({
    {"-s", "--symbol",      &Args::symbol},
    {"",   "--annotations", &Args::annotations_path},
    {"",   "--export-annotations", &Args::export_annotations},
    {"",   "--trace",       &Args::trace_path},
    {"",   "--cache-dir",   &Args::cache_dir},
    {"",   "--diff",        &Args::diff_path},
    {"",   "--diff-format", &Args::diff_format},
    {"",   "--fingerprint-out", &Args::fp_out},
    {"",   "--fingerprint-old", &Args::fp_old_in},
    {"",   "--fingerprint-new", &Args::fp_new_in},
    {"",   "--refs-to",     &Args::refs_to},
    {"",   "--callees",      &Args::callees},
    {"",   "--containing-fn", &Args::containing_fn},
    {"",   "--validate",    &Args::validate_name},
    {"",   "--callees-class", &Args::callees_class},
    {"",   "--disasm-at",   &Args::disasm_at},
    {"",   "--count",       &Args::disasm_count},
    {"",   "--apply-patches", &Args::apply_patches},
    {"",   "--apply",       &Args::apply_ember},
    {"",   "--pdb",         &Args::pdb_path},
    {"-o", "--output",      &Args::output_path},
    {"",   "--regions",     &Args::regions_manifest},
    {"",   "--raw-bytes",   &Args::raw_bytes_path},
    {"",   "--base-va",     &Args::raw_base_va},
});

template <class F>
[[nodiscard]] bool matches(std::string_view s, const F& f) {
    return (!f.short_.empty() && s == f.short_) || s == f.long_;
}

}  // namespace

void apply_stage_implications(Args& a) {
    if (a.pseudo) a.strct = true;
    if (a.strct)  a.opt   = true;
    if (a.opt)    a.ssa   = true;
    if (a.ssa)    a.ir    = true;
}

Result<Args> parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        const std::string_view s = argv[i];

        // `--functions=PATTERN` — unambiguous way to specify the filter
        // without positional-order gotchas (main vs binary path).
        if (s.starts_with("--functions=")) {
            a.functions = true;
            a.functions_pattern = std::string(s.substr(12));
            continue;
        }

        // `--pat PATH` — repeatable. Collect into a vector since the
        // bool/value-flag tables only handle single-shot scalars.
        if (s == "--pat") {
            if (++i >= argc) {
                return std::unexpected(Error::invalid_format("--pat requires a path"));
            }
            a.pat_paths.emplace_back(argv[i]);
            continue;
        }
        if (s.starts_with("--pat=")) {
            a.pat_paths.emplace_back(s.substr(6));
            continue;
        }

        // `--force-fn-start VA` — repeatable. Each VA becomes a
        // synthetic Function symbol so resolve_containing_function
        // returns a window AT the VA instead of rebinding to the
        // closest-below symbol.
        if (s == "--force-fn-start") {
            if (++i >= argc) {
                return std::unexpected(Error::invalid_format(
                    "--force-fn-start requires a hex VA"));
            }
            a.force_fn_starts.emplace_back(argv[i]);
            continue;
        }
        if (s.starts_with("--force-fn-start=")) {
            a.force_fn_starts.emplace_back(s.substr(17));
            continue;
        }

        bool hit = false;
        for (const auto& f : kBoolFlags) {
            if (matches(s, f)) { a.*f.field = true; hit = true; break; }
        }
        if (hit) continue;

        for (const auto& f : kValueFlags) {
            if (matches(s, f)) {
                if (++i >= argc) {
                    return std::unexpected(Error::invalid_format(
                        std::format("{} requires an argument", s)));
                }
                a.*f.field = argv[i];
                hit = true;
                break;
            }
        }
        if (hit) continue;

        if (s.starts_with("-")) {
            return std::unexpected(Error::invalid_format(
                std::format("unknown flag: {}", s)));
        } else if (a.binary.empty()) {
            a.binary = s;
        } else if (a.functions && a.functions_pattern.empty()) {
            a.functions_pattern = s;
        } else {
            return std::unexpected(Error::invalid_format(
                std::format("unexpected positional argument: {}", s)));
        }
    }
    // Rescue the common `ember --functions PATTERN BINARY` mis-order:
    // positionals are taken left-to-right, so a user who types the filter
    // first has PATTERN interpreted as the binary path. If the binary slot
    // names a non-existent path but the pattern slot names an existing
    // file, swap them.
    if (a.functions && !a.binary.empty() && !a.functions_pattern.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        const bool bin_is_file = fs::is_regular_file(a.binary, ec);
        const bool pat_is_file = fs::is_regular_file(a.functions_pattern, ec);
        if (!bin_is_file && pat_is_file) {
            std::swap(a.binary, a.functions_pattern);
        }
    }

    // A positional binary is not required when the user is diffing two
    // already-computed fingerprint TSVs — no bytes to parse. Likewise
    // --dump-types is a self-test that doesn't read any binary, and
    // --regions / --raw-bytes point at non-PE inputs that bypass the
    // positional argument.
    const bool diffs_from_tsvs = !a.fp_old_in.empty() && !a.fp_new_in.empty();
    if (!a.help && a.binary.empty() && !diffs_from_tsvs && !a.dump_types
        && a.regions_manifest.empty() && a.raw_bytes_path.empty()) {
        return std::unexpected(Error::invalid_format("no binary specified"));
    }
    if (!a.raw_bytes_path.empty() && a.raw_base_va.empty()) {
        return std::unexpected(Error::invalid_format(
            "--raw-bytes requires --base-va <hex>"));
    }
    apply_stage_implications(a);
    return a;
}

}  // namespace ember::cli
