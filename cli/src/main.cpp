#include <cstdlib>
#include <memory>
#include <print>
#include <utility>

#include <ember/binary/binary.hpp>
#include <ember/binary/raw_regions.hpp>
#include <ember/common/error.hpp>

#include "args.hpp"
#include "cli_error.hpp"
#include "dbg.hpp"
#include "fingerprint.hpp"
#include "info.hpp"
#include "patches.hpp"
#include "subcommands.hpp"

namespace {

void apply_quiet_env(const ember::cli::Args& args) {
    if (!args.quiet) return;
#ifdef _WIN32
    ::_putenv_s("EMBER_QUIET", "1");
#else
    ::setenv("EMBER_QUIET", "1", 1);
#endif
}

[[nodiscard]] ember::Result<std::unique_ptr<ember::Binary>>
load_binary_from_args(const ember::cli::Args& args) {
    // --regions skips magic-byte dispatch and loads via the manifest
    // path; the manifest's first region's vaddr becomes the natural
    // entry for analysis (the user can override with -s <addr>).
    if (!args.regions_manifest.empty()) {
        auto rr = ember::RawRegionsBinary::load_from_manifest(args.regions_manifest);
        if (!rr) return std::unexpected(std::move(rr).error());
        return std::unique_ptr<ember::Binary>(std::move(*rr));
    }
    // --raw-bytes is the one-region shortcut for runtime captures —
    // splice a memory dump into a single rwx region at --base-va. No
    // PE container, no manifest. base_va parsed as 0x-prefixed or
    // bare hex; bases parsed as hex regardless of prefix to match the
    // rest of the CLI's address-flag style.
    if (!args.raw_bytes_path.empty()) {
        std::string_view va_tok = args.raw_base_va;
        if (va_tok.starts_with("0x") || va_tok.starts_with("0X")) {
            va_tok.remove_prefix(2);
        }
        ember::addr_t va = 0;
        for (char c : va_tok) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                : -1;
            if (d < 0) {
                return std::unexpected(ember::Error::invalid_format(
                    "raw-bytes: --base-va must be hex"));
            }
            va = (va << 4) | static_cast<ember::addr_t>(d);
        }
        auto rr = ember::RawRegionsBinary::load_from_raw_bytes(
            args.raw_bytes_path, va);
        if (!rr) return std::unexpected(std::move(rr).error());
        return std::unique_ptr<ember::Binary>(std::move(*rr));
    }
    ember::LoadOptions opts;
    if (!args.pdb_path.empty()) opts.pdb_path = args.pdb_path;
    opts.no_pdb = args.no_pdb;
    return ember::load_binary(args.binary, opts);
}

}  // namespace

int main(int argc, char** argv) {
    using namespace ember::cli;

    auto args_r = parse_args(argc, argv);
    if (!args_r) {
        std::println(stderr, "ember: {}", args_r.error().message);
        print_help();
        return EXIT_FAILURE;
    }
    const auto& args = *args_r;

    apply_quiet_env(args);

    if (args.help)        { print_help();             return EXIT_SUCCESS; }
    if (args.dump_types)  { return run_dump_types();                       }

    if (!args.diff_path.empty() ||
        !args.fp_old_in.empty() ||
        !args.fp_new_in.empty()) {
        return run_diff(args);
    }
    // --apply-patches is a one-shot file operation: it loads the binary
    // only to consult the section table for vaddr→file-offset
    // translation, then writes a patched copy. No analysis runs.
    if (!args.apply_patches.empty()) return run_apply_patches(args);

    // Aux-binary loading happens once, up front, so both the no-primary
    // (--attach-pid) and primary-loaded paths share the same setup.
    // Each `--aux-binary PATH[@HEX]` token is split on '@'; the
    // optional hex tail pins the runtime base for the slide computation
    // (the debugger will skip its /proc/maps size-match heuristic).
    std::vector<std::unique_ptr<ember::Binary>>          aux_storage;
    std::vector<ember::cli::AuxBinarySpec>               aux_specs;
    aux_storage.reserve(args.aux_binary_paths.size());
    aux_specs.reserve(args.aux_binary_paths.size());
    for (const auto& tok : args.aux_binary_paths) {
        std::string path = tok;
        std::optional<ember::addr_t> manual_base;
        if (auto at = tok.find('@'); at != std::string::npos) {
            path = tok.substr(0, at);
            std::string_view va_tok = std::string_view(tok).substr(at + 1);
            if (va_tok.starts_with("0x") || va_tok.starts_with("0X")) {
                va_tok.remove_prefix(2);
            }
            ember::addr_t v = 0;
            bool ok = !va_tok.empty();
            for (char c : va_tok) {
                const int d = (c >= '0' && c <= '9') ? c - '0'
                    : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                    : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                    : -1;
                if (d < 0) { ok = false; break; }
                v = (v << 4) | static_cast<ember::addr_t>(d);
            }
            if (!ok) {
                std::println(stderr,
                    "ember: --aux-binary: bad hex base after '@' in '{}'", tok);
                return EXIT_FAILURE;
            }
            manual_base = v;
        }
        auto loaded = ember::load_binary(path);
        if (!loaded) {
            std::println(stderr, "ember: --aux-binary {}: {}: {}",
                         path, loaded.error().kind_name(),
                         loaded.error().message);
            return EXIT_FAILURE;
        }
        aux_storage.push_back(std::move(*loaded));
        aux_specs.push_back({aux_storage.back().get(), std::move(path), manual_base});
    }

    // --debug --attach-pid PID can run without a binary path; the
    // REPL auto-attaches and symbol resolution falls back to aux
    // binaries (or nothing).
    if (args.debug && args.binary.empty()) {
        return run_debug(args, nullptr, aux_specs);
    }

    auto bin = load_binary_from_args(args);
    if (!bin) return report(bin.error());

    // --force-fn-start: synthesize Function symbols at each user-
    // specified VA so resolve_containing_function returns a window AT
    // the VA instead of rebinding to the closest-below symbol. Common
    // when obfuscators merge functions or stash a real entry mid-body.
    for (const auto& tok : args.force_fn_starts) {
        std::string_view va_tok = tok;
        if (va_tok.starts_with("0x") || va_tok.starts_with("0X")) {
            va_tok.remove_prefix(2);
        } else if (va_tok.starts_with("sub_")) {
            va_tok.remove_prefix(4);
        }
        ember::addr_t va = 0;
        bool ok = !va_tok.empty();
        for (char c : va_tok) {
            const int d = (c >= '0' && c <= '9') ? c - '0'
                : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                : -1;
            if (d < 0) { ok = false; break; }
            va = (va << 4) | static_cast<ember::addr_t>(d);
        }
        if (!ok) {
            std::println(stderr, "ember: --force-fn-start: bad hex VA '{}'", tok);
            return EXIT_FAILURE;
        }
        (*bin)->add_synthetic_function_start(va);
    }
    const ember::Binary& b = **bin;

    if (!args.trace_path.empty())          load_trace_edges(args, b);
    if (!args.export_annotations.empty())  return run_export_annotations(args);
    if (!args.apply_ember.empty())         return run_apply_ember(args, b);

    if (args.debug)                        return run_debug(args, &b, aux_specs);

    if (args.xrefs)              return run_xrefs(args, b);
    if (args.data_xrefs)         return run_data_xrefs(args, b);
    if (!args.refs_to.empty())   return run_refs_to(args, b);
    if (!args.containing_fn.empty())  return run_containing_fn(args, b);
    if (!args.validate_name.empty())  return run_validate_name(args, b);
    if (args.collisions)         return run_collisions(args, b);
    if (!args.callees.empty())   return run_callees(args, b);
    if (!args.callees_class.empty()) return run_callees_class(args, b);
    if (!args.disasm_at.empty()) return run_disasm_at(args, b);
    if (!args.list_syscalls.empty()) return run_list_syscalls(args, b);
    if (args.strings)            return run_strings(args, b);
    if (args.fingerprints)       return run_fingerprints(args, b);
    if (args.teef)               return run_teef(args, b);
    if (args.objc_names)         return run_objc_names(args, b);
    if (args.objc_protos)        return run_objc_protos(args, b);
    if (args.rtti)               return run_rtti(args, b);
    if (args.vm_detect)          return run_vm_detect(args, b);
    if (args.arities)            return run_arities(args, b);
    if (args.functions)          return run_functions(args, b);

    return run_emit(args, b);
}
