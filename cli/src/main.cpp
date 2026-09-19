#include <cstdlib>
#include <expected>
#include <filesystem>
#include <format>
#include <limits>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <stdlib.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/analysis/strings.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/dtk_project.hpp>
#include <spelunk/binary/raw_regions.hpp>
#include <spelunk/binary/rel.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/common/timing.hpp>
#include <spelunk/common/types.hpp>

#include "args.hpp"
#include "cli_error.hpp"
#include "dbg.hpp"
#include "fingerprint.hpp"
#include "info.hpp"
#include "kismet.hpp"
#include "patches.hpp"
#include "subcommands.hpp"
#include "util.hpp"

namespace {

void apply_quiet_env(const spelunk::cli::Args& args) {
    if (!args.quiet) return;
#ifdef _WIN32
    ::_putenv_s("SPELUNK_QUIET", "1");
#else
    ::setenv("SPELUNK_QUIET", "1", 1);
#endif
}

[[nodiscard]] spelunk::Result<std::unique_ptr<spelunk::Binary>>
load_binary_from_args(const spelunk::cli::Args& args) {
    // --regions skips magic-byte dispatch and loads via the manifest
    // path; the manifest's first region's vaddr becomes the natural
    // entry for analysis (the user can override with -s <addr>).
    if (!args.regions_manifest.empty()) {
        auto rr = spelunk::RawRegionsBinary::load_from_manifest(args.regions_manifest);
        if (!rr) return std::unexpected(std::move(rr).error());
        return std::unique_ptr<spelunk::Binary>(std::move(*rr));
    }
    // --raw-bytes is the one-region shortcut for runtime captures -
    // splice a memory dump into a single rwx region at --base-va. No
    // PE container, no manifest. base_va parsed as 0x-prefixed or
    // bare hex; bases parsed as hex regardless of prefix to match the
    // rest of the CLI's address-flag style.
    if (!args.raw_bytes_path.empty()) {
        const auto va = spelunk::cli::parse_cli_addr(args.raw_base_va);
        if (!va) {
            return std::unexpected(spelunk::Error::invalid_format(
                "raw-bytes: --base-va must be a non-empty 64-bit hex address"));
        }
        auto rr = spelunk::RawRegionsBinary::load_from_raw_bytes(
            args.raw_bytes_path, *va);
        if (!rr) return std::unexpected(std::move(rr).error());
        return std::unique_ptr<spelunk::Binary>(std::move(*rr));
    }
    spelunk::LoadOptions opts;
    if (!args.pdb_path.empty()) opts.pdb_path = args.pdb_path;
    if (!args.dtk_symbols_path.empty()) opts.dol_symbols_path = args.dtk_symbols_path;
    opts.no_pdb = args.no_pdb;
    return spelunk::load_binary(args.binary, opts);
}

[[nodiscard]] spelunk::Result<std::size_t>
apply_dtk_rel_context(const spelunk::DtkProject& main_project,
                      std::span<const spelunk::DtkProject> rel_projects,
                      std::string_view selected_module,
                      spelunk::Binary& primary) {
    auto* selected = dynamic_cast<spelunk::RelBinary*>(&primary);
    if (!selected) {
        return std::unexpected(spelunk::Error::invalid_format(
            "dtk: selected module did not load as a Wii REL"));
    }

    spelunk::LoadOptions main_options;
    main_options.dol_symbols_path = main_project.symbols_path;
    auto main_binary = spelunk::load_binary(main_project.object_path, main_options);
    if (!main_binary) return std::unexpected(std::move(main_binary).error());

    std::vector<std::unique_ptr<spelunk::Binary>> peer_storage;
    std::vector<std::string> peer_names;
    std::vector<spelunk::RelLinkModule> link_modules;
    peer_storage.reserve(rel_projects.size());
    peer_names.reserve(rel_projects.size());
    link_modules.reserve(rel_projects.size());
    link_modules.push_back({selected, selected_module});

    constexpr spelunk::addr_t kContextAlignment = 0x10000;
    const spelunk::addr_t selected_high = selected->preferred_load_base() +
                                        selected->mapped_size();
    if (selected_high < selected->preferred_load_base() ||
        selected_high > std::numeric_limits<spelunk::u32>::max() -
                        (kContextAlignment - 1)) {
        return std::unexpected(spelunk::Error::invalid_format(
            "dtk: selected REL leaves no room for peer modules"));
    }
    spelunk::addr_t cursor = (selected_high + kContextAlignment - 1) &
                           ~(kContextAlignment - 1);

    for (const auto& project : rel_projects) {
        if (project.module_name == selected_module) continue;

        spelunk::LoadOptions options;
        options.dol_symbols_path = project.symbols_path;
        options.rel_load_base = cursor;
        auto loaded = spelunk::load_binary(project.object_path, options);
        if (!loaded) return std::unexpected(std::move(loaded).error());
        auto* peer = dynamic_cast<spelunk::RelBinary*>(loaded->get());
        if (!peer) {
            return std::unexpected(spelunk::Error::invalid_format(std::format(
                "dtk: module '{}' did not load as a Wii REL",
                project.module_name)));
        }
        const spelunk::addr_t high = peer->preferred_load_base() +
                                   peer->mapped_size();
        if (high < peer->preferred_load_base() ||
            high > std::numeric_limits<spelunk::u32>::max() -
                   (kContextAlignment - 1)) {
            return std::unexpected(spelunk::Error::invalid_format(std::format(
                "dtk: REL context exceeds PPC32 after module '{}'",
                project.module_name)));
        }
        cursor = (high + kContextAlignment - 1) & ~(kContextAlignment - 1);
        peer_storage.push_back(std::move(*loaded));
        peer_names.push_back(project.module_name);
        link_modules.push_back({peer, project.module_name});
    }

    auto linked = spelunk::link_rel_modules(link_modules, main_binary->get());
    if (!linked) return std::unexpected(std::move(linked).error());

    for (std::size_t index = 0; index < peer_storage.size(); ++index) {
        selected->adopt_linked_binary(
            std::move(peer_storage[index]), peer_names[index]);
    }
    return *linked;
}

[[nodiscard]] std::filesystem::path
resolve_dsym_bundle_path(const std::filesystem::path& p,
                         const std::filesystem::path& primary) {
    std::error_code ec;
    if (!std::filesystem::is_directory(p, ec) || ec) return p;

    const auto dwarf_dir = p / "Contents" / "Resources" / "DWARF";
    if (!std::filesystem::is_directory(dwarf_dir, ec) || ec) return p;

    auto by_primary_name = dwarf_dir / primary.filename();
    if (std::filesystem::exists(by_primary_name, ec) && !ec) return by_primary_name;

    std::filesystem::path only;
    for (const auto& entry : std::filesystem::directory_iterator(dwarf_dir, ec)) {
        if (ec) break;
        if (!entry.is_regular_file(ec) || ec) continue;
        if (!only.empty()) return p;
        only = entry.path();
    }
    return only.empty() ? p : only;
}

[[nodiscard]] std::filesystem::path
resolve_dsym_path(const spelunk::cli::Args& args) {
    return resolve_dsym_bundle_path(args.dsym_path, args.binary);
}

[[nodiscard]] std::filesystem::path
auto_dsym_path(const spelunk::cli::Args& args) {
    const std::filesystem::path primary(args.binary);
    std::error_code ec;
    for (const auto& candidate : {
        std::filesystem::path(args.binary + ".dSYM"),
        primary.parent_path() / (primary.filename().string() + ".dSYM"),
        primary.parent_path() / (primary.stem().string() + ".dSYM"),
    }) {
        if (candidate.empty()) continue;
        if (std::filesystem::is_directory(candidate, ec) && !ec) {
            const auto resolved = resolve_dsym_bundle_path(candidate, primary);
            if (std::filesystem::is_regular_file(resolved, ec) && !ec) return resolved;
        }
    }
    return {};
}

[[nodiscard]] int apply_dsym_overlay(const spelunk::cli::Args& args,
                                     spelunk::Binary& primary) {
    const bool explicit_dsym = !args.dsym_path.empty();
    const auto path = explicit_dsym ? resolve_dsym_path(args) : auto_dsym_path(args);
    if (path.empty()) return EXIT_SUCCESS;
    auto loaded = spelunk::load_binary(path);
    if (!loaded) {
        std::println(stderr, "spelunk: {} {}: {}: {}",
                     explicit_dsym ? "--dsym" : "auto-dSYM",
                     path.string(), loaded.error().kind_name(),
                     loaded.error().message);
        return explicit_dsym ? EXIT_FAILURE : EXIT_SUCCESS;
    }
    const std::size_t added = primary.overlay_symbols_from(**loaded);
    if (!args.quiet) {
        std::println(stderr, "spelunk: dSYM symbols: {} ({})",
                     added, path.string());
    }
    return EXIT_SUCCESS;
}

[[nodiscard]] int apply_string_name_inference(const spelunk::cli::Args& args,
                                              spelunk::Binary& b) {
    if (!args.infer_string_names) return EXIT_SUCCESS;
    const auto candidates = spelunk::infer_function_names_from_strings(b);
    std::size_t added = 0;
    for (const auto& c : candidates) {
        if (b.add_inferred_function_name(c.function, c.name)) ++added;
    }
    if (!args.quiet) {
        std::println(stderr, "spelunk: string-inferred names: {}", added);
    }
    return EXIT_SUCCESS;
}

[[nodiscard]] bool inferred_functions_cache_available(const spelunk::cli::Args& args) {
    if (!args.infer_string_names || !args.functions || args.no_cache) return false;
    const auto dir = args.cache_dir.empty() ? spelunk::cache::default_dir()
                                            : std::filesystem::path(args.cache_dir);
    auto key = spelunk::cache::key_for(args.binary, spelunk::cli::cache_scope_tag(args));
    if (!key) return false;
    return spelunk::cache::read(dir, *key, spelunk::cli::functions_cache_tag(args)).has_value();
}

}  // namespace

int main(int argc, char** argv) {
    using namespace spelunk::cli;

    auto args_r = parse_args(argc, argv);
    if (!args_r) {
        // Parse errors get the specific message plus a one-line pointer
        // to --help; the full banner stays reserved for explicit
        // -h/--help so failures don't scroll the terminal.
        std::println(stderr, "spelunk: {}", args_r.error().message);
        std::println(stderr, "run 'spelunk --help' for full usage");
        return EXIT_FAILURE;
    }
    auto args = std::move(*args_r);

    if (args.help) {
        if (args.help_topic.empty()) print_help();
        else                         print_help_topic(args.help_topic);
        return EXIT_SUCCESS;
    }
    if (args.version) {
        std::println("spelunk {}", SPELUNK_VERSION_STRING);
        return EXIT_SUCCESS;
    }
    std::optional<spelunk::DtkProject> dtk_main_project;
    std::vector<spelunk::DtkProject> dtk_rel_projects;
    std::string selected_dtk_module;
    if (!args.dtk_project_path.empty()) {
        auto project = spelunk::resolve_dtk_project(
            args.dtk_project_path, args.dtk_version, args.dtk_module);
        if (!project) return report(project.error());
        args.binary = project->object_path.string();
        args.dtk_symbols_path = project->symbols_path.string();
        if (!args.quiet) {
            std::println(stderr, "spelunk: DTK {} [{}]", project->module_name,
                         project->version.empty() ? "default" : project->version);
            std::println(stderr, "spelunk: object  {}", args.binary);
            std::println(stderr, "spelunk: symbols {}", args.dtk_symbols_path);
        }
        if (!args.dtk_module.empty()) {
            // A REL context depends on the main DOL and every configured peer,
            // while the legacy cache key hashes only the selected object.
            // Bypass it until context-wide cache identities are available.
            args.no_cache = true;
            auto main_project = spelunk::resolve_dtk_project(
                args.dtk_project_path, args.dtk_version);
            if (!main_project) return report(main_project.error());
            auto modules = spelunk::resolve_dtk_project_modules(
                args.dtk_project_path, args.dtk_version);
            if (!modules) return report(modules.error());
            selected_dtk_module = project->module_name;
            dtk_main_project = std::move(*main_project);
            dtk_rel_projects = std::move(*modules);
        }
    }

    apply_quiet_env(args);

    if (args.dump_types)  { return run_dump_types();                       }
    if (!args.kismet_bundle.empty()) { return run_kismet(args);             }

    if (!args.diff_path.empty() ||
        !args.fp_old_in.empty() ||
        !args.fp_new_in.empty()) {
        return run_diff(args);
    }
    // --apply-patches is a one-shot file operation: it loads the binary
    // only to consult the section table for vaddr→file-offset
    // translation, then writes a patched copy. No analysis runs.
    if (!args.apply_patches.empty()) return run_apply_patches(args);

    // Mutual-exclusion notice for the exclusive output selectors. The
    // dispatch chain below always ran only its first match, silently
    // ignoring the rest - indistinguishable from the flags combining.
    // Name every requested selector plus the single winner on stderr
    // (stdout stays parseable), then proceed so existing scripts keep
    // working. Must sit ahead of run_functions_cache_only: a warm
    // --functions cache entry would otherwise emit output before the
    // warning and outrank the dispatch-order winner.
    const auto view_flags = requested_view_flags(args);
    if (view_flags.size() > 1) {
        std::string requested_list;
        for (std::size_t i = 0; i < view_flags.size(); ++i) {
            if (i) requested_list += ", ";
            requested_list += view_flags[i];
        }
        std::println(stderr,
                     "spelunk: multiple view flags requested ({}); running {} only",
                     requested_list, view_flags.front());
    }
    if (view_flags.size() <= 1 || view_flags.front() == "--functions") {
        if (auto cached_functions = run_functions_cache_only(args)) {
            return *cached_functions;
        }
    }
    if (surfaces_artifacts_only_requested(args)) {
        return run_surface_artifacts(args);
    }

    // Aux-binary loading happens once, up front, so both the no-primary
    // (--attach-pid) and primary-loaded paths share the same setup.
    // Each `--aux-binary PATH[@HEX]` token is split on '@'; the
    // optional hex tail pins the runtime base for the slide computation
    // (the debugger will skip its /proc/maps size-match heuristic).
    std::vector<std::unique_ptr<spelunk::Binary>>          aux_storage;
    std::vector<spelunk::cli::AuxBinarySpec>               aux_specs;
    aux_storage.reserve(args.aux_binary_paths.size());
    aux_specs.reserve(args.aux_binary_paths.size());
    for (const auto& tok : args.aux_binary_paths) {
        std::string path = tok;
        std::optional<spelunk::addr_t> manual_base;
        if (auto at = tok.find('@'); at != std::string::npos) {
            path = tok.substr(0, at);
            const std::string_view va_tok = std::string_view(tok).substr(at + 1);
            auto parsed = spelunk::cli::parse_cli_addr(va_tok);
            if (!parsed) {
                std::println(stderr,
                    "spelunk: --aux-binary: bad hex base after '@' in '{}'", tok);
                return EXIT_FAILURE;
            }
            manual_base = *parsed;
        }
        auto loaded = spelunk::load_binary(path);
        if (!loaded) {
            std::println(stderr, "spelunk: --aux-binary {}: {}: {}",
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

    auto bin = [&] {
        spelunk::ScopedTimer t("load_binary");
        return load_binary_from_args(args);
    }();
    if (!bin) return report(bin.error());
    if (dtk_main_project) {
        auto linked = apply_dtk_rel_context(
            *dtk_main_project, dtk_rel_projects, selected_dtk_module, **bin);
        if (!linked) return report(linked.error());
        if (!args.quiet) {
            std::println(stderr,
                "spelunk: REL context {} modules, {} external relocations resolved",
                dtk_rel_projects.size(), *linked);
        }
    }
    if (const int rc = apply_dsym_overlay(args, **bin); rc != EXIT_SUCCESS) {
        return rc;
    }
    if (!inferred_functions_cache_available(args)) {
        if (const int rc = apply_string_name_inference(args, **bin); rc != EXIT_SUCCESS) {
            return rc;
        }
    }

    // --force-fn-start: synthesize Function symbols at each user-
    // specified VA so resolve_containing_function returns a window AT
    // the VA instead of rebinding to the closest-below symbol. Common
    // when obfuscators merge functions or stash a real entry mid-body.
    for (const auto& tok : args.force_fn_starts) {
        auto va = spelunk::cli::parse_cli_addr(tok);
        if (!va) {
            std::println(stderr, "spelunk: --force-fn-start: bad hex VA '{}'", tok);
            return EXIT_FAILURE;
        }
        (*bin)->add_synthetic_function_start(*va);
    }
    const spelunk::Binary& b = **bin;

    if (!args.trace_path.empty())          load_trace_edges(args, b);
    if (!args.export_annotations.empty())  return run_export_annotations(args);

    if (args.debug)                        return run_debug(args, &b, aux_specs);
    if (args.xrefs)              return run_xrefs(args, b);
    if (args.data_xrefs)         return run_data_xrefs(args, b);
    if (!args.symtable.empty())  return run_symtable(args, b);
    if (!args.symresolve.empty()) return run_symresolve(args, b);
    if (!args.symuses.empty())   return run_symuses(args, b);
    if (!args.refs_to.empty())   return run_refs_to(args, b);
    if (!args.refs_to_loose.empty()) return run_refs_to_loose(args, b);
    if (!args.state_map.empty()) return run_state_map(args, b);
    if (!args.branch_on.empty()) return run_branch_on(args, b);
    if (!args.guard_map.empty()) return run_guard_map(args, b);
    if (!args.state_lifetime.empty()) return run_state_lifetime(args, b);
    if (!args.side_effects.empty()) return run_side_effects(args, b);
    if (!args.object_roles.empty()) return run_object_roles(args, b);
    if (!args.explain_address.empty()) return run_explain_address(args, b);
    if (!args.explain_vcall.empty()) return run_explain_vcall(args, b);
    if (args.recover_imports)    return run_recover_imports(args, b);
    if (!args.vtable_at.empty()) return run_vtables(args, b);
    if (!args.dump_object.empty()) return run_dump_object(args, b);
    if (!args.containing_fn.empty())  return run_containing_fn(args, b);
    if (!args.validate_name.empty())  return run_validate_name(args, b);
    if (args.collisions)         return run_collisions(args, b);
    if (!args.callees.empty())   return run_callees(args, b);
    if (!args.callees_class.empty()) return run_callees_class(args, b);
    if (!args.patch_plan.empty()) return run_patch_plan(args, b);
    if (!args.disasm_at.empty()) return run_disasm_at(args, b);
    if (!args.disasm_window.empty()) return run_disasm_window(args, b);
    if (!args.list_syscalls.empty()) return run_list_syscalls(args, b);
    if (!args.forge_spec.empty())    return run_forge_spec(args, b);
    if (!args.annotate_addr.empty()) return run_annotate(args, b);
    if (args.list_annotations)       return run_list_annotations(args, b);
    if (!args.decompile_data.empty()) return run_decompile_data(args, b);
    if (!args.evt_script.empty())     return run_evt_script(args, b);
    if (args.strings)            return run_strings(args, b);
    if (args.surfaces)           return run_surfaces(args, b);
    if (args.graphics)           return run_graphics(args, b);
    if (args.log_categories)     return run_log_categories(args, b);
    if (args.fingerprints)       return run_fingerprints(args, b);
    if (args.identify)           return run_identify(args, b);
    if (args.objc_names)         return run_objc_names(args, b);
    if (args.objc_protos)        return run_objc_protos(args, b);
    if (args.objc_surfaces)      return run_objc_surfaces(args, b);
    if (args.rtti)               return run_rtti(args, b);
    if (args.vtables)            return run_vtables(args, b);
    if (args.int3_resolve)       return run_int3_resolve(args, b);
    if (args.ppc_coverage)       return run_ppc_coverage(args, b);
    if (args.arities)            return run_arities(args, b);
    if (args.functions)          return run_functions(args, b);

    return run_emit(args, b);
}
