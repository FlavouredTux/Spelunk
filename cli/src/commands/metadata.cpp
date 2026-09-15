// Runtime metadata: Objective-C, RTTI, vtables, import recovery.

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <spelunk/analysis/recover_imports.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/format.hpp>
#include <spelunk/binary/pe.hpp>
#include <spelunk/common/types.hpp>

#include "../args.hpp"
#include "../builders.hpp"
#include "../subcommands.hpp"
#include "../util.hpp"

namespace spelunk::cli {

int run_objc_names(const Args& args, const Binary& b) {
    return run_cached(args, "objc-names", [&] { return build_objc_names_output(b); });
}

int run_objc_protos(const Args& args, const Binary& b) {
    return run_cached(args, "objc-protocols",
                      [&] { return build_objc_protocols_output(b); });
}

int run_objc_surfaces(const Args& args, const Binary& b) {
    return run_cached(args, "objc-surfaces",
                      [&] { return build_objc_surfaces_output(b); });
}

int run_rtti(const Args& args, const Binary& b) {
    return run_cached(args, "rtti-v2", [&] { return build_rtti_output(b); });
}

int run_recover_imports(const Args& args, const Binary& b) {
    namespace fs = std::filesystem;

    // Gather reference DLL paths: explicit --dll files plus every *.dll in
    // --dll-dir (non-recursive). Without real DLLs there's nothing to name
    // against - the export RVA→name table lives in the DLL, not the dump.
    std::vector<fs::path> dll_paths;
    for (const auto& p : args.recover_dll_paths) dll_paths.emplace_back(p);
    if (!args.recover_dll_dir.empty()) {
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(args.recover_dll_dir, ec)) {
            if (!e.is_regular_file(ec)) continue;
            auto ext = e.path().extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return std::tolower(c); });
            if (ext == ".dll") dll_paths.push_back(e.path());
        }
        if (ec) {
            std::println(stderr, "spelunk: --dll-dir: cannot read '{}': {}",
                         args.recover_dll_dir, ec.message());
        }
    }
    if (dll_paths.empty()) {
        std::println(stderr,
            "spelunk: --recover-imports needs reference DLLs. Pass --dll-dir DIR "
            "(a folder of *.dll) and/or --dll PATH. Point it at real Windows "
            "system DLLs (ntdll, kernel32, kernelbase, user32, ...): a pointer "
            "into a DLL you don't have cannot be named.");
        return EXIT_FAILURE;
    }

    // Parse each reference DLL's export table once. Module label = the
    // lowercased file name.
    std::sort(dll_paths.begin(), dll_paths.end());
    std::vector<ReferenceExports> refs;
    std::vector<std::unique_ptr<Binary>> ref_holders;  // keep symbols alive
    std::size_t total_exports = 0;
    for (const auto& path : dll_paths) {
        auto loaded = load_binary(path);
        if (!loaded) {
            std::println(stderr, "spelunk: --recover-imports: skipping '{}': {}",
                         path.string(), loaded.error().message);
            continue;
        }
        if ((*loaded)->format() != Format::Pe) {
            std::println(stderr,
                "spelunk: --recover-imports: skipping '{}': not a PE image",
                path.string());
            continue;
        }
        std::string mod = path.filename().string();
        std::transform(mod.begin(), mod.end(), mod.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        auto ref = reference_exports_from(**loaded, mod);
        total_exports += ref.by_rva.size();
        refs.push_back(std::move(ref));
        ref_holders.push_back(std::move(*loaded));
    }
    if (refs.empty()) {
        std::println(stderr,
            "spelunk: --recover-imports: no usable reference DLLs loaded");
        return EXIT_FAILURE;
    }

    ImportRecoveryOptions opts;
    // Own-image base for slot-RVA keys: explicit --image-base wins, else
    // the PE image base, else the lowest mapped region.
    if (!args.recover_image_base.empty()) {
        addr_t v = 0;
        std::string_view s = args.recover_image_base;
        if (s.starts_with("0x") || s.starts_with("0X")) s.remove_prefix(2);
        auto r = std::from_chars(s.data(), s.data() + s.size(), v, 16);
        if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) {
            std::println(stderr, "spelunk: --image-base: bad hex '{}'",
                         args.recover_image_base);
            return EXIT_FAILURE;
        }
        opts.own_base = v;
    } else if (const auto* pe = dynamic_cast<const PeBinary*>(&b)) {
        opts.own_base = pe->image_base();
    } else {
        addr_t lo = 0;
        for (const auto& s : b.sections()) {
            if (s.data.empty()) continue;
            if (lo == 0 || s.vaddr < lo) lo = s.vaddr;
        }
        opts.own_base = lo;
    }

    const auto result = recover_imports(b, refs, opts);

    // Diagnostics to stderr; the machine-readable contract goes to stdout.
    std::println(stderr,
        "spelunk: {} reference DLL(s), {} export(s); harvested {} IAT slot(s) "
        "into {} cluster(s)",
        refs.size(), total_exports, result.harvested, result.clusters.size());
    for (const auto& c : result.clusters) {
        if (!c.module.empty()) {
            std::println(stderr,
                "  [{:#x}..{:#x}] {} @ base {:#x}  {}/{} resolved",
                c.low, c.high, c.module, c.base, c.hits, c.slots);
        } else {
            std::println(stderr,
                "  [{:#x}..{:#x}] UNRESOLVED  {} slot(s)",
                c.low, c.high, c.slots);
        }
    }

    const bool rva_keys = opts.own_base != 0;
    if (args.json) {
        // The converter contract: { "<slot-rva-hex>": "dll!func", ... }.
        std::print("{{");
        bool first = true;
        for (const auto& imp : result.imports) {
            const std::string qualified = imp.module + "!" + imp.name;
            std::print("{}\n  \"{:#x}\": \"{}\"",
                       first ? "" : ",",
                       rva_keys ? imp.rva : imp.slot,
                       json_escape(qualified));
            first = false;
        }
        std::println("{}}}", result.imports.empty() ? "" : "\n");
    } else {
        // TSV: slot_va  rva  target  dll!func
        for (const auto& imp : result.imports) {
            std::println("{:#x}\t{:#x}\t{:#x}\t{}!{}",
                         imp.slot, imp.rva, imp.target, imp.module, imp.name);
        }
    }
    return EXIT_SUCCESS;
}

int run_vtables(const Args& args, const Binary& b) {
    if (!args.vtable_at.empty()) {
        auto va = parse_cli_addr(args.vtable_at);
        if (!va) {
            std::println(stderr, "spelunk: --vtable-at: bad address '{}'", args.vtable_at);
            return 2;
        }
        std::print("{}", build_vtable_at_output(b, *va, args.vtable_limit));
        return 0;
    }
    return run_cached(args, "vtables-v1", [&] { return build_vtables_output(b); });
}

int run_int3_resolve(const Args& args, const Binary& b) {
    return run_cached(args, "int3-resolve", [&] { return build_int3_resolve_output(b); });
}

}  // namespace spelunk::cli
