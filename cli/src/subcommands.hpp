#pragma once

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <print>
#include <string>
#include <string_view>
#include <utility>

#include <ember/common/annotations.hpp>
#include <ember/common/cache.hpp>
#include <ember/common/error.hpp>
#include <ember/decompile/emit_options.hpp>

#include "args.hpp"

namespace ember { class Binary; }

namespace ember::cli {

// One-shot helpers (run before any analysis pipeline kicks in).

int run_dump_types();
int run_export_annotations(const Args& args);
int run_apply_ember(const Args& args, const Binary& b);

// Pre-analysis side effects (no exit code — caller continues).

void load_trace_edges(const Args& args, const Binary& b);

// Cached output runners. Each calls the matching builders.cpp helper
// through run_cached so successive invocations hit the disk cache.

int run_xrefs       (const Args& args, const Binary& b);
int run_data_xrefs  (const Args& args, const Binary& b);
int run_strings     (const Args& args, const Binary& b);
int run_fingerprints(const Args& args, const Binary& b);
int run_teef        (const Args& args, const Binary& b);
int run_orbit_dump  (const Args& args, const Binary& b);
int run_recognize   (const Args& args, const Binary& b);
int run_objc_names  (const Args& args, const Binary& b);
int run_objc_protos (const Args& args, const Binary& b);
int run_rtti        (const Args& args, const Binary& b);
int run_vm_detect   (const Args& args, const Binary& b);
int run_int3_resolve(const Args& args, const Binary& b);
int run_arities     (const Args& args, const Binary& b);
int run_functions   (const Args& args, const Binary& b);

// Direct-output runners (cache logic varies, so they handle it locally).

int run_refs_to      (const Args& args, const Binary& b);
int run_containing_fn(const Args& args, const Binary& b);
int run_validate_name(const Args& args, const Binary& b);
int run_collisions   (const Args& args, const Binary& b);
int run_callees      (const Args& args, const Binary& b);
int run_callees_class(const Args& args, const Binary& b);
int run_disasm_at    (const Args& args, const Binary& b);
int run_list_syscalls(const Args& args, const Binary& b);

// The pseudo / struct / ir / cfg / cfg-pseudo / disasm pipeline. Loads
// annotations, applies any --pat sigs, runs IPA / EH / indirect-call
// resolver / PE prologue parse / Obj-C selref harvest as opted in by
// the user, then dispatches to the requested view (or print_info if
// nothing was requested). Returns the process exit code.
int run_emit(const Args& args, const Binary& b);

// --serve: long-lived daemon. Reads tab-delimited tool requests on
// stdin, dispatches to the same code paths as the one-shot
// subcommands, writes length-framed responses on stdout. Exits on
// EOF. The binary is loaded once at startup and reused across every
// request — wins back the wait4 dominance in agent-fanout strace.
int run_serve(const Args& args, const Binary& b);

// Lower-level handlers retained for callers that already have the
// emit-options block built and just want to drive a single view.

int run_disasm    (const Binary& b, std::string_view symbol);
int run_cfg       (const Binary& b, std::string_view symbol);
int run_cfg_pseudo(const Binary& b, std::string_view symbol,
                   const Annotations* ann, EmitOptions opts);
int run_ir        (const Binary& b, std::string_view symbol,
                   bool run_ssa, bool run_opt);
int run_struct    (const Binary& b, std::string_view symbol, bool pseudo,
                   const Annotations* annotations, EmitOptions opts);

// Generic cache-or-compute wrapper: serve from disk cache if possible,
// otherwise call `compute()` to build the canonical output, write it
// back to the cache, and stream to stdout. `tag` keys the cache slot
// alongside the binary-content hash. --no-cache bypasses both legs.
template <class Compute>
int run_cached(const Args& args, std::string_view tag, Compute compute) {
    const auto dir = args.cache_dir.empty()
        ? cache::default_dir()
        : std::filesystem::path(args.cache_dir);
    std::string key;
    bool cacheable = !args.no_cache;
    if (cacheable) {
        auto k = cache::key_for(args.binary);
        if (k) {
            key = std::move(*k);
        } else {
            std::println(stderr, "ember: warning: {}: {} (caching disabled)",
                         k.error().kind_name(), k.error().message);
            cacheable = false;
        }
    }
    if (cacheable) {
        if (auto hit = cache::read(dir, key, tag); hit) {
            std::fwrite(hit->data(), 1, hit->size(), stdout);
            return EXIT_SUCCESS;
        }
    }
    const std::string out = compute();
    std::fwrite(out.data(), 1, out.size(), stdout);
    if (cacheable) {
        if (auto rv = cache::write(dir, key, tag, out); !rv) {
            std::println(stderr, "ember: warning: {}: {}",
                         rv.error().kind_name(), rv.error().message);
        }
    }
    return EXIT_SUCCESS;
}

}  // namespace ember::cli
