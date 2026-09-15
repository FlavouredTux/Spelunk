// TEEF corpus loading and recognition orchestration.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/teef_recognize.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/progress.hpp>
#include <spelunk/common/types.hpp>

#include "../subcommands.hpp"
#include "common.hpp"
#include "teef_internal.hpp"

namespace spelunk::cli {

namespace {

// Kept separate so long-lived callers can reuse one TeefCorpus instead of
// re-parsing 50-150 MB of TSV per recognition request.
[[nodiscard]] std::unique_ptr<TeefCorpus>
load_corpus_from_args(const Args& args) {
    if (args.corpus_paths.empty()) return nullptr;
    auto corpus = std::make_unique<TeefCorpus>();
    std::size_t total_rows = 0;
    const auto t_start = std::chrono::steady_clock::now();
    for (const auto& p : args.corpus_paths) {
        // Per-file timings come from TeefCorpus::load_tsv itself -
        // it logs phase breakdown (mmap / parse / merge / total).
        const std::size_t n = corpus->load_tsv(p);
        total_rows += n;
    }
    const auto t_end = std::chrono::steady_clock::now();
    const double total_ms = std::chrono::duration<double, std::milli>(
        t_end - t_start).count();
    std::println(stderr,
        "spelunk: corpus loaded: {} fns / {} chunks across {} TSVs "
        "({} rows) in {:.0f} ms",
        corpus->function_count(), corpus->chunk_count(),
        args.corpus_paths.size(), total_rows, total_ms);
    // Anti-corpus: same TSV format but only hashes are kept. Recognize
    // short-circuits any query whose L2/L4/prefix hash matches.
    if (!args.anti_corpus_paths.empty()) {
        std::size_t anti_rows = 0;
        const auto t_anti_start = std::chrono::steady_clock::now();
        for (const auto& p : args.anti_corpus_paths) {
            anti_rows += corpus->load_anti_tsv(p);
        }
        const auto t_anti_end = std::chrono::steady_clock::now();
        const double anti_ms = std::chrono::duration<double, std::milli>(
            t_anti_end - t_anti_start).count();
        std::println(stderr,
            "spelunk: anti-corpus loaded: {} blocked hashes from {} rows "
            "across {} TSVs in {:.0f} ms",
            corpus->blocked_count(), anti_rows,
            args.anti_corpus_paths.size(), anti_ms);
    }
    return corpus;
}

// Heuristic: classify the query binary's runtime/ABI for the TEEF
// recognizer's cross-language plausibility filter. Only the obvious
// cases get a tag; "" means unknown / wildcard. Conservative - false
// positives here (saying a Rust binary is C) just disable filtering;
// false negatives (saying a C binary is Rust) would block legitimate
// libstdc++ matches on a C++ binary.
[[nodiscard]] std::string_view detect_query_runtime(const Binary& b) {
    std::size_t rust_hits     = 0;
    std::size_t cxx_std_hits  = 0;
    std::size_t cxx_hits      = 0;
    std::size_t msvc_cxx_hits = 0;
    std::size_t msvcrt_hits   = 0;
    std::size_t winapi_hits   = 0;
    for (const auto& s : b.symbols()) {
        if (s.name.empty()) continue;
        // Rust: _R-mangled names or the runtime alloc/panic shims.
        if (s.name.starts_with("_R") || s.name.starts_with("__rust_")) {
            ++rust_hits;
            continue;
        }
        // MSVC C++ ABI: ?... mangled names. msvcrt.dll exports look like
        // ??0... (constructor), ??1... (destructor), ?... (mangled fn).
        if (s.name.starts_with("?") || s.name.starts_with("??")) {
            ++msvc_cxx_hits;
            continue;
        }
        // libstdc++ template instantiations are dominantly _ZSt / _ZNSt.
        if (s.name.starts_with("_ZSt") || s.name.starts_with("_ZNSt")) {
            ++cxx_std_hits;
            continue;
        }
        // Generic Itanium-mangled C++.
        if (s.name.starts_with("_Z")) {
            ++cxx_hits;
            continue;
        }
        // Windows imports - kernel32/ntdll/user32 etc export plain
        // names, so we recognize via known-API surface. is_import
        // filters to the bound IAT entries.
        if (s.is_import) {
            const std::string_view n = s.name;
            // Kernel/Win32 surface tells us this is a Windows binary.
            if (n == "GetProcAddress" || n == "LoadLibraryA" || n == "LoadLibraryW" ||
                n == "VirtualAlloc" || n == "VirtualProtect" ||
                n == "CreateFileW"  || n == "CreateFileA" ||
                n == "ReadFile"     || n == "WriteFile" ||
                n == "GetModuleHandleA" || n == "GetModuleHandleW" ||
                n == "ExitProcess"  || n == "GetCommandLineW" ||
                n == "RtlAllocateHeap" || n == "RtlFreeHeap" ||
                n == "NtCreateFile" || n.starts_with("Nt")) {
                ++winapi_hits;
                continue;
            }
            // CRT entry points.
            if (n == "_initterm" || n == "_set_app_type" || n == "exit" ||
                n.starts_with("_CRT_") || n.starts_with("__chkstk")) {
                ++msvcrt_hits;
            }
        }
    }
    if (rust_hits >= 4)        return teef_runtime::kRust;
    if (msvc_cxx_hits >= 4)    return teef_runtime::kCxxMsvc;
    if (cxx_std_hits >= 4)     return teef_runtime::kLibstdcxx;
    if (cxx_hits >= 8)         return teef_runtime::kCxx;
    if (winapi_hits >= 3)      return teef_runtime::kWinapi;
    if (msvcrt_hits >= 2)      return teef_runtime::kMsvcrt;
    return "";
}

}  // namespace

int run_recognize(const Args& args, const Binary& b) {
    if (args.corpus_paths.empty()) {
        std::println(stderr,
            "spelunk: --recognize requires at least one --corpus PATH");
        return EXIT_FAILURE;
    }
    // Identical --corpus PATH lists reuse the parsed in-memory indices
    // across repeated calls in the same process. One-shot CLI runs hit
    // this path exactly once, so the static is a no-op for them.
    static std::vector<std::string> cached_paths;
    static std::vector<std::string> cached_anti_paths;
    static std::unique_ptr<TeefCorpus> cached_corpus;
    if (!cached_corpus ||
        cached_paths != args.corpus_paths ||
        cached_anti_paths != args.anti_corpus_paths) {
        cached_corpus = load_corpus_from_args(args);
        cached_paths = args.corpus_paths;
        cached_anti_paths = args.anti_corpus_paths;
    } else {
        std::println(stderr,
            "spelunk: reusing cached corpus ({} fns / {} chunks)",
            cached_corpus->function_count(), cached_corpus->chunk_count());
    }
    const TeefCorpus& corpus = *cached_corpus;

    // Resolve --module if any. Inactive scope = no-op everywhere below.
    // An unresolved scope (user passed a name but it didn't match any
    // module) bails - running unscoped would silently process the wrong
    // surface and waste work.
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);
    if (!args.module_filter.empty() && !scope.active) {
        return EXIT_FAILURE;
    }

    // Walk every named-or-discovered function in the binary, fingerprint
    // it, ask the corpus for matches above threshold.
    std::unordered_map<addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (!scope.contains(s.addr)) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }
    // Stride-1 dedup. enumerate_functions() can emit multiple
    // overlapping addresses on stripped binaries when the prologue-
    // sweep heuristic fires at consecutive bytes inside one real fn's
    // body. Without this filter, --recognize re-fingerprints each of
    // those shadow entries, producing dozens of identical-name hits at
    // a stride of 1 (the user-reported "126x _ZSt7getlineIw..." case
    // in libloader.so). Fix: walk sorted, drop any addr that lands
    // inside a previously-seen fn's [entry, entry+size) window.
    std::map<addr_t, u64> windows;     // entry -> known size
    for (const auto& [a, _] : name_by_addr) windows[a]; // size 0 by default
    for (const auto& d : enumerate_functions(b, EnumerateMode::Auto,
                                             scope.lo, scope.hi)) {
        if (b.import_at_plt(d.addr)) continue;
        auto& sz = windows[d.addr];
        if (d.size > sz) sz = d.size;  // prefer the larger known extent
    }
    std::set<addr_t> fns;
    addr_t shadow_until = 0;
    std::size_t shadow_dropped = 0;
    for (auto [a, sz] : windows) {
        if (a < shadow_until) { ++shadow_dropped; continue; }
        fns.insert(a);
        if (sz > 0) shadow_until = a + sz;
    }
    if (shadow_dropped > 0) {
        std::println(stderr,
            "spelunk: recognize: dropped {} shadow entries (stride-1 dedup)",
            shadow_dropped);
    }

    const std::size_t total = fns.size();
    const unsigned hw = std::thread::hardware_concurrency();
    const unsigned threads = std::max(1u, std::min(hw ? hw : 4u, 16u));
    std::vector<addr_t> fns_vec(fns.begin(), fns.end());

    // A cache hit reads the stored TSV; a miss runs build_tsv and stores it.
    // A --module run is a strict subset of the unscoped table, so it
    // bypasses the cache in both directions.
    const bool cacheable = !args.no_cache && !scope.active;
    std::string target_tsv;
    bool cache_hit = false;
    if (cacheable) {
        const auto dir = args.cache_dir.empty()
            ? cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
            const std::string tag = teef_internal::cache_tag(args);
            if (auto hit = cache::read(dir, *k, tag); hit) {
                target_tsv = std::move(*hit);
                cache_hit = true;
            }
        }
    }
    if (!cache_hit) {
        // --l0-prefilter: target fns whose L0 topology is absent from
        // the corpus skip L4. Fast on obfuscated targets, lossy across
        // opt levels, so off by default. Topologies shared by more than
        // kMaxTopoPopularity corpus entries are generic shapes and are
        // excluded (SPELUNK_TEEF_MAX_TOPO_POPULARITY, 0 disables).
        std::unordered_set<u64> corpus_topos;
        if (args.l0_prefilter) {
            static const std::size_t kMaxTopoPopularity = []() -> std::size_t {
                if (const char* s = std::getenv("SPELUNK_TEEF_MAX_TOPO_POPULARITY")) {
                    try { return static_cast<std::size_t>(std::stoull(s)); }
                    catch (...) {}
                }
                return 50;
            }();
            corpus_topos = corpus.topo_hashes(kMaxTopoPopularity);
            std::println(stderr,
                "spelunk: --l0-prefilter on; {} corpus topologies "
                "(after popularity guard ≤{})",
                corpus_topos.size(), kMaxTopoPopularity);
        }
        TeefComputeOptions target_opts;
        target_opts.min_chunk_insts = 10;
        target_opts.l4_topo_filter = args.l0_prefilter ? &corpus_topos : nullptr;
        target_opts.skip_l4 = args.teef_no_l4;
        target_opts.max_cfg_blocks = args.max_cfg_blocks;
        target_opts.max_cfg_edges = args.max_cfg_edges;
        target_opts.max_cfg_insts = args.max_cfg_insts;
        target_opts.max_ir_insts = args.max_ir_insts;

        const auto t_fp_start = std::chrono::steady_clock::now();
        target_tsv = teef_internal::build_tsv(
            b, scope, /*corpus_mode=*/false,
            args.min_fn_bytes, args.max_fn_bytes, target_opts);
        const auto t_fp_end = std::chrono::steady_clock::now();
        const double fp_ms = std::chrono::duration<double, std::milli>(
            t_fp_end - t_fp_start).count();
        std::println(stderr,
            "spelunk: target fingerprint built in {:.0f} ms ({} bytes, {} fns)",
            fp_ms, target_tsv.size(), total);
        if (cacheable) {
            const auto dir = args.cache_dir.empty()
                ? cache::default_dir()
                : std::filesystem::path(args.cache_dir);
            if (auto k = cache::key_for(args.binary, cache_scope_tag(args)); k) {
                const std::string tag = teef_internal::cache_tag(args);
                (void)cache::write(dir, *k, tag, target_tsv);
            }
        }
    } else {
        std::println(stderr, "spelunk: reusing cached TEEF for target ({} bytes)",
                     target_tsv.size());
    }

    std::vector<TeefFunction> fps(total);
    {
        auto parsed = teef_internal::parse_tsv(target_tsv);
        std::unordered_map<addr_t, std::size_t> idx;
        for (std::size_t i = 0; i < total; ++i) idx[fns_vec[i]] = i;
        for (auto& [addr, tf] : parsed) {
            auto it = idx.find(addr);
            if (it != idx.end()) fps[it->second] = std::move(tf);
        }
    }
    std::unordered_map<u64, std::size_t> query_popularity;
    std::unordered_map<u64, std::size_t> query_popularity_l4;
    for (const auto& tf : fps) {
        if (tf.whole.exact_hash != 0) ++query_popularity[tf.whole.exact_hash];
        if (tf.behav.exact_hash != 0) ++query_popularity_l4[tf.behav.exact_hash];
    }
    constexpr std::size_t kQueryPopularityCap = 8;
    // L4 cap mirrors the L2 one. Trivial-behaviour fns (return-zero,
    // return-arg-byte, simple float predicates like __isinfl) hash to
    // the same L4 multiset across thousands of unrelated stubs in
    // obfuscator-heavy targets. Without this guard a single corpus
    // entry like __isinfl pulls 20+ false-positive behav-exact hits
    // because the target's stubs all share its trivial behaviour.
    constexpr std::size_t kQueryPopularityCapL4 = 8;

    // Detect the query binary's runtime once. The recognizer uses it
    // to skip cross-language matches (e.g. Rust binary against
    // libstdc++ template instantiations).
    const std::string_view query_runtime = detect_query_runtime(b);
    if (!query_runtime.empty()) {
        std::println(stderr,
            "spelunk: recognize: query runtime detected as '{}'", query_runtime);
    }

    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> hit_count{0};
    std::atomic<std::size_t> done_count{0};
    const float threshold = args.recognize_threshold;
    const bool show = progress_enabled();
    if (show) {
        std::println(stderr,
            "spelunk: recognize {} functions across {} threads (corpus has {} fns)...",
            total, threads, corpus.function_count());
        std::fflush(stderr);
    }
    // Stream output as each fn finishes - gives the user visible progress
    // on big-corpus runs that previously sat silent for minutes. Order is
    // completion-order (workers race), not address-sorted; pipe through
    // `sort -n` if you need sorted output. The mutex bounds the number of
    // print calls to one in flight; the actual `recognize()` work runs
    // unlocked.
    std::mutex out_mu;
    const auto t_scan_start = std::chrono::steady_clock::now();
    std::atomic<bool> scan_phase_done{false};
    // Same time-driven progress ticker as the fingerprint phase.
    // Refresh independent of work cadence so a single slow recognize
    // call doesn't leave the user staring at a stale line.
    std::thread scan_ticker;
    if (show) {
        scan_ticker = std::thread([&] {
            while (!scan_phase_done.load(std::memory_order_relaxed)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                const std::size_t d = done_count.load(std::memory_order_relaxed);
                if (d == 0 || d == total) continue;
                const auto now = std::chrono::steady_clock::now();
                const double elapsed = std::chrono::duration<double>(
                    now - t_scan_start).count();
                const double rate = elapsed > 0
                    ? static_cast<double>(d) / elapsed : 0.0;
                const double eta = rate > 0
                    ? static_cast<double>(total - d) / rate : 0.0;
                std::lock_guard<std::mutex> lock(out_mu);
                std::fprintf(stderr,
                    "\r  recognize [%zu/%zu] %.0f fn/s · elapsed %.1fs · eta %.1fs   ",
                    d, total, rate, elapsed, eta);
                std::fflush(stderr);
            }
        });
    }
    auto worker = [&] {
        while (true) {
            const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
            if (i >= total) break;
            const addr_t a = fns_vec[i];
            const auto& tf = fps[i];
            done_count.fetch_add(1, std::memory_order_relaxed);
            if (tf.whole.exact_hash == 0) continue;
            // Skip gcc partition variants in the query - they're
            // fragments of real fns whose generic shape (load string +
            // call + abort, for the .cold case) chunk-vote-matches
            // arbitrary library functions and emits garbage labels.
            // The base function (without the suffix) goes through
            // recognize normally and surfaces the real identity.
            if (auto qit = name_by_addr.find(a);
                qit != name_by_addr.end() &&
                teef_internal::is_compiler_partition_variant(qit->second)) {
                continue;
            }
            // Skip query functions whose whole-fn TEEF appears too
            // many times in this binary - they're trivial-shape stubs
            // (xgetbv, return-zero) that would ALL collapse onto a
            // single arbitrary corpus name without this gate.
            if (query_popularity[tf.whole.exact_hash] > kQueryPopularityCap) continue;
            // L4-side trivial-behaviour guard. See kQueryPopularityCapL4.
            if (tf.behav.exact_hash != 0 &&
                query_popularity_l4[tf.behav.exact_hash] > kQueryPopularityCapL4) {
                continue;
            }
            auto matches = corpus.recognize(tf, /*top_k=*/3, query_runtime);
            if (matches.empty()) continue;
            if (matches[0].confidence < threshold) continue;
            ++hit_count;
            std::string current;
            if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
                current = it->second;
            } else {
                current = std::format("sub_{:x}", a);
            }
            std::string row = std::format("{:x}\t{}\t{}\t{:.3f}\t{}",
                                          a, current,
                                          matches[0].name,
                                          matches[0].confidence,
                                          matches[0].via);
            // Append top-2/top-3 alternates if present, for transparency.
            for (std::size_t k = 1; k < matches.size(); ++k) {
                row += std::format("\t{}={:.3f}",
                                   matches[k].name, matches[k].confidence);
            }
            row += '\n';
            {
                std::lock_guard<std::mutex> lock(out_mu);
                std::fputs(row.c_str(), stdout);
                std::fflush(stdout);
            }
        }
    };
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (unsigned k = 0; k < threads; ++k) pool.emplace_back(worker);
    for (auto& t : pool) t.join();
    scan_phase_done.store(true, std::memory_order_relaxed);
    if (scan_ticker.joinable()) scan_ticker.join();

    const auto t_scan_end = std::chrono::steady_clock::now();
    const double scan_s = std::chrono::duration<double>(
        t_scan_end - t_scan_start).count();
    if (show) {
        const double rate = scan_s > 0
            ? static_cast<double>(total) / scan_s : 0.0;
        std::fprintf(stderr,
            "\r  recognize [%zu/%zu] %.0f fn/s · elapsed %.1fs · done           \n",
            total, total, rate, scan_s);
        std::fflush(stderr);
    }
    const double per_fn_us = total > 0
        ? (scan_s * 1e6) / static_cast<double>(total) : 0.0;
    std::println(stderr,
        "spelunk: recognize: {} suggestions at threshold {:.2f} "
        "(scan {:.2f}s, {:.0f} µs/fn)",
        hit_count.load(), threshold, scan_s, per_fn_us);
    return EXIT_SUCCESS;
}

}  // namespace spelunk::cli
