// TEEF fingerprint construction, orbit dumps and --identify.

#include <spelunk/analysis/teef.hpp>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <mutex>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/analysis/identify.hpp>
#include <spelunk/analysis/pipeline.hpp>
#include <spelunk/analysis/strings.hpp>
#include <spelunk/analysis/teef_behav.hpp>
#include <spelunk/analysis/teef_orbit.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/binary/symbol.hpp>
#include <spelunk/common/cache.hpp>
#include <spelunk/common/hash.hpp>
#include <spelunk/common/progress.hpp>
#include <spelunk/common/threads.hpp>
#include <spelunk/common/types.hpp>

#include "../fingerprint.hpp"
#include "../progress_panel.hpp"
#include "../subcommands.hpp"
#include "common.hpp"
#include "teef_internal.hpp"

namespace spelunk::cli {

namespace teef_internal {

// gcc/LTO clone suffixes (.cold, .isra.N, .constprop.N, .part.N,
// .lto_priv.N) mark fragments of a real function. Cold halves are tiny
// "load string, call, abort" stubs that chunk-vote against any
// generic-shape library fn, so drop them from corpus emit and from
// recognize input; the unsuffixed parent keeps the identity. LLVM's
// `.llvm.<hash>` clones are real instantiations and stay.
bool is_compiler_partition_variant(std::string_view nm) noexcept {
    if (nm.find(".cold")      != std::string_view::npos) return true;
    if (nm.find(".isra")      != std::string_view::npos) return true;
    if (nm.find(".constprop") != std::string_view::npos) return true;
    if (nm.find(".part")      != std::string_view::npos) return true;
    if (nm.find(".lto_priv")  != std::string_view::npos) return true;
    return false;
}

}  // namespace teef_internal

namespace {

// Hand-rolled hex appenders. The TSV worker emits ~22 fixed-width and
// 1-2 variable-width hex tokens per F row plus 9 per chunk row; on a
// 200K-fn binary that's millions of std::format calls, each of which
// goes through the format-spec parser, allocates a temporary string,
// and concatenates. These appenders write directly into the row
// buffer with a 16-byte char[] on the stack - measured 3-5× faster
// than std::format("{:016x}", v) for the hot path on gcc 15.
inline void append_hex16(std::string& s, u64 v) noexcept {
    static constexpr char kHex[] = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; --i) {
        buf[i] = kHex[v & 0xF];
        v >>= 4;
    }
    s.append(buf, 16);
}

inline void append_hex(std::string& s, u64 v) noexcept {
    // Variable-length lowercase hex matching std::format("{:x}", v).
    static constexpr char kHex[] = "0123456789abcdef";
    if (v == 0) { s += '0'; return; }
    char buf[16];
    int i = 16;
    while (v) {
        buf[--i] = kHex[v & 0xF];
        v >>= 4;
    }
    s.append(buf + i, static_cast<std::size_t>(16 - i));
}

}  // namespace

namespace teef_internal {

std::string cache_tag(const Args& args) {
    std::string tag = std::format("teef-{}", kTeefSchema);
    if (args.teef_no_l4) tag += "-nol4";
    if (args.min_fn_bytes) tag += std::format("-min{}", args.min_fn_bytes);
    if (args.max_fn_bytes) tag += std::format("-max{}", args.max_fn_bytes);
    if (args.max_cfg_blocks) tag += std::format("-cb{}", args.max_cfg_blocks);
    if (args.max_cfg_edges) tag += std::format("-ce{}", args.max_cfg_edges);
    if (args.max_cfg_insts) tag += std::format("-ci{}", args.max_cfg_insts);
    if (args.max_ir_insts) tag += std::format("-ii{}", args.max_ir_insts);
    return tag;
}

}  // namespace teef_internal

namespace {

// Parse hex string -> u64. Used by parse_tsv below.
[[nodiscard]] u64 parse_u64_hex_local(std::string_view s) noexcept {
    u64 v = 0;
    for (char c : s) {
        u64 d = (c >= '0' && c <= '9') ? static_cast<u64>(c - '0')
              : (c >= 'a' && c <= 'f') ? static_cast<u64>(c - 'a' + 10)
              : (c >= 'A' && c <= 'F') ? static_cast<u64>(c - 'A' + 10)
              : 0u;
        v = (v << 4) | d;
    }
    return v;
}

}  // namespace

namespace teef_internal {

// Parse a TEEF TSV (output of build_tsv / `spelunk --teef`) back into
// a per-function structure suitable for the recognizer's query path.
// Lets `--recognize` reuse the disk cache that `--teef` writes - no need
// to re-fingerprint a binary that was already analyzed once.
[[nodiscard]] std::vector<std::pair<addr_t, TeefFunction>>
parse_tsv(std::string_view tsv) {
    std::vector<std::pair<addr_t, TeefFunction>> out;
    std::unordered_map<addr_t, std::size_t> idx_by_addr;
    auto split_tabs = [](std::string_view line) {
        std::vector<std::string_view> f;
        std::size_t s = 0;
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (line[i] == '\t') { f.emplace_back(line.substr(s, i - s)); s = i + 1; }
        }
        f.emplace_back(line.substr(s));
        return f;
    };
    std::size_t pos = 0;
    while (pos < tsv.size()) {
        std::size_t nl = tsv.find('\n', pos);
        if (nl == std::string_view::npos) nl = tsv.size();
        auto line = tsv.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.empty()) continue;
        auto f = split_tabs(line);
        if (f.empty()) continue;
        if (f[0] == "F" && f.size() >= 24) {
            // 24-field rows are pre-max.4; 25-field rows carry prefix_hash
            // in the trailing column.
            // F row: addr  L2_exact  L2_mh*8  name
            //         L4_exact  L4_mh*8  L4_done  L4_aborted  topo_hash
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            TeefFunction tf;
            tf.whole.exact_hash = parse_u64_hex_local(f[2]);
            for (std::size_t k = 0; k < 8; ++k) {
                tf.whole.minhash[k] = parse_u64_hex_local(f[3 + k]);
            }
            tf.behav.exact_hash = parse_u64_hex_local(f[12]);
            for (std::size_t k = 0; k < 8; ++k) {
                tf.behav.minhash[k] = parse_u64_hex_local(f[13 + k]);
            }
            u32 done = 0;
            std::from_chars(f[21].data(),
                            f[21].data() + f[21].size(), done);
            tf.behav.traces_done = static_cast<u8>(std::min<u32>(done, 255));
            u32 aborted = 0;
            std::from_chars(f[22].data(),
                            f[22].data() + f[22].size(), aborted);
            tf.behav.traces_aborted = static_cast<u8>(std::min<u32>(aborted, 255));
            tf.topo_hash = parse_u64_hex_local(f[23]);
            tf.prefix_hash = (f.size() >= 25) ? parse_u64_hex_local(f[24]) : 0u;
            idx_by_addr[a] = out.size();
            out.emplace_back(a, std::move(tf));
        } else if (f[0] == "S" && f.size() >= 3) {
            // S<TAB>addr<TAB>hash1,hash2,...
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            auto it = idx_by_addr.find(a);
            if (it == idx_by_addr.end()) continue;
            std::string_view csv = f[2];
            std::size_t cp = 0;
            while (cp < csv.size()) {
                std::size_t comma = csv.find(',', cp);
                if (comma == std::string_view::npos) comma = csv.size();
                std::string_view tok = csv.substr(cp, comma - cp);
                if (!tok.empty()) {
                    out[it->second].second.string_hashes.push_back(parse_u64_hex_local(tok));
                }
                cp = comma + 1;
            }
        } else if (f[0] == "C" && f.size() >= 14) {
            const addr_t a = static_cast<addr_t>(parse_u64_hex_local(f[1]));
            auto it = idx_by_addr.find(a);
            if (it == idx_by_addr.end()) continue;
            TeefChunk ch;
            // kind + inst_count are emitted as decimal by build_tsv.
            u32 v = 0; std::from_chars(f[2].data(), f[2].data() + f[2].size(), v);
            ch.kind = static_cast<u8>(v);
            v = 0; std::from_chars(f[3].data(), f[3].data() + f[3].size(), v);
            ch.inst_count = v;
            ch.sig.exact_hash = parse_u64_hex_local(f[4]);
            for (std::size_t k = 0; k < 8; ++k) {
                ch.sig.minhash[k] = parse_u64_hex_local(f[5 + k]);
            }
            out[it->second].second.chunks.push_back(ch);
        }
    }
    return out;
}

// Shared by --teef and --recognize (cache miss). `scope` filters every
// fn-walking step. `corpus_mode` skips the K=64 behavioural traces for
// unnamed fns: load_tsv drops sub_* rows after counting their L2 hash,
// so their L4 columns are never read; recognize-time queries need L4
// for every fn and leave it false. `min_fn_bytes`/`max_fn_bytes` cull
// by byte extent before any per-fn work (obfuscated targets carry both
// hundreds of thousands of sub-32-byte stubs and section-spanning VM
// dispatchers whose cfg.build alone costs tens of ms); 0 means no
// bound. `l4_topo_filter` is the corpus's L0 topology set: target fns
// whose topology is absent skip the trace pass.
[[nodiscard]] std::string
build_tsv(const Binary& b,
          const ModuleScope& scope,
          bool corpus_mode,
          u64 min_fn_bytes,
          u64 max_fn_bytes,
          const TeefComputeOptions& compute_opts,
          std::ostream* stream) {
    const bool show = progress_enabled();

        std::unordered_map<addr_t, std::string> name_by_addr;
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.name.empty()) continue;
            if (!scope.contains(s.addr)) continue;
            name_by_addr.try_emplace(s.addr, s.name);
        }

        // Use enumerate_functions - same source as --functions - so we
        // pick up CFG-discovered sub_* on stripped / static-pie targets
        // (HellGates, Rust release builds, Go binaries). compute_call_graph
        // alone misses these because it filters on s.size != 0.
        std::vector<addr_t> fns;
        std::size_t filtered_small = 0;
        std::size_t filtered_large = 0;
        // Run enumerate_functions once and reuse for both the fn-address
        // gather AND the sized_fns table built below. The pass walks the
        // call graph and CFG-discovery sweep - on a 200K-fn binary it's
        // tens of seconds; doing it twice was outright duplicated work.
        auto disc = enumerate_functions(b, EnumerateMode::Auto,
                                        scope.lo, scope.hi);
        std::sort(disc.begin(), disc.end(),
            [](const auto& x, const auto& y) { return x.addr < y.addr; });
        {
            std::set<addr_t> uniq;
            // Named fns always go in regardless of size - they may be
            // intentional small thunks (deregister_tm_clones, _init).
            for (const auto& [a, _] : name_by_addr) uniq.insert(a);
            // CFG-discovered fns may have size=0 when the discovery
            // pass doesn't know the extent (linear-sweep entry points,
            // hellgate stubs, the bulk of obfuscator-spawned tiny
            // helpers). For the size-bracket filter we need a usable
            // size estimate; derive it from the gap to the next
            // discovered fn after sorting. Upper bound - over-counts
            // when there's padding/jump tables in between, but that's
            // the safe direction for filtering both ends.
            for (std::size_t i = 0; i < disc.size(); ++i) {
                u64 sz = disc[i].size;
                if (sz == 0 && i + 1 < disc.size() &&
                    disc[i + 1].addr > disc[i].addr) {
                    sz = disc[i + 1].addr - disc[i].addr;
                }
                if (b.import_at_plt(disc[i].addr)) continue;
                if (min_fn_bytes > 0 && sz > 0 && sz < min_fn_bytes) {
                    ++filtered_small;
                    continue;
                }
                if (max_fn_bytes > 0 && sz > max_fn_bytes) {
                    ++filtered_large;
                    continue;
                }
                uniq.insert(disc[i].addr);
            }
            fns.assign(uniq.begin(), uniq.end());
        }
        if (show && filtered_small > 0) {
            std::println(stderr,
                "spelunk: TEEF: --min-fn-size dropped {} fns smaller than {} bytes",
                filtered_small, min_fn_bytes);
        }
        if (show && filtered_large > 0) {
            std::println(stderr,
                "spelunk: TEEF: --max-fn-size dropped {} fns larger than {} bytes",
                filtered_large, max_fn_bytes);
        }

        // Per-fn reachable strings (TEEF schema v4): bucket each string
        // xref site into its containing fn by binary search over the
        // sized entries. Two structurally identical fns with disjoint
        // string sets are almost never the same function, so the
        // recognizer uses this to suppress structural false positives.
        // Size-0 shadow entries (linear-sweep probes inside another
        // fn) are skipped; their sites attribute to the real fn.
        std::vector<std::pair<addr_t, u64>> sized_fns;
        sized_fns.reserve(disc.size());
        for (const auto& d : disc) {
            if (b.import_at_plt(d.addr)) continue;
            if (d.size == 0) continue;
            sized_fns.emplace_back(d.addr, d.size);
        }
        // Also include named symbols whose size we can derive.
        for (const auto& s : b.symbols()) {
            if (s.is_import) continue;
            if (s.kind != SymbolKind::Function) continue;
            if (s.addr == 0 || s.size == 0) continue;
            if (!scope.contains(s.addr)) continue;
            sized_fns.emplace_back(s.addr, s.size);
        }
        std::sort(sized_fns.begin(), sized_fns.end());
        sized_fns.erase(std::unique(sized_fns.begin(), sized_fns.end(),
            [](const auto& x, const auto& y) { return x.first == y.first; }),
            sized_fns.end());

        std::unordered_map<addr_t, std::vector<std::string>> strings_by_fn;
        if (show) {
            std::println(stderr, "spelunk: TEEF: scanning strings for per-fn anchors...");
            std::fflush(stderr);
        }
        for (const auto& s : scan_strings(b)) {
            // Filter pure-noise strings - too short to identify. The
            // scanner already enforces ≥4-char strings; we tighten here
            // to 4 (== scanner floor; everything below is library-name-
            // length-or-less and contributes more noise than signal).
            if (s.text.size() < 4) continue;
            for (addr_t site : s.xrefs) {
                // Find the sized fn whose [entry, entry+size) actually
                // contains the site. upper_bound + walk back, then
                // verify containment. Sites that fall in gaps (no fn
                // covers them) are skipped - they can't be reliably
                // attributed.
                auto it = std::upper_bound(sized_fns.begin(), sized_fns.end(),
                    std::pair<addr_t, u64>{site, ~u64{0}});
                if (it == sized_fns.begin()) continue;
                --it;
                if (site >= it->first + it->second) continue;
                strings_by_fn[it->first].push_back(s.text);
            }
        }
        // Dedup + cap to top-8 by length per fn. Length-biased because
        // long unique strings ("X509_CHECK_FLAG_NO_WILDCARDS") are far
        // more identifying than short common ones ("ok", "%s").
        for (auto& [_, list] : strings_by_fn) {
            std::sort(list.begin(), list.end());
            list.erase(std::unique(list.begin(), list.end()), list.end());
            if (list.size() > 8) {
                std::partial_sort(list.begin(), list.begin() + 8, list.end(),
                    [](const std::string& x, const std::string& y) {
                        return x.size() > y.size();
                    });
                list.resize(8);
            }
        }

        const std::size_t total = fns.size();
        const unsigned threads = thread_pool_size(16);
        if (show) {
            std::println(stderr,
                "spelunk: TEEF on {} functions across {} threads (full decompile per fn)...",
                total, threads);
            std::fflush(stderr);
        }

        // Per-function results in input order. Workers pull indices off
        // `next` atomically; ordering is preserved by writing into the
        // pre-sized result vector at the function's index.
        std::vector<std::string> rows;
        if (!stream) rows.resize(total);
        std::mutex stream_mu;
        std::atomic<std::size_t> next{0};
        std::atomic<std::size_t> done{0};
        // Counters for the post-phase summary so the user can see how
        // much --l0-prefilter is actually helping vs. how many fns
        // still go through the full pipeline.
        std::atomic<std::size_t> early_exit_topo{0};
        std::atomic<std::size_t> empty_fingerprint{0};
        std::atomic<bool> fp_phase_done{false};

        // Time-driven progress panel. Workers used to print every Nth
        // fn; on huge or VM-protected targets a single fn can take
        // hundreds of milliseconds, so the user saw no update for tens
        // of seconds at a time. The ticker runs independently, refreshes
        // every 500 ms with whatever `done` and the worker pool have
        // accomplished, and renders a 3-line ANSI panel (header / bar /
        // stats) that's atomically repainted in place - no scrollback
        // noise. Falls back to a one-shot info line when stderr isn't
        // a TTY (`progress_enabled()` returns false).
        ProgressPanel panel;
        if (show) {
            panel.start("TEEF fingerprint", total, threads);
        }
        std::thread fp_ticker;
        if (show) {
            fp_ticker = std::thread([&] {
                while (!fp_phase_done.load(std::memory_order_relaxed)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                    const std::size_t d  = done.load(std::memory_order_relaxed);
                    const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
                    panel.tick(d, ee);
                }
            });
        }

        auto worker = [&] {
            while (true) {
                const std::size_t i = next.fetch_add(1, std::memory_order_relaxed);
                if (i >= total) break;
                const addr_t a = fns[i];
                // Corpus mode: sub_* rows lose their L4 sketch in
                // load_tsv anyway, so skip the K=64 traces (~3 ms each).
                const auto name_it = name_by_addr.find(a);
                const bool is_named = (name_it != name_by_addr.end());
                // Skip gcc partition variants (.cold/.isra/.constprop/
                // .part/.lto_priv) - fragments of real fns, not
                // standalone targets. Cold halves in particular all
                // share a "load string + call printf + abort" shape
                // that chunk-vote-collides against generic libstdc++
                // fns and emits confidently-wrong labels at recognize
                // time. The base function (without the suffix) still
                // gets fingerprinted; we just don't pollute the
                // corpus with its partition fragments.
                if (is_named && is_compiler_partition_variant(name_it->second)) {
                    done.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                const bool full_l4  = !corpus_mode || is_named;
                const auto tf = full_l4
                    ? compute_teef_max(b, a, compute_opts)
                    : compute_teef_with_chunks(b, a, compute_opts);
                const auto& bs = tf.behav;
                done.fetch_add(1, std::memory_order_relaxed);
                // Telemetry: distinguish "early-exited via topo filter"
                // from "made it through the full pipeline but came out
                // empty" (e.g., insn-cap hit). Lets the user see at a
                // glance whether --l0-prefilter is paying off.
                if (tf.whole.exact_hash == 0) {
                    if (compute_opts.l4_topo_filter && tf.topo_hash != 0 &&
                        !compute_opts.l4_topo_filter->contains(tf.topo_hash)) {
                        early_exit_topo.fetch_add(1, std::memory_order_relaxed);
                    } else {
                        empty_fingerprint.fetch_add(1, std::memory_order_relaxed);
                    }
                }
                if (tf.whole.exact_hash == 0) continue;
                std::string name;
                if (is_named) {
                    name = name_it->second;
                } else {
                    name = std::format("sub_{:x}", a);
                }
                // F row, 25 tab-separated fields:
                //   F addr L2_exact L2_mh*8 name L4_exact L4_mh*8
                //   L4_done L4_aborted topo_hash prefix_hash
                // L4 columns trail the name so fields 0..11 stay fixed.
                // prefix_hash is non-zero only for tiny fns (<= 16 insns).
                std::string buf;
                buf.reserve(512);
                buf += "F\t";
                append_hex(buf, a);
                buf += '\t';
                append_hex16(buf, tf.whole.exact_hash);
                for (u64 mh : tf.whole.minhash) {
                    buf += '\t';
                    append_hex16(buf, mh);
                }
                buf += '\t';
                buf += name;
                buf += '\t';
                append_hex16(buf, bs.exact_hash);
                for (u64 mh : bs.minhash) {
                    buf += '\t';
                    append_hex16(buf, mh);
                }
                buf += '\t';
                buf += std::to_string(static_cast<u32>(bs.traces_done));
                buf += '\t';
                buf += std::to_string(static_cast<u32>(bs.traces_aborted));
                buf += '\t';
                append_hex16(buf, tf.topo_hash);
                buf += '\t';
                append_hex16(buf, tf.prefix_hash);
                buf += '\n';

                // String-anchor row: S<TAB>addr<TAB>hash1,hash2,...
                // Up to 8 fnv1a64 hashes of the function's identifying
                // strings. Loader stores them on WholeEntry; recognizer
                // uses overlap as a precision filter against
                // structural false positives.
                if (auto sit = strings_by_fn.find(a); sit != strings_by_fn.end() && !sit->second.empty()) {
                    buf += "S\t";
                    append_hex(buf, a);
                    bool first = true;
                    for (const auto& str : sit->second) {
                        buf += first ? '\t' : ',';
                        first = false;
                        append_hex16(buf, fnv1a_64(str));
                    }
                    buf += '\n';
                }
                // Chunk rows: C<TAB>addr<TAB>kind<TAB>insts<TAB>exact<TAB>mh0..7<TAB>name
                for (const auto& ch : tf.chunks) {
                    if (ch.sig.exact_hash == 0) continue;
                    buf += "C\t";
                    append_hex(buf, a);
                    buf += '\t';
                    buf += std::to_string(static_cast<unsigned>(ch.kind));
                    buf += '\t';
                    buf += std::to_string(ch.inst_count);
                    buf += '\t';
                    append_hex16(buf, ch.sig.exact_hash);
                    for (u64 mh : ch.sig.minhash) {
                        buf += '\t';
                        append_hex16(buf, mh);
                    }
                    buf += '\t';
                    buf += name;
                    buf += '\n';
                }
                if (stream) {
                    std::lock_guard lock(stream_mu);
                    (*stream) << buf;
                } else {
                    rows[i] = std::move(buf);
                }
            }
        };

        std::vector<std::thread> pool;
        pool.reserve(threads);
        for (unsigned k = 0; k < threads; ++k) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
        fp_phase_done.store(true, std::memory_order_relaxed);
        if (fp_ticker.joinable()) fp_ticker.join();
        if (show) {
            const std::size_t ee = early_exit_topo.load(std::memory_order_relaxed);
            const std::size_t eg = empty_fingerprint.load(std::memory_order_relaxed);
            // Pin the final frame in scrollback so the user can see
            // the completed run after the next phase prints over it.
            panel.finish(total, ee);
            const std::size_t full_pipe = (total > ee + eg) ? (total - ee - eg) : 0;
            std::println(stderr,
                "spelunk: TEEF: {} fns full-pipeline, {} early-exit (l0-prefilter), "
                "{} empty (insn-cap / lift bail)",
                full_pipe, ee, eg);
        }

    if (stream) {
        stream->flush();
        return {};
    }

    std::string out;
    std::size_t total_bytes = 0;
    for (const auto& r : rows) total_bytes += r.size();
    out.reserve(total_bytes);
    for (const auto& r : rows) out += r;
    return out;
}

}  // namespace teef_internal

int run_identify(const Args& args, const Binary& b) {
    auto hits = identify_functions(b, args.identify_threshold);
    const auto tsv = format_identify_tsv(hits);
    std::fwrite(tsv.data(), 1, tsv.size(), stdout);
    return EXIT_SUCCESS;
}

int run_teef(const Args& args, const Binary& b) {
    TeefComputeOptions opts;
    opts.min_chunk_insts = 10;
    opts.skip_l4 = args.teef_no_l4;
    opts.max_cfg_blocks = args.max_cfg_blocks;
    opts.max_cfg_edges = args.max_cfg_edges;
    opts.max_cfg_insts = args.max_cfg_insts;
    opts.max_ir_insts = args.max_ir_insts;

    if (args.no_cache) {
        (void)teef_internal::build_tsv(
            b, {}, /*corpus_mode=*/true,
            args.min_fn_bytes, args.max_fn_bytes, opts, &std::cout);
        return EXIT_SUCCESS;
    }

    return run_cached(args, teef_internal::cache_tag(args), [&] {
        return teef_internal::build_tsv(
            b, {}, /*corpus_mode=*/true,
            args.min_fn_bytes, args.max_fn_bytes, opts);
    });
}

// --orbit-dump: one TSV row per fn with the L2, L3 (orbit) and L4
// signatures side by side, for the cross-compile recall script.
//   addr name L2_exact L2_mh*8 L3_exact L3_mh*16 L3_nodes L3_iters
//   L3_budget L4_exact L4_mh*8 L4_traces_done L4_traces_aborted
// Honours --module; never cached.
int run_orbit_dump(const Args& args, const Binary& b) {
    const ModuleScope scope = resolve_module_scope(b, args.module_filter);

    std::unordered_map<addr_t, std::string> name_by_addr;
    for (const auto& s : b.symbols()) {
        if (s.is_import) continue;
        if (s.kind != SymbolKind::Function) continue;
        if (s.addr == 0 || s.name.empty()) continue;
        if (!scope.contains(s.addr)) continue;
        name_by_addr.try_emplace(s.addr, s.name);
    }

    std::set<addr_t> uniq;
    for (const auto& [a, _] : name_by_addr) uniq.insert(a);
    for (const auto& d : enumerate_functions(b, EnumerateMode::Auto, scope.lo, scope.hi)) {
        if (!b.import_at_plt(d.addr)) uniq.insert(d.addr);
    }
    std::vector<addr_t> fns(uniq.begin(), uniq.end());

    std::string out;
    out.reserve(fns.size() * 384);
    out += "# orbit-dump  cols: addr name L2_exact L2_mh*8 "
           "L3_exact L3_mh*16 L3_nodes L3_iters L3_budget "
           "L4_exact L4_mh*8 L4_done L4_aborted\n";
    for (addr_t a : fns) {
        const auto tf = compute_teef_with_chunks(b, a);
        const auto os = compute_orbit_sig(b, a);
        const auto bs = compute_behav_sig(b, a);

        std::string name;
        if (auto it = name_by_addr.find(a); it != name_by_addr.end()) {
            name = it->second;
        } else {
            name = std::format("sub_{:x}", a);
        }

        out += std::format("0x{:x}\t{}\t{:016x}", a, name, tf.whole.exact_hash);
        for (u64 m : tf.whole.minhash) out += std::format("\t{:016x}", m);
        out += std::format("\t{:016x}", os.exact_hash);
        for (u64 m : os.minhash)       out += std::format("\t{:016x}", m);
        out += std::format("\t{}\t{}\t{}",
                            os.egraph_nodes,
                            static_cast<u32>(os.total_iters),
                            os.budget_hit ? 1 : 0);
        out += std::format("\t{:016x}", bs.exact_hash);
        for (u64 m : bs.minhash)       out += std::format("\t{:016x}", m);
        out += std::format("\t{}\t{}",
                            static_cast<u32>(bs.traces_done),
                            static_cast<u32>(bs.traces_aborted));
        out += '\n';
    }
    std::cout << out;
    std::cout.flush();
    return EXIT_SUCCESS;
}

int run_fingerprints(const Args& args, const Binary& b) {
    const int rc = run_cached(args, fingerprints_cache_tag(args),
                              [&] {
                                  return build_fingerprints_output(
                                      b, args.min_fn_bytes, args.max_fn_bytes);
                              });
    // Mirror the output to --fingerprint-out PATH so the fingerprints can
    // travel between machines / repo checkouts where the disk cache
    // doesn't apply.
    if (rc == EXIT_SUCCESS && !args.fp_out.empty()) {
        const auto dir = args.cache_dir.empty()
            ? cache::default_dir()
            : std::filesystem::path(args.cache_dir);
        auto k = cache::key_for(args.binary, cache_scope_tag(args));
        if (k) {
            if (auto hit = cache::read(dir, *k, fingerprints_cache_tag(args)); hit) {
                std::ofstream f(args.fp_out, std::ios::binary | std::ios::trunc);
                if (f) f.write(hit->data(), static_cast<std::streamsize>(hit->size()));
            }
        }
    }
    return rc;
}

}  // namespace spelunk::cli
