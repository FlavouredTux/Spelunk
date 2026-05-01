#include <ember/analysis/teef_recognize.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ember/analysis/teef.hpp>
#include <ember/common/progress.hpp>

namespace ember {

namespace {

// Parse a 16-char lowercase hex token into u64. Returns 0 on failure
// — corpus rows with malformed hashes are dropped.
[[nodiscard]] u64 parse_u64_hex(std::string_view s) noexcept {
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

[[nodiscard]] float
jaccard_minhash(const std::array<u64, 8>& a, const std::array<u64, 8>& b) noexcept {
    int eq = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        if (a[i] == b[i]) ++eq;
    }
    return static_cast<float>(eq) / 8.0f;
}

}  // namespace

// Whether two runtime tags can plausibly match. Conservative — only
// the obvious cross-language false-positive lanes are blocked. A Rust
// binary linking libc / libcrypto / libgcc_s is normal; a Rust binary
// matching libstdc++ template instantiations is the noise class we're
// trying to suppress.
bool runtime_compatible(std::string_view q, std::string_view c) noexcept {
    if (q.empty() || c.empty()) return true;       // unknown matches all
    if (q == c) return true;

    // ---- Helper buckets (each tag belongs to one or more of these) ----
    // Plain C — both POSIX libc-ish and Windows CRT count as "C-shaped"
    // runtimes for matching purposes. A Win32 binary calling memcpy
    // can validly match a libc/musl memcpy fingerprint.
    auto is_c_family = [](std::string_view t) {
        return t == teef_runtime::kC
            || t == teef_runtime::kLibc
            || t == teef_runtime::kMsvcrt
            || t == teef_runtime::kUcrt
            || t == teef_runtime::kVcruntime;
    };
    auto is_winapi = [](std::string_view t) {
        return t == teef_runtime::kWinapi;
    };
    auto is_itanium_cxx = [](std::string_view t) {
        return t == teef_runtime::kLibstdcxx
            || t == teef_runtime::kCxx;
    };
    auto is_msvc_cxx = [](std::string_view t) {
        return t == teef_runtime::kCxxMsvc;
    };

    // Rust never matches C++ stdlib (Itanium OR MSVC). Rust↔C/winapi/
    // openssl is fine — Rust binaries link those for real.
    if (q == teef_runtime::kRust) {
        return !is_itanium_cxx(c) && !is_msvc_cxx(c);
    }
    // Symmetrically a libstdc++/cxx/cxxmsvc query shouldn't match Rust.
    if (is_itanium_cxx(q) || is_msvc_cxx(q)) {
        if (c == teef_runtime::kRust) return false;
    }
    // Itanium C++ vs MSVC C++ stdlib — different ABIs, different name
    // mangling, different vtable layout. Block.
    if (is_itanium_cxx(q) && is_msvc_cxx(c)) return false;
    if (is_msvc_cxx(q) && is_itanium_cxx(c)) return false;

    // C-family ↔ C-family (libc/msvcrt/ucrt/vcruntime/c): all compatible.
    // Lots of std C functions (memcpy, strlen, qsort) appear in both
    // POSIX and Windows runtimes with matching structure.
    if (is_c_family(q) && is_c_family(c)) return true;

    // winapi against POSIX libc — usually different (kernel32 has no
    // POSIX equivalent), but also low-volume. Allow; structural match
    // alone is the gate.
    if (is_winapi(q) || is_winapi(c)) return true;

    return true;
}

namespace {

// Per-row parsed records. The parallel parse phase emits these into
// per-thread buffers; the serial merge phase below walks them in file
// order to populate the corpus indexes.
struct ParsedF {
    u64                 addr;
    u64                 l2_exact;
    std::array<u64, 8>  l2_mh;
    u64                 l4_exact;
    std::array<u64, 8>  l4_mh;
    u64                 topo_hash;
    std::string         name;
    std::string         runtime;
};
struct ParsedS {
    u64                 addr;
    std::vector<u64>    hashes;
};
struct ParsedC {
    u64                 chunk_hash;
    u32                 inst_count;
    std::string         name;
    std::string         runtime;
};
struct ChunkParse {
    std::vector<ParsedF>  f;
    std::vector<ParsedS>  s;
    std::vector<ParsedC>  c;
    // T rows in this chunk, ordered by position. The merge phase
    // applies them in document order across all chunks to get the
    // active_runtime tag right for each subsequent F/C row.
    std::vector<std::pair<std::size_t /*chunk-relative pos*/,
                          std::string /*runtime tag*/>> t;
};

// Parse one F row's 24 tab-separated fields directly from the line
// view into a ParsedF. Skips invalid rows (returns false). The line
// must NOT include the trailing newline.
[[nodiscard]] bool parse_f_row(std::string_view line,
                               const std::string& active_runtime,
                               ParsedF& out) {
    // Walk fields by tab, populating out as we go. We expect 24 fields:
    //   F addr L2_exact L2_mh*8 name L4_exact L4_mh*8 L4_done L4_aborted topo_hash
    std::array<std::string_view, 24> f;
    std::size_t cur = 0;
    std::size_t n   = 0;
    for (std::size_t i = 0; i < line.size() && n < f.size(); ++i) {
        if (line[i] == '\t') {
            f[n++] = line.substr(cur, i - cur);
            cur = i + 1;
        }
    }
    if (n < f.size()) f[n++] = line.substr(cur);
    if (n < 24) return false;

    out.addr     = parse_u64_hex(f[1]);
    out.l2_exact = parse_u64_hex(f[2]);
    for (std::size_t k = 0; k < 8; ++k) out.l2_mh[k] = parse_u64_hex(f[3 + k]);
    out.name.assign(f[11]);
    out.l4_exact = parse_u64_hex(f[12]);
    for (std::size_t k = 0; k < 8; ++k) out.l4_mh[k] = parse_u64_hex(f[13 + k]);
    out.topo_hash = parse_u64_hex(f[23]);
    out.runtime   = active_runtime;
    return true;
}

[[nodiscard]] bool parse_c_row(std::string_view line,
                               const std::string& active_runtime,
                               ParsedC& out) {
    // C addr kind insts exact mh*8 name (14 fields)
    std::array<std::string_view, 14> f;
    std::size_t cur = 0;
    std::size_t n   = 0;
    for (std::size_t i = 0; i < line.size() && n < f.size(); ++i) {
        if (line[i] == '\t') {
            f[n++] = line.substr(cur, i - cur);
            cur = i + 1;
        }
    }
    if (n < f.size()) f[n++] = line.substr(cur);
    if (n < 14) return false;

    out.chunk_hash = parse_u64_hex(f[4]);
    if (out.chunk_hash == 0) return false;
    u32 sz = 0;
    std::from_chars(f[3].data(), f[3].data() + f[3].size(), sz);
    out.inst_count = sz;
    out.name.assign(f[13]);
    out.runtime.assign(active_runtime);
    return true;
}

[[nodiscard]] bool parse_s_row(std::string_view line, ParsedS& out) {
    // S addr csv-of-hashes (3 fields)
    auto t1 = line.find('\t');
    if (t1 == std::string_view::npos) return false;
    auto t2 = line.find('\t', t1 + 1);
    if (t2 == std::string_view::npos) return false;
    out.addr = parse_u64_hex(line.substr(t1 + 1, t2 - t1 - 1));
    out.hashes.clear();
    std::string_view csv = line.substr(t2 + 1);
    std::size_t cp = 0;
    while (cp < csv.size()) {
        std::size_t comma = csv.find(',', cp);
        if (comma == std::string_view::npos) comma = csv.size();
        std::string_view tok = csv.substr(cp, comma - cp);
        if (!tok.empty()) out.hashes.push_back(parse_u64_hex(tok));
        cp = comma + 1;
    }
    return true;
}

// Parse a chunk of the mmap'd file [begin, end) into per-row records.
// `initial_runtime` is the active T-tag at chunk start (determined by
// a serial pre-scan of T rows). Each chunk's local T-row updates apply
// only WITHIN the chunk; the merge phase serializes T-row effects
// across the whole file.
void parse_chunk(const char* begin, const char* end,
                 std::string initial_runtime,
                 std::size_t chunk_offset,
                 ChunkParse& out) {
    std::string runtime = std::move(initial_runtime);
    const char* p = begin;
    while (p < end) {
        const char* nl = static_cast<const char*>(
            std::memchr(p, '\n', static_cast<std::size_t>(end - p)));
        if (!nl) nl = end;
        std::string_view line(p, static_cast<std::size_t>(nl - p));
        // Strip optional trailing CR.
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        if (line.empty()) { p = nl + (nl < end ? 1 : 0); continue; }

        const char tag = line[0];
        if (tag == 'F') {
            ParsedF f;
            if (parse_f_row(line, runtime, f)) out.f.push_back(std::move(f));
        } else if (tag == 'S') {
            ParsedS s;
            if (parse_s_row(line, s)) out.s.push_back(std::move(s));
        } else if (tag == 'C') {
            ParsedC c;
            if (parse_c_row(line, runtime, c)) out.c.push_back(std::move(c));
        } else if (tag == 'T') {
            // T runtime <tag>
            auto t1 = line.find('\t');
            auto t2 = (t1 != std::string_view::npos) ? line.find('\t', t1 + 1)
                                                     : std::string_view::npos;
            if (t1 != std::string_view::npos && t2 != std::string_view::npos) {
                if (line.substr(t1 + 1, t2 - t1 - 1) == "runtime") {
                    runtime.assign(line.substr(t2 + 1));
                    out.t.emplace_back(
                        chunk_offset + static_cast<std::size_t>(p - begin),
                        runtime);
                }
            }
        }
        p = nl + (nl < end ? 1 : 0);
    }
}

}  // namespace

std::unordered_set<u64> TeefCorpus::topo_hashes() const {
    std::unordered_set<u64> out;
    out.reserve(whole_by_name_.size());
    for (const auto& e : whole_by_name_) {
        if (e.topo_hash != 0) out.insert(e.topo_hash);
    }
    return out;
}

std::size_t TeefCorpus::load_tsv(const std::filesystem::path& path) {
    using clock_t  = std::chrono::steady_clock;
    using ms_t     = std::chrono::duration<double, std::milli>;
    // Per-file load timing. Suppressed when EMBER_QUIET=1; printed
    // unconditionally otherwise (even when stderr isn't a TTY, since
    // these lines are diagnostic — users running the recognizer over
    // multi-100MB corpora want to know what's slow). progress_enabled()
    // gates the noisy progress bars; this is a one-shot per file.
    const bool dbg = !(std::getenv("EMBER_QUIET") != nullptr &&
                       std::getenv("EMBER_QUIET")[0] == '1');
    const auto t_open = clock_t::now();

    // ---- mmap the file -------------------------------------------------
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (::fstat(fd, &st) < 0 || st.st_size <= 0) {
        ::close(fd);
        return 0;
    }
    const std::size_t sz = static_cast<std::size_t>(st.st_size);
    void* m = ::mmap(nullptr, sz, PROT_READ, MAP_PRIVATE, fd, 0);
    ::close(fd);   // mapping survives the close
    if (m == MAP_FAILED) return 0;
    const char* const data = static_cast<const char*>(m);
    const char* const file_end = data + sz;
    const auto t_mmap = clock_t::now();

    // ---- T-row pre-scan ------------------------------------------------
    // T rows are rare (current build_teef_tsv emits none, but the format
    // supports them and older corpora may have them). Walk the file
    // serially picking out their offsets so each chunk worker starts
    // with the correct active_runtime. Single-pass `memchr` over the
    // mmap is fast even for 80MB inputs.
    std::vector<std::pair<std::size_t /*offset of next char after T row*/,
                          std::string /*runtime tag*/>> t_marks;
    {
        const char* p = data;
        while (p < file_end) {
            const char* nl = static_cast<const char*>(
                std::memchr(p, '\n', static_cast<std::size_t>(file_end - p)));
            const char* line_end = nl ? nl : file_end;
            if (line_end > p && p[0] == 'T') {
                std::string_view line(p, static_cast<std::size_t>(line_end - p));
                if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
                auto t1 = line.find('\t');
                auto t2 = (t1 != std::string_view::npos) ? line.find('\t', t1 + 1)
                                                         : std::string_view::npos;
                if (t1 != std::string_view::npos && t2 != std::string_view::npos
                    && line.substr(t1 + 1, t2 - t1 - 1) == "runtime") {
                    t_marks.emplace_back(
                        static_cast<std::size_t>(line_end - data) +
                        (nl ? 1 : 0),
                        std::string(line.substr(t2 + 1)));
                }
            }
            p = nl ? nl + 1 : file_end;
        }
    }
    auto runtime_at_offset = [&](std::size_t off) -> std::string {
        std::string r;
        for (const auto& [pos, tag] : t_marks) {
            if (pos <= off) r = tag;
            else break;
        }
        return r;
    };

    // ---- Chunk the mmap'd region at line boundaries -------------------
    const unsigned hw = std::max(1u, std::thread::hardware_concurrency());
    // For tiny files, avoid the per-thread overhead — a single worker
    // beats spawning four for an 80 KB input.
    const unsigned threads = (sz < (256u * 1024u))
        ? 1u
        : std::min(hw, 16u);
    std::vector<std::pair<const char*, const char*>> bounds(threads);
    if (threads == 1) {
        bounds[0] = {data, file_end};
    } else {
        const std::size_t chunk_size = sz / threads;
        for (unsigned t = 0; t < threads; ++t) {
            const char* begin = data + t * chunk_size;
            const char* end_p = (t == threads - 1) ? file_end
                                                   : data + (t + 1) * chunk_size;
            // Align begin (except chunk 0) to the start of the next line —
            // the previous chunk owns whatever line straddles the boundary.
            if (t > 0 && begin < file_end) {
                const char* nl = static_cast<const char*>(
                    std::memchr(begin, '\n',
                                static_cast<std::size_t>(file_end - begin)));
                begin = nl ? nl + 1 : file_end;
            }
            // Align end to the start of the next line so the chunk owns
            // its last line in full.
            if (end_p < file_end) {
                const char* nl = static_cast<const char*>(
                    std::memchr(end_p, '\n',
                                static_cast<std::size_t>(file_end - end_p)));
                end_p = nl ? nl + 1 : file_end;
            }
            bounds[t] = {begin, end_p};
        }
    }

    // ---- Parallel parse ------------------------------------------------
    std::vector<ChunkParse> parts(threads);
    if (threads == 1) {
        parse_chunk(bounds[0].first, bounds[0].second,
                    runtime_at_offset(0), 0, parts[0]);
    } else {
        std::vector<std::thread> pool;
        pool.reserve(threads);
        for (unsigned t = 0; t < threads; ++t) {
            pool.emplace_back([&, t] {
                const std::size_t off =
                    static_cast<std::size_t>(bounds[t].first - data);
                parse_chunk(bounds[t].first, bounds[t].second,
                            runtime_at_offset(off), off, parts[t]);
            });
        }
        for (auto& th : pool) th.join();
    }
    const auto t_parsed = clock_t::now();

    // ---- Serial merge into corpus indexes ------------------------------
    // Order matters for correctness: F rows establish idx_by_addr that
    // S rows depend on, so do all F rows first, then S rows. C rows are
    // independent. Within the F pass we also build the inverted indexes
    // (whole_exact_, whole_l4_exact_, whole_topo_, whole_minhash_,
    // whole_popularity_, whole_l4_popularity_).
    std::size_t rows = 0;
    std::unordered_map<u64, std::size_t> idx_by_addr;

    // Pre-reserve to avoid quadratic vector growth during merge.
    {
        std::size_t total_f = 0;
        for (const auto& p : parts) total_f += p.f.size();
        whole_by_name_.reserve(whole_by_name_.size() + total_f);
    }

    for (const auto& part : parts) {
        for (auto& f : part.f) {
            // Popularity counts every F row including sub_* (the
            // recognizer's "trivial-shape" guard depends on this).
            if (f.l2_exact != 0) ++whole_popularity_[f.l2_exact];
            if (f.name.empty() || f.name.starts_with("sub_")) continue;
            const std::size_t idx = whole_by_name_.size();
            WholeEntry e;
            e.name       = f.name;
            e.exact_hash = f.l2_exact;
            e.minhash    = f.l2_mh;
            e.runtime    = f.runtime;
            e.l4_exact   = f.l4_exact;
            e.l4_minhash = f.l4_mh;
            e.topo_hash  = f.topo_hash;
            whole_by_name_.push_back(std::move(e));
            const auto& we = whole_by_name_[idx];
            if (we.exact_hash != 0) {
                whole_exact_.emplace(we.exact_hash, idx);
            }
            if (we.l4_exact != 0) {
                whole_l4_exact_.emplace(we.l4_exact, idx);
                ++whole_l4_popularity_[we.l4_exact];
            }
            if (we.topo_hash != 0) {
                whole_topo_.emplace(we.topo_hash, idx);
            }
            for (std::size_t k = 0; k < 8; ++k) {
                whole_minhash_[k][we.minhash[k]]
                    .push_back(static_cast<u32>(idx));
            }
            if (f.addr != 0) idx_by_addr.emplace(f.addr, idx);
            idx_by_name_.try_emplace(we.name, idx);
            ++rows;
        }
    }

    // S rows attach per-fn identifying-string hashes to a previously-
    // loaded WholeEntry by addr. F rows from sub_* drop their addr from
    // idx_by_addr, so S rows on those silently no-op.
    for (auto& part : parts) {
        for (auto& s : part.s) {
            auto it = idx_by_addr.find(s.addr);
            if (it == idx_by_addr.end()) continue;
            auto& target = whole_by_name_[it->second].string_hashes;
            target.insert(target.end(), s.hashes.begin(), s.hashes.end());
            ++rows;
        }
    }

    for (auto& part : parts) {
        for (auto& c : part.c) {
            if (c.name.empty() || c.name.starts_with("sub_")) continue;
            chunk_index_[c.chunk_hash].push_back(
                ChunkRef{std::move(c.name), c.inst_count, std::move(c.runtime)});
            ++rows;
        }
    }

    const auto t_merged = clock_t::now();
    ::munmap(m, sz);

    if (dbg) {
        const double mb       = static_cast<double>(sz) / (1024.0 * 1024.0);
        const auto   t_open_ms   = ms_t(t_mmap   - t_open).count();
        const auto   t_parse_ms  = ms_t(t_parsed - t_mmap).count();
        const auto   t_merge_ms  = ms_t(t_merged - t_parsed).count();
        const auto   t_total_ms  = ms_t(t_merged - t_open).count();
        std::fprintf(stderr,
            "ember: corpus %s: %.1f MB / %zu rows  "
            "(mmap+pre %.0fms · parse %.0fms ×%u · merge %.0fms · total %.0fms)\n",
            path.c_str(), mb, rows,
            t_open_ms, t_parse_ms, threads, t_merge_ms, t_total_ms);
    }
    return rows;
}

std::vector<TeefMatch>
TeefCorpus::recognize(const TeefFunction& query, std::size_t top_k,
                      std::string_view query_runtime) const {
    if (query.whole.exact_hash == 0) return {};

    // String-anchor disqualifier. If the query AND the candidate both
    // have ≥2 identifying strings and they share zero hashes, the
    // structural similarity is overwhelmingly likely to be coincidence
    // (different error messages, different format strings, different
    // path constants). Returns true ⇒ "this candidate is plausible";
    // false ⇒ "ditch it." Conservative — when either side has < 2
    // strings (small fns, EH cleanup, anonymous helpers), the filter
    // is bypassed and structural match is the sole signal as before.
    const auto& qs = query.string_hashes;
    auto strings_compatible = [&](const std::vector<u64>& cs) -> bool {
        if (qs.size() < 2 || cs.size() < 2) return true;
        for (u64 q : qs) {
            for (u64 c : cs) if (q == c) return true;
        }
        return false;
    };

    // L4 (behavioural) jaccard helper — used both as the primary path
    // when query has an L4 sketch and as a verifier on top of the L2
    // whole-jaccard path. Returns 0.0 if either side has no L4 sketch.
    const bool query_has_l4 = (query.behav.exact_hash != 0);
    auto l4_jaccard_with = [&](const WholeEntry& we) -> float {
        if (!query_has_l4 || we.l4_exact == 0) return 0.0f;
        if (we.l4_exact == query.behav.exact_hash) return 1.0f;
        int eq = 0;
        for (std::size_t k = 0; k < 8; ++k) {
            if (we.l4_minhash[k] == query.behav.minhash[k]) ++eq;
        }
        return static_cast<float>(eq) / 8.0f;
    };

    // ---- Behavioural exact match (highest precision) ----
    // L4 collisions are 64-trace I/O-multiset hashes; an accidental
    // collision between two semantically-distinct functions is
    // vanishingly rare. Same boilerplate guard as L2 — if the L4 hash
    // is shared by many corpus rows it's a "trivial-shape behaviour"
    // (return-zero, identity stub) and a single canonical name
    // shouldn't be surfaced. kMaxL4Bucket is tighter than the L2
    // counterpart since L4 collisions on substantive code are very
    // unusual.
    constexpr std::size_t kMaxL4Bucket = 4;
    if (query_has_l4) {
        auto l4_pop = whole_l4_popularity_.find(query.behav.exact_hash);
        const std::size_t l4_pop_n = (l4_pop == whole_l4_popularity_.end())
            ? 0u : l4_pop->second;
        const std::size_t bucket = whole_l4_exact_.count(query.behav.exact_hash);
        if (l4_pop_n <= kMaxL4Bucket && bucket > 0 && bucket <= kMaxL4Bucket) {
            auto [it_lo, it_hi] = whole_l4_exact_.equal_range(query.behav.exact_hash);
            std::unordered_set<std::string> distinct;
            std::vector<std::string> ordered;
            for (auto it = it_lo; it != it_hi; ++it) {
                const auto& we = whole_by_name_[it->second];
                if (!runtime_compatible(query_runtime, we.runtime)) continue;
                if (!strings_compatible(we.string_hashes)) continue;
                if (distinct.insert(we.name).second) ordered.push_back(we.name);
            }
            if (ordered.size() == 1) {
                return { TeefMatch{ordered[0], 1.0f, "behav-exact", 0} };
            }
            if (!ordered.empty()) {
                std::vector<TeefMatch> out;
                const float conf = 1.0f / static_cast<float>(ordered.size());
                for (auto& nm : ordered) {
                    out.push_back(TeefMatch{std::move(nm), conf, "behav-exact-tied", 0});
                    if (out.size() >= top_k) break;
                }
                return out;
            }
        }
    }

    // Corpus-side gate: a hash shared by many corpus F rows (named
    // OR sub_*) is a "common trivial shape" and a single canonical
    // name shouldn't be surfaced as the unique answer. Caller-side
    // gates (query-side popularity in particular) handle the
    // complementary case where the unknown binary itself has many
    // tiny functions hashing the same.
    auto pop_it = whole_popularity_.find(query.whole.exact_hash);
    const std::size_t hash_popularity = (pop_it == whole_popularity_.end())
        ? 0u : pop_it->second;
    const bool hash_too_common = hash_popularity > kMaxWholeBucket;

    // ---- Whole-function exact match (highest precision) ----
    // If the corpus has exactly one function with our query's hash,
    // that's the answer. Multiple matches → ambiguous; emit the first
    // few as low-confidence candidates.
    //
    // Boilerplate guard: if the corpus has MANY entries with this hash
    // (e.g., a 1-instruction `xgetbv` stub that hundreds of trivial
    // functions hash equivalent to), we can't trust whole-exact even
    // if `distinct` size is 1 — the query is itself just a trivial
    // stub that happens to match a popular name. Skip and fall through
    // to chunk-vote, which requires substantive evidence.
    {
        const std::size_t bucket = whole_exact_.count(query.whole.exact_hash);
        if (!hash_too_common && bucket > 0 && bucket <= kMaxWholeBucket) {
            auto [it_lo, it_hi] = whole_exact_.equal_range(query.whole.exact_hash);
            std::unordered_set<std::string> distinct;
            std::vector<std::string> ordered;
            for (auto it = it_lo; it != it_hi; ++it) {
                const auto& we = whole_by_name_[it->second];
                if (!runtime_compatible(query_runtime, we.runtime)) continue;
                if (!strings_compatible(we.string_hashes)) continue;
                if (distinct.insert(we.name).second) ordered.push_back(we.name);
            }
            if (ordered.size() == 1) {
                return { TeefMatch{ordered[0], 1.0f, "whole-exact", 0} };
            }
            if (!ordered.empty()) {
                std::vector<TeefMatch> out;
                const float conf = 1.0f / static_cast<float>(ordered.size());
                for (auto& nm : ordered) {
                    out.push_back(TeefMatch{std::move(nm), conf, "whole-exact-tied", 0});
                    if (out.size() >= top_k) break;
                }
                return out;
            }
        }
    }

    // ---- Whole-function jaccard fallback ----
    // CEBin-style two-stage: L2 whole-jaccard narrows candidates, then
    // L4 re-ranks. When the query has an L4 sketch, the per-candidate
    // score is 0.5·L2_jacc + 0.5·L4_jacc and the acceptance bar drops
    // to 0.6 (with a 0.20 second-best margin) — behavioural agreement
    // is much stronger evidence than structural similarity alone, so a
    // weaker L2 with strong L4 backing is now trusted.
    //
    // L0 topo pre-filter: when the query has a topo_hash and the corpus
    // has entries with the same topo, scan that bucket first. Most query
    // fns have a unique topo collision in the corpus, so the bucket
    // narrows the candidate set from O(corpus) to O(few). Falls through
    // to a full scan if the bucket is empty or doesn't yield a
    // confident enough match — pure perf optimization, never rejects
    // a candidate.
    //
    // When the query has no L4 (the L4 interpreter aborted on this
    // function — rare, but happens on pathological IR), the score
    // collapses to pure L2 and the conservative thresholds (0.875 bar,
    // 0.25 margin) apply.
    if (!hash_too_common) {
        // Per-candidate scorer + verdict, shared by the topo-bucket
        // and full-scan paths.
        struct ScanState {
            std::string best_name;     float best_combined  = 0.0f;
            std::string second_name;   float second_combined = 0.0f;
            bool        best_has_l4 = false;
        };
        auto score_entry = [&](const WholeEntry& e, ScanState& s) {
            if (e.exact_hash == 0) return;
            if (!runtime_compatible(query_runtime, e.runtime)) return;
            if (!strings_compatible(e.string_hashes)) return;
            const float l2j = jaccard_minhash(query.whole.minhash, e.minhash);
            const float l4j = l4_jaccard_with(e);
            const bool has_l4 = (query_has_l4 && e.l4_exact != 0);
            const float combined = has_l4 ? (0.5f * l2j + 0.5f * l4j) : l2j;
            if (combined > s.best_combined) {
                s.second_combined = s.best_combined;
                s.second_name     = std::move(s.best_name);
                s.best_combined   = combined;
                s.best_name       = e.name;
                s.best_has_l4     = has_l4;
            } else if (combined > s.second_combined) {
                s.second_combined = combined;
                s.second_name     = e.name;
            }
        };
        auto verdict = [&](ScanState& s) -> std::optional<TeefMatch> {
            const float bar    = s.best_has_l4 ? 0.6f  : 0.875f;
            const float margin = s.best_has_l4 ? 0.20f : 0.25f;
            if (s.best_combined < bar) return std::nullopt;
            if ((s.best_combined - s.second_combined) < margin) return std::nullopt;
            const std::string via = s.best_has_l4 ? "whole-jaccard+behav" : "whole-jaccard";
            return TeefMatch{std::move(s.best_name), s.best_combined, via, 0};
        };

        // Stage 1 — L2 MinHash inverted index. The query's 8 slot
        // values index into per-slot buckets of corpus entry idxs;
        // entries appearing in ≥ kMinSlotHits buckets have a
        // probabilistic L2 jaccard ≥ kMinSlotHits/8. Only those get
        // scored. Cuts O(N) full-scan to O(slot_bucket × 8) per query
        // — the difference between minutes and milliseconds on
        // 100K-fn library corpora.
        //
        // EMBER_TEEF_MAX_SLOT_BUCKET caps the size of any single slot
        // bucket we'll iterate; values shared by thousands of corpus
        // entries are "popular trivial bits" (boilerplate stubs) that
        // would dominate the candidate set without adding precision.
        // Threshold of 2/8 lets L4-corroborated low-L2-jaccard candidates
        // through: combined = 0.5·L2 + 0.5·L4, and a query with weak L2
        // (≥0.25) but strong L4 (=1.0) gives combined ≈ 0.625 > 0.6 bar.
        // Higher thresholds drop those L4-rescued matches in cross-config
        // runs (verified: kMinSlotHits=3 lost 4/361 matches in the
        // probe2 6-config matrix).
        constexpr u8 kMinSlotHits = 2;     // estimate jaccard ≥ 2/8 = 0.25
        static const std::size_t kMaxSlotBucket = []() -> std::size_t {
            if (const char* s = std::getenv("EMBER_TEEF_MAX_SLOT_BUCKET")) {
                try { return static_cast<std::size_t>(std::stoull(s)); }
                catch (...) { /* fall through */ }
            }
            return 5000;
        }();
        {
            std::unordered_map<u32, u8> hits;
            for (std::size_t k = 0; k < 8; ++k) {
                const u64 v = query.whole.minhash[k];
                auto it = whole_minhash_[k].find(v);
                if (it == whole_minhash_[k].end()) continue;
                if (it->second.size() > kMaxSlotBucket) continue;
                for (u32 idx : it->second) ++hits[idx];
            }
            ScanState s;
            for (const auto& [idx, count] : hits) {
                if (count < kMinSlotHits) continue;
                score_entry(whole_by_name_[idx], s);
            }
            if (auto m = verdict(s)) return { *m };
        }

        // Stage 2 — topo bucket fallback. Catches cases where slot
        // collisions are too sparse to cross kMinSlotHits but the L0
        // topology agrees (small fns where minhash entropy is low and
        // jaccard estimates are noisy). Bounded — topo buckets are
        // rarely huge.
        if (query.topo_hash != 0) {
            auto [lo, hi] = whole_topo_.equal_range(query.topo_hash);
            if (lo != hi) {
                ScanState s2;
                for (auto it = lo; it != hi; ++it) {
                    score_entry(whole_by_name_[it->second], s2);
                }
                if (auto m = verdict(s2)) return { *m };
            }
        }
    }

    // ---- Chunk vote ----
    // Each query chunk that hits the corpus contributes its size to
    // the candidate functions that contain that chunk (capped at
    // kMaxChunkFns to avoid boilerplate noise).
    std::unordered_map<std::string, u64> votes;
    for (const auto& ch : query.chunks) {
        if (ch.sig.exact_hash == 0) continue;
        auto it = chunk_index_.find(ch.sig.exact_hash);
        if (it == chunk_index_.end()) continue;
        if (it->second.size() > kMaxChunkFns) continue;
        for (const auto& ref : it->second) {
            if (!runtime_compatible(query_runtime, ref.runtime)) continue;
            votes[ref.name] += ch.inst_count;
        }
    }
    if (votes.empty()) return {};

    // String-anchor filter on chunk-vote candidates. The whole-exact
    // and whole-jaccard paths already filter via strings_compatible
    // on each WholeEntry. Chunk-vote operates on names, so we look
    // up each candidate's parent fn via idx_by_name_ and apply the
    // same filter. Skips when the parent has no string_hashes (the
    // filter falls through automatically — strings_compatible
    // returns true on empty corpus side).
    // Two-tier filter:
    //  - strings_compatible (lenient): empty corpus side passes;
    //    same as whole-exact/whole-jaccard.
    //  - structural-coincidence guard (strict, chunk-vote only):
    //    if the query function has substantive strings (≥3) and the
    //    candidate's parent fn has zero, the chunk-vote match is
    //    structural coincidence (e.g. Wayland main hitting a
    //    libstdc++ wide-char template). Drop. Cuts the
    //    high-volume FP class without touching the recall lane —
    //    most library fns with shared structure also share at
    //    least some characteristic strings.
    if (!qs.empty()) {
        for (auto it = votes.begin(); it != votes.end(); ) {
            auto nit = idx_by_name_.find(it->first);
            if (nit == idx_by_name_.end()) { ++it; continue; }
            const auto& we = whole_by_name_[nit->second];
            const bool drop =
                !strings_compatible(we.string_hashes) ||
                (qs.size() >= 3 && we.string_hashes.empty());
            if (drop) {
                it = votes.erase(it);
            } else {
                ++it;
            }
        }
        if (votes.empty()) return {};
    }

    std::vector<std::pair<std::string, u64>> ranked(votes.begin(), votes.end());
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    // L4 chunk-vote corroboration: when the query has an L4 sketch and
    // the top vote winner's parent fn has an L4 sketch with high
    // jaccard, boost confidence by re-ranking by (vote_score, L4_jacc).
    // Tag the via with "+behav" when the L4 path corroborated the vote
    // winner. Behavioural agreement on a chunk-vote winner is a strong
    // anti-FP signal — the existing string-anchor filter already
    // suppresses *most* structural FPs, but it can't help when the
    // corpus parent has empty string_hashes; L4 fills exactly that gap.
    bool behav_agreed = false;
    if (query_has_l4 && !ranked.empty()) {
        auto top_l4 = [&](const std::string& nm) -> float {
            auto it = idx_by_name_.find(nm);
            if (it == idx_by_name_.end()) return 0.0f;
            return l4_jaccard_with(whole_by_name_[it->second]);
        };
        // Re-rank: combined = vote_norm + L4_jacc * top_vote_score.
        // Practical effect: among similar vote scores, prefer the
        // candidate with stronger behavioural agreement.
        const u64 top_score = ranked.front().second;
        if (top_score > 0) {
            std::vector<std::tuple<u64, float, std::string>> rescored;
            rescored.reserve(ranked.size());
            for (auto& [nm, sc] : ranked) {
                const float l4j = top_l4(nm);
                rescored.emplace_back(sc, l4j, std::move(nm));
            }
            std::sort(rescored.begin(), rescored.end(),
                      [](const auto& a, const auto& b) {
                          // Primary: vote score (within 25% of top).
                          // Secondary: L4 jaccard.
                          auto& [sa, ja, na] = a;
                          auto& [sb, jb, nb] = b;
                          // Compare vote scores; if within a small tolerance,
                          // prefer L4 jaccard.
                          if (sa != sb) {
                              const u64 hi = std::max(sa, sb);
                              const u64 lo = std::min(sa, sb);
                              if (hi - lo > hi / 4) return sa > sb;
                          }
                          return ja > jb;
                      });
            ranked.clear();
            ranked.reserve(rescored.size());
            for (auto& [sc, l4j, nm] : rescored) {
                ranked.emplace_back(std::move(nm), sc);
            }
            behav_agreed = (top_l4(ranked.front().first) >= 0.5f);
        }
    }

    std::vector<TeefMatch> out;
    out.reserve(top_k);
    const u64 top1 = ranked[0].second;
    const u64 top2 = ranked.size() > 1 ? ranked[1].second : 0;
    const float margin_raw = static_cast<float>(top1) /
                             static_cast<float>(std::max<u64>(1, top1 + top2));
    // Behavioural agreement boosts margin into the high-confidence
    // band when chunk-vote alone wouldn't have crossed the recognizer's
    // typical 0.6 threshold.
    const float margin = behav_agreed
        ? std::min(1.0f, margin_raw + 0.25f)
        : margin_raw;
    const std::string_view via_tag = behav_agreed ? "chunk-vote+behav" : "chunk-vote";
    for (std::size_t i = 0; i < ranked.size() && i < top_k; ++i) {
        TeefMatch m;
        m.name       = std::move(ranked[i].first);
        m.via        = std::string(via_tag);
        m.confidence = (i == 0) ? margin :
            static_cast<float>(ranked[i].second) / static_cast<float>(top1 + top2);
        m.vote_score = static_cast<u32>(ranked[i].second);
        out.push_back(std::move(m));
    }
    return out;
}

}  // namespace ember
