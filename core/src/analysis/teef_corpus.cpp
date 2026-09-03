#include <ember/analysis/teef_recognize.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <ios>
#include <ratio>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ember {

u32 TeefCorpus::intern_string(std::string_view s) {
    // Fast path: heterogeneous find avoids allocating a std::string
    // for the lookup key. Names like "memcpy" and runtime tags like
    // "libc" are repeated millions of times across a multi-100MB
    // corpus - the cold-path allocation only fires on first sight.
    if (auto it = intern_ids_.find(s); it != intern_ids_.end()) return it->second;
    const u32 id = static_cast<u32>(intern_strings_.size());
    auto [it, _] = intern_ids_.emplace(std::string(s), id);
    intern_strings_.push_back(&it->first);
    return id;
}

u32 TeefCorpus::intern_string(std::string&& s) {
    // Move overload for the F/C-row merge: the parser already produced
    // a std::string per row, so on miss we move it straight into the
    // map instead of copying.
    if (auto it = intern_ids_.find(s); it != intern_ids_.end()) return it->second;
    const u32 id = static_cast<u32>(intern_strings_.size());
    auto [it, _] = intern_ids_.emplace(std::move(s), id);
    intern_strings_.push_back(&it->first);
    return id;
}

std::string_view TeefCorpus::interned(u32 id) const noexcept {
    if (id >= intern_strings_.size()) return {};
    return *intern_strings_[id];
}

namespace {

// 256-entry hex digit table. 0xFF = invalid (treated as 0 by the
// parser to preserve original "malformed → 0" semantics).
inline constexpr auto kHexTable = []() {
    std::array<u8, 256> t{};
    for (auto& x : t) x = 0;
    for (unsigned c = '0'; c <= '9'; ++c) t[c] = static_cast<u8>(c - '0');
    for (unsigned c = 'a'; c <= 'f'; ++c) t[c] = static_cast<u8>(c - 'a' + 10);
    for (unsigned c = 'A'; c <= 'F'; ++c) t[c] = static_cast<u8>(c - 'A' + 10);
    return t;
}();

// Parse a lowercase hex token (typically 16 chars) into u64. Returns
// 0 on empty input. A 16-char hash is read 16× per F row × millions
// of rows; the table lookup beats the ternary chain on branch
// predictability and per-char latency.
[[nodiscard]] u64 parse_u64_hex(std::string_view s) noexcept {
    u64 v = 0;
    for (char c : s) {
        v = (v << 4) | kHexTable[static_cast<unsigned char>(c)];
    }
    return v;
}

// gcc clone suffixes are fragments, not labels (the CLI filters them
// at corpus emit); dropping them here covers TSVs built before that.
[[nodiscard]] bool is_compiler_partition_variant(std::string_view nm) noexcept {
    if (nm.find(".cold")      != std::string_view::npos) return true;
    if (nm.find(".isra")      != std::string_view::npos) return true;
    if (nm.find(".constprop") != std::string_view::npos) return true;
    if (nm.find(".part")      != std::string_view::npos) return true;
    if (nm.find(".lto_priv")  != std::string_view::npos) return true;
    return false;
}

// Parsed rows accumulate in per-thread buffers before the serial merge.
// Names refer into the mmap'd region and are interned during that merge.
// Runtime tags own their storage because T rows can change the active tag.
struct ParsedF {
    u64                 addr;
    u64                 l2_exact;
    std::array<u64, 8>  l2_mh;
    u64                 l4_exact;
    std::array<u64, 8>  l4_mh;
    u64                 topo_hash;
    u64                 prefix_hash;
    std::string_view    name;
    std::string         runtime;
};
struct ParsedS {
    u64                 addr;
    std::vector<u64>    hashes;
};
struct ParsedC {
    u64                 chunk_hash;
    u32                 inst_count;
    std::string_view    name;
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

// Tab-walk a line into up to N fields via memchr (SIMD-vectorized
// in glibc). Returns the number of fields populated. Matches the
// previous byte-loop semantics: at most N fields, with the final
// field bounded by the next tab (not the end of line) - extra
// trailing tabs are dropped on the floor as before.
template <std::size_t N>
[[nodiscard]] std::size_t split_tabs(std::string_view line,
                                     std::array<std::string_view, N>& out) {
    const char* const begin = line.data();
    const char* const end   = begin + line.size();
    const char* cur = begin;
    std::size_t n = 0;
    while (n < N) {
        const char* tab = static_cast<const char*>(
            std::memchr(cur, '\t', static_cast<std::size_t>(end - cur)));
        if (!tab) {
            out[n++] = std::string_view(cur, static_cast<std::size_t>(end - cur));
            break;
        }
        out[n++] = std::string_view(cur, static_cast<std::size_t>(tab - cur));
        cur = tab + 1;
    }
    return n;
}

// Parse one F row's tab-separated fields directly from the line view.
// Invalid rows return false; the view must not include its newline.
[[nodiscard]] bool parse_f_row(std::string_view line,
                               const std::string& active_runtime,
                               ParsedF& out) {
    // We expect 25 fields:
    //   F addr L2_exact L2_mh*8 name L4_exact L4_mh*8 L4_done L4_aborted
    //     topo_hash prefix_hash
    // Pre-max.4 corpora omit the last field; older 24-field rows still
    // load with prefix_hash defaulted to 0 (no L1 fast path on those).
    std::array<std::string_view, 25> f;
    const std::size_t n = split_tabs(line, f);
    if (n < 24) return false;

    out.addr     = parse_u64_hex(f[1]);
    out.l2_exact = parse_u64_hex(f[2]);
    for (std::size_t k = 0; k < 8; ++k) out.l2_mh[k] = parse_u64_hex(f[3 + k]);
    out.name     = f[11];
    out.l4_exact = parse_u64_hex(f[12]);
    for (std::size_t k = 0; k < 8; ++k) out.l4_mh[k] = parse_u64_hex(f[13 + k]);
    out.topo_hash   = parse_u64_hex(f[23]);
    out.prefix_hash = (n >= 25) ? parse_u64_hex(f[24]) : 0u;
    out.runtime     = active_runtime;
    return true;
}

[[nodiscard]] bool parse_c_row(std::string_view line,
                               const std::string& active_runtime,
                               ParsedC& out) {
    // C addr kind insts exact mh*8 name (14 fields)
    std::array<std::string_view, 14> f;
    const std::size_t n = split_tabs(line, f);
    if (n < 14) return false;

    out.chunk_hash = parse_u64_hex(f[4]);
    if (out.chunk_hash == 0) return false;
    u32 sz = 0;
    std::from_chars(f[3].data(), f[3].data() + f[3].size(), sz);
    out.inst_count = sz;
    out.name       = f[13];
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

std::unordered_set<u64>
TeefCorpus::topo_hashes(std::size_t max_popularity) const {
    if (max_popularity == 0) {
        // No popularity guard - return every distinct topo.
        std::unordered_set<u64> out;
        out.reserve(whole_by_name_.size());
        for (const auto& e : whole_by_name_) {
            if (e.topo_hash != 0) out.insert(e.topo_hash);
        }
        return out;
    }
    // Two-pass: count occurrences per topo, then keep only those with
    // count <= max_popularity. Excludes generic boilerplate shapes
    // (single-block return-stub etc.) that match thousands of fns
    // and would force every target fn with the same shape through
    // the full pipeline for no real-match opportunity.
    std::unordered_map<u64, std::size_t> counts;
    counts.reserve(whole_by_name_.size());
    for (const auto& e : whole_by_name_) {
        if (e.topo_hash != 0) ++counts[e.topo_hash];
    }
    std::unordered_set<u64> out;
    out.reserve(counts.size());
    for (const auto& [t, c] : counts) {
        if (c <= max_popularity) out.insert(t);
    }
    return out;
}

std::size_t TeefCorpus::load_anti_tsv(const std::filesystem::path& path) {
    // Anti-corpora are typically small (a UPX dump is ~50 fns; even a
    // chunky packer-prologue collection is < 1k rows). Skip the
    // mmap+parallel-parse path used by load_tsv - a serial readline
    // pass is plenty and avoids the merge-phase machinery we don't
    // need (no name interning, no minhash inverted index).
    std::ifstream in(path, std::ios::binary);
    if (!in) return 0;
    std::string line;
    std::size_t rows = 0;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line.front() == '#') continue;
        if (line.front() != 'F') continue;  // S/C/T rows carry no
                                            // hashes worth blocking
        std::string_view sv(line);
        std::array<std::string_view, 25> f;
        const std::size_t n = split_tabs(sv, f);
        if (n < 24) continue;
        // Same field offsets as parse_f_row: f[2] = L2 exact, f[12]
        // = L4 exact, f[24] = L1 prefix (only present in max.4+).
        if (const u64 h = parse_u64_hex(f[2]);  h != 0) blocked_l2_.insert(h);
        if (const u64 h = parse_u64_hex(f[12]); h != 0) blocked_l4_.insert(h);
        if (n >= 25) {
            if (const u64 h = parse_u64_hex(f[24]); h != 0) blocked_prefix_.insert(h);
        }
        ++rows;
    }
    return rows;
}

std::size_t TeefCorpus::load_tsv(const std::filesystem::path& path) {
    using steady_t  = std::chrono::steady_clock;
    using ms_t     = std::chrono::duration<double, std::milli>;
    // Per-file load timing. Suppressed when EMBER_QUIET=1; printed
    // unconditionally otherwise (even when stderr isn't a TTY, since
    // these lines are diagnostic - users running the recognizer over
    // multi-100MB corpora want to know what's slow). progress_enabled()
    // gates the noisy progress bars; this is a one-shot per file.
    const bool dbg = !(std::getenv("EMBER_QUIET") != nullptr &&
                       std::getenv("EMBER_QUIET")[0] == '1');
    const auto t_open = steady_t::now();

    // ---- Acquire the file as a contiguous byte range -------------------
    // POSIX mmaps for zero-copy parallel parse. Windows reads the whole
    // file into a heap buffer - the platform's file-mapping API works
    // but the wstring/HANDLE plumbing isn't worth it for a one-shot
    // load; the parsing phase dwarfs the copy on multi-100MB inputs.
#if defined(_WIN32)
    std::vector<char> buf;
    {
#ifdef _MSC_VER
        FILE* fp = nullptr;
        if (::fopen_s(&fp, path.string().c_str(), "rb") != 0 || !fp) return 0;
#else
        FILE* fp = std::fopen(path.string().c_str(), "rb");
        if (!fp) return 0;
#endif
        std::fseek(fp, 0, SEEK_END);
        const long n = std::ftell(fp);
        std::fseek(fp, 0, SEEK_SET);
        if (n <= 0) { std::fclose(fp); return 0; }
        buf.resize(static_cast<std::size_t>(n));
        const std::size_t got = std::fread(buf.data(), 1,
                                           static_cast<std::size_t>(n), fp);
        std::fclose(fp);
        if (got != static_cast<std::size_t>(n)) return 0;
    }
    const std::size_t sz = buf.size();
    const char* const data = buf.data();
    const char* const file_end = data + sz;
#else
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
    // Sequential-read hint - kernel reads ahead more aggressively
    // and drops pages behind us. Free win on cold-cache loads of
    // multi-100MB corpus TSVs. WILLNEED kicks readahead immediately
    // so the parse phase isn't first-touching every page.
    ::madvise(m, sz, MADV_SEQUENTIAL);
    ::madvise(m, sz, MADV_WILLNEED);
    const char* const data = static_cast<const char*>(m);
    const char* const file_end = data + sz;
#endif
    const auto t_mmap = steady_t::now();

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
    // For tiny files, avoid the per-thread overhead - a single worker
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
            // Align begin (except chunk 0) to the start of the next line -
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
    const auto t_parsed = steady_t::now();

    // ---- Serial merge into corpus indexes ------------------------------
    // Order matters for correctness: F rows establish idx_by_addr that
    // S rows depend on, so do all F rows first, then S rows. C rows are
    // independent. Within the F pass we also build the inverted indexes
    // (whole_exact_, whole_l4_exact_, whole_topo_, whole_minhash_,
    // whole_popularity_, whole_l4_popularity_).
    std::size_t rows = 0;
    std::unordered_map<u64, std::size_t> idx_by_addr;

    // Pre-reserve to avoid rehashing during merge. Sizes here are
    // upper bounds (sub_* rows get filtered out for some indexes) -
    // reserving a touch high is far cheaper than a rehash at 80%
    // load with 100K+ entries.
    std::size_t total_f = 0;
    std::size_t total_c = 0;
    for (const auto& p : parts) { total_f += p.f.size(); total_c += p.c.size(); }
    {
        whole_by_name_.reserve(whole_by_name_.size() + total_f);
        const std::size_t hint_f = whole_by_name_.size() + total_f;
        whole_exact_.reserve(hint_f);
        whole_l4_exact_.reserve(hint_f);
        whole_topo_.reserve(hint_f);
        whole_prefix_.reserve(hint_f);
        whole_popularity_.reserve(hint_f);
        whole_l4_popularity_.reserve(hint_f);
        whole_prefix_popularity_.reserve(hint_f);
        for (auto& slot : whole_minhash_) slot.reserve(hint_f);
        idx_by_name_.reserve(hint_f);
        intern_ids_.reserve(intern_ids_.size() + total_f * 2 + total_c * 2);
        idx_by_addr.reserve(total_f);
        chunk_index_.reserve(chunk_index_.size() + total_c);
    }

    for (auto& part : parts) {
        for (auto& f : part.f) {
            // Popularity counts every F row including sub_* (the
            // recognizer's "trivial-shape" guard depends on this).
            if (f.l2_exact != 0) ++whole_popularity_[f.l2_exact];
            if (f.name.empty() || f.name.starts_with("sub_")) continue;
            // Drop gcc partition variants at load time - works for
            // pre-existing TSVs built before subcommands.cpp learned
            // to skip them at emit, without forcing a re-fingerprint.
            if (is_compiler_partition_variant(f.name)) continue;
            const std::size_t idx = whole_by_name_.size();
            WholeEntry e;
            e.name_id    = intern_string(f.name);
            e.exact_hash = f.l2_exact;
            e.minhash    = f.l2_mh;
            e.runtime_id = intern_string(std::move(f.runtime));
            e.l4_exact   = f.l4_exact;
            e.l4_minhash = f.l4_mh;
            e.topo_hash   = f.topo_hash;
            e.prefix_hash = f.prefix_hash;
            whole_by_name_.push_back(e);
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
            if (we.prefix_hash != 0) {
                whole_prefix_.emplace(we.prefix_hash, idx);
                ++whole_prefix_popularity_[we.prefix_hash];
            }
            for (std::size_t k = 0; k < 8; ++k) {
                whole_minhash_[k][we.minhash[k]]
                    .push_back(static_cast<u32>(idx));
            }
            if (f.addr != 0) idx_by_addr.emplace(f.addr, idx);
            // Heterogeneous find - name string already lives in
            // intern_strings_; only allocate when this is a name we
            // haven't seen before in idx_by_name_.
            const auto name_sv = interned(we.name_id);
            if (idx_by_name_.find(name_sv) == idx_by_name_.end()) {
                idx_by_name_.emplace(std::string(name_sv), idx);
            }
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
            for (u64 h : s.hashes) {
                if (target.count >= target.values.size()) break;
                target.values[target.count++] = h;
            }
            ++rows;
        }
    }

    for (auto& part : parts) {
        for (auto& c : part.c) {
            if (c.name.empty() || c.name.starts_with("sub_")) continue;
            if (is_compiler_partition_variant(c.name)) continue;
            const u32 nm_id  = intern_string(c.name);
            const u32 rt_id  = intern_string(std::move(c.runtime));
            chunk_index_[c.chunk_hash].push_back(
                ChunkRef{nm_id, c.inst_count, rt_id});
            ++rows;
        }
    }

    // Recompute distinct-name counts for every hashed key. Bucket-size
    // guards (kMaxWholeBucket / kMaxL4Bucket / kMaxPrefixBucket /
    // kMaxChunkFns) operate on these - a popular fn replicated across N
    // corpus versions (50× glibc memcpy under the same name) would
    // otherwise trip the boilerplate floor and get dropped, when really
    // it's one well-known fn replicated. Done as an end-of-load pass so
    // multi-TSV loads don't double-count names seen in both files.
    {
        // Distinct names per hash bucket. Keyed on interned name_id
        // (u32) instead of string_view - same identity (intern_string
        // returns the same id for the same string regardless of which
        // TSV it came from), but a u32 hash is a single instruction
        // vs. a multi-cache-line string hash.
        std::unordered_map<u64, std::unordered_set<u32>> seen;
        auto recount_whole = [&](const std::unordered_multimap<u64, std::size_t>& src,
                                 std::unordered_map<u64, std::size_t>& dst) {
            seen.clear();
            for (const auto& [hash, idx] : src) {
                seen[hash].insert(whole_by_name_[idx].name_id);
            }
            dst.clear();
            dst.reserve(seen.size());
            for (const auto& [hash, names] : seen) dst[hash] = names.size();
        };
        recount_whole(whole_exact_,    whole_exact_distinct_);
        recount_whole(whole_l4_exact_, whole_l4_distinct_);
        recount_whole(whole_prefix_,   whole_prefix_distinct_);

        seen.clear();
        for (const auto& [hash, refs] : chunk_index_) {
            auto& s = seen[hash];
            for (const auto& r : refs) s.insert(r.name_id);
        }
        chunk_distinct_.clear();
        chunk_distinct_.reserve(seen.size());
        for (const auto& [hash, names] : seen) chunk_distinct_[hash] = names.size();
    }

    const auto t_merged = steady_t::now();
#if !defined(_WIN32)
    ::munmap(m, sz);
#endif

    if (dbg) {
        const double mb       = static_cast<double>(sz) / (1024.0 * 1024.0);
        const auto   t_open_ms   = ms_t(t_mmap   - t_open).count();
        const auto   t_parse_ms  = ms_t(t_parsed - t_mmap).count();
        const auto   t_merge_ms  = ms_t(t_merged - t_parsed).count();
        const auto   t_total_ms  = ms_t(t_merged - t_open).count();
        std::fprintf(stderr,
            "ember: corpus %s: %.1f MB / %zu rows  "
            "(mmap+pre %.0fms · parse %.0fms ×%u · merge %.0fms · total %.0fms)\n",
            path.string().c_str(), mb, rows,
            t_open_ms, t_parse_ms, threads, t_merge_ms, t_total_ms);
    }
    return rows;
}

}  // namespace ember
