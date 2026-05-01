#include <ember/analysis/teef_recognize.hpp>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <ember/analysis/teef.hpp>

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

[[nodiscard]] std::vector<std::string_view>
split_tabs(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i < line.size(); ++i) {
        if (line[i] == '\t') {
            out.emplace_back(line.substr(start, i - start));
            start = i + 1;
        }
    }
    out.emplace_back(line.substr(start));
    return out;
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

std::size_t TeefCorpus::load_tsv(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return 0;

    std::size_t rows = 0;
    std::string active_runtime;     // set by `T runtime <tag>` rows
    std::unordered_map<u64, std::size_t> idx_by_addr; // F-row addr → whole_by_name_ index
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        auto fields = split_tabs(line);
        if (fields.empty()) continue;

        if (fields[0] == "T") {
            // T<TAB>runtime<TAB><tag>  — applies to all subsequent
            // F/C rows in this TSV. Multiple T rows in one file mean
            // mixed-runtime corpora (rare but supported).
            if (fields.size() >= 3 && fields[1] == "runtime") {
                active_runtime.assign(fields[2]);
            }
            continue;
        }

        if (fields[0] == "F") {
            // F row: F  addr  L2_exact  L2_mh*8  name
            //          L4_exact  L4_mh*8  L4_done  L4_aborted  topo_hash
            // 24 fields total. Rows with fewer columns are dropped —
            // TEEF Max requires the full per-fn signal stack.
            if (fields.size() < 24) continue;
            const u64 hash = parse_u64_hex(fields[2]);
            if (hash != 0) ++whole_popularity_[hash];
            const std::string name(fields[11]);
            if (name.empty() || name.starts_with("sub_")) continue;
            WholeEntry e;
            e.name = name;
            e.exact_hash = hash;
            e.runtime = active_runtime;
            for (std::size_t k = 0; k < 8; ++k) {
                e.minhash[k] = parse_u64_hex(fields[3 + k]);
            }
            // L4 columns at positions 12..22. fields[21]/[22] are
            // diagnostic-only (traces_done / traces_aborted).
            e.l4_exact = parse_u64_hex(fields[12]);
            for (std::size_t k = 0; k < 8; ++k) {
                e.l4_minhash[k] = parse_u64_hex(fields[13 + k]);
            }
            // L0 topology hash at position 23.
            e.topo_hash = parse_u64_hex(fields[23]);
            const u64 addr = parse_u64_hex(fields[1]);
            const std::size_t idx = whole_by_name_.size();
            whole_by_name_.push_back(std::move(e));
            if (whole_by_name_[idx].exact_hash != 0) {
                whole_exact_.emplace(whole_by_name_[idx].exact_hash, idx);
            }
            if (whole_by_name_[idx].l4_exact != 0) {
                whole_l4_exact_.emplace(whole_by_name_[idx].l4_exact, idx);
                ++whole_l4_popularity_[whole_by_name_[idx].l4_exact];
            }
            if (whole_by_name_[idx].topo_hash != 0) {
                whole_topo_.emplace(whole_by_name_[idx].topo_hash, idx);
            }
            if (addr != 0) idx_by_addr.emplace(addr, idx);
            idx_by_name_.try_emplace(whole_by_name_[idx].name, idx);
            ++rows;
        } else if (fields[0] == "S") {
            // S<TAB>addr<TAB>hash1,hash2,...   (TEEF schema v4)
            // Attaches per-fn identifying-string hashes to the WholeEntry
            // whose F row landed at the same addr. The recognizer uses
            // the overlap as a precision filter against structural
            // false positives. Skipped silently if the F row was
            // discarded (sub_*-named) — string anchors only matter for
            // named library functions.
            if (fields.size() < 3) continue;
            const u64 addr = parse_u64_hex(fields[1]);
            auto it = idx_by_addr.find(addr);
            if (it == idx_by_addr.end()) continue;
            std::string_view csv = fields[2];
            std::size_t cp = 0;
            while (cp < csv.size()) {
                std::size_t comma = csv.find(',', cp);
                if (comma == std::string_view::npos) comma = csv.size();
                std::string_view tok = csv.substr(cp, comma - cp);
                if (!tok.empty()) {
                    whole_by_name_[it->second].string_hashes.push_back(parse_u64_hex(tok));
                }
                cp = comma + 1;
            }
            ++rows;
        } else if (fields[0] == "C") {
            // C<TAB>addr<TAB>kind<TAB>insts<TAB>exact<TAB>mh0..7<TAB>name
            if (fields.size() < 14) continue;
            const std::string name(fields[13]);
            if (name.empty() || name.starts_with("sub_")) continue;
            const u64 chunk_hash = parse_u64_hex(fields[4]);
            if (chunk_hash == 0) continue;
            u32 sz = 0;
            std::from_chars(fields[3].data(),
                            fields[3].data() + fields[3].size(), sz);
            chunk_index_[chunk_hash].push_back(ChunkRef{name, sz, active_runtime});
            ++rows;
        }
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
        // Per-candidate scorer; returns combined score and whether L4
        // contributed. Used by both the topo-bucket scan and the full
        // fallback scan below.
        struct ScanState {
            std::string best_name;     float best_combined  = 0.0f;
            std::string second_name;   float second_combined = 0.0f;
            bool        best_has_l4 = false;
        };
        auto scan = [&](auto begin, auto end, ScanState& s) {
            for (auto it = begin; it != end; ++it) {
                const auto& e = whole_by_name_[*it];
                if (e.exact_hash == 0) continue;
                if (!runtime_compatible(query_runtime, e.runtime)) continue;
                if (!strings_compatible(e.string_hashes)) continue;
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

        // Stage 1 — topo bucket. If the query has a topo_hash and the
        // corpus has entries in the same bucket, try those first. The
        // common case is "exactly one match in this topo bucket" → we
        // confirm via L2/L4 jaccard and return without scanning the
        // rest of the corpus.
        if (query.topo_hash != 0) {
            std::vector<std::size_t> idxs;
            auto [lo, hi] = whole_topo_.equal_range(query.topo_hash);
            for (auto it = lo; it != hi; ++it) idxs.push_back(it->second);
            if (!idxs.empty()) {
                ScanState s;
                scan(idxs.begin(), idxs.end(), s);
                if (auto m = verdict(s)) return { *m };
            }
        }

        // Stage 2 — full scan fallback. We arrive here when no topo
        // pre-filter applied (query has no topo, or no corpus entry
        // shared its topo, or the topo bucket didn't yield a confident
        // match). Scan every corpus entry; same scorer.
        std::vector<std::size_t> all;
        all.reserve(whole_by_name_.size());
        for (std::size_t i = 0; i < whole_by_name_.size(); ++i) all.push_back(i);
        ScanState s;
        scan(all.begin(), all.end(), s);
        if (auto m = verdict(s)) return { *m };
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
