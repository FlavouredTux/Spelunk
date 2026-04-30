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

std::size_t TeefCorpus::load_tsv(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return 0;

    std::size_t rows = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        auto fields = split_tabs(line);
        if (fields.empty()) continue;

        if (fields[0] == "F") {
            // F<TAB>addr<TAB>exact<TAB>mh0..7<TAB>name
            if (fields.size() < 12) continue;
            const u64 hash = parse_u64_hex(fields[2]);
            // Always count toward popularity — even sub_* contributes.
            // Two corpus entries (one named, one sub_*) sharing a hash
            // is a "shape that hundreds of trivial functions reach."
            if (hash != 0) ++whole_popularity_[hash];
            const std::string name(fields[11]);
            if (name.empty() || name.starts_with("sub_")) continue;
            WholeEntry e;
            e.name = name;
            e.exact_hash = hash;
            for (std::size_t k = 0; k < 8; ++k) {
                e.minhash[k] = parse_u64_hex(fields[3 + k]);
            }
            const std::size_t idx = whole_by_name_.size();
            whole_by_name_.push_back(std::move(e));
            if (whole_by_name_[idx].exact_hash != 0) {
                whole_exact_.emplace(whole_by_name_[idx].exact_hash, idx);
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
            chunk_index_[chunk_hash].push_back(ChunkRef{name, sz});
            ++rows;
        }
    }
    return rows;
}

std::vector<TeefMatch>
TeefCorpus::recognize(const TeefFunction& query, std::size_t top_k) const {
    if (query.whole.exact_hash == 0) return {};

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
                const auto& nm = whole_by_name_[it->second].name;
                if (distinct.insert(nm).second) ordered.push_back(nm);
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
    // Only trust a jaccard match when there's a clear unique winner —
    // otherwise tiny stub functions (which often hash to 7/8 ≅ 0.875
    // jaccard against many unrelated functions) would surface false
    // positives. Require the best match to be ≥0.875 AND for the
    // second-best to be at least 0.25 lower than the best. Anything
    // below that bar falls through to the chunk-vote path. Skip
    // entirely when the query has no chunks AND the hash is also
    // common — both cues say "this is too generic to identify."
    if (!hash_too_common) {
        std::string best_name; float best_j = 0.0f;
        std::string second_name; float second_j = 0.0f;
        for (const auto& e : whole_by_name_) {
            if (e.exact_hash == 0) continue;
            const float j = jaccard_minhash(query.whole.minhash, e.minhash);
            if (j > best_j) {
                second_j = best_j; second_name = std::move(best_name);
                best_j = j; best_name = e.name;
            } else if (j > second_j) {
                second_j = j; second_name = e.name;
            }
        }
        if (best_j >= 0.875f && (best_j - second_j) >= 0.25f) {
            return { TeefMatch{std::move(best_name), best_j, "whole-jaccard", 0} };
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
            votes[ref.name] += ch.inst_count;
        }
    }
    if (votes.empty()) return {};

    std::vector<std::pair<std::string, u64>> ranked(votes.begin(), votes.end());
    std::sort(ranked.begin(), ranked.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    std::vector<TeefMatch> out;
    out.reserve(top_k);
    const u64 top1 = ranked[0].second;
    const u64 top2 = ranked.size() > 1 ? ranked[1].second : 0;
    const float margin = static_cast<float>(top1) /
                         static_cast<float>(std::max<u64>(1, top1 + top2));
    for (std::size_t i = 0; i < ranked.size() && i < top_k; ++i) {
        TeefMatch m;
        m.name       = std::move(ranked[i].first);
        m.via        = "chunk-vote";
        m.confidence = (i == 0) ? margin :
            static_cast<float>(ranked[i].second) / static_cast<float>(top1 + top2);
        m.vote_score = static_cast<u32>(ranked[i].second);
        out.push_back(std::move(m));
    }
    return out;
}

}  // namespace ember
