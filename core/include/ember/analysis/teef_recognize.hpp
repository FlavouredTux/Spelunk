#pragma once

#include <array>
#include <filesystem>
#include <string>
#include <unordered_map>
#include <vector>

#include <ember/analysis/teef.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One library-recognition candidate for a query function.
// `confidence` is the vote-margin of the top match against the second
// (1.0 = clear winner, 0.5 = coin flip vs the runner-up). `via`
// records which signal produced this match: "whole-exact",
// "whole-jaccard", "chunk-vote".
struct TeefMatch {
    std::string name;
    float       confidence = 0.0f;
    std::string via;
    u32         vote_score = 0;     // raw chunk-size-weighted vote total (0 for whole-fn matches)
};

// Library corpus loaded from one or more `ember --teef` TSVs. Holds
// inverted indexes for fast whole-function and chunk-vote lookup.
class TeefCorpus {
public:
    // Load (and merge) corpus rows from a TSV file. Multiple paths can
    // be loaded into the same corpus; later loads do not invalidate
    // earlier indexes. Returns the number of F + C rows ingested.
    [[nodiscard]] std::size_t load_tsv(const std::filesystem::path& path);

    // Look up a query function's matches. The query is a TeefFunction
    // produced by compute_teef_with_chunks on the unknown binary.
    // Returns up to `top_k` candidates ranked by combined confidence.
    [[nodiscard]] std::vector<TeefMatch>
    recognize(const TeefFunction& query, std::size_t top_k = 3) const;

    [[nodiscard]] std::size_t function_count() const noexcept { return whole_by_name_.size(); }
    [[nodiscard]] std::size_t chunk_count()    const noexcept { return chunk_index_.size(); }

private:
    struct WholeEntry {
        std::string         name;
        u64                 exact_hash;
        std::array<u64, 8>  minhash;
    };
    struct ChunkRef {
        std::string name;
        u32         size;     // inst count, used as vote weight
    };

    std::vector<WholeEntry>                                whole_by_name_;
    std::unordered_multimap<u64, std::size_t>              whole_exact_;   // exact_hash → idx into whole_by_name_
    std::unordered_map<u64, std::size_t>                   whole_popularity_;  // exact_hash → total F-row occurrences (includes sub_*)
    std::unordered_map<u64, std::vector<ChunkRef>>         chunk_index_;   // chunk_exact_hash → corpus chunks

    // Chunks that appear in too many distinct functions are
    // boilerplate. The recognizer drops them from voting.
    static constexpr std::size_t kMaxChunkFns    = 6;

    // Whole-function exact-hash buckets with more than this many
    // entries are "popular trivial stubs" (CPU-feature query, alloc
    // shim, etc.). Trusting whole-exact on these would surface a
    // single arbitrary name for hundreds of unrelated query
    // functions. Skip and fall through to chunk-vote.
    static constexpr std::size_t kMaxWholeBucket = 8;
};

}  // namespace ember
