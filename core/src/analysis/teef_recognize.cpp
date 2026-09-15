#include <spelunk/analysis/teef_recognize.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace spelunk {

namespace {

[[nodiscard]] float
jaccard_minhash(const std::array<u64, 8>& a, const std::array<u64, 8>& b) noexcept {
    int eq = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        if (a[i] == b[i]) ++eq;
    }
    return static_cast<float>(eq) / 8.0f;
}

// Names that are correct but useless as labels: Rust drop glue, panic
// forwarders and fmt trait impls, Itanium destructors and __cxa_*
// forwarders. Their bodies are trivial and collide with thousands of
// unrelated fns, so a match is capped below the 0.85 auto-promote
// threshold instead of reported at 1.0.
[[nodiscard]] bool is_boilerplate_label(std::string_view nm) noexcept {
    // Match raw identifier substrings that appear in all three name
    // forms a real Rust binary will throw at us:
    //   1. demangled                  : `core::ptr::drop_in_place::<…>`
    //   2. legacy mangle (length+$..) : `_ZN4core3ptr…drop_in_place$LT$…$GT$…E`
    //   3. v0 mangle      (_R prefix) : `_RINvNtCs…_4core3ptr13drop_in_place…`
    // Length-prefixed identifiers like `13drop_in_place` and
    // `9panic_fmt` always contain the bare identifier as a substring,
    // so a single `find()` covers all three encodings.
    if (nm.find("drop_in_place") != std::string_view::npos) return true;
    if (nm.find("panic_fmt")     != std::string_view::npos) return true;
    if (nm.find("panicking")     != std::string_view::npos) return true;
    if (nm.find("raw_vec")       != std::string_view::npos) return true;
    // fmt trait impls - three encodings of the "X as Trait" qualifier.
    if (nm.find("as core::fmt::") != std::string_view::npos)         return true;  // demangled
    if (nm.find("$u20$as$u20$core..fmt..") != std::string_view::npos) return true; // legacy
    if (nm.find("core::fmt::Formatter") != std::string_view::npos)   return true;  // demangled
    // <T as core::ops::drop::Drop>::drop - user-defined Drop impls.
    // Same FP-class as drop_in_place: structurally trivial, hashes
    // across types. Three encodings: legacy Itanium uses "Drop$GT$4drop"
    // (the '$GT$' = '>' closes the "as Drop" qualifier); v0 mangle of
    // the trait method nests the trait Drop and method drop as length-
    // prefixed identifiers ("Drop4drop"); demangled is the human form.
    if (nm.find("Drop$GT$4drop") != std::string_view::npos)            return true;
    if (nm.find("Drop4drop")     != std::string_view::npos)            return true;
    if (nm.find("as core::ops::drop::Drop") != std::string_view::npos) return true;
    // FnOnce / FnMut / Fn trait dispatch shims. These are vtable-shim
    // bodies that load a fn pointer and jump - minimal IR, structural
    // collisions across closure types are guaranteed. Use length-
    // prefixed substrings (Itanium and v0 both length-prefix idents)
    // so we don't accidentally cap user fns named "call_once".
    if (nm.find("6FnOnce9call_once") != std::string_view::npos) return true;
    if (nm.find("5FnMut8call_mut")   != std::string_view::npos) return true;
    if (nm.find("function2Fn4call")  != std::string_view::npos) return true;
    // Itanium-mangled C++ destructors (D0 base-object, D1 complete,
    // D2 deleting) and __cxa_* runtime forwarders. Same FP-class as
    // Rust drop glue: trivial bodies that hash across types.
    if (nm.starts_with("_ZN") &&
        (nm.find("D0Ev") != std::string_view::npos ||
         nm.find("D1Ev") != std::string_view::npos ||
         nm.find("D2Ev") != std::string_view::npos)) return true;
    if (nm.starts_with("__cxa_")) return true;
    return false;
}

}  // namespace

// Whether two runtime tags can plausibly match. Conservative - only
// the obvious cross-language false-positive lanes are blocked. A Rust
// binary linking libc / libcrypto / libgcc_s is normal; a Rust binary
// matching libstdc++ template instantiations is the noise class we're
// trying to suppress.
bool runtime_compatible(std::string_view q, std::string_view c) noexcept {
    if (q.empty() || c.empty()) return true;       // unknown matches all
    if (q == c) return true;

    // ---- Helper buckets (each tag belongs to one or more of these) ----
    // Plain C - both POSIX libc-ish and Windows CRT count as "C-shaped"
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
    // openssl is fine - Rust binaries link those for real.
    if (q == teef_runtime::kRust) {
        return !is_itanium_cxx(c) && !is_msvc_cxx(c);
    }
    // Symmetrically a libstdc++/cxx/cxxmsvc query shouldn't match Rust.
    if (is_itanium_cxx(q) || is_msvc_cxx(q)) {
        if (c == teef_runtime::kRust) return false;
    }
    // Itanium C++ vs MSVC C++ stdlib - different ABIs, different name
    // mangling, different vtable layout. Block.
    if (is_itanium_cxx(q) && is_msvc_cxx(c)) return false;
    if (is_msvc_cxx(q) && is_itanium_cxx(c)) return false;

    // C-family ↔ C-family (libc/msvcrt/ucrt/vcruntime/c): all compatible.
    // Lots of std C functions (memcpy, strlen, qsort) appear in both
    // POSIX and Windows runtimes with matching structure.
    if (is_c_family(q) && is_c_family(c)) return true;

    // winapi against POSIX libc - usually different (kernel32 has no
    // POSIX equivalent), but also low-volume. Allow; structural match
    // alone is the gate.
    if (is_winapi(q) || is_winapi(c)) return true;

    return true;
}

namespace {

// Exact-tier verdict. A unique name is reported at `cap`; several names
// share the confidence evenly and the via gets a "-tied" suffix. Empty
// input means "no verdict, fall through to the next tier".
[[nodiscard]] std::vector<TeefMatch>
exact_tier_matches(std::vector<std::string> names, float cap,
                   std::string_view via, std::size_t top_k) {
    auto capped = [&](float raw, std::string_view nm) {
        float c = std::min(raw, cap);
        if (is_boilerplate_label(nm)) c = std::min(c, 0.7f);
        return c;
    };
    if (names.size() == 1) {
        return { TeefMatch{names[0], capped(1.0f, names[0]), std::string(via), 0} };
    }
    std::vector<TeefMatch> out;
    const float base = 1.0f / static_cast<float>(names.size());
    for (auto& nm : names) {
        const float conf = capped(base, nm);
        out.push_back(TeefMatch{std::move(nm), conf, std::string(via) + "-tied", 0});
        if (out.size() >= top_k) break;
    }
    return out;
}

}  // namespace

struct TeefCorpus::RecognizeQuery {
    const TeefFunction& query;
    std::string_view    runtime;
    std::size_t         top_k;
    bool                has_l4;           // query carries a behavioural sketch
    bool                hash_too_common;  // L2 hash shared by > kMaxWholeBucket corpus rows

    // String-anchor disqualifier. If the query AND the candidate both
    // have ≥2 identifying strings and they share zero hashes, the
    // structural similarity is overwhelmingly likely to be coincidence
    // (different error messages, different format strings, different
    // path constants). Returns true ⇒ "this candidate is plausible";
    // false ⇒ "ditch it." Conservative - when either side has < 2
    // strings (small fns, EH cleanup, anonymous helpers), the filter
    // is bypassed and structural match is the sole signal as before.
    [[nodiscard]] bool strings_compatible(const SmallStringHashes& cs) const noexcept {
        const auto& qs = query.string_hashes;
        // Query has no string evidence (anonymous helper, EH cleanup, pure
        // arithmetic) → can't filter, structural match is the sole signal.
        if (qs.empty()) return true;
        // Query has strings, candidate has none → different domain. Without
        // this check, a tiny fn referencing one library-specific string
        // (e.g. a Lua error builder pushing "%s: bytecode version
        // mismatch...") collides with any tiny fn from a foreign codebase
        // (e.g. ICU's compareMappings) on prefix/whole-exact and emits a
        // confident rename across unrelated libraries.
        if (cs.count == 0) return false;
        for (u64 q : qs) {
            for (std::size_t i = 0; i < cs.count; ++i) {
                if (q == cs.values[i]) return true;
            }
        }
        return false;
    }

    // L4 (behavioural) jaccard helper - used both as the primary path
    // when query has an L4 sketch and as a verifier on top of the L2
    // whole-jaccard path. Returns 0.0 if either side has no L4 sketch.
    [[nodiscard]] float l4_jaccard_with(const WholeEntry& we) const noexcept {
        if (!has_l4 || we.l4_exact == 0) return 0.0f;
        if (we.l4_exact == query.behav.exact_hash) return 1.0f;
        int eq = 0;
        for (std::size_t k = 0; k < 8; ++k) {
            if (we.l4_minhash[k] == query.behav.minhash[k]) ++eq;
        }
        return static_cast<float>(eq) / 8.0f;
    }
};

// Anti-corpus short-circuit. Queries whose L2/L4/prefix hash
// matches any blocked entry are structurally-identifiable junk
// (UPX prologues, packer trampolines, CRT bootloaders) - surface
// nothing rather than letting the cascade emit a misleading
// confident label from a coincidentally-shaped corpus entry.
// Cheap: three unordered_set lookups, all O(1).
bool TeefCorpus::query_blocked(const TeefFunction& query) const noexcept {
    if (blocked_l2_.contains(query.whole.exact_hash)) return true;
    if (query.behav.exact_hash != 0 &&
        blocked_l4_.contains(query.behav.exact_hash)) return true;
    return query.prefix_hash != 0 && blocked_prefix_.contains(query.prefix_hash);
}

// L1: byte-prefix exact match for tiny fns (<= 16 insns / 64 bytes),
// where the L2 token bag and the L4 trace multiset both collapse to a
// couple of values. The raw prefix keeps register identity and small
// immediates, which is what FLIRT gets right at this size. Same
// popularity guard as whole-exact: a prefix shared by many corpus fns
// is a generic stub, not an identity.
std::vector<TeefMatch>
TeefCorpus::match_prefix_exact(const RecognizeQuery& rq) const {
    constexpr std::size_t kMaxPrefixBucket = 4;
    if (rq.query.prefix_hash == 0) return {};
    // Distinct-name count instead of raw bucket - see the comment on
    // whole_prefix_distinct_ for why.
    auto dn = whole_prefix_distinct_.find(rq.query.prefix_hash);
    const std::size_t names_n = (dn == whole_prefix_distinct_.end())
        ? 0u : dn->second;
    const std::size_t bucket = whole_prefix_.count(rq.query.prefix_hash);
    if (names_n > 0 && names_n <= kMaxPrefixBucket && bucket > 0) {
        auto [lo, hi] = whole_prefix_.equal_range(rq.query.prefix_hash);
        std::unordered_set<std::string> distinct;
        std::vector<std::string> ordered;
        for (auto it = lo; it != hi; ++it) {
            const auto& we = whole_by_name_[it->second];
            if (!runtime_compatible(rq.runtime, interned(we.runtime_id))) continue;
            if (!rq.strings_compatible(we.string_hashes)) continue;
            const auto name = interned(we.name_id);
            if (distinct.insert(std::string(name)).second) ordered.emplace_back(name);
        }
        // Confidence floor for prefix-exact when the query has no
        // string evidence. Anonymous helpers (no strings) hitting a
        // single corpus prefix-exact target previously emitted 1.0 -
        // for a 3-instruction stub that's overconfident: the corpus
        // entry could be from any unrelated codebase that happens to
        // share the same byte prefix. Cap at 0.7 so the match still
        // surfaces for review but won't auto-promote at the typical
        // 0.85 cascade threshold. Queries WITH strings already
        // require an overlap in strings_compatible above.
        const float zero_string_cap =
            rq.query.string_hashes.empty() ? 0.7f : 1.0f;
        return exact_tier_matches(std::move(ordered), zero_string_cap,
                                  "prefix-exact", rq.top_k);
    }
    return {};
}

// ---- Behavioural exact match (highest precision) ----
// L4 collisions are 64-trace I/O-multiset hashes; an accidental
// collision between two semantically-distinct functions is
// vanishingly rare. Same boilerplate guard as L2 - if the L4 hash
// is shared by many corpus rows it's a "trivial-shape behaviour"
// (return-zero, identity stub) and a single canonical name
// shouldn't be surfaced. kMaxL4Bucket is tighter than the L2
// counterpart since L4 collisions on substantive code are very
// unusual.
std::vector<TeefMatch>
TeefCorpus::match_behav_exact(const RecognizeQuery& rq) const {
    constexpr std::size_t kMaxL4Bucket = 4;
    if (!rq.has_l4) return {};
    // Distinct-name count: 50 corpus versions of `memcpy` should
    // collapse to 1 distinct name, not trip the boilerplate floor.
    auto dn = whole_l4_distinct_.find(rq.query.behav.exact_hash);
    const std::size_t names_n = (dn == whole_l4_distinct_.end())
        ? 0u : dn->second;
    const std::size_t bucket = whole_l4_exact_.count(rq.query.behav.exact_hash);
    if (names_n > 0 && names_n <= kMaxL4Bucket && bucket > 0) {
        auto [it_lo, it_hi] = whole_l4_exact_.equal_range(rq.query.behav.exact_hash);
        std::unordered_set<std::string> distinct;
        std::vector<std::string> ordered;
        // Track best L2 minhash jaccard across the L4-colliding
        // candidates. K=64 traces on small / low-entropy fns can
        // collide spuriously across semantically-unrelated fns
        // whose I/O arity happens to match. Adapt the corroboration
        // floor to the QUERY's L2 minhash entropy: a query with
        // many duplicate minhash slot values has a degenerate
        // canonical token stream and even high-jaccard L2 agreement
        // is suspect for small wrappers. Tighten the floor when
        // entropy is low.
        auto minhash_unique_slots = [](const std::array<u64, 8>& mh) -> int {
            std::array<u64, 8> sorted = mh;
            std::sort(sorted.begin(), sorted.end());
            return static_cast<int>(
                std::unique(sorted.begin(), sorted.end()) - sorted.begin());
        };
        const int q_entropy = minhash_unique_slots(rq.query.whole.minhash);
        // Empirical floors: full-entropy (8 unique slots) → 0.25
        // catches genuine cross-compiler matches; ≤4 unique slots
        // → 0.625 (5/8 agree) demands stronger structural overlap
        // because both K=64 trace AND minhash collapse on small
        // wrapper fns.
        const float l2_floor = (q_entropy <= 4) ? 0.625f : 0.25f;
        float best_l2j = 0.0f;
        // Topology agreement: a third orthogonal signal. Same
        // source across compiler versions produces the same
        // high-level CFG (block/edge/return/loop counts), so
        // same topo_hash. Spurious L4 collisions across
        // semantically-unrelated fns produce different CFGs and
        // different topo hashes. Only apply when both sides
        // actually have a non-zero topo (build_teef_tsv emits 0
        // for fns whose CFG signal is unreliable).
        bool topo_disagrees = false;
        for (auto it = it_lo; it != it_hi; ++it) {
            const auto& we = whole_by_name_[it->second];
            if (!runtime_compatible(rq.runtime, interned(we.runtime_id))) continue;
            if (!rq.strings_compatible(we.string_hashes)) continue;
            const float l2j = jaccard_minhash(rq.query.whole.minhash, we.minhash);
            if (l2j > best_l2j) best_l2j = l2j;
            if (rq.query.topo_hash != 0 && we.topo_hash != 0 &&
                rq.query.topo_hash != we.topo_hash) {
                topo_disagrees = true;
            }
            const auto name = interned(we.name_id);
            if (distinct.insert(std::string(name)).second) ordered.emplace_back(name);
        }
        const float l2_cap =
            (best_l2j >= l2_floor && !topo_disagrees) ? 1.0f : 0.7f;
        return exact_tier_matches(std::move(ordered), l2_cap,
                                  "behav-exact", rq.top_k);
    }
    return {};
}

// L2: whole-function exact match. One corpus name is the answer;
// several are emitted as tied low-confidence candidates. A hash shared
// by many corpus rows (a one-instruction stub hundreds of fns reduce
// to) is skipped even when it maps to a single name; chunk vote
// demands more evidence.
std::vector<TeefMatch>
TeefCorpus::match_whole_exact(const RecognizeQuery& rq) const {
    // Distinct-name guard: same bug pattern as L4/prefix. The
    // rq.hash_too_common check above stays - it counts ALL F rows
    // (including sub_*) and detects "this L2 hash is a generic
    // shape that many trivial stubs share," which is a different
    // signal than the named-fn replication we're fixing here.
    auto dn = whole_exact_distinct_.find(rq.query.whole.exact_hash);
    const std::size_t names_n = (dn == whole_exact_distinct_.end())
        ? 0u : dn->second;
    const std::size_t bucket = whole_exact_.count(rq.query.whole.exact_hash);
    if (!rq.hash_too_common && names_n > 0 && names_n <= kMaxWholeBucket && bucket > 0) {
        auto [it_lo, it_hi] = whole_exact_.equal_range(rq.query.whole.exact_hash);
        std::unordered_set<std::string> distinct;
        std::vector<std::string> ordered;
        for (auto it = it_lo; it != it_hi; ++it) {
            const auto& we = whole_by_name_[it->second];
            if (!runtime_compatible(rq.runtime, interned(we.runtime_id))) continue;
            if (!rq.strings_compatible(we.string_hashes)) continue;
            const auto name = interned(we.name_id);
            if (distinct.insert(std::string(name)).second) ordered.emplace_back(name);
        }
        // Thin-evidence cap: pure-structural L2 collision with no
        // string anchor and no behavioural corroboration is the FP
        // class for Rust generic helpers (e.g. small `impl<T>` fns
        // whose canonical token stream collides across types). The
        // match still surfaces but doesn't auto-promote at 0.85.
        // Mirrors the prefix-exact zero_string_cap.
        const float thin_cap = (rq.query.string_hashes.empty() && !rq.has_l4) ? 0.7f : 1.0f;
        return exact_tier_matches(std::move(ordered), thin_cap,
                                  "whole-exact", rq.top_k);
    }
    return {};
}

// L2 jaccard narrows, L4 re-ranks. With an L4 sketch the score is
// 0.5*L2 + 0.5*L4 against a 0.6 bar and 0.20 margin; without one (the
// interpreter aborted) it is pure L2 against 0.875 and 0.25. The
// topology bucket is scanned when the MinHash index yields nothing
// confident.
std::vector<TeefMatch>
TeefCorpus::match_whole_jaccard(const RecognizeQuery& rq) const {
    if (rq.hash_too_common) return {};
    // Per-candidate scorer + verdict, shared by the topo-bucket
    // and full-scan paths.
    struct ScanState {
        std::string best_name;     float best_combined  = 0.0f;
        std::string second_name;   float second_combined = 0.0f;
        bool        best_has_l4 = false;
    };
    auto score_entry = [&](const WholeEntry& e, ScanState& s) {
        if (e.exact_hash == 0) return;
        if (!runtime_compatible(rq.runtime, interned(e.runtime_id))) return;
        if (!rq.strings_compatible(e.string_hashes)) return;
        const float l2j = jaccard_minhash(rq.query.whole.minhash, e.minhash);
        const float l4j = rq.l4_jaccard_with(e);
        const bool has_l4 = (rq.has_l4 && e.l4_exact != 0);
        const float combined = has_l4 ? (0.5f * l2j + 0.5f * l4j) : l2j;
        if (combined > s.best_combined) {
            s.second_combined = s.best_combined;
            s.second_name     = std::move(s.best_name);
            s.best_combined   = combined;
            s.best_name       = std::string(interned(e.name_id));
            s.best_has_l4     = has_l4;
        } else if (combined > s.second_combined) {
            s.second_combined = combined;
            s.second_name     = std::string(interned(e.name_id));
        }
    };
    auto verdict = [&](ScanState& s) -> std::optional<TeefMatch> {
        const float bar    = s.best_has_l4 ? 0.6f  : 0.875f;
        const float margin = s.best_has_l4 ? 0.20f : 0.25f;
        if (s.best_combined < bar) return std::nullopt;
        if ((s.best_combined - s.second_combined) < margin) return std::nullopt;
        const std::string via = s.best_has_l4 ? "whole-jaccard+behav" : "whole-jaccard";
        float conf = s.best_combined;
        if (is_boilerplate_label(s.best_name)) conf = std::min(conf, 0.7f);
        return TeefMatch{std::move(s.best_name), conf, via, 0};
    };

    // Stage 1: L2 MinHash inverted index. Entries hit by at least
    // kMinSlotHits of the query's 8 slot values have an estimated
    // jaccard >= kMinSlotHits/8 and are the only ones scored. Slot
    // buckets larger than SPELUNK_TEEF_MAX_SLOT_BUCKET are boilerplate
    // and skipped. 2/8 keeps L4-rescued candidates: weak L2 (0.25)
    // with L4 = 1.0 scores 0.625, above the 0.6 bar; 3/8 lost 4/361
    // matches on the probe2 matrix.
    constexpr u8 kMinSlotHits = 2;     // estimate jaccard ≥ 2/8 = 0.25
    static const std::size_t kMaxSlotBucket = []() -> std::size_t {
        if (const char* s = std::getenv("SPELUNK_TEEF_MAX_SLOT_BUCKET")) {
            try { return static_cast<std::size_t>(std::stoull(s)); }
            catch (...) { /* fall through */ }
        }
        return 5000;
    }();
    {
        std::unordered_map<u32, u8> hits;
        for (std::size_t k = 0; k < 8; ++k) {
            const u64 v = rq.query.whole.minhash[k];
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

    // Stage 2 - topo bucket fallback. Catches cases where slot
    // collisions are too sparse to cross kMinSlotHits but the L0
    // topology agrees (small fns where minhash entropy is low and
    // jaccard estimates are noisy). Bounded - topo buckets are
    // rarely huge.
    if (rq.query.topo_hash != 0) {
        auto [lo, hi] = whole_topo_.equal_range(rq.query.topo_hash);
        if (lo != hi) {
            ScanState s2;
            for (auto it = lo; it != hi; ++it) {
                score_entry(whole_by_name_[it->second], s2);
            }
            if (auto m = verdict(s2)) return { *m };
        }
    }
    return {};
}

// ---- Chunk vote ----
// Each query chunk that hits the corpus contributes its size to
// the candidate functions that contain that chunk (capped at
// kMaxChunkFns to avoid boilerplate noise).
std::vector<TeefMatch>
TeefCorpus::match_chunk_vote(const RecognizeQuery& rq) const {
    std::unordered_map<std::string, u64> votes;
    for (const auto& ch : rq.query.chunks) {
        if (ch.sig.exact_hash == 0) continue;
        auto it = chunk_index_.find(ch.sig.exact_hash);
        if (it == chunk_index_.end()) continue;
        // Boilerplate floor: a chunk used by many DISTINCT named fns is
        // generic. Raw bucket size would falsely flag a popular chunk
        // (memcpy's hot loop replicated across 50 glibc versions, all
        // under the same name) as boilerplate.
        auto dn = chunk_distinct_.find(ch.sig.exact_hash);
        const std::size_t names_n = (dn == chunk_distinct_.end())
            ? it->second.size() : dn->second;
        if (names_n > kMaxChunkFns) continue;
        for (const auto& ref : it->second) {
            if (!runtime_compatible(rq.runtime, interned(ref.runtime_id))) continue;
            votes[std::string(interned(ref.name_id))] += ch.inst_count;
        }
    }
    if (votes.empty()) return {};

    // String-anchor filter for chunk-vote candidates, applied to each
    // candidate's parent fn. On top of strings_compatible, a query with
    // >= 3 strings never matches a parent with none: that overlap is
    // coincidence (a Wayland main hitting a libstdc++ wide-char
    // template).
    if (!rq.query.string_hashes.empty()) {
        for (auto it = votes.begin(); it != votes.end(); ) {
            auto nit = idx_by_name_.find(it->first);
            if (nit == idx_by_name_.end()) { ++it; continue; }
            const auto& we = whole_by_name_[nit->second];
            const bool drop =
                !rq.strings_compatible(we.string_hashes) ||
                (rq.query.string_hashes.size() >= 3 && we.string_hashes.empty());
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
    // anti-FP signal - the existing string-anchor filter already
    // suppresses *most* structural FPs, but it can't help when the
    // corpus parent has empty string_hashes; L4 fills exactly that gap.
    bool behav_agreed = false;
    if (rq.has_l4 && !ranked.empty()) {
        auto top_l4 = [&](const std::string& nm) -> float {
            auto it = idx_by_name_.find(nm);
            if (it == idx_by_name_.end()) return 0.0f;
            return rq.l4_jaccard_with(whole_by_name_[it->second]);
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
    out.reserve(rq.top_k);
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
    // Thin-evidence cap: chunk-vote alone (no string anchor on the
    // query, no L4 corroboration on the winner) is the most FP-prone
    // lane - multiple unrelated functions can share enough chunk
    // shapes to win the vote. Cap to 0.7 so the match surfaces but
    // doesn't auto-promote at 0.85. behav_agreed=true means L4
    // re-ranking confirmed the winner; that lifts the cap.
    const float thin_cap =
        (rq.query.string_hashes.empty() && !behav_agreed) ? 0.7f : 1.0f;
    auto cap_for = [&](float raw, std::string_view nm) {
        float c = std::min(raw, thin_cap);
        if (is_boilerplate_label(nm)) c = std::min(c, 0.7f);
        return c;
    };
    for (std::size_t i = 0; i < ranked.size() && i < rq.top_k; ++i) {
        TeefMatch m;
        m.name       = std::move(ranked[i].first);
        m.via        = std::string(via_tag);
        const float raw_conf = (i == 0) ? margin :
            static_cast<float>(ranked[i].second) / static_cast<float>(top1 + top2);
        m.confidence = cap_for(raw_conf, m.name);
        m.vote_score = static_cast<u32>(ranked[i].second);
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<TeefMatch>
TeefCorpus::recognize(const TeefFunction& query, std::size_t top_k,
                      std::string_view query_runtime) const {
    if (query.whole.exact_hash == 0) return {};
    if (query_blocked(query)) return {};

    // Corpus-side gate: a hash shared by many corpus F rows (named
    // OR sub_*) is a "common trivial shape" and a single canonical
    // name shouldn't be surfaced as the unique answer. Caller-side
    // gates (query-side popularity in particular) handle the
    // complementary case where the unknown binary itself has many
    // tiny functions hashing the same.
    auto pop_it = whole_popularity_.find(query.whole.exact_hash);
    const std::size_t hash_popularity = (pop_it == whole_popularity_.end())
        ? 0u : pop_it->second;
    const RecognizeQuery rq{query, query_runtime, top_k,
                            /*has_l4=*/query.behav.exact_hash != 0,
                            /*hash_too_common=*/hash_popularity > kMaxWholeBucket};

    if (auto m = match_prefix_exact(rq); !m.empty()) return m;
    if (auto m = match_behav_exact(rq); !m.empty()) return m;
    if (auto m = match_whole_exact(rq); !m.empty()) return m;
    if (auto m = match_whole_jaccard(rq); !m.empty()) return m;
    return match_chunk_vote(rq);
}

}  // namespace spelunk
