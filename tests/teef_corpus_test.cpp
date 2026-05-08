// Unit tests for the TeefCorpus loader (`core/src/analysis/teef_recognize.cpp`).
//
// The corpus loader has historically had no direct test coverage — its
// behavior was only exercised end-to-end via `--corpus + --recognize`,
// which means parser regressions, intern-table bugs, and merge-phase
// rewrites all flew under the radar. These tests synthesize tiny TSVs
// in-memory, write them to a temp file, load them via the public API,
// and assert the recognizer returns the expected matches.
//
// Coverage targets:
//   - Basic F-row load + L2 whole-exact match
//   - sub_* names dropped from indexed entries (still counted in
//     popularity for the trivial-shape guard)
//   - Multi-TSV merge with name interning across files
//   - Distinct-name guard: same fingerprint replicated under one name
//     across many corpus versions still resolves; different names trip
//     the boilerplate floor
//   - T-row runtime transitions apply to subsequent rows
//   - 24-field back-compat (pre-max.4 corpora without prefix_hash)
//   - L1 prefix-exact lane on tiny-fn fast path
//   - C-row chunk-vote returns the winning name
//   - S-row identifying-string filter rejects structural FPs across
//     unrelated codebases

#include <ember/analysis/teef.hpp>
#include <ember/analysis/teef_recognize.hpp>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

int fails = 0;

void fail(const char* ctx) {
    std::fprintf(stderr, "FAIL: %s\n", ctx);
    ++fails;
}

template <typename T, typename U>
void check_eq(const T& got, const U& want, const char* ctx) {
    if (!(got == want)) {
        std::fprintf(stderr, "FAIL: %s\n", ctx);
        ++fails;
    }
}

void check_true(bool cond, const char* ctx) {
    if (!cond) fail(ctx);
}

// Format a u64 as 16-char lowercase hex — matches build_teef_tsv output.
std::string hex16(ember::u64 v) {
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016lx", static_cast<unsigned long>(v));
    return std::string(buf, 16);
}

// Write a string to a temp file path; caller is responsible for unlink.
fs::path write_tmp(const std::string& contents, const char* tag) {
    const auto base = fs::temp_directory_path();
    const auto path = base / (std::string("ember_teef_corpus_test_") + tag + ".tsv");
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    f.close();
    return path;
}

// Build an F row matching the build_teef_tsv format. minhash_seed
// generates 8 distinct slot values so each test fn has its own
// L2 minhash without us spelling all 8 out by hand.
std::string make_f_row(ember::u64 addr, ember::u64 l2_exact,
                       ember::u64 minhash_seed,
                       std::string_view name,
                       ember::u64 l4_exact = 0,
                       ember::u64 topo = 0,
                       ember::u64 prefix = 0) {
    std::string row = "F\t";
    row += hex16(addr);                row += '\t';
    row += hex16(l2_exact);            row += '\t';
    for (std::size_t k = 0; k < 8; ++k) {
        row += hex16(minhash_seed + static_cast<ember::u64>(k));
        row += '\t';
    }
    row += name;                       row += '\t';
    row += hex16(l4_exact);            row += '\t';
    for (std::size_t k = 0; k < 8; ++k) {
        row += hex16(l4_exact ? (l4_exact + static_cast<ember::u64>(k)) : 0u);
        row += '\t';
    }
    row += "0\t0\t";                                  // L4_done, L4_aborted
    row += hex16(topo);                row += '\t';
    row += hex16(prefix);              row += '\n';
    return row;
}

// Same as make_f_row but emits a 24-field row (no prefix_hash) — the
// pre-max.4 corpus shape we still claim back-compat for.
std::string make_f_row_24(ember::u64 addr, ember::u64 l2_exact,
                          ember::u64 minhash_seed,
                          std::string_view name,
                          ember::u64 topo = 0) {
    std::string row = "F\t";
    row += hex16(addr);                row += '\t';
    row += hex16(l2_exact);            row += '\t';
    for (std::size_t k = 0; k < 8; ++k) {
        row += hex16(minhash_seed + static_cast<ember::u64>(k));
        row += '\t';
    }
    row += name;                       row += '\t';
    row += hex16(0);                   row += '\t';   // L4_exact = 0
    for (std::size_t k = 0; k < 8; ++k) { row += hex16(0); row += '\t'; }
    row += "0\t0\t";                                  // L4_done, L4_aborted
    row += hex16(topo);                row += '\n';   // no trailing prefix
    return row;
}

std::string make_c_row(ember::u64 addr, ember::u64 chunk_hash,
                       ember::u32 inst_count, std::string_view name) {
    std::string row = "C\t";
    row += hex16(addr);                row += '\t';
    row += "0\t";                                     // kind
    row += std::to_string(inst_count); row += '\t';
    row += hex16(chunk_hash);          row += '\t';
    for (std::size_t k = 0; k < 8; ++k) {
        row += hex16(chunk_hash + static_cast<ember::u64>(k + 1));
        row += '\t';
    }
    row += name;                       row += '\n';
    return row;
}

std::string make_s_row(ember::u64 addr, std::vector<ember::u64> hashes) {
    std::string row = "S\t";
    row += hex16(addr);                row += '\t';
    bool first = true;
    for (auto h : hashes) {
        if (!first) row += ',';
        first = false;
        row += hex16(h);
    }
    row += '\n';
    return row;
}

std::string make_t_runtime(std::string_view tag) {
    std::string row = "T\truntime\t";
    row += tag;
    row += '\n';
    return row;
}

// Build a synthetic query TeefFunction. Test cases populate only the
// signal lanes they care about and leave the others at zero so we
// know which recognizer tier the match came from.
ember::TeefFunction make_query(ember::u64 l2_exact,
                               ember::u64 minhash_seed,
                               ember::u64 l4_exact = 0,
                               ember::u64 topo = 0,
                               ember::u64 prefix = 0) {
    ember::TeefFunction q;
    q.whole.exact_hash = l2_exact;
    for (std::size_t k = 0; k < 8; ++k) {
        q.whole.minhash[k] = minhash_seed + static_cast<ember::u64>(k);
    }
    q.behav.exact_hash = l4_exact;
    if (l4_exact != 0) {
        for (std::size_t k = 0; k < 8; ++k) {
            q.behav.minhash[k] = l4_exact + static_cast<ember::u64>(k);
        }
    }
    q.topo_hash   = topo;
    q.prefix_hash = prefix;
    return q;
}

// ---- Test cases ----------------------------------------------------------

void test_basic_l2_exact() {
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0xAAAA1, /*mh*/0x10, "encrypt_block");
    tsv += make_f_row(0x2000, /*l2*/0xBBBB2, /*mh*/0x20, "decrypt_block");
    const auto path = write_tmp(tsv, "basic");

    ember::TeefCorpus c;
    const std::size_t rows = c.load_tsv(path);
    check_eq(rows, std::size_t{2}, "basic_l2_exact: rows ingested");
    check_eq(c.function_count(), std::size_t{2}, "basic_l2_exact: function_count");

    auto q = make_query(0xAAAA1, 0x10);
    auto matches = c.recognize(q, /*top_k*/3);
    check_true(!matches.empty(), "basic_l2_exact: matches non-empty");
    if (!matches.empty()) {
        check_eq(matches[0].name, std::string{"encrypt_block"},
                 "basic_l2_exact: name");
    }
    fs::remove(path);
}

void test_sub_star_dropped() {
    // sub_* rows count toward popularity (trivial-shape guard) but
    // never become indexed corpus entries — they have no ground-truth
    // name to surface.
    std::string tsv;
    tsv += make_f_row(0x1000, 0x1111, 0x10, "sub_1000");
    tsv += make_f_row(0x2000, 0x2222, 0x20, "sub_2000");
    tsv += make_f_row(0x3000, 0x3333, 0x30, "real_function");
    const auto path = write_tmp(tsv, "substar");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    check_eq(c.function_count(), std::size_t{1}, "sub_star_dropped: only real_function indexed");

    // Sub_* hash should not be reachable as a match.
    auto q_sub = make_query(0x1111, 0x10);
    auto m_sub = c.recognize(q_sub, 3);
    check_true(m_sub.empty(), "sub_star_dropped: sub_* hash unmatchable");

    auto q_real = make_query(0x3333, 0x30);
    auto m_real = c.recognize(q_real, 3);
    check_true(!m_real.empty(), "sub_star_dropped: real_function still matches");
    if (!m_real.empty()) {
        check_eq(m_real[0].name, std::string{"real_function"},
                 "sub_star_dropped: real_function name");
    }
    fs::remove(path);
}

void test_multi_tsv_merge() {
    // Two TSVs loaded into the same corpus. Names that appear in both
    // intern to the same id (same string content), so the
    // distinct-name guard treats them as one — same-name replicas
    // across versions don't trip the boilerplate floor.
    std::string a;
    a += make_f_row(0x1000, /*l2*/0x9001, 0x10, "memcpy");
    a += make_f_row(0x2000, /*l2*/0x9002, 0x20, "strlen");
    std::string b;
    b += make_f_row(0x1000, /*l2*/0x9001, 0x10, "memcpy");   // same hash + name
    b += make_f_row(0x3000, /*l2*/0x9003, 0x30, "strcmp");
    const auto pa = write_tmp(a, "merge_a");
    const auto pb = write_tmp(b, "merge_b");

    ember::TeefCorpus c;
    (void)c.load_tsv(pa);
    (void)c.load_tsv(pb);
    check_eq(c.function_count(), std::size_t{4},
             "multi_tsv_merge: 4 raw F entries indexed");

    // memcpy hash appears 2× in whole_exact_, but with one distinct
    // name — recognizer must surface it as the unique answer, not
    // ambiguous. (Without the distinct-name guard, raw bucket size
    // 2 with kMaxWholeBucket=8 would still pass; the test ensures
    // the merged corpus actually returns it cleanly.) Confidence is
    // capped at 0.7 by the thin-evidence guard since the query has
    // no string anchors and no L4 — see test_thin_evidence_cap below
    // for the rationale.
    auto q = make_query(0x9001, 0x10);
    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "multi_tsv_merge: memcpy match exists");
    if (!m.empty()) {
        check_eq(m[0].name, std::string{"memcpy"}, "multi_tsv_merge: memcpy");
        check_true(m[0].confidence > 0.0f && m[0].confidence <= 0.7f,
                   "multi_tsv_merge: thin-evidence capped");
    }
    fs::remove(pa);
    fs::remove(pb);
}

void test_distinct_name_guard_rejects_ambiguous() {
    // Same L2 hash, two genuinely different names → ambiguous; the
    // recognizer should NOT promote either as the unique 1.0 answer.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0x4242, 0x10, "candidate_a");
    tsv += make_f_row(0x2000, /*l2*/0x4242, 0x20, "candidate_b");
    const auto path = write_tmp(tsv, "ambiguous");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    auto q = make_query(0x4242, 0x10);
    auto m = c.recognize(q, 3);
    if (!m.empty()) {
        // Either candidate is fine; what's NOT fine is a 1.0 confidence
        // claim — both are equally valid so confidence must be split.
        check_true(m[0].confidence < 1.0f,
                   "distinct_name_guard: ambiguous match split confidence");
    }
    fs::remove(path);
}

void test_t_runtime_transition() {
    // T row mid-file flips active runtime. Subsequent F rows pick up
    // the new tag — verify by querying with a runtime that's
    // compatible with one but not the other.
    std::string tsv;
    tsv += make_t_runtime("rust");
    tsv += make_f_row(0x1000, /*l2*/0x7001, 0x10, "rust_alloc");
    tsv += make_t_runtime("libstdcxx");
    tsv += make_f_row(0x2000, /*l2*/0x7002, 0x20, "_ZNSt6vectorIiE_M_emplaceEv");
    const auto path = write_tmp(tsv, "runtime");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    check_eq(c.function_count(), std::size_t{2}, "t_runtime: both rows loaded");

    // Query tagged rust → must match rust_alloc but NOT the libstdcxx fn
    // (Rust never matches libstdcxx per runtime_compatible).
    auto q_rust = make_query(0x7002, 0x20);
    auto m_rust = c.recognize(q_rust, 3, /*query_runtime*/"rust");
    check_true(m_rust.empty(),
               "t_runtime: rust query rejects libstdcxx candidate");

    auto q_rust_self = make_query(0x7001, 0x10);
    auto m_rust_self = c.recognize(q_rust_self, 3, "rust");
    check_true(!m_rust_self.empty(),
               "t_runtime: rust query matches rust_alloc");
}

void test_24_field_back_compat() {
    // Pre-max.4 corpora omit the trailing prefix_hash field. Loader
    // must still ingest them (with prefix_hash=0).
    std::string tsv;
    tsv += make_f_row_24(0x1000, /*l2*/0x5500, 0x10, "old_format_fn");
    const auto path = write_tmp(tsv, "v24");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    check_eq(c.function_count(), std::size_t{1},
             "24_field_back_compat: row ingested");
    auto q = make_query(0x5500, 0x10);
    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "24_field_back_compat: still matches");
    if (!m.empty()) {
        check_eq(m[0].name, std::string{"old_format_fn"}, "24_field name");
    }
    fs::remove(path);
}

void test_prefix_exact_l1_lane() {
    // L1 byte-prefix fast path — for tiny fns (≤16 insns / ≤64 bytes)
    // where L2/L4 collapse to noise. Set a non-zero prefix on both
    // corpus and query.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0x6601, 0x10, "tiny_stub",
                      /*l4*/0, /*topo*/0, /*prefix*/0xDEADBEEFCAFE);
    const auto path = write_tmp(tsv, "prefix");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    auto q = make_query(/*l2*/0x6601, /*mh*/0x10,
                        /*l4*/0, /*topo*/0, /*prefix*/0xDEADBEEFCAFE);
    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "prefix_exact: matches");
    if (!m.empty()) {
        // Either prefix-exact or whole-exact lane — both are valid for
        // a single-entry corpus. Just check we got the right name.
        check_eq(m[0].name, std::string{"tiny_stub"}, "prefix_exact: name");
    }
    fs::remove(path);
}

void test_chunk_vote() {
    // F row anchors the named function; multiple C rows attribute
    // chunks to it. Query has matching chunk hashes but a *different*
    // L2 whole-exact, so whole-exact misses and the recognizer falls
    // through to chunk-vote.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0x8801, 0x10, "voter_target");
    tsv += make_c_row(0x1000, /*chunk*/0xC0FFEE01, 50, "voter_target");
    tsv += make_c_row(0x1000, /*chunk*/0xC0FFEE02, 30, "voter_target");
    tsv += make_c_row(0x1000, /*chunk*/0xC0FFEE03, 20, "voter_target");
    const auto path = write_tmp(tsv, "vote");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);
    check_eq(c.chunk_count(), std::size_t{3}, "chunk_vote: 3 distinct chunks");

    // Query L2 hash deliberately doesn't match the corpus — exercises
    // the chunk-vote fallback exclusively.
    auto q = make_query(/*l2*/0xDEAD, 0x99);
    ember::TeefChunk c1; c1.sig.exact_hash = 0xC0FFEE01; c1.inst_count = 50;
    ember::TeefChunk c2; c2.sig.exact_hash = 0xC0FFEE02; c2.inst_count = 30;
    q.chunks = {c1, c2};

    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "chunk_vote: voter_target wins");
    if (!m.empty()) {
        check_eq(m[0].name, std::string{"voter_target"}, "chunk_vote: name");
    }
    fs::remove(path);
}

void test_thin_evidence_cap() {
    // Whole-exact with a structurally-thin query (no strings, no L4)
    // is FP-prone on Rust generic helpers — the L2 token stream
    // collides across small impl<T> bodies. Cap confidence to 0.7
    // so the match still surfaces but doesn't auto-promote at the
    // typical 0.85 cascade threshold.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0xCAFE01, 0x10, "some_helper");
    const auto path = write_tmp(tsv, "thin");
    ember::TeefCorpus c;
    (void)c.load_tsv(path);

    // Thin query: no strings, no L4. Should hit whole-exact with cap.
    auto q_thin = make_query(0xCAFE01, 0x10);
    auto m_thin = c.recognize(q_thin, 3);
    check_true(!m_thin.empty(), "thin_evidence: still matches");
    if (!m_thin.empty()) {
        check_true(m_thin[0].confidence <= 0.7f,
                   "thin_evidence: capped at 0.7");
    }

    // Same query but with L4 corroboration — cap lifts.
    auto q_l4 = make_query(0xCAFE01, 0x10, /*l4*/0x1234);
    auto m_l4 = c.recognize(q_l4, 3);
    check_true(!m_l4.empty(), "thin_evidence: L4 query matches");
    if (!m_l4.empty()) {
        check_true(m_l4[0].confidence > 0.7f,
                   "thin_evidence: L4 corroboration lifts cap");
    }
    fs::remove(path);
}

void test_boilerplate_label_cap() {
    // drop_in_place / panic / fmt-trait names are correct-but-useless
    // labels. A single-collision lookup must NOT auto-rename a query
    // function with one of these — cap confidence to 0.7 even when
    // the structural and string evidence is otherwise solid.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0xDEADC0DE, 0x10,
                      "core::ptr::drop_in_place::<alloc::string::String>");
    tsv += make_s_row(0x1000, {0xAAA1, 0xAAA2});
    tsv += make_f_row(0x2000, /*l2*/0xBEEFC0DE, 0x20,
                      "core::panicking::panic_fmt");
    const auto path = write_tmp(tsv, "boilerplate");
    ember::TeefCorpus c;
    (void)c.load_tsv(path);

    // Query with matching strings — would normally get conf 1.0 via
    // whole-exact, but the boilerplate-label cap demotes to 0.7.
    auto q = make_query(0xDEADC0DE, 0x10);
    q.string_hashes = {0xAAA1, 0xAAA2};
    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "boilerplate_label: drop_in_place still surfaces");
    if (!m.empty()) {
        check_true(m[0].confidence <= 0.7f,
                   "boilerplate_label: drop_in_place capped at 0.7");
    }

    // Same for panic_fmt.
    auto q2 = make_query(0xBEEFC0DE, 0x20);
    auto m2 = c.recognize(q2, 3);
    check_true(!m2.empty(), "boilerplate_label: panic_fmt surfaces");
    if (!m2.empty()) {
        check_true(m2[0].confidence <= 0.7f,
                   "boilerplate_label: panic_fmt capped");
    }
    fs::remove(path);
}

void test_boilerplate_label_mangled_forms() {
    // Real Rust binaries store names in mangled form. The detector
    // must catch the `drop_in_place` / `panic_fmt` substrings inside
    // both legacy mangle (length-prefixed + $LT$/$GT$/$u20$ escapes)
    // and v0 mangle (_R-prefixed, length-prefixed). Without this,
    // the boilerplate cap silently fails on every real Rust target.
    std::string tsv;
    // Legacy mangle of `core::ptr::drop_in_place::<HashMap<K,V>>`
    tsv += make_f_row(0x1000, /*l2*/0x111, 0x10,
                      "_ZN4core3ptr181drop_in_place$LT$std..collections..hash..map.."
                      "HashMap$LT$alloc..string..String$C$alloc..vec..Vec$LT$i32$GT$"
                      "$GT$$GT$17h20d4f14c1cf79a0aE");
    // v0 mangle of `core::panicking::panic_fmt`
    tsv += make_f_row(0x2000, /*l2*/0x222, 0x20,
                      "_RNvNtCsgEmfK2I1SDS_4core9panicking9panic_fmt");
    // v0 mangle of `core::ptr::drop_in_place::<…>`
    tsv += make_f_row(0x3000, /*l2*/0x333, 0x30,
                      "_RINvNtCsgEmfK2I1SDS_4core3ptr13drop_in_placeINtNtCs_"
                      "alloc6string6StringEEB1n_");
    // Legacy mangle of `<T as core::fmt::Debug>::fmt`
    tsv += make_f_row(0x4000, /*l2*/0x444, 0x40,
                      "_ZN52_$LT$alloc..string..String$u20$as$u20$core..fmt.."
                      "Debug$GT$3fmt17habcdef0123456789E");
    const auto path = write_tmp(tsv, "mangled");
    ember::TeefCorpus c;
    (void)c.load_tsv(path);

    struct Case { ember::u64 hash; ember::u64 mh; const char* desc; };
    const Case cases[] = {
        {0x111, 0x10, "legacy mangle drop_in_place"},
        {0x222, 0x20, "v0 mangle panic_fmt"},
        {0x333, 0x30, "v0 mangle drop_in_place"},
        {0x444, 0x40, "legacy mangle fmt::Debug impl"},
    };
    for (const auto& tc : cases) {
        auto q = make_query(tc.hash, tc.mh);
        auto m = c.recognize(q, 3);
        check_true(!m.empty(), tc.desc);
        if (!m.empty()) {
            // Cap should fire — confidence ≤ 0.7 regardless of how
            // strong the structural collision was.
            check_true(m[0].confidence <= 0.7f, tc.desc);
        }
    }
    fs::remove(path);
}

void test_chunk_vote_thin_evidence_cap() {
    // Chunk-vote with no string anchor and no L4 corroboration is
    // the most FP-prone lane — multiple unrelated functions share
    // chunk shapes. Cap to 0.7.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0x77001, 0x10, "vote_winner");
    tsv += make_c_row(0x1000, /*chunk*/0xCC01, 50, "vote_winner");
    tsv += make_c_row(0x1000, /*chunk*/0xCC02, 30, "vote_winner");
    const auto path = write_tmp(tsv, "votecap");
    ember::TeefCorpus c;
    (void)c.load_tsv(path);

    auto q = make_query(/*l2 mismatch*/0xDEAD, 0x99);
    ember::TeefChunk c1; c1.sig.exact_hash = 0xCC01; c1.inst_count = 50;
    ember::TeefChunk c2; c2.sig.exact_hash = 0xCC02; c2.inst_count = 30;
    q.chunks = {c1, c2};

    auto m = c.recognize(q, 3);
    check_true(!m.empty(), "chunk_vote_cap: matches");
    if (!m.empty()) {
        check_eq(m[0].name, std::string{"vote_winner"}, "chunk_vote_cap: name");
        check_true(m[0].confidence <= 0.7f,
                   "chunk_vote_cap: thin-evidence capped");
    }
    fs::remove(path);
}

void test_strings_filter_rejects_disjoint() {
    // String anchor: query has identifying strings, corpus candidate
    // has disjoint strings. strings_compatible returns false → match
    // dropped. Without this filter, the L2 collision would surface a
    // confident-but-wrong rename across unrelated codebases.
    std::string tsv;
    tsv += make_f_row(0x1000, /*l2*/0xBEEF, 0x10, "library_fn_A");
    tsv += make_s_row(0x1000, {0xAAA1, 0xAAA2});
    const auto path = write_tmp(tsv, "strings");

    ember::TeefCorpus c;
    (void)c.load_tsv(path);

    auto q = make_query(0xBEEF, 0x10);
    q.string_hashes = {0xBBB1, 0xBBB2};   // disjoint from corpus side

    auto m = c.recognize(q, 3);
    check_true(m.empty(), "strings_filter: disjoint strings reject match");
    fs::remove(path);
}

}  // namespace

int main() {
    test_basic_l2_exact();
    test_sub_star_dropped();
    test_multi_tsv_merge();
    test_distinct_name_guard_rejects_ambiguous();
    test_t_runtime_transition();
    test_24_field_back_compat();
    test_prefix_exact_l1_lane();
    test_chunk_vote();
    test_strings_filter_rejects_disjoint();
    test_thin_evidence_cap();
    test_boilerplate_label_cap();
    test_boilerplate_label_mangled_forms();
    test_chunk_vote_thin_evidence_cap();

    if (fails) {
        std::fprintf(stderr, "teef_corpus_test: %d failure(s)\n", fails);
        return EXIT_FAILURE;
    }
    std::fprintf(stderr, "teef_corpus_test: ok\n");
    return EXIT_SUCCESS;
}
