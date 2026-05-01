#include <ember/analysis/teef.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/decompile/emit_options.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>
#include <ember/structure/region.hpp>
#include <ember/structure/structurer.hpp>

namespace ember {

namespace {

// FNV-1a-64 over a string view. Hot loop over per-token strings; no
// std::hash because we need bit-stable output across hosts/builds.
[[nodiscard]] constexpr u64 fnv1a(std::string_view s) noexcept {
    u64 h = 0xcbf29ce484222325ULL;
    for (char c : s) {
        h ^= static_cast<u8>(c);
        h *= 0x100000001b3ULL;
    }
    return h;
}

[[nodiscard]] u64 mix64(u64 a, u64 b) noexcept {
    u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

// Cheap bigram hash over the post-canonicalization token stream.
[[nodiscard]] u64 bigram_hash(u64 a, u64 b) noexcept { return mix64(a, b); }

// ---- Canonicalizer ----------------------------------------------------
//
// Take the emitter's pseudo-C output and produce a token stream where
// per-build noise (SSA temp numbers, sub-address suffixes, large literal
// values, identifier choices) is removed. See docs/teef.md for the rules.
//
// Approach: hand-rolled tokenizer (no regex), one pass over the string.
// Each token is hashed with fnv1a and either kept verbatim, replaced
// with a category-class hash, or alpha-renamed.

constexpr u64 kClassCallRet = fnv1a("CALL_RET");
constexpr u64 kClassCallee  = fnv1a("CALLEE");
constexpr u64 kClassAddr    = fnv1a("ADDR");     // beyond literal range

// C / pseudo-C keywords + ember type names that we keep verbatim.
[[nodiscard]] bool is_kept_keyword(std::string_view s) noexcept {
    static constexpr std::string_view kKeywords[] = {
        "if","else","while","for","do","return","switch","case","default",
        "break","continue","goto","void","char","int","long","short","signed",
        "unsigned","float","double","bool","true","false","NULL",
        "u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","f80","f128",
        "s8","s16","s32","s64",
        "size_t","ptrdiff_t","addr_t","static","extern","inline",
        "struct","union","enum","typedef","const","volatile","restrict",
    };
    for (auto kw : kKeywords) if (s == kw) return true;
    return false;
}

// `t<digits>` and `a<digits>` are SSA temps and arg names — alpha-rename
// in order-of-first-appearance. Other identifiers (callee names, struct
// fields, types, externs) are anchor points and stay verbatim.
[[nodiscard]] bool is_temp_ident(std::string_view s) noexcept {
    if (s.size() < 2) return false;
    if (s[0] != 't' && s[0] != 'a') return false;
    for (std::size_t i = 1; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
    }
    return true;
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view pre) noexcept {
    return s.size() >= pre.size() && s.compare(0, pre.size(), pre) == 0;
}

[[nodiscard]] bool is_identifier_start(char c) noexcept {
    return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

[[nodiscard]] bool is_identifier_cont(char c) noexcept {
    return c == '_' || c == '$' || (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}

// Classify a hex / decimal literal. Two principles:
//   1. Small literals (<= 0x10000) keep their literal value — these are
//      bit masks, struct offsets, flag bits, syscall numbers, TLS slot
//      offsets, etc., and they're the dominant identifying signal that
//      distinguishes otherwise shape-equivalent functions
//      (e.g. isalpha vs isdigit only differ in the bit they mask).
//   2. Anything bigger goes to ADDR — those are rip-relative addresses
//      that ASLR/relocation perturbs across builds.
[[nodiscard]] u64 literal_class(u64 v) noexcept {
    if (v <= 0x10000u) {
        // Literal verbatim, but distinguish positive from sign-extended
        // negatives so `-1` vs `0xffffffff` still match.
        char buf[24];
        const int n = std::snprintf(buf, sizeof buf, "%lx", static_cast<unsigned long>(v));
        return fnv1a(std::string_view(buf, static_cast<std::size_t>(n)));
    }
    // Negative i64 immediates land here too (high bits set). For those
    // we still want a stable class — emit a sign-extended-class token.
    const i64 s = static_cast<i64>(v);
    if (s < 0 && s >= -0x10000) {
        char buf[24];
        const int n = std::snprintf(buf, sizeof buf, "-%lx", static_cast<unsigned long>(-s));
        return fnv1a(std::string_view(buf, static_cast<std::size_t>(n)));
    }
    return kClassAddr;
}

[[nodiscard]] u64 parse_hex_literal(std::string_view s) noexcept {
    u64 v = 0;
    for (char c : s) {
        const u64 d = (c >= '0' && c <= '9') ? static_cast<u64>(c - '0')
                    : (c >= 'a' && c <= 'f') ? static_cast<u64>(c - 'a' + 10)
                    : (c >= 'A' && c <= 'F') ? static_cast<u64>(c - 'A' + 10)
                    : 0u;
        v = (v << 4) | d;
    }
    return v;
}

[[nodiscard]] u64 parse_decimal_literal(std::string_view s) noexcept {
    u64 v = 0;
    for (char c : s) v = v * 10 + static_cast<u64>(c - '0');
    return v;
}

// Strip everything outside the function body — return type, signature,
// trailing closing brace. The emitter's signature line carries
// type-inference results that drift between builds (the signature
// might be `u64` in one build and `double` in another for the same
// function); ignoring it focuses the hash on the actual code.
[[nodiscard]] std::string_view body_only(std::string_view src) noexcept {
    auto first = src.find('{');
    if (first == std::string_view::npos) return src;
    auto last = src.rfind('}');
    if (last == std::string_view::npos || last <= first) return src;
    return src.substr(first + 1, last - first - 1);
}

// One pass, emits one u64 per canonical token into `out`.
void tokenize_canonical(std::string_view src, std::vector<u64>& out) {
    out.clear();
    out.reserve(src.size() / 4);
    std::unordered_map<std::string, u64> alpha;  // local-name → renamed hash

    auto rename = [&](std::string_view name) -> u64 {
        // ID0, ID1, ID2 ... assigned in first-appearance order. The
        // hashes are picked deterministically so the same canonical
        // form across runs produces the same bigrams.
        std::string key(name);
        auto it = alpha.find(key);
        if (it != alpha.end()) return it->second;
        const u64 h = fnv1a("ID") ^ (alpha.size() * 0x9e3779b97f4a7c15ULL);
        alpha.emplace(std::move(key), h);
        return h;
    };

    const std::size_t n = src.size();
    std::size_t i = 0;
    while (i < n) {
        const char c = src[i];
        // ---- whitespace ----
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') { ++i; continue; }
        // ---- line comment ----
        if (c == '/' && i + 1 < n && src[i + 1] == '/') {
            while (i < n && src[i] != '\n') ++i;
            continue;
        }
        // ---- hex literal ----
        if (c == '0' && i + 1 < n && (src[i + 1] == 'x' || src[i + 1] == 'X')) {
            std::size_t j = i + 2;
            while (j < n && (std::isxdigit(static_cast<unsigned char>(src[j])))) ++j;
            const u64 v = parse_hex_literal(src.substr(i + 2, j - i - 2));
            out.push_back(literal_class(v));
            i = j;
            continue;
        }
        // ---- decimal literal ----
        if (c >= '0' && c <= '9') {
            std::size_t j = i;
            while (j < n && src[j] >= '0' && src[j] <= '9') ++j;
            const u64 v = parse_decimal_literal(src.substr(i, j - i));
            out.push_back(literal_class(v));
            i = j;
            continue;
        }
        // ---- identifier / keyword ----
        if (is_identifier_start(c)) {
            std::size_t j = i + 1;
            while (j < n && is_identifier_cont(src[j])) ++j;
            std::string_view ident = src.substr(i, j - i);
            i = j;
            if (starts_with(ident, "r_sub_")) { out.push_back(kClassCallRet); continue; }
            if (starts_with(ident, "sub_"))   { out.push_back(kClassCallee);  continue; }
            if (is_kept_keyword(ident)) {
                out.push_back(fnv1a(ident));
                continue;
            }
            if (is_temp_ident(ident)) {
                out.push_back(rename(ident));
                continue;
            }
            // Any other identifier (callee name, type, struct field,
            // extern global) is an anchor — preserve verbatim. This is
            // exactly the cross-version stable signal: sigs don't
            // shift just because the compiler renumbered SSA temps.
            out.push_back(fnv1a(ident));
            continue;
        }
        // ---- punctuation ----
        // Group runs of operator characters (e.g. `>>=`, `<<`, `==`)
        // so that the bigram hash sees them as one token.
        constexpr std::string_view ops = "+-*/%&|^~!<>=?:.";
        if (ops.find(c) != std::string_view::npos) {
            std::size_t j = i + 1;
            while (j < n && ops.find(src[j]) != std::string_view::npos) ++j;
            out.push_back(fnv1a(src.substr(i, j - i)));
            i = j;
            continue;
        }
        if (c == '{' || c == '}' || c == '(' || c == ')' ||
            c == '[' || c == ']' || c == ',' || c == ';') {
            out.push_back(fnv1a(std::string_view{&src[i], 1}));
            ++i;
            continue;
        }
        // ---- unknown byte — skip ----
        ++i;
    }
}

// MinHash sketch over the bigram set. Standard construction: for each
// of K hash functions, store the minimum hash value across the bigram
// set. Two sketches' Jaccard ≈ fraction of positions where minimums
// match. K=8 is at the lower end of useful (precision ~12% on Jaccard
// estimate) but compact enough to fit in the existing fingerprint
// row; matchers wanting tighter precision can use the exact_hash for
// the high-confidence path.
constexpr std::size_t kMinHashSlots = 8;

[[nodiscard]] std::array<u64, kMinHashSlots>
minhash_bigrams(const std::vector<u64>& tokens) noexcept {
    std::array<u64, kMinHashSlots> mh;
    mh.fill(std::numeric_limits<u64>::max());
    if (tokens.size() < 2) return mh;
    for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
        const u64 b = bigram_hash(tokens[i], tokens[i + 1]);
        for (std::size_t k = 0; k < kMinHashSlots; ++k) {
            // Per-slot deterministic hash perturbation. mix64 with a
            // slot-specific salt gives K independent hash families.
            const u64 hk = mix64(b, fnv1a(kTeefSchema) + k * 0x9e3779b97f4a7c15ULL);
            if (hk < mh[k]) mh[k] = hk;
        }
    }
    return mh;
}

[[nodiscard]] u64 exact_token_stream_hash(const std::vector<u64>& tokens) noexcept {
    u64 h = fnv1a(kTeefSchema);
    for (u64 t : tokens) h = mix64(h, t);
    return h;
}

}  // namespace

float jaccard_estimate(const TeefSig& a, const TeefSig& b) noexcept {
    if (a.exact_hash == 0 || b.exact_hash == 0) return 0.0f;
    if (a.exact_hash == b.exact_hash) return 1.0f;
    int eq = 0;
    for (std::size_t i = 0; i < kMinHashSlots; ++i) {
        if (a.minhash[i] == b.minhash[i]) ++eq;
    }
    return static_cast<float>(eq) / static_cast<float>(kMinHashSlots);
}

TeefSig teef_from_pseudo_c(std::string_view pseudo_c) {
    TeefSig out;
    if (pseudo_c.empty()) return out;
    std::vector<u64> tokens;
    tokenize_canonical(body_only(pseudo_c), tokens);
    if (tokens.empty()) return out;
    out.exact_hash = exact_token_stream_hash(tokens);
    out.minhash    = minhash_bigrams(tokens);
    return out;
}

// ---- Direct IR-walking TEEF ----------------------------------------
//
// The text-based path (lift → structure → emit pseudo-C → tokenize the
// string → hash) was bottlenecked on the emitter's recursive expression
// inliner and std::format calls — profiling showed those alone took
// >70% of compute time. Since the canonical hash doesn't actually need
// the string, we skip the emitter and walk the structured IR directly,
// hashing canonical tokens straight into the bigram stream.
//
// Token alphabet (one u64 each):
//   • Region kinds (Block, Seq, IfThen, IfElse, While, ...) — fixed
//     per-RegionKind hash, plus structural delimiters.
//   • IR opcode names from op_name(IrOp).
//   • Operand classes:
//       Reg  → alpha-rename(canonical_reg, version)
//       Temp → alpha-rename(temp_id)
//       Imm  → SMI / MEDI / ADDR / literal-as-string for v<16
//       Flag → flag name verbatim
//   • Anchor names (callee names, intrinsic names, import targets) —
//     fnv1a of the verbatim string, kept across canonicalization.

namespace {

constexpr std::array<u64, 14> kRegionKindHashes = {
    fnv1a("R/Empty"),       fnv1a("R/Block"),       fnv1a("R/Seq"),
    fnv1a("R/IfThen"),      fnv1a("R/IfElse"),      fnv1a("R/While"),
    fnv1a("R/DoWhile"),     fnv1a("R/For"),         fnv1a("R/Loop"),
    fnv1a("R/Switch"),      fnv1a("R/Return"),      fnv1a("R/Unreachable"),
    fnv1a("R/Break"),       fnv1a("R/Continue"),
};
constexpr u64 kRegionGoto      = fnv1a("R/Goto");
constexpr u64 kRegionOpen      = fnv1a("{");
constexpr u64 kRegionClose     = fnv1a("}");
constexpr u64 kCondTok         = fnv1a("?");
constexpr u64 kInvertTok       = fnv1a("!");
constexpr u64 kIntrinsicTok    = fnv1a("INTRINSIC");
constexpr u64 kFlagTok         = fnv1a("FLAG");

struct IrTokenizer {
    std::vector<u64>& out;
    const Binary&     bin;
    std::unordered_map<u64, u64> reg_alpha;   // (reg<<32 | version) → ID hash
    std::unordered_map<u32, u64> temp_alpha;  // temp_id → ID hash
    std::size_t next_alpha = 0;

    IrTokenizer(std::vector<u64>& o, const Binary& b) : out(o), bin(b) {}

    // Resolve an absolute VA to a stable name token. Try in order:
    //   PLT slot → import name (call sites)
    //   GOT slot → import name (the per-instance global pointer family
    //     — __ctype_b_loc, __errno_location, __h_errno_location all
    //     read distinct GOT slots that resolve to distinct symbols)
    //   defined object → its symbol name (rip-rel global accesses)
    //   nothing matches → ADDR class
    [[nodiscard]] u64 resolve_addr_token(addr_t a) const noexcept {
        if (const auto* imp = bin.import_at_plt(a); imp && !imp->name.empty()) {
            return fnv1a(imp->name);
        }
        if (const auto* imp = bin.import_at_got(a); imp && !imp->name.empty()) {
            return fnv1a(imp->name);
        }
        if (const auto* sym = bin.defined_object_at(a); sym && !sym->name.empty()) {
            return fnv1a(sym->name);
        }
        return kClassAddr;
    }

    [[nodiscard]] u64 alpha(u64 key, std::unordered_map<u64, u64>& map) {
        auto it = map.find(key);
        if (it != map.end()) return it->second;
        const u64 h = fnv1a("ID") ^ (next_alpha++ * 0x9e3779b97f4a7c15ULL);
        map.emplace(key, h);
        return h;
    }

    void emit_value(const IrValue& v) {
        // Type tag: i1, i8, ..., i64, f32/f64. Distinguishes operand
        // shapes — `Add i32` (likely an int) hashes differently from
        // `Add i64` (likely a pointer offset).
        out.push_back(fnv1a(type_name(v.type)));
        switch (v.kind) {
            case IrValueKind::None:
                out.push_back(fnv1a("none"));
                return;
            case IrValueKind::Reg: {
                const u64 key = (static_cast<u64>(v.reg) << 32)
                              | static_cast<u64>(v.version);
                out.push_back(alpha(key, reg_alpha));
                return;
            }
            case IrValueKind::Temp: {
                u64 key = 0;
                auto it = temp_alpha.find(v.temp);
                if (it == temp_alpha.end()) {
                    key = fnv1a("ID") ^ (next_alpha++ * 0x9e3779b97f4a7c15ULL);
                    temp_alpha.emplace(v.temp, key);
                } else {
                    key = it->second;
                }
                out.push_back(key);
                return;
            }
            case IrValueKind::Imm: {
                const u64 u = static_cast<u64>(v.imm);
                if (u > 0x10000u) {
                    out.push_back(resolve_addr_token(static_cast<addr_t>(u)));
                } else {
                    out.push_back(literal_class(u));
                }
                return;
            }
            case IrValueKind::Flag:
                out.push_back(kFlagTok);
                out.push_back(fnv1a(flag_name(v.flag)));
                return;
        }
    }

    void emit_inst(const IrInst& inst) {
        if (inst.op == IrOp::Nop) return;
        out.push_back(fnv1a(op_name(inst.op)));
        // Segment-prefixed loads/stores (fs:[..] for TLS, gs:[..] for
        // PEB) are distinguishing signal — `read TLS canary` vs `read
        // ordinary global` look the same opcode-wise but the segment
        // tags them apart.
        if (inst.segment != Reg::None) {
            out.push_back(fnv1a("seg"));
            out.push_back(fnv1a(reg_name(inst.segment)));
        }
        if (inst.op == IrOp::Call) {
            // Anchor weighting: a call to a NAMED import/symbol is far
            // stronger fingerprint signal than the surrounding alpha-
            // renamed reg arithmetic. A function calling malloc + free
            // + memcpy has a more discriminating identity than two
            // unrelated functions sharing some random reg-arith
            // patterns. Repeat the resolved-name token 3x in the
            // stream so it dominates both the exact hash and the
            // bigram-derived MinHash. Unresolved (kClassAddr) calls
            // get a single token as before — no weighting boost when
            // we can't tell what's being called.
            const u64 t = resolve_addr_token(inst.target1);
            out.push_back(t);
            if (t != kClassAddr) {
                out.push_back(t);
                out.push_back(t);
            }
        } else if (inst.op == IrOp::Intrinsic && !inst.name.empty()) {
            // Intrinsic names (cpuid, rdtsc, syscall, x64.lock, etc) are
            // also strong anchors — same 3x weighting.
            const u64 nameTok = fnv1a(inst.name);
            out.push_back(kIntrinsicTok);
            out.push_back(nameTok);
            out.push_back(nameTok);
            out.push_back(nameTok);
        }
        if (inst.dst.kind != IrValueKind::None) emit_value(inst.dst);
        for (u8 i = 0; i < inst.src_count; ++i) emit_value(inst.srcs[i]);
    }
};

void emit_block_tokens(IrTokenizer& t, const IrFunction& fn, addr_t block_addr) {
    auto it = fn.block_at.find(block_addr);
    if (it == fn.block_at.end()) return;
    const IrBlock& bb = fn.blocks[it->second];
    for (const auto& inst : bb.insts) t.emit_inst(inst);
}

// (kept for future use; emit_region_tokens references it)

void emit_region_tokens(IrTokenizer& t, const IrFunction& fn, const Region& r) {
    if (r.kind == RegionKind::Goto) {
        t.out.push_back(kRegionGoto);
        return;
    }
    const std::size_t k = static_cast<std::size_t>(r.kind);
    if (k < kRegionKindHashes.size()) {
        t.out.push_back(kRegionKindHashes[k]);
    } else {
        t.out.push_back(fnv1a("R/?"));
    }
    if (r.kind == RegionKind::Block) {
        emit_block_tokens(t, fn, r.block_start);
        return;
    }
    if (r.kind == RegionKind::IfThen   || r.kind == RegionKind::IfElse ||
        r.kind == RegionKind::While    || r.kind == RegionKind::DoWhile ||
        r.kind == RegionKind::For) {
        t.out.push_back(kCondTok);
        if (r.invert) t.out.push_back(kInvertTok);
        t.emit_value(r.condition);
    }
    t.out.push_back(kRegionOpen);
    for (const auto& child : r.children) {
        if (child) emit_region_tokens(t, fn, *child);
    }
    t.out.push_back(kRegionClose);
}

}  // namespace

namespace {

// Sum the IR instructions in a region's subtree (excluding Nops). Used
// to threshold which chunks are worth fingerprinting; tiny regions are
// not identifying.
[[nodiscard]] u32 subtree_insts(const IrFunction& fn, const Region& r) {
    u32 total = 0;
    if (r.kind == RegionKind::Block) {
        if (auto it = fn.block_at.find(r.block_start); it != fn.block_at.end()) {
            for (const auto& ins : fn.blocks[it->second].insts) {
                if (ins.op != IrOp::Nop) ++total;
            }
        }
    }
    for (const auto& c : r.children) {
        if (c) total += subtree_insts(fn, *c);
    }
    return total;
}

// Compute a fresh TeefSig over just `r`'s subtree. Each call uses its
// own IrTokenizer, so the alpha-rename map is independent — this is
// the whole point: a chunk hashes the same regardless of where in
// its parent it sits.
[[nodiscard]] TeefSig sig_for_region(const Binary& b, const IrFunction& fn,
                                     const Region& r) {
    std::vector<u64> tokens;
    IrTokenizer t(tokens, b);
    emit_region_tokens(t, fn, r);
    TeefSig s;
    if (!tokens.empty()) {
        s.exact_hash = exact_token_stream_hash(tokens);
        s.minhash    = minhash_bigrams(tokens);
    }
    return s;
}

// Region kinds worth fingerprinting as standalone chunks. The big-fn
// recovery case (huge bucket on glibc 2.35→2.39) requires more than
// just nested control-flow regions: long state-machine arms are flat
// Seq / Block regions, but if they're big enough they're highly
// identifying. So we accept Seq / Block too, with the size threshold
// (collect_chunks's min_insts gate) doing the actual filtering. Goto
// / Return / Continue / Break / Empty stay excluded — they're
// terminators with no meaningful body.
[[nodiscard]] bool is_chunkable_kind(RegionKind k) noexcept {
    switch (k) {
        case RegionKind::IfThen:
        case RegionKind::IfElse:
        case RegionKind::While:
        case RegionKind::DoWhile:
        case RegionKind::For:
        case RegionKind::Loop:
        case RegionKind::Switch:
        case RegionKind::Seq:
        case RegionKind::Block:
            return true;
        default:
            return false;
    }
}

void collect_chunks(const Binary& b, const IrFunction& fn, const Region& r,
                    u32 min_insts, bool is_root,
                    std::vector<TeefChunk>& out) {
    const u32 sz = subtree_insts(fn, r);
    if (!is_root && is_chunkable_kind(r.kind) && sz >= min_insts) {
        TeefChunk ch;
        ch.sig        = sig_for_region(b, fn, r);
        ch.inst_count = sz;
        ch.kind       = static_cast<u8>(r.kind);
        if (ch.sig.exact_hash != 0) out.push_back(ch);
    }
    for (const auto& c : r.children) {
        if (c) collect_chunks(b, fn, *c, min_insts, false, out);
    }
}

}  // namespace

TeefFunction
compute_teef_with_chunks(const Binary& b, addr_t fn_start, u32 min_chunk_insts) {
    TeefFunction out;

    auto dec_r = make_decoder(b);
    if (!dec_r) return out;
    const CfgBuilder cfg(b, **dec_r);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return out;

    auto lifter_r = make_lifter(b);
    if (!lifter_r) return out;
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return out;

    // ---- L0 topology hash ----
    // Computed from the fresh-lifted IR (pre-SSA, pre-cleanup) so the
    // shape we hash is the one the recognizer's pre-filter will see
    // for query fns too. Features:
    //   • num_blocks  — coarse size signal
    //   • num_edges   — sum of successors over all blocks
    //   • max_in_degree, max_out_degree — branching density
    //   • num_loop_headers — blocks with > 1 predecessor (proxy for loops
    //     and re-entry points; cleanup-stable)
    //   • num_returns — blocks whose terminator is Return
    // Each is folded with mix64; final u64 is the topo hash. Two
    // structurally-identical CFGs collide → recognizer can pre-filter on
    // it. Compiler diversity that adds/removes a block (e.g. an extra
    // cleanup or split-block from optimization) shifts the hash and the
    // pre-filter misses, but the recognizer falls through to the full
    // scan automatically — so this is lossy for perf, not correctness.
    {
        u32 num_blocks       = static_cast<u32>(ir_r->blocks.size());
        u32 num_edges        = 0;
        u32 max_in_degree    = 0;
        u32 max_out_degree   = 0;
        u32 num_loop_headers = 0;
        u32 num_returns      = 0;
        for (const auto& bb : ir_r->blocks) {
            num_edges      += static_cast<u32>(bb.successors.size());
            max_in_degree   = std::max<u32>(max_in_degree,
                                            static_cast<u32>(bb.predecessors.size()));
            max_out_degree  = std::max<u32>(max_out_degree,
                                            static_cast<u32>(bb.successors.size()));
            if (bb.predecessors.size() > 1) ++num_loop_headers;
            if (!bb.insts.empty() && bb.insts.back().op == IrOp::Return) ++num_returns;
        }
        u64 h = fnv1a("topo");
        h = mix64(h, num_blocks);
        h = mix64(h, num_edges);
        h = mix64(h, max_in_degree);
        h = mix64(h, max_out_degree);
        h = mix64(h, num_loop_headers);
        h = mix64(h, num_returns);
        out.topo_hash = h;
    }

    // Insn-count gate. VMP / Themida / Enigma protected code expands
    // every original fn into tens of thousands of junk-injected,
    // deeply nested regions; TEEF's region-tree walk is roughly
    // O(insns × region_depth), so a single 50k-insn fn dominates a
    // parallel matcha sweep for 30+ minutes while the other 11999
    // matcha fns sit done. Bail before SSA when the lifted IR is
    // already past the budget — emit an empty `out` so the recognizer
    // treats the fn as "no fingerprint, fall through to LLM-only
    // naming". Override via EMBER_TEEF_MAX_INSNS for users who want
    // to spend the time on a heavily-protected target.
    static const std::size_t kMaxInsnsPerFn = []() -> std::size_t {
        if (const char* s = std::getenv("EMBER_TEEF_MAX_INSNS")) {
            try { return static_cast<std::size_t>(std::stoull(s)); }
            catch (...) { /* malformed → fall through to default */ }
        }
        return 4096;     // a normal fn is ~50–500 insns; 4k handles aggressive inlining
    }();
    {
        std::size_t total = 0;
        for (const auto& bb : ir_r->blocks) total += bb.insts.size();
        if (total > kMaxInsnsPerFn) return out;
    }

    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return out;
    if (auto rv = run_cleanup(*ir_r); !rv) return out;

    const Structurer s;
    auto sf = s.structure(*ir_r);
    if (!sf || !sf->body) return out;

    out.whole = sig_for_region(b, *ir_r, *sf->body);
    if (out.whole.exact_hash == 0) return out;

    collect_chunks(b, *ir_r, *sf->body, min_chunk_insts,
                   /*is_root=*/true, out.chunks);
    std::sort(out.chunks.begin(), out.chunks.end(),
              [](const TeefChunk& x, const TeefChunk& y) {
                  return x.inst_count > y.inst_count;
              });
    return out;
}

TeefSig compute_teef(const Binary& b, addr_t fn_start) {
    return compute_teef_with_chunks(b, fn_start, /*min_chunk_insts=*/10).whole;
}

}  // namespace ember
