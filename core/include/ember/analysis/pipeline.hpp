#pragma once

#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/decompile/emitter.hpp>

namespace ember {

struct FuncWindow {
    addr_t      start = 0;
    u64         size  = 0;   // 0 when unknown; formatters fall back to terminator
    std::string label;
};

std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol);

std::optional<FuncWindow>
resolve_function_at(const Binary& b, addr_t addr);

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w);

Result<std::string>
format_disasm_range(const Binary& b, addr_t start, addr_t end);

Result<std::string>
format_cfg(const Binary& b, const FuncWindow& w);

// CFG view with each block's body rendered as pseudo-C statements
// (PseudoCEmitter::emit_per_block) instead of raw disasm. Output uses
// the same `bb_<addr>:` / `-> bb_xxx (label)` framing as `format_cfg`
// so a single CFG parser handles both modes — only the body lines
// differ. Annotations / hash-name / RTTI / Win64-vs-SysV ABI all flow
// through the same way they do for `format_struct`.
Result<std::string>
format_cfg_pseudo(const Binary& b, const FuncWindow& w,
                  const Annotations* ann = nullptr,
                  EmitOptions options = {});

Result<std::string>
format_struct(const Binary& b, const FuncWindow& w,
              bool pseudo, const Annotations* ann,
              EmitOptions options = {});

struct CallEdge { addr_t caller = 0; addr_t callee = 0; };
std::vector<CallEdge> compute_call_graph(const Binary& b);
std::vector<addr_t>   compute_callees(const Binary& b, addr_t fn);
std::vector<addr_t>   compute_callers(const Binary& b, addr_t fn);

// A function entry the decompiler can walk from: either a defined
// function symbol, or a call target the CFG builder discovered at
// another function's call site (classic stripped-binary `sub_*`).
// `size` comes from the symbol table when kind == Symbol; for Sub
// entries it's left 0 because determining the extent requires building
// the CFG, which `enumerate_functions` intentionally doesn't do.
struct DiscoveredFunction {
    enum class Kind : u8 { Symbol, Sub };
    addr_t      addr = 0;
    u64         size = 0;
    std::string name;
    Kind        kind = Kind::Sub;
};

[[nodiscard]] constexpr std::string_view
discovered_kind_name(DiscoveredFunction::Kind k) noexcept {
    switch (k) {
        case DiscoveredFunction::Kind::Symbol: return "symbol";
        case DiscoveredFunction::Kind::Sub:    return "sub";
    }
    return "?";
}

// Union of defined function symbols and CFG-discovered call targets,
// deduplicated and sorted by address. PLT stubs are excluded — they're
// import thunks, not definitions. Shared by the scripting binding
// (`binary.functions()`) and the `--functions` CLI output so both stay
// in sync.
[[nodiscard]] std::vector<DiscoveredFunction>
enumerate_functions(const Binary& b);

// Per-call edge classification used by `ember --callees`. `Direct` covers
// `call <imm>`; `Tail` covers an unconditional `jmp` whose target is a
// known function entry (defined symbol or PLT stub); `IndirectConst`
// covers `call qword ptr [rip + disp]` where the dereferenced 8 bytes
// resolve to an executable address (vtable/IAT/RTTI thunk patterns).
// Genuinely opaque indirect calls are dropped — by design the primitive
// only emits edges with a concrete callee VA.
enum class CalleeKind : u8 { Direct, Tail, IndirectConst };

[[nodiscard]] constexpr std::string_view callee_kind_name(CalleeKind k) noexcept {
    switch (k) {
        case CalleeKind::Direct:        return "direct";
        case CalleeKind::Tail:          return "tail";
        case CalleeKind::IndirectConst: return "indirect_const";
    }
    return "?";
}

struct ClassifiedCallee {
    addr_t     target = 0;
    CalleeKind kind   = CalleeKind::Direct;
    // Source instruction VA (the call/jmp site). Useful when downstream
    // tooling wants to back-reference the edge to a specific opcode.
    addr_t     site   = 0;
};

// Resolve an address to the function whose extent contains it. Uses
// the union of defined function symbols + CFG-discovered `sub_*`
// entries (i.e. `enumerate_functions`), sorted by start, and binary-
// searches for the largest start ≤ `addr`. Nullopt when nothing covers
// `addr` or the enclosing function is a PLT stub / has no bytes
// mapped.
struct ContainingFn {
    addr_t      entry         = 0;
    u64         size          = 0;   // 0 when unknown
    std::string name;
    u64         offset_within = 0;   // addr - entry
};

[[nodiscard]] std::optional<ContainingFn>
containing_function(const Binary& b, addr_t addr);

// Disambiguate a name lookup. Tonight's "wrong VA" hours all came from
// `find_by_name` returning one address while a near-identical function
// elsewhere matched the user's mental model. `validate_name` reports
// every address that carries `name` plus the byte-similar candidates the
// caller should sanity-check before trusting any one of them.
//
// "Byte-similar" is tuple equality on (blocks, insts, calls). FNV-1a is
// binary equality only — no useful Hamming distance — so the shape
// counters from FunctionFingerprint are the disambiguator. Cheap (one
// pass over the function set) and surfaces exactly the lookalikes that
// caused the recurring confusion (cxa_guard getters, shared_ptr
// release stubs, OTLP method bodies).
struct NameValidation {
    enum class Verdict : u8 {
        Strong,    // single bound, no near-matches → safe to use
        Weak,      // single bound but N functions share the same shape
        Ambiguous, // name resolves to multiple addresses
        Unknown,   // name has no defined symbol
    };

    struct NearMatch {
        addr_t              addr = 0;
        FunctionFingerprint fp;
        std::string         name;   // symbol name or `sub_<hex>` fallback
    };

    std::vector<addr_t>              bound;        // every non-import addr carrying `name`
    std::vector<FunctionFingerprint> fps;          // 1:1 with `bound`; 0-hash if addr is not a fn entry
    std::vector<u64>                 offsets;      // 1:1 with `bound`; offset within enclosing fn (0 if entry)
    std::vector<NearMatch>           near_matches; // shape-tuple twins with a different hash
    Verdict                          verdict = Verdict::Unknown;
};

[[nodiscard]] constexpr std::string_view
verdict_name(NameValidation::Verdict v) noexcept {
    switch (v) {
        case NameValidation::Verdict::Strong:    return "STRONG";
        case NameValidation::Verdict::Weak:      return "WEAK";
        case NameValidation::Verdict::Ambiguous: return "AMBIGUOUS";
        case NameValidation::Verdict::Unknown:   return "UNKNOWN";
    }
    return "?";
}

// One row of an externally-supplied fingerprint table. Threading this
// through validate_name / collect_collisions lets the CLI (or any other
// caller) skip the per-fn lift+SSA pipeline by reading from the cached
// `--fingerprints` TSV — the killer perf path on 100MB+ binaries with
// 500K+ functions where re-fingerprinting every callsite costs minutes.
struct FingerprintRow {
    addr_t              addr = 0;
    FunctionFingerprint fp;
    std::string         name;   // symbol name or `sub_<hex>` fallback
};

// `precomputed`: optional snapshot of every function's fingerprint. When
// non-empty, used as the authoritative shape index — no compute_fingerprint
// or enumerate_functions calls happen in the hot path. When empty (the
// default), the function falls back to walking enumerate_functions and
// fingerprinting each entry, matching the original v1 behaviour.
[[nodiscard]] NameValidation
validate_name(const Binary& b, std::string_view name,
              std::span<const FingerprintRow> precomputed = {});

// Sweep the binary for ambiguity that would silently mis-resolve a name
// or fingerprint lookup downstream. Two flavours:
//
//   by_name        — symbol-table names bound to >1 non-import address
//                    (typically a fingerprint-import that hit twice, or
//                    a hand rename that aliased a stub).
//   by_fingerprint — distinct functions whose content hash collides.
//                    These are the false-positive risks for a name DB:
//                    importing a name keyed on this fingerprint will
//                    apply to the wrong twin half the time.
//
// Both vectors are sorted: `by_name` lexicographically, `by_fingerprint`
// by address of the first member. Each group's `addrs` is sorted ascending.
struct NameCollision {
    std::string         name;
    std::vector<addr_t> addrs;
};

struct FingerprintCollision {
    u64                 hash = 0;
    std::vector<addr_t> addrs;
};

struct Collisions {
    std::vector<NameCollision>        by_name;
    std::vector<FingerprintCollision> by_fingerprint;
};

[[nodiscard]] Collisions
collect_collisions(const Binary& b,
                   std::span<const FingerprintRow> precomputed = {});

// Walk the CFG of the function at `fn` and return its outgoing direct
// call/tail/indirect-const edges. Sorted by target VA, deduped on
// (target, kind) pairs. Empty when `fn` is not a decodable function.
//
// Vtable back-trace: `call [reg + disp]` is resolved when preceded
// (within the same basic block) by a `mov reg, [rip + k]` whose target
// is a known Itanium vtable base. The edge is emitted as IndirectConst
// with `target` set to the slot's IMP. Cross-block tracking is
// intentionally out of scope — a register redef on a join path would
// produce misleading resolutions without flow analysis.
[[nodiscard]] std::vector<ClassifiedCallee>
compute_classified_callees(const Binary& b, addr_t fn);

// Per-call-site resolution of the function at `fn`. Returns the subset
// of classified-callee edges keyed by call-site VA, so a renderer can
// answer "what does this specific `call [rax+0x38]` actually invoke?"
// in O(log n). Missing entries mean the edge was genuinely opaque —
// callers should NOT assume every CallIndirect has a resolution.
[[nodiscard]] std::map<addr_t /*site*/, addr_t /*target*/>
compute_call_resolutions(const Binary& b, addr_t fn);

}  // namespace ember
