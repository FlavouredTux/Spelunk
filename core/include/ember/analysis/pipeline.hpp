#pragma once

#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

#include <ember/analysis/fingerprint.hpp>
#include <ember/analysis/function.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/annotations.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/decompile/emit_options.hpp>

namespace ember {

struct FuncWindow {
    addr_t      start = 0;
    u64         size  = 0;   // 0 when unknown; formatters fall back to terminator
    std::string label;
};

// Resolve a `-s NAME` token: `-[Class sel]` / `+[Class sel]`, then a
// hex VA or `sub_<hex>`, then the symbol table, then (with `ann`) a
// rename from the annotations file. An ambiguous rename is rejected
// like an ambiguous symbol; pass the VA instead.
std::optional<FuncWindow>
resolve_function(const Binary& b, std::string_view symbol,
                 const Annotations* ann = nullptr);

std::optional<FuncWindow>
resolve_function_at(const Binary& b, addr_t addr);

// Optional knobs for `format_disasm`.
struct DisasmOptions {
    // Callers to list in the `;   xrefs from:` header. Unset: compute them
    // with `compute_callers`, which costs one whole-program call-graph
    // walk per call. Set: use as-is; an empty span omits the header.
    // Interactive front ends build the graph once per session and pass
    // the slice for this function here.
    std::optional<std::span<const addr_t>> callers;
};

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w);

Result<std::string>
format_disasm(const Binary& b, const FuncWindow& w, const DisasmOptions& opts);

Result<std::string>
format_disasm_range(const Binary& b, addr_t start, addr_t end);

Result<std::string>
format_cfg(const Binary& b, const FuncWindow& w);

// CFG view with each block's body rendered as pseudo-C statements
// (PseudoCEmitter::emit_per_block) instead of raw disasm. Output uses
// the same `bb_<addr>:` / `-> bb_xxx (label)` framing as `format_cfg`
// so a single CFG parser handles both modes - only the body lines
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
enum class CallGraphMode : u8 {
    FullCfg,  // exact historical path: build a CFG per function
    Fast,     // linear x86-64 edge scan for whole-program xrefs/fingerprints
};
// `scope`, when non-empty, restricts edge construction to callers in
// the set - the work list is intersected with `scope` before lifting,
// so a single-function CLI invocation pays only for its function
// instead of every function in the binary. Empty span = whole program
// (the back-compat default). Edges to callees outside `scope` are
// still emitted; only the *caller* side is filtered.
std::vector<CallEdge> compute_call_graph(const Binary& b,
                                         std::span<const addr_t> scope = {},
                                         CallGraphMode mode = CallGraphMode::FullCfg);
std::vector<addr_t>   compute_callees(const Binary& b, addr_t fn);
std::vector<addr_t>   compute_callers(const Binary& b, addr_t fn);

// A function entry the decompiler can walk from: either a defined
// function symbol, or a call target the CFG builder discovered at
// another function's call site (classic stripped-binary `sub_*`).
// `size` comes from the symbol table when available; otherwise it is estimated
// from the gap to the next discovered function (or section boundary) so that
// downstream tools (fingerprints, xrefs, size filters) still work on sparse or
// stripped symbol metadata.
struct DiscoveredFunction {
    enum class Kind : u8 { Symbol, Sub };
    addr_t      addr = 0;
    u64         size = 0;
    std::string name;
    Kind        kind = Kind::Sub;
};

// Stack block literals synthesized inside Obj-C methods do not appear in
// __block_literal metadata. This is the recovered surface for their invoke
// functions plus capture names inferred from the parent method's stores.
struct ObjcStackBlockInvoke {
    addr_t                invoke = 0;
    std::string           name;
    std::map<u64, std::string> captures;
    std::string           captured_self_class;
};

[[nodiscard]] std::vector<ObjcStackBlockInvoke>
discover_objc_stack_block_invokes(const Binary& b);

[[nodiscard]] constexpr std::string_view
discovered_kind_name(DiscoveredFunction::Kind k) noexcept {
    switch (k) {
        case DiscoveredFunction::Kind::Symbol: return "symbol";
        case DiscoveredFunction::Kind::Sub:    return "sub";
    }
    return "?";
}

// Auto: skip the CFG-walked pass on packed binaries (it only chases
// imm32s through encrypted stubs) and drop call targets that land in
// high-entropy sections. Full: walk everything (the indirect-call
// resolver). Cheap: skip the CFG walk unconditionally, for per-function
// CLI views that only need to map a VA to its enclosing function.
enum class EnumerateMode { Auto, Full, Cheap };

// Defined function symbols plus CFG-discovered call targets, deduped
// and sorted; PLT stubs excluded. Backs both `--functions` and the
// scripting `binary.functions()`. When `hi > lo`, every pass is
// restricted to [lo, hi) (`--module` on minidumps); the prologue sweep
// clips its byte range per section.
[[nodiscard]] std::vector<DiscoveredFunction>
enumerate_functions(const Binary& b, EnumerateMode m = EnumerateMode::Auto,
                    addr_t lo = 0, addr_t hi = 0);

// Per-call edge classification used by `ember --callees`. `Direct` covers
// `call <imm>`; `Tail` covers an unconditional `jmp` whose target is a
// known function entry (defined symbol or PLT stub); `IndirectConst`
// covers `call qword ptr [rip + disp]` where the dereferenced 8 bytes
// resolve to an executable address (vtable/IAT/RTTI thunk patterns).
// Genuinely opaque indirect calls are dropped - by design the primitive
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

// Every address carrying `name`, plus byte-similar lookalikes the
// caller should check before trusting one of them. "Byte-similar" is
// equality on the (blocks, insts, calls) shape counters; the FNV
// content hash has no useful distance. This catches cxa_guard getters,
// shared_ptr release stubs and OTLP method bodies that resolve to the
// wrong twin.
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
// `--fingerprints` TSV - the killer perf path on 100MB+ binaries with
// 500K+ functions where re-fingerprinting every callsite costs minutes.
struct FingerprintRow {
    addr_t              addr = 0;
    FunctionFingerprint fp;
    std::string         name;   // symbol name or `sub_<hex>` fallback
};

// `precomputed`: optional snapshot of every function's fingerprint. When
// non-empty, used as the authoritative shape index - no compute_fingerprint
// or enumerate_functions calls happen in the hot path. When empty (the
// default), the function falls back to walking enumerate_functions and
// fingerprinting each entry, matching the original v1 behaviour.
[[nodiscard]] NameValidation
validate_name(const Binary& b, std::string_view name,
              std::span<const FingerprintRow> precomputed = {});

// Ambiguity that would silently mis-resolve a name or fingerprint:
//   by_name         symbol names bound to more than one non-import
//                   address (a fingerprint import that hit twice, a
//                   hand rename aliasing a stub)
//   by_fingerprint  distinct functions with the same content hash;
//                   importing a name keyed on it hits the wrong twin
// `by_name` sorts lexicographically, `by_fingerprint` by first
// address; each group's `addrs` ascends.
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

// Outgoing direct call / tail / indirect-const edges of the function at
// `fn`, sorted by target and deduped on (target, kind); empty when `fn`
// does not decode. `call [reg + disp]` resolves to a vtable slot when
// the same block loaded `reg` from a known Itanium vtable; no
// cross-block tracking.
[[nodiscard]] std::vector<ClassifiedCallee>
compute_classified_callees(const Binary& b, addr_t fn,
                           const std::unordered_set<addr_t>* known_entries = nullptr);

// Per-call-site resolution of the function at `fn`. Returns the subset
// of classified-callee edges keyed by call-site VA, so a renderer can
// answer "what does this specific `call [rax+0x38]` actually invoke?"
// in O(log n). Missing entries mean the edge was genuinely opaque -
// callers should NOT assume every CallIndirect has a resolution.
[[nodiscard]] std::map<addr_t /*site*/, addr_t /*target*/>
compute_call_resolutions(const Binary& b, addr_t fn,
                         const std::unordered_set<addr_t>* known_entries = nullptr);

}  // namespace ember
