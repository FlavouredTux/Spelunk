#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

// Walk the CFG of the function at `fn` and return its outgoing direct
// call/tail/indirect-const edges. Sorted by target VA, deduped on
// (target, kind) pairs. Empty when `fn` is not a decodable function.
[[nodiscard]] std::vector<ClassifiedCallee>
compute_classified_callees(const Binary& b, addr_t fn);

}  // namespace ember
