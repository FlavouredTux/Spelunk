#pragma once

#include <array>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/common/types.hpp>

namespace ember::egraph {

// Bounded e-graph for IR-level equivalence-orbit fingerprinting. The
// e-graph compactly represents a set of expressions equivalent under
// a registered ruleset; saturation enumerates the orbit by applying
// rewrites to fixpoint (or until a node-count budget is hit).
//
// Used by L3 of TEEF Max. Two functions in the
// same compiler-equivalence orbit have e-graphs that, after saturation
// with our compiler-mimicking ruleset, hash to overlapping multisets
// of canonical-form e-class hashes — so MinHash overlap on those
// hashes recovers cross-compiler / cross-flag matches that the
// single-point cleanup-canonical hash (L2) misses.
//
// Design choices:
//   - Op alphabet is a compact subset of IrOp. Algebraically uninteresting
//     ops (Phi/Branch/Call/Load/Store/Clobber) collapse into Opaque
//     carrying a stable id, so they participate in hash-cons but never
//     unify with each other.
//   - Type tag is part of the node identity — Add/i32 doesn't unify
//     with Add/i64. Matches what real compilers do.
//   - Children are ClassIds (after find()), not NodeIds. Hash-cons keys
//     become invalid after merge() and need rebuild() before lookup.
//   - No persistent store. EGraph is per-function and discarded after
//     fingerprint extraction.

using NodeId  = u32;
using ClassId = u32;
inline constexpr NodeId  kNullNode  = static_cast<NodeId>(-1);
inline constexpr ClassId kNullClass = static_cast<ClassId>(-1);

// Compact operator alphabet. Maps loosely onto IrOp; new entries should
// always be added to op_name() too.
enum class Op : u16 {
    // Leaves
    Const,        // imm carries the value
    Var,          // imm carries an alpha-renamed SSA-temp / reg key
    Opaque,       // imm carries a stable hash for an unmodelled value

    // Arithmetic
    Add, Sub, Mul, DivS, DivU, ModS, ModU, Neg,

    // Bitwise
    And, Or, Xor, Not, Shl, LShr, AShr,

    // Comparisons (i1 result)
    CmpEq, CmpNe,
    CmpUlt, CmpUle, CmpUgt, CmpUge,
    CmpSlt, CmpSle, CmpSgt, CmpSge,

    // Casts
    ZExt, SExt, Trunc,

    // Ternary
    Select,
};

[[nodiscard]] std::string_view op_name(Op op) noexcept;

// 8-bit type tag matching the bitwidths/families the orbit cares about.
enum class Type : u8 {
    Any,
    I1, I8, I16, I32, I64, I128,
    F32, F64,
};

[[nodiscard]] std::string_view type_name(Type t) noexcept;

// One e-node. After build, `children` holds canonical (find()) ClassIds.
// Hash-cons collapses identical e-nodes into the same NodeId.
struct ENode {
    Op    op   = Op::Opaque;
    Type  type = Type::Any;
    u8    n_children = 0;
    u8    _pad = 0;
    u64   imm  = 0;       // value for Const, opaque-id for Var/Opaque
    std::array<ClassId, 3> children = {kNullClass, kNullClass, kNullClass};
};

// Public-facing pattern surface for the rewrite engine. Patterns are
// trees of `Pat::*` factory results; placeholders (`Pat::var(name)`)
// match any e-class and bind it to `name`. Limited expressiveness on
// purpose — only what the 6-rule prototype actually needs.
struct Pat {
    enum class Kind : u8 { Var, Const, Op };
    Kind                            kind = Kind::Var;
    Op                              op   = Op::Opaque;
    Type                            type = Type::Any;
    u32                             var_id = 0;       // for Kind::Var
    u64                             imm    = 0;       // for Kind::Const
    std::vector<Pat>                children;         // for Kind::Op

    // ---- Factories ----
    [[nodiscard]] static Pat var(u32 id, Type t = Type::Any);
    [[nodiscard]] static Pat constant(u64 v, Type t);
    [[nodiscard]] static Pat node(Op op, Type t, std::vector<Pat> ch);
};

// Match bindings. Pattern var_id → ClassId.
struct Subst {
    std::array<ClassId, 8> binds{};      // var_id ∈ [0, 8) is enough for our rules
    std::array<bool, 8>    set{};

    [[nodiscard]] bool bind(u32 var_id, ClassId c) noexcept;
    [[nodiscard]] ClassId get(u32 var_id) const noexcept;
};

// A rewrite rule: lhs ⇒ rhs (or bidirectional via two rules). The engine
// finds matches of `lhs` in the e-graph, substitutes the bound vars into
// `rhs`, adds it back, and unions the new class with the matched-root
// class (lhs and rhs are equivalent).
struct Rule {
    std::string_view name;
    Pat              lhs;
    Pat              rhs;
};

class EGraph {
public:
    EGraph();

    // ---- Construction --------------------------------------------------

    // Add or hash-cons an arbitrary node. `n.children` must be valid
    // ClassIds already in the graph (or kNullClass for unused slots).
    [[nodiscard]] ClassId add(ENode n);

    [[nodiscard]] ClassId add_const(Type t, u64 v);
    [[nodiscard]] ClassId add_var(Type t, u64 key);
    [[nodiscard]] ClassId add_opaque(Type t, u64 key);
    [[nodiscard]] ClassId add_unop(Op op, Type t, ClassId a);
    [[nodiscard]] ClassId add_binop(Op op, Type t, ClassId a, ClassId b);
    [[nodiscard]] ClassId add_select(Type t, ClassId cond,
                                     ClassId a, ClassId b);

    // ---- Union-find ---------------------------------------------------

    // Path-compressing find. Safe to call any time.
    [[nodiscard]] ClassId find(ClassId c) const noexcept;

    // Returns true if the two classes were distinct (i.e., an actual merge
    // happened). After any merges, call rebuild() before further matching
    // or hash queries.
    bool merge(ClassId a, ClassId b);

    // ---- Saturation ---------------------------------------------------

    void add_rule(Rule r);

    // Apply registered rules until no merge fires this iteration, or until
    // the iteration / node-count budget is exhausted. Returns total merges.
    std::size_t saturate(std::size_t max_iters = 16,
                         std::size_t max_nodes = 4096);

    // ---- Extraction & hashing ----------------------------------------

    // Recursively compute the canonical hash of the smallest-cost subtree
    // rooted at e-class `root`. Cost = node count. Ties broken by
    // (op, type, child-hash) lexicographically.
    //
    // `max_depth` caps recursion in case of phi-style cycles in the
    // e-graph (should not happen with our rule set, but defensively).
    [[nodiscard]] u64 canonical_hash(ClassId root,
                                     std::size_t max_depth = 24) const;

    // ---- Stats --------------------------------------------------------

    [[nodiscard]] std::size_t node_count() const noexcept { return nodes_.size(); }
    [[nodiscard]] std::size_t class_count() const noexcept;
    [[nodiscard]] bool budget_hit() const noexcept { return budget_hit_; }
    [[nodiscard]] std::size_t total_iters() const noexcept { return total_iters_; }

private:
    struct EClass {
        ClassId             parent = kNullClass;     // union-find pointer
        u32                 rank   = 0;
        std::vector<NodeId> nodes;                   // all e-nodes in this class
        std::vector<NodeId> use_list;                // nodes that reference this class
    };

    // Mutable so find() can path-compress. Doesn't change observable state.
    mutable std::vector<EClass>      classes_;
    std::vector<ENode>               nodes_;
    std::vector<ClassId>             node_to_class_;
    std::unordered_map<u64, NodeId>  hash_cons_;
    std::vector<ClassId>             dirty_;
    std::vector<Rule>                rules_;
    bool                             budget_hit_  = false;
    std::size_t                      total_iters_ = 0;
    mutable std::vector<u64>         hash_memo_;     // ClassId → canonical hash (filled lazily)

    // Internal helpers
    [[nodiscard]] u64    enode_key(const ENode& n) const noexcept;
    [[nodiscard]] ENode  canonicalize_node(ENode n) const noexcept;
    void                 rebuild_();
    void                 repair_class_(ClassId c);

    struct MatchHit { ClassId root; Subst s; };
    void match_(const Pat& p, std::vector<MatchHit>& out) const;
    [[nodiscard]] bool match_at_(const Pat& p, ClassId c, Subst& s) const;
    [[nodiscard]] ClassId instantiate_(const Pat& p, const Subst& s);

    // Cost-aware recursive hash. memoizes per-class.
    [[nodiscard]] u64 hash_class_(ClassId c, std::size_t depth) const;
    [[nodiscard]] u64 hash_node_(const ENode& n, std::size_t depth) const;
    [[nodiscard]] u32 cost_class_(ClassId c, std::size_t depth,
                                  std::vector<u32>& memo) const;
};

}  // namespace ember::egraph
