// Unit tests for the e-graph saturation core. Self-contained: builds
// e-graphs from synthetic terms (no IR involved), exercises hash-cons,
// union-find, congruence closure, and bounded saturation against
// hand-crafted rule sets, and verifies canonical_hash convergence on
// the orbit-equivalent forms of a few small algebraic identities.

#include <ember/analysis/egraph.hpp>
#include <ember/common/types.hpp>

#include <cstdio>
#include <cstdlib>
#include <vector>

using namespace ember::egraph;
using ember::u64;

namespace {

int fails = 0;

void check(bool ok, const char* ctx) {
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", ctx); ++fails; }
}

void check_eq_u64(u64 got, u64 want, const char* ctx) {
    if (got != want) {
        std::fprintf(stderr, "FAIL: %s (got %lx, want %lx)\n",
                     ctx, static_cast<unsigned long>(got),
                     static_cast<unsigned long>(want));
        ++fails;
    }
}

void check_neq_u64(u64 got, u64 forbid, const char* ctx) {
    if (got == forbid) {
        std::fprintf(stderr, "FAIL: %s (both equal %lx, expected distinct)\n",
                     ctx, static_cast<unsigned long>(got));
        ++fails;
    }
}

// ---- 1. Hash-cons -------------------------------------------------------
//
// Two adds of the same operand classes should resolve to the same e-class.

void test_hash_cons() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto y = g.add_var(Type::I64, 2);
    auto a = g.add_binop(Op::Add, Type::I64, x, y);
    auto b = g.add_binop(Op::Add, Type::I64, x, y);
    check(a == b, "hash_cons: identical adds collapse");
    auto c = g.add_binop(Op::Add, Type::I64, y, x);
    check(c != a, "hash_cons: order matters before commutativity rule");
    check(g.node_count() == 4u, "hash_cons: node count");
}

// ---- 2. Union-find ------------------------------------------------------
//
// Manual merge of two classes should make find() return the same root.

void test_union_find() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto y = g.add_var(Type::I64, 2);
    check(g.find(x) != g.find(y), "uf: initially distinct");
    check(g.merge(x, y), "uf: merge returns true on first union");
    check(g.find(x) == g.find(y), "uf: same root after merge");
    check(!g.merge(x, y), "uf: idempotent merge");
}

// ---- 3. Commutativity rule ---------------------------------------------
//
// After registering Add commutativity and saturating, both `add(x,y)` and
// `add(y,x)` should hash identically (canonical_hash converges).

void test_commutativity() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto y = g.add_var(Type::I64, 2);
    auto a = g.add_binop(Op::Add, Type::I64, x, y);
    auto b = g.add_binop(Op::Add, Type::I64, y, x);

    // Pre-saturation: distinct.
    check_neq_u64(g.canonical_hash(a), g.canonical_hash(b),
                  "commutativity: distinct before rule");

    Rule r{
        "add-comm",
        Pat::node(Op::Add, Type::I64,
                  {Pat::var(0), Pat::var(1)}),
        Pat::node(Op::Add, Type::I64,
                  {Pat::var(1), Pat::var(0)})
    };
    g.add_rule(r);
    g.saturate(8, 4096);
    check_eq_u64(g.canonical_hash(a), g.canonical_hash(b),
                 "commutativity: same after saturation");
}

// ---- 4. Identity (x + 0 = x) -------------------------------------------

void test_add_zero() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto z = g.add_const(Type::I64, 0);
    auto a = g.add_binop(Op::Add, Type::I64, x, z);
    check_neq_u64(g.canonical_hash(a), g.canonical_hash(x),
                  "add_zero: distinct before rule");
    Rule r{
        "add-zero",
        Pat::node(Op::Add, Type::I64,
                  {Pat::var(0), Pat::constant(0, Type::I64)}),
        Pat::var(0)
    };
    g.add_rule(r);
    g.saturate(8, 4096);
    check_eq_u64(g.canonical_hash(a), g.canonical_hash(x),
                 "add_zero: same after saturation");
}

// ---- 5. Strength reduction (x * 2 ↔ x << 1) ----------------------------
//
// The classic "compiler equivalent" — gcc -O2 emits one form, clang -Os
// the other. With this rule, both fingerprints collapse.

void test_mul_to_shl() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto k1 = g.add_const(Type::I64, 1);
    auto k2 = g.add_const(Type::I64, 2);
    auto a = g.add_binop(Op::Mul, Type::I64, x, k2);
    auto b = g.add_binop(Op::Shl, Type::I64, x, k1);
    check_neq_u64(g.canonical_hash(a), g.canonical_hash(b),
                  "mul-to-shl: distinct before rule");
    Rule r{
        "mul2-to-shl1",
        Pat::node(Op::Mul, Type::I64,
                  {Pat::var(0), Pat::constant(2, Type::I64)}),
        Pat::node(Op::Shl, Type::I64,
                  {Pat::var(0), Pat::constant(1, Type::I64)})
    };
    g.add_rule(r);
    g.saturate(8, 4096);
    check_eq_u64(g.canonical_hash(a), g.canonical_hash(b),
                 "mul-to-shl: same after saturation");
}

// ---- 6. Congruence after manual merge ----------------------------------
//
// Critical correctness: if you manually unify x and y, then any expression
// involving x must hash the same as the corresponding expression with y.
// This requires rebuild() to walk parent uses.

void test_congruence() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto y = g.add_var(Type::I64, 2);
    auto z = g.add_var(Type::I64, 3);
    auto fxz = g.add_binop(Op::Add, Type::I64, x, z);
    auto fyz = g.add_binop(Op::Add, Type::I64, y, z);
    check_neq_u64(g.canonical_hash(fxz), g.canonical_hash(fyz),
                  "congruence: distinct before merge");
    g.merge(x, y);
    g.saturate(0, 4096);   // 0 iters — just trigger rebuild
    check_eq_u64(g.canonical_hash(fxz), g.canonical_hash(fyz),
                 "congruence: same after merging operands");
}

// ---- 7. Saturation budget bail-out -------------------------------------
//
// Pathological case: distributivity unbounded. With max_nodes capped, the
// engine should stop cleanly and report budget_hit() == true.

void test_budget() {
    EGraph g;
    auto x = g.add_var(Type::I64, 1);
    auto y = g.add_var(Type::I64, 2);
    // Build a deep mul-of-add chain.
    auto cur = x;
    for (int i = 0; i < 8; ++i) {
        auto k = g.add_const(Type::I64, static_cast<u64>(i));
        auto add = g.add_binop(Op::Add, Type::I64, y, k);
        cur = g.add_binop(Op::Mul, Type::I64, cur, add);
    }
    // Distributivity: a*(b+c) ↔ a*b + a*c — generates exponentially many
    // forms.
    Rule r{
        "distrib",
        Pat::node(Op::Mul, Type::I64,
                  {Pat::var(0),
                   Pat::node(Op::Add, Type::I64,
                             {Pat::var(1), Pat::var(2)})}),
        Pat::node(Op::Add, Type::I64,
                  {Pat::node(Op::Mul, Type::I64, {Pat::var(0), Pat::var(1)}),
                   Pat::node(Op::Mul, Type::I64, {Pat::var(0), Pat::var(2)})})
    };
    g.add_rule(r);
    const std::size_t pre = g.node_count();
    g.saturate(8, /*max_nodes=*/64);
    const std::size_t post = g.node_count();
    check(post >= pre, "budget: graph didn't shrink");
    check(post <= 256u, "budget: graph stayed bounded");
    // canonical_hash still works.
    auto h = g.canonical_hash(cur);
    check(h != 0, "budget: hash still computable after bail");
}

}  // namespace

int main() {
    test_hash_cons();
    test_union_find();
    test_commutativity();
    test_add_zero();
    test_mul_to_shl();
    test_congruence();
    test_budget();

    if (fails) {
        std::fprintf(stderr, "%d failure(s)\n", fails);
        return 1;
    }
    std::printf("egraph: all tests passed\n");
    return 0;
}
