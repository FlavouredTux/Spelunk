#include <ember/analysis/egraph.hpp>

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace ember::egraph {

namespace {

constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
constexpr u64 kFnvPrime  = 0x100000001b3ULL;

[[nodiscard]] constexpr u64 fnv1a(const void* p, std::size_t n) noexcept {
    const auto* b = static_cast<const u8*>(p);
    u64 h = kFnvOffset;
    for (std::size_t i = 0; i < n; ++i) {
        h ^= b[i];
        h *= kFnvPrime;
    }
    return h;
}

[[nodiscard]] constexpr u64 mix64(u64 a, u64 b) noexcept {
    u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
    x ^= x >> 30;  x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;  x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

}  // namespace

std::string_view op_name(Op op) noexcept {
    switch (op) {
        case Op::Const:   return "const";
        case Op::Var:     return "var";
        case Op::Opaque:  return "opaque";
        case Op::Add:     return "add";
        case Op::Sub:     return "sub";
        case Op::Mul:     return "mul";
        case Op::DivS:    return "divs";
        case Op::DivU:    return "divu";
        case Op::ModS:    return "mods";
        case Op::ModU:    return "modu";
        case Op::Neg:     return "neg";
        case Op::And:     return "and";
        case Op::Or:      return "or";
        case Op::Xor:     return "xor";
        case Op::Not:     return "not";
        case Op::Shl:     return "shl";
        case Op::LShr:    return "lshr";
        case Op::AShr:    return "ashr";
        case Op::CmpEq:   return "eq";
        case Op::CmpNe:   return "ne";
        case Op::CmpUlt:  return "ult";
        case Op::CmpUle:  return "ule";
        case Op::CmpUgt:  return "ugt";
        case Op::CmpUge:  return "uge";
        case Op::CmpSlt:  return "slt";
        case Op::CmpSle:  return "sle";
        case Op::CmpSgt:  return "sgt";
        case Op::CmpSge:  return "sge";
        case Op::ZExt:    return "zext";
        case Op::SExt:    return "sext";
        case Op::Trunc:   return "trunc";
        case Op::Select:  return "select";
    }
    return "?";
}

std::string_view type_name(Type t) noexcept {
    switch (t) {
        case Type::Any:  return "any";
        case Type::I1:   return "i1";
        case Type::I8:   return "i8";
        case Type::I16:  return "i16";
        case Type::I32:  return "i32";
        case Type::I64:  return "i64";
        case Type::I128: return "i128";
        case Type::F32:  return "f32";
        case Type::F64:  return "f64";
    }
    return "?";
}

// ---- Pat / Subst ---------------------------------------------------------

Pat Pat::var(u32 id, Type t) {
    Pat p; p.kind = Kind::Var; p.var_id = id; p.type = t; return p;
}
Pat Pat::constant(u64 v, Type t) {
    Pat p; p.kind = Kind::Const; p.imm = v; p.type = t; return p;
}
Pat Pat::node(Op op, Type t, std::vector<Pat> ch) {
    Pat p; p.kind = Kind::Op; p.op = op; p.type = t; p.children = std::move(ch); return p;
}

bool Subst::bind(u32 var_id, ClassId c) noexcept {
    if (var_id >= 8) return false;
    if (set[var_id]) return binds[var_id] == c;
    set[var_id] = true; binds[var_id] = c;
    return true;
}
ClassId Subst::get(u32 var_id) const noexcept {
    return (var_id < 8 && set[var_id]) ? binds[var_id] : kNullClass;
}

// ---- EGraph --------------------------------------------------------------

EGraph::EGraph() {
    nodes_.reserve(256);
    classes_.reserve(256);
    node_to_class_.reserve(256);
    hash_cons_.reserve(512);
}

ClassId EGraph::find(ClassId c) const noexcept {
    if (c == kNullClass || c >= classes_.size()) return kNullClass;
    while (classes_[c].parent != kNullClass) {
        ClassId p = classes_[c].parent;
        ClassId g = classes_[p].parent;
        if (g != kNullClass) {
            classes_[c].parent = g;     // path compression
            c = g;
        } else {
            c = p;
        }
    }
    return c;
}

u64 EGraph::enode_key(const ENode& n) const noexcept {
    // Pack everything that distinguishes one node from another into a
    // contiguous buffer and FNV it. Order matters so two distinct
    // canonical forms always hash differently.
    // MSVC has no __attribute__((packed)); use #pragma pack so the
    // hashed struct has the same byte layout (28 bytes, no trailing
    // alignment) on every compiler.
#pragma pack(push, 1)
    struct Packed {
        u16     op;
        u8      type;
        u8      n_children;
        u32     _pad;
        u64     imm;
        ClassId c0, c1, c2;
    };
#pragma pack(pop)
    Packed p{};
    p.op = static_cast<u16>(n.op);
    p.type = static_cast<u8>(n.type);
    p.n_children = n.n_children;
    p.imm = n.imm;
    p.c0 = (n.n_children > 0) ? find(n.children[0]) : kNullClass;
    p.c1 = (n.n_children > 1) ? find(n.children[1]) : kNullClass;
    p.c2 = (n.n_children > 2) ? find(n.children[2]) : kNullClass;
    return fnv1a(&p, sizeof p);
}

ENode EGraph::canonicalize_node(ENode n) const noexcept {
    for (u8 i = 0; i < n.n_children; ++i) {
        n.children[i] = find(n.children[i]);
    }
    return n;
}

ClassId EGraph::add(ENode n) {
    n = canonicalize_node(n);
    const u64 key = enode_key(n);
    if (auto it = hash_cons_.find(key); it != hash_cons_.end()) {
        return find(node_to_class_[it->second]);
    }
    const NodeId nid = static_cast<NodeId>(nodes_.size());
    const ClassId cid = static_cast<ClassId>(classes_.size());
    nodes_.push_back(n);
    classes_.push_back({});
    classes_.back().nodes.push_back(nid);
    node_to_class_.push_back(cid);
    hash_cons_.emplace(key, nid);
    // Register in each child's use_list so subsequent rebuilds can
    // re-canonicalize this node when a child class is merged.
    for (u8 i = 0; i < n.n_children; ++i) {
        const ClassId ci = find(n.children[i]);
        if (ci != kNullClass) classes_[ci].use_list.push_back(nid);
    }
    return cid;
}

ClassId EGraph::add_const(Type t, u64 v) {
    ENode n; n.op = Op::Const; n.type = t; n.imm = v; return add(n);
}
ClassId EGraph::add_var(Type t, u64 key) {
    ENode n; n.op = Op::Var; n.type = t; n.imm = key; return add(n);
}
ClassId EGraph::add_opaque(Type t, u64 key) {
    ENode n; n.op = Op::Opaque; n.type = t; n.imm = key; return add(n);
}
ClassId EGraph::add_unop(Op op, Type t, ClassId a) {
    ENode n; n.op = op; n.type = t; n.n_children = 1;
    n.children[0] = a; return add(n);
}
ClassId EGraph::add_binop(Op op, Type t, ClassId a, ClassId b) {
    ENode n; n.op = op; n.type = t; n.n_children = 2;
    n.children[0] = a; n.children[1] = b; return add(n);
}
ClassId EGraph::add_select(Type t, ClassId cond, ClassId a, ClassId b) {
    ENode n; n.op = Op::Select; n.type = t; n.n_children = 3;
    n.children[0] = cond; n.children[1] = a; n.children[2] = b;
    return add(n);
}

bool EGraph::merge(ClassId a, ClassId b) {
    a = find(a); b = find(b);
    if (a == kNullClass || b == kNullClass || a == b) return false;
    // Union by rank
    if (classes_[a].rank < classes_[b].rank) std::swap(a, b);
    classes_[b].parent = a;
    if (classes_[a].rank == classes_[b].rank) classes_[a].rank++;
    // Move b's nodes and use_list into a. We don't dedupe — rebuild() does.
    auto& ca = classes_[a];
    auto& cb = classes_[b];
    ca.nodes.insert(ca.nodes.end(), cb.nodes.begin(), cb.nodes.end());
    ca.use_list.insert(ca.use_list.end(), cb.use_list.begin(), cb.use_list.end());
    cb.nodes.clear();
    cb.use_list.clear();
    dirty_.push_back(a);
    return true;
}

void EGraph::repair_class_(ClassId c) {
    c = find(c);
    if (c == kNullClass) return;
    // Snapshot use_list to avoid iterator invalidation when nested merges
    // append back into it.
    std::vector<NodeId> uses;
    uses.swap(classes_[c].use_list);
    for (NodeId nid : uses) {
        if (find(node_to_class_[nid]) == kNullClass) continue;
        // Canonicalize children. We don't bother removing the OLD key
        // from hash_cons_: lookups always go through canonicalize_node()
        // → enode_key(), which recomputes from current find()s, so a
        // stale entry under the old key is unreachable. With a 64-bit
        // FNV the chance of an accidental collision against a future
        // distinct node is ~2^-64.
        const ENode neu = canonicalize_node(nodes_[nid]);
        nodes_[nid] = neu;
        const u64 newKey = enode_key(neu);
        auto [it, inserted] = hash_cons_.try_emplace(newKey, nid);
        if (!inserted && it->second != nid) {
            // Congruence conflict: another node has the same canonical
            // key as this one → their host classes must merge.
            const NodeId other = it->second;
            const ClassId cN = find(node_to_class_[nid]);
            const ClassId cO = find(node_to_class_[other]);
            if (cN != cO) merge(cN, cO);
        }
        // Re-register in child use lists. Duplicates are tolerated and
        // get pruned the next time this class is repaired.
        for (u8 i = 0; i < neu.n_children; ++i) {
            const ClassId ci = find(neu.children[i]);
            if (ci != kNullClass) classes_[ci].use_list.push_back(nid);
        }
    }
}

void EGraph::rebuild_() {
    while (!dirty_.empty()) {
        auto ws = std::move(dirty_);
        dirty_.clear();
        // Dedupe by canonical id.
        std::sort(ws.begin(), ws.end(),
                  [&](ClassId x, ClassId y){ return find(x) < find(y); });
        ws.erase(std::unique(ws.begin(), ws.end(),
                  [&](ClassId x, ClassId y){ return find(x) == find(y); }), ws.end());
        for (ClassId c : ws) repair_class_(c);
    }
}

// ---- Pattern matching ----------------------------------------------------

bool EGraph::match_at_(const Pat& p, ClassId c, Subst& s) const {
    c = find(c);
    if (c == kNullClass) return false;
    switch (p.kind) {
        case Pat::Kind::Var:
            // Type filter, if any.
            if (p.type != Type::Any) {
                bool any = false;
                for (NodeId n : classes_[c].nodes) {
                    if (nodes_[n].type == p.type) { any = true; break; }
                }
                if (!any) return false;
            }
            return s.bind(p.var_id, c);
        case Pat::Kind::Const:
            for (NodeId n : classes_[c].nodes) {
                const ENode& en = nodes_[n];
                if (en.op == Op::Const && en.imm == p.imm &&
                    (p.type == Type::Any || en.type == p.type)) return true;
            }
            return false;
        case Pat::Kind::Op:
            for (NodeId n : classes_[c].nodes) {
                const ENode& en = nodes_[n];
                if (en.op != p.op) continue;
                if (p.type != Type::Any && en.type != p.type) continue;
                if (en.n_children != p.children.size()) continue;
                Subst snap = s;
                bool ok = true;
                for (std::size_t i = 0; i < p.children.size(); ++i) {
                    if (!match_at_(p.children[i], en.children[i], s)) {
                        ok = false; break;
                    }
                }
                if (ok) return true;
                s = snap;
            }
            return false;
    }
    return false;
}

void EGraph::match_(const Pat& p, std::vector<MatchHit>& out) const {
    const std::size_t n = classes_.size();
    for (ClassId c = 0; c < n; ++c) {
        if (classes_[c].parent != kNullClass) continue;       // not canonical
        Subst s{};
        if (match_at_(p, c, s)) {
            out.push_back({c, s});
        }
    }
}

ClassId EGraph::instantiate_(const Pat& p, const Subst& s) {
    switch (p.kind) {
        case Pat::Kind::Var:
            return s.get(p.var_id);
        case Pat::Kind::Const:
            return add_const(p.type == Type::Any ? Type::I64 : p.type, p.imm);
        case Pat::Kind::Op: {
            ENode n;
            n.op = p.op;
            n.type = (p.type == Type::Any) ? Type::I64 : p.type;
            n.n_children = static_cast<u8>(p.children.size());
            for (std::size_t i = 0; i < p.children.size(); ++i) {
                n.children[i] = instantiate_(p.children[i], s);
                if (n.children[i] == kNullClass) return kNullClass;
            }
            return add(n);
        }
    }
    return kNullClass;
}

void EGraph::add_rule(Rule r) {
    rules_.push_back(std::move(r));
}

std::size_t EGraph::saturate(std::size_t max_iters, std::size_t max_nodes) {
    std::size_t merges = 0;
    budget_hit_ = false;
    for (std::size_t iter = 0; iter < max_iters; ++iter) {
        ++total_iters_;
        if (nodes_.size() > max_nodes) { budget_hit_ = true; break; }
        // Phase 1: collect all matches against the current snapshot.
        std::vector<std::pair<const Rule*, MatchHit>> hits;
        for (const auto& r : rules_) {
            std::vector<MatchHit> rh;
            match_(r.lhs, rh);
            for (auto& h : rh) hits.push_back({&r, std::move(h)});
        }
        // Phase 2: apply matches. Each match instantiates rhs and unions
        // with the matched-root class.
        bool fired = false;
        for (auto& [rule, hit] : hits) {
            if (nodes_.size() > max_nodes) { budget_hit_ = true; break; }
            const ClassId rhs_c = instantiate_(rule->rhs, hit.s);
            if (rhs_c == kNullClass) continue;
            if (merge(hit.root, rhs_c)) { fired = true; ++merges; }
        }
        // Phase 3: rebuild congruence after this iteration's merges.
        rebuild_();
        if (!fired) break;
    }
    return merges;
}

// ---- Stats / extraction --------------------------------------------------

std::size_t EGraph::class_count() const noexcept {
    std::size_t n = 0;
    for (ClassId c = 0; c < classes_.size(); ++c) {
        if (classes_[c].parent == kNullClass) ++n;
    }
    return n;
}

u32 EGraph::cost_class_(ClassId c, std::size_t depth,
                        std::vector<u32>& memo) const {
    c = find(c);
    if (c == kNullClass) return 1;
    if (memo[c] != 0) return memo[c];
    if (depth == 0) { memo[c] = 1; return 1; }
    u32 best = std::numeric_limits<u32>::max();
    // Tentative mark to break cycles (treat self-reference as cost +∞).
    memo[c] = 1;
    for (NodeId nid : classes_[c].nodes) {
        const ENode& n = nodes_[nid];
        u32 sum = 1;
        bool ok = true;
        for (u8 i = 0; i < n.n_children; ++i) {
            const u32 ck = cost_class_(n.children[i], depth - 1, memo);
            if (ck >= std::numeric_limits<u32>::max() / 4) { ok = false; break; }
            sum += ck;
            if (sum >= best) { ok = false; break; }
        }
        if (ok && sum < best) best = sum;
    }
    memo[c] = best;
    return best;
}

u64 EGraph::hash_node_(const ENode& n, std::size_t depth) const {
    u64 h = mix64(static_cast<u64>(n.op),
                  static_cast<u64>(n.type) ^ (static_cast<u64>(n.n_children) << 8));
    h = mix64(h, n.imm);
    for (u8 i = 0; i < n.n_children; ++i) {
        h = mix64(h, hash_class_(n.children[i], depth - 1));
    }
    return h;
}

u64 EGraph::hash_class_(ClassId c, std::size_t depth) const {
    c = find(c);
    if (c == kNullClass) return 0;
    if (hash_memo_.size() <= c) hash_memo_.resize(classes_.size(), 0);
    if (hash_memo_[c] != 0) return hash_memo_[c];
    if (depth == 0) {
        // Past the depth bound: return a stable content-free constant so
        // structurally identical e-graphs give the same hash regardless
        // of ClassId numbering. Different deep subtrees collide here, but
        // that's the budget cap doing its job.
        constexpr u64 kDepthCap = 0xCAFEFEEDDEADBEEFULL;
        hash_memo_[c] = kDepthCap;
        return kDepthCap;
    }
    // Compute a deterministic class hash that is a function of the
    // class's ENode SET, not of ClassId numbering. Approach:
    //   1. Pre-mark this class with a stable cycle-break sentinel so
    //      recursion through cycles converges.
    //   2. For each ENode in the class, compute hash_node_ recursively.
    //   3. Sort the node-hashes, fold them with mix64 — a multiset hash
    //      of the class's ENode contents. ClassId-independent.
    constexpr u64 kCycleSentinel = 0xFEEDFACEDEADC0DEULL;
    hash_memo_[c] = kCycleSentinel;

    std::vector<u64> nhs;
    nhs.reserve(classes_[c].nodes.size());
    for (NodeId nid : classes_[c].nodes) {
        nhs.push_back(hash_node_(nodes_[nid], depth));
    }
    if (nhs.empty()) {
        hash_memo_[c] = 0;
        return 0;
    }
    std::sort(nhs.begin(), nhs.end());
    nhs.erase(std::unique(nhs.begin(), nhs.end()), nhs.end());
    u64 h = 0xa5a5a5a5a5a5a5a5ULL;
    for (u64 x : nhs) h = mix64(h, x);
    hash_memo_[c] = h;
    return h;
}

u64 EGraph::canonical_hash(ClassId root, std::size_t max_depth) const {
    if (root == kNullClass) return 0;
    hash_memo_.clear();
    hash_memo_.resize(classes_.size(), 0);
    return hash_class_(find(root), max_depth);
}

}  // namespace ember::egraph
