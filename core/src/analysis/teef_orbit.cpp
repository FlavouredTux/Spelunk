#include <ember/analysis/teef_orbit.hpp>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/analysis/cfg_builder.hpp>
#include <ember/analysis/egraph.hpp>
#include <ember/analysis/pipeline.hpp>
#include <ember/binary/binary.hpp>
#include <ember/disasm/decoder.hpp>
#include <ember/ir/lifter.hpp>
#include <ember/ir/passes.hpp>
#include <ember/ir/ssa.hpp>

namespace ember {

namespace {

using namespace egraph;

constexpr u64 kFnvOffset = 0xcbf29ce484222325ULL;
constexpr u64 kFnvPrime  = 0x100000001b3ULL;

[[nodiscard]] constexpr u64 fnv1a(std::string_view s) noexcept {
    u64 h = kFnvOffset;
    for (char c : s) { h ^= static_cast<u8>(c); h *= kFnvPrime; }
    return h;
}

[[nodiscard]] constexpr u64 mix64(u64 a, u64 b) noexcept {
    u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
    x ^= x >> 30;  x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;  x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

[[nodiscard]] Type map_type(IrType t) noexcept {
    switch (t) {
        case IrType::I1:   return Type::I1;
        case IrType::I8:   return Type::I8;
        case IrType::I16:  return Type::I16;
        case IrType::I32:  return Type::I32;
        case IrType::I64:  return Type::I64;
        case IrType::I128: return Type::I128;
        case IrType::F32:  return Type::F32;
        case IrType::F64:  return Type::F64;
    }
    return Type::I64;
}

// Map an IrOp to an egraph::Op when the algebra is interesting; return
// false (via the optional) otherwise so the caller can emit Opaque.
[[nodiscard]] bool map_op(IrOp src, Op& out) noexcept {
    switch (src) {
        case IrOp::Add:    out = Op::Add;    return true;
        case IrOp::Sub:    out = Op::Sub;    return true;
        case IrOp::Mul:    out = Op::Mul;    return true;
        case IrOp::And:    out = Op::And;    return true;
        case IrOp::Or:     out = Op::Or;     return true;
        case IrOp::Xor:    out = Op::Xor;    return true;
        case IrOp::Neg:    out = Op::Neg;    return true;
        case IrOp::Not:    out = Op::Not;    return true;
        case IrOp::Shl:    out = Op::Shl;    return true;
        case IrOp::Lshr:   out = Op::LShr;   return true;
        case IrOp::Ashr:   out = Op::AShr;   return true;
        case IrOp::CmpEq:  out = Op::CmpEq;  return true;
        case IrOp::CmpNe:  out = Op::CmpNe;  return true;
        case IrOp::CmpUlt: out = Op::CmpUlt; return true;
        case IrOp::CmpUle: out = Op::CmpUle; return true;
        case IrOp::CmpUgt: out = Op::CmpUgt; return true;
        case IrOp::CmpUge: out = Op::CmpUge; return true;
        case IrOp::CmpSlt: out = Op::CmpSlt; return true;
        case IrOp::CmpSle: out = Op::CmpSle; return true;
        case IrOp::CmpSgt: out = Op::CmpSgt; return true;
        case IrOp::CmpSge: out = Op::CmpSge; return true;
        case IrOp::ZExt:   out = Op::ZExt;   return true;
        case IrOp::SExt:   out = Op::SExt;   return true;
        case IrOp::Trunc:  out = Op::Trunc;  return true;
        case IrOp::Select: out = Op::Select; return true;
        default: return false;
    }
}

// ---- Frontier extraction (declared before Walker so walk() can use it) -

[[nodiscard]] u64 ir_value_use_key(const IrValue& v) noexcept;
[[nodiscard]] std::vector<bool> compute_frontier_mask(const IrFunction& fn);
[[nodiscard]] bool is_observable_op(IrOp op) noexcept;

// ---- IR walker -----------------------------------------------------------

struct Walker {
    EGraph&                          g;
    const IrFunction&                fn;
    const Binary&                    bin;

    std::unordered_map<u64, ClassId> value_to_class;
    std::unordered_map<u32, u64>     temp_alpha;
    u64                              next_alpha = 0;
    std::vector<ClassId>             roots;

    Walker(EGraph& g_, const IrFunction& fn_, const Binary& b_)
        : g(g_), fn(fn_), bin(b_) {}

    [[nodiscard]] u64 alpha_for_temp(u32 id) {
        auto [it, ok] = temp_alpha.emplace(id, 0);
        if (ok) it->second = next_alpha++;
        return it->second;
    }

    [[nodiscard]] u64 var_key(const IrValue& v) const {
        switch (v.kind) {
            case IrValueKind::Reg:
                return mix64(fnv1a("reg"),
                             (static_cast<u64>(v.reg) << 16) | v.version);
            case IrValueKind::Temp: {
                // Alpha-rename temp so two structurally identical fns
                // hash the same. Const-time lookup: the writer above
                // populated temp_alpha eagerly on first appearance.
                auto it = temp_alpha.find(v.temp);
                const u64 a = (it == temp_alpha.end()) ? v.temp : it->second;
                return mix64(fnv1a("temp"), (a << 8) | v.version);
            }
            case IrValueKind::Flag:
                return mix64(fnv1a("flag"), static_cast<u64>(v.flag));
            default:
                return 0;
        }
    }

    // Resolve an addr to a stable hash. PLT/GOT/defined-object names are
    // strong anchors that survive compiler diversity; unresolved
    // addresses fall back to a generic "address" class so they don't
    // trivially collide across binaries.
    [[nodiscard]] u64 addr_class_hash(addr_t a) const noexcept {
        if (const auto* imp = bin.import_at_plt(a); imp && !imp->name.empty())
            return mix64(fnv1a("plt"), fnv1a(imp->name));
        if (const auto* imp = bin.import_at_got(a); imp && !imp->name.empty())
            return mix64(fnv1a("got"), fnv1a(imp->name));
        if (const auto* sym = bin.defined_object_at(a); sym && !sym->name.empty())
            return mix64(fnv1a("sym"), fnv1a(sym->name));
        return fnv1a("addr");
    }

    [[nodiscard]] ClassId resolve(const IrValue& v) {
        switch (v.kind) {
            case IrValueKind::None:
                return kNullClass;
            case IrValueKind::Imm:
                return g.add_const(map_type(v.type),
                                   static_cast<u64>(v.imm));
            case IrValueKind::Reg:
            case IrValueKind::Temp:
            case IrValueKind::Flag: {
                if (v.kind == IrValueKind::Temp) {
                    // Make sure alpha is allocated before var_key reads it.
                    auto [it, ok] = temp_alpha.emplace(v.temp, 0);
                    if (ok) it->second = next_alpha++;
                }
                const u64 k = var_key(v);
                if (auto it = value_to_class.find(k);
                    it != value_to_class.end()) return it->second;
                const ClassId c = g.add_var(map_type(v.type), k);
                value_to_class[k] = c;
                return c;
            }
        }
        return kNullClass;
    }

    void bind_dst(const IrValue& dst, ClassId c) {
        if (dst.kind == IrValueKind::Temp) {
            auto [it, ok] = temp_alpha.emplace(dst.temp, 0);
            if (ok) it->second = next_alpha++;
        }
        const u64 k = var_key(dst);
        if (k == 0) return;
        value_to_class[k] = c;
    }

    // Eagerly fold simple binary ops on two constants. Skips floats and
    // anything where wraparound semantics matter beyond i64 (we mask).
    [[nodiscard]] bool try_const_fold(IrOp op, const IrValue& a,
                                      const IrValue& b, u64& out) const noexcept {
        if (a.kind != IrValueKind::Imm || b.kind != IrValueKind::Imm) return false;
        const u64 ua = static_cast<u64>(a.imm);
        const u64 ub = static_cast<u64>(b.imm);
        switch (op) {
            case IrOp::Add: out = ua + ub; return true;
            case IrOp::Sub: out = ua - ub; return true;
            case IrOp::Mul: out = ua * ub; return true;
            case IrOp::And: out = ua & ub; return true;
            case IrOp::Or:  out = ua | ub; return true;
            case IrOp::Xor: out = ua ^ ub; return true;
            case IrOp::Shl: out = ua << (ub & 63); return true;
            case IrOp::Lshr:out = ua >> (ub & 63); return true;
            default: return false;
        }
    }

    // Process one IR instruction; return the resulting e-class id (or
    // kNullClass if no class produced). The caller decides whether to
    // push that class onto the fingerprint roots based on a frontier
    // analysis.
    [[nodiscard]] ClassId process_inst(const IrInst& inst) {
        if (inst.op == IrOp::Nop) return kNullClass;
        if (inst.dst.kind == IrValueKind::None) {
            // Side-effecting / control-flow inst. Build a stable opaque
            // node from (op, target-class, src classes) — NOT from
            // insertion order — so the e-class is positionally invariant
            // across compilations that order ops differently.
            u64 oid = fnv1a(op_name(inst.op));
            if (inst.op == IrOp::Call || inst.op == IrOp::CallIndirect ||
                inst.op == IrOp::Branch || inst.op == IrOp::CondBranch ||
                inst.op == IrOp::BranchIndirect) {
                oid = mix64(oid, addr_class_hash(inst.target1));
            }
            std::array<ClassId, 3> ch{kNullClass, kNullClass, kNullClass};
            u8 nch = 0;
            for (u8 i = 0; i < inst.src_count && i < 3; ++i) {
                ch[i] = resolve(inst.srcs[i]);
                if (ch[i] != kNullClass) ++nch;
            }
            ENode n;
            n.op   = Op::Opaque;
            n.type = Type::I64;
            n.imm  = oid;
            n.n_children = nch;
            n.children = ch;
            return g.add(n);
        }

        // Const-fold binary arithmetic up-front so the orbit doesn't
        // burn budget enumerating equivalent forms of pure-imm
        // computations.
        if (inst.src_count == 2) {
            u64 folded = 0;
            if (try_const_fold(inst.op, inst.srcs[0], inst.srcs[1], folded)) {
                const ClassId c = g.add_const(map_type(inst.dst.type), folded);
                bind_dst(inst.dst, c);
                return c;
            }
        }

        Op eop;
        if (!map_op(inst.op, eop)) {
            // Side-effecting or unmodelled: route through Opaque with a
            // payload that captures *what* it was (op name) and a
            // resolved-address class for memory ops / calls so two
            // calls to memcpy hash the same across compilers but a
            // call to malloc hashes differently from memcpy.
            u64 payload = fnv1a(op_name(inst.op));
            if (inst.op == IrOp::Call || inst.op == IrOp::Branch ||
                inst.op == IrOp::CondBranch || inst.op == IrOp::BranchIndirect ||
                inst.op == IrOp::CallIndirect) {
                payload = mix64(payload, addr_class_hash(inst.target1));
            }
            if (inst.op == IrOp::Intrinsic && !inst.name.empty()) {
                payload = mix64(payload, fnv1a(inst.name));
            }
            // Children: each src contributes via its existing class id
            // so the opaque's identity is sensitive to its input shape.
            std::array<ClassId, 3> ch{kNullClass, kNullClass, kNullClass};
            u8 nch = 0;
            for (u8 i = 0; i < inst.src_count && i < 3; ++i) {
                ch[i] = resolve(inst.srcs[i]);
                if (ch[i] != kNullClass) ++nch;
            }
            ENode n;
            n.op   = Op::Opaque;
            n.type = map_type(inst.dst.type);
            n.imm  = payload;
            n.n_children = nch;
            n.children = ch;
            const ClassId c = g.add(n);
            bind_dst(inst.dst, c);
            return c;
        }

        const Type t = map_type(inst.dst.type);
        ClassId c = kNullClass;
        switch (inst.src_count) {
            case 1: {
                const ClassId a = resolve(inst.srcs[0]);
                if (a != kNullClass) c = g.add_unop(eop, t, a);
                break;
            }
            case 2: {
                const ClassId a = resolve(inst.srcs[0]);
                const ClassId b = resolve(inst.srcs[1]);
                if (a != kNullClass && b != kNullClass)
                    c = g.add_binop(eop, t, a, b);
                break;
            }
            case 3: {
                const ClassId cnd = resolve(inst.srcs[0]);
                const ClassId thn = resolve(inst.srcs[1]);
                const ClassId els = resolve(inst.srcs[2]);
                if (cnd != kNullClass && thn != kNullClass && els != kNullClass) {
                    c = g.add_select(t, cnd, thn, els);
                }
                break;
            }
            default:
                break;
        }
        if (c == kNullClass) return kNullClass;
        bind_dst(inst.dst, c);
        return c;
    }

    void walk() {
        // First, compute the frontier mask: which insn dsts are worth
        // hashing as fingerprint roots vs. just being intermediate
        // computations absorbed by their parents' canonical forms.
        const auto frontier = compute_frontier_mask(fn);

        // Block-by-block, in IR-block order. Phi nodes are processed by
        // the lifter but for orbit purposes we treat them as opaque
        // joins.
        std::size_t pos = 0;
        for (const auto& bb : fn.blocks) {
            for (const auto& inst : bb.insts) {
                const ClassId c = process_inst(inst);
                if (c != kNullClass) {
                    const bool is_frontier = pos < frontier.size() && frontier[pos];
                    const bool is_obs = is_observable_op(inst.op);
                    if (is_frontier || is_obs) roots.push_back(c);
                }
                ++pos;
            }
        }
    }
};

// ---- Frontier extraction -------------------------------------------------
//
// Hashing every IR insn's dst class as a root inflates the multiset with
// intermediate sub-computations that are already captured *recursively*
// inside their parents' canonical-form hashes. On loop-heavy fns where
// compiler diversity perturbs intermediate temps but preserves overall
// shape, this redundancy *amplifies* divergence: a single extra
// intermediate temp adds one new hash to A's multiset and one different
// hash to B's, dragging Jaccard down with no informational gain.
//
// The fix: push every dst into the e-graph (so saturation has full
// context) but build the FINAL multiset only from "frontier" roots —
// dst keys that no later insn reads. Plus all observable side effects
// (stores, calls, returns) and the function's live-out values.
//
// Frontier detection runs a single forward sweep over the IR collecting
// all read keys, then keeps only the dst keys that weren't read. This
// matches the standard "live-out at fn exit" approximation and is
// stable across compiler diversity for the cases that matter (the
// returned value, observable I/O).

[[nodiscard]] u64 ir_value_use_key(const IrValue& v) noexcept {
    // Mirrors Walker::var_key but is a free function so it can be used
    // before Walker exists. Keys are byte-equal to Walker's only for
    // Reg / Flag (no temp_alpha indirection); Walker resolves Temp keys
    // through the per-fn alpha map, but for the use-set we only need a
    // bijection from raw IrValue to a u64 — so we use the raw temp id
    // here, on both sides. Identity within the fn is what matters.
    constexpr u64 kFnvOff = 0xcbf29ce484222325ULL;
    constexpr u64 kFnvPr  = 0x100000001b3ULL;
    auto fnv = [&](std::string_view s) {
        u64 h = kFnvOff;
        for (char c : s) { h ^= static_cast<u8>(c); h *= kFnvPr; }
        return h;
    };
    auto mix = [](u64 a, u64 b) {
        u64 x = a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
        x ^= x >> 30; x *= 0xbf58476d1ce4e5b9ULL;
        x ^= x >> 27; x *= 0x94d049bb133111ebULL;
        x ^= x >> 31; return x;
    };
    switch (v.kind) {
        case IrValueKind::Reg:
            return mix(fnv("reg-use"),
                       (static_cast<u64>(v.reg) << 16) | v.version);
        case IrValueKind::Temp:
            return mix(fnv("temp-use"),
                       (static_cast<u64>(v.temp) << 8) | v.version);
        case IrValueKind::Flag:
            return mix(fnv("flag-use"), static_cast<u64>(v.flag));
        default:
            return 0;
    }
}

[[nodiscard]] std::vector<bool>
compute_frontier_mask(const IrFunction& fn) {
    // Returns a parallel mask indicating, for each insn in fn (block-major
    // order), whether its dst is "frontier" (no subsequent read) and
    // whether it's an observable side effect — both push to roots.
    std::unordered_map<u64, std::size_t> last_read_pos;     // use_key → last-read insn pos
    std::vector<std::size_t> dst_pos;                       // insn pos → dst use_key (or 0)
    std::vector<u64>         dst_key;
    // First pass: linearize and collect read positions per use_key.
    std::size_t pos = 0;
    for (const auto& bb : fn.blocks) {
        for (const auto& inst : bb.insts) {
            for (u8 i = 0; i < inst.src_count; ++i) {
                const u64 k = ir_value_use_key(inst.srcs[i]);
                if (k) last_read_pos[k] = pos;
            }
            // Phi reads its operand list too.
            for (const auto& v : inst.phi_operands) {
                const u64 k = ir_value_use_key(v);
                if (k) last_read_pos[k] = pos;
            }
            const u64 k = ir_value_use_key(inst.dst);
            dst_pos.push_back(pos);
            dst_key.push_back(k);
            ++pos;
        }
    }
    // Second pass: a dst is frontier iff its key is never read AFTER its
    // own definition. For SSA the simple rule is "never read at all"
    // (definition is unique), so we just check absence in last_read_pos.
    std::vector<bool> mask(dst_pos.size(), false);
    for (std::size_t i = 0; i < dst_pos.size(); ++i) {
        const u64 k = dst_key[i];
        if (k == 0) continue;
        auto it = last_read_pos.find(k);
        if (it == last_read_pos.end()) mask[i] = true;     // never read → frontier
    }
    return mask;
}

[[nodiscard]] bool is_observable_op(IrOp op) noexcept {
    switch (op) {
        case IrOp::Store:
        case IrOp::Call:
        case IrOp::CallIndirect:
        case IrOp::Return:
        case IrOp::Branch:
        case IrOp::CondBranch:
        case IrOp::BranchIndirect:
            return true;
        default:
            return false;
    }
}

// ---- Rule set ------------------------------------------------------------
//
// Six rule families across i32 + i64 (the bitwidths that make up >95% of
// real x86-64 / aarch64 IR). Patterns are short by design — the orbit
// signal comes from saturating these against the function's algebra,
// not from cleverness in any single rule.

void install_rules(EGraph& g) {
    // For each typed binop we build commutativity + associativity (where
    // applicable) and the small identity / absorption / strength-reduction
    // set that compiler optimizers actually emit.
    auto add_typed = [&](Type t) {
        // ---- Commutativity ----
        const std::array<Op, 5> comm{Op::Add, Op::Mul, Op::And, Op::Or, Op::Xor};
        for (Op op : comm) {
            g.add_rule({"comm",
                Pat::node(op, t, {Pat::var(0), Pat::var(1)}),
                Pat::node(op, t, {Pat::var(1), Pat::var(0)})});
        }
        // ---- Associativity ----
        // (a op (b op c)) ↔ ((a op b) op c)
        for (Op op : {Op::Add, Op::Mul, Op::And, Op::Or, Op::Xor}) {
            g.add_rule({"assoc-r",
                Pat::node(op, t,
                    {Pat::var(0),
                     Pat::node(op, t, {Pat::var(1), Pat::var(2)})}),
                Pat::node(op, t,
                    {Pat::node(op, t, {Pat::var(0), Pat::var(1)}),
                     Pat::var(2)})});
            g.add_rule({"assoc-l",
                Pat::node(op, t,
                    {Pat::node(op, t, {Pat::var(0), Pat::var(1)}),
                     Pat::var(2)}),
                Pat::node(op, t,
                    {Pat::var(0),
                     Pat::node(op, t, {Pat::var(1), Pat::var(2)})})});
        }
        // ---- Identity ----
        g.add_rule({"add-zero",
            Pat::node(Op::Add, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        g.add_rule({"mul-one",
            Pat::node(Op::Mul, t, {Pat::var(0), Pat::constant(1, t)}),
            Pat::var(0)});
        g.add_rule({"or-zero",
            Pat::node(Op::Or,  t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        g.add_rule({"xor-zero",
            Pat::node(Op::Xor, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        g.add_rule({"shl-zero",
            Pat::node(Op::Shl, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        g.add_rule({"lshr-zero",
            Pat::node(Op::LShr, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        g.add_rule({"ashr-zero",
            Pat::node(Op::AShr, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::var(0)});
        // ---- Absorption ----
        g.add_rule({"mul-zero",
            Pat::node(Op::Mul, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::constant(0, t)});
        g.add_rule({"and-zero",
            Pat::node(Op::And, t, {Pat::var(0), Pat::constant(0, t)}),
            Pat::constant(0, t)});
        // ---- Strength reduction (mul by power of two ↔ shift) ----
        // Cover the cases real compilers actually emit.
        for (u64 k = 1; k <= 6; ++k) {
            g.add_rule({"mul2k-to-shl",
                Pat::node(Op::Mul, t, {Pat::var(0), Pat::constant(1ULL << k, t)}),
                Pat::node(Op::Shl, t, {Pat::var(0), Pat::constant(k, t)})});
        }
        // ---- Sub-of-self → 0 / xor-of-self → 0 ----
        // Pattern-match same var on both sides.
        g.add_rule({"sub-self",
            Pat::node(Op::Sub, t, {Pat::var(0), Pat::var(0)}),
            Pat::constant(0, t)});
        g.add_rule({"xor-self",
            Pat::node(Op::Xor, t, {Pat::var(0), Pat::var(0)}),
            Pat::constant(0, t)});
    };

    add_typed(Type::I32);
    add_typed(Type::I64);
}

[[nodiscard]] std::pair<std::size_t, std::size_t> read_budget() noexcept {
    static const auto pair = []() -> std::pair<std::size_t, std::size_t> {
        std::size_t mn = kOrbitDefaultMaxNodes;
        std::size_t mi = kOrbitDefaultMaxIters;
        if (const char* s = std::getenv("EMBER_ORBIT_MAX_NODES")) {
            try { mn = static_cast<std::size_t>(std::stoull(s)); } catch (...) {}
        }
        if (const char* s = std::getenv("EMBER_ORBIT_MAX_ITERS")) {
            try { mi = static_cast<std::size_t>(std::stoull(s)); } catch (...) {}
        }
        return {mn, mi};
    }();
    return pair;
}

[[nodiscard]] std::array<u64, 16>
minhash_multiset(const std::vector<u64>& xs) noexcept {
    std::array<u64, 16> mh;
    mh.fill(std::numeric_limits<u64>::max());
    if (xs.empty()) return mh;
    const u64 schemaSalt = fnv1a(kOrbitSchema);
    for (u64 x : xs) {
        for (std::size_t k = 0; k < 16; ++k) {
            const u64 hk = mix64(x, schemaSalt + k * 0x9e3779b97f4a7c15ULL);
            if (hk < mh[k]) mh[k] = hk;
        }
    }
    return mh;
}

[[nodiscard]] u64 multiset_exact_hash(const std::vector<u64>& xs) noexcept {
    u64 h = fnv1a(kOrbitSchema);
    // Already sorted by caller.
    for (u64 x : xs) h = mix64(h, x);
    return h;
}

}  // namespace

OrbitSig compute_orbit_sig(const Binary& bin, addr_t fn_start) {
    OrbitSig out;

    auto dec_r = make_decoder(bin);
    if (!dec_r) return out;
    const CfgBuilder cfg(bin, **dec_r);
    auto fn_r = cfg.build(fn_start, {});
    if (!fn_r) return out;
    auto lifter_r = make_lifter(bin);
    if (!lifter_r) return out;
    auto ir_r = (*lifter_r)->lift(*fn_r);
    if (!ir_r) return out;
    const SsaBuilder ssa;
    if (auto rv = ssa.convert(*ir_r); !rv) return out;
    if (auto rv = run_cleanup(*ir_r); !rv) return out;

    EGraph g;
    install_rules(g);
    Walker w(g, *ir_r, bin);
    w.walk();
    if (w.roots.empty()) return out;

    const auto [maxNodes, maxIters] = read_budget();
    g.saturate(maxIters, maxNodes);

    // Collect the canonical hash of every produced root; build the
    // sorted multiset.
    std::vector<u64> hashes;
    hashes.reserve(w.roots.size());
    for (ClassId r : w.roots) {
        const u64 h = g.canonical_hash(r);
        if (h != 0) hashes.push_back(h);
    }
    if (hashes.empty()) return out;
    // Sort and dedupe — multiplicity is sensitive to compiler-driven
    // intermediate reordering whereas presence-or-absence is robust.
    // MinHash is multiplicity-invariant by construction; the exact-hash
    // (sorted-multiset fold) DOES drift with multiplicities, so dedup
    // there too for stability.
    std::sort(hashes.begin(), hashes.end());
    hashes.erase(std::unique(hashes.begin(), hashes.end()), hashes.end());

    out.exact_hash   = multiset_exact_hash(hashes);
    out.minhash      = minhash_multiset(hashes);
    out.egraph_nodes = static_cast<u32>(g.node_count());
    out.total_iters  = static_cast<u8>(std::min<std::size_t>(g.total_iters(), 255));
    out.budget_hit   = g.budget_hit();
    return out;
}

float orbit_jaccard(const OrbitSig& a, const OrbitSig& b) noexcept {
    if (a.exact_hash == 0 || b.exact_hash == 0) return 0.0f;
    if (a.exact_hash == b.exact_hash) return 1.0f;
    int eq = 0;
    for (std::size_t i = 0; i < 16; ++i) {
        if (a.minhash[i] == b.minhash[i]) ++eq;
    }
    return static_cast<float>(eq) / 16.0f;
}

}  // namespace ember
