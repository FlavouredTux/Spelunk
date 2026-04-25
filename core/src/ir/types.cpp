#include <ember/ir/types.hpp>

#include <format>
#include <string>

namespace ember {

namespace {

// Pack int (bits, sign_known, is_signed) into a single dedup key.
[[nodiscard]] constexpr u64 int_key(u8 bits, bool sign_known, bool is_signed) noexcept {
    return (static_cast<u64>(bits) << 2)
         | (static_cast<u64>(sign_known ? 1 : 0) << 1)
         |  static_cast<u64>(is_signed ? 1 : 0);
}

[[nodiscard]] constexpr u64 ptr_key(TypeRef pointee, u8 addr_space) noexcept {
    return (static_cast<u64>(pointee.id) << 8) | static_cast<u64>(addr_space);
}

[[nodiscard]] constexpr u64 array_key(TypeRef elem, u32 count) noexcept {
    return (static_cast<u64>(elem.id) << 32) | static_cast<u64>(count);
}

// Cheap mixing for func dedup. Collisions force a fall-through scan, so
// correctness doesn't depend on this being a great hash.
[[nodiscard]] u64 func_key(TypeRef ret, const std::vector<TypeRef>& params,
                            bool varargs, Abi abi) noexcept {
    u64 h = 0xcbf29ce484222325ull;
    auto mix = [&](u64 v) {
        h ^= v;
        h *= 0x100000001b3ull;
    };
    mix(ret.id);
    mix(params.size());
    for (auto p : params) mix(p.id);
    mix(varargs ? 1 : 0);
    mix(static_cast<u64>(abi));
    return h;
}

[[nodiscard]] bool func_equals(const FuncInfo& a, TypeRef ret,
                                const std::vector<TypeRef>& params,
                                bool varargs, Abi abi) noexcept {
    if (a.ret != ret || a.varargs != varargs || a.abi != abi) return false;
    if (a.params.size() != params.size()) return false;
    for (std::size_t k = 0; k < params.size(); ++k) {
        if (a.params[k] != params[k]) return false;
    }
    return true;
}

}  // namespace

TypeArena::TypeArena() {
    nodes_.reserve(16);
    auto seed = [this](TypeKind k) {
        TypeNode n; n.kind = k;
        return push_(std::move(n));
    };
    seed(TypeKind::Top);                         // id 0
    seed(TypeKind::Bottom);                      // id 1
    void_id_ = TypeRef{seed(TypeKind::Void)};

    // Pre-intern the common width-only ints + the two scalar floats so
    // emitter/inferencer hot paths don't pay a hash lookup for them.
    for (u8 bits : {u8{1}, u8{8}, u8{16}, u8{32}, u8{64}}) {
        [[maybe_unused]] auto _ = int_t(bits);
    }
    [[maybe_unused]] auto _f32 = float_t(32);
    [[maybe_unused]] auto _f64 = float_t(64);
}

u32 TypeArena::push_(TypeNode n) {
    nodes_.push_back(std::move(n));
    return static_cast<u32>(nodes_.size() - 1);
}

TypeRef TypeArena::int_t(u8 bits, bool sign_known, bool is_signed) {
    const u64 k = int_key(bits, sign_known, is_signed);
    if (auto it = int_dedup_.find(k); it != int_dedup_.end()) {
        return TypeRef{it->second};
    }
    TypeNode n; n.kind = TypeKind::Int;
    n.i = IntInfo{.bits = bits, .sign_known = sign_known, .is_signed = is_signed};
    const u32 id = push_(std::move(n));
    int_dedup_.emplace(k, id);
    return TypeRef{id};
}

TypeRef TypeArena::float_t(u8 bits) {
    if (auto it = float_dedup_.find(bits); it != float_dedup_.end()) {
        return TypeRef{it->second};
    }
    TypeNode n; n.kind = TypeKind::Float;
    n.f = FloatInfo{.bits = bits};
    const u32 id = push_(std::move(n));
    float_dedup_.emplace(bits, id);
    return TypeRef{id};
}

TypeRef TypeArena::ptr_t(TypeRef pointee, u8 addr_space) {
    const u64 k = ptr_key(pointee, addr_space);
    if (auto it = ptr_dedup_.find(k); it != ptr_dedup_.end()) {
        return TypeRef{it->second};
    }
    TypeNode n; n.kind = TypeKind::Ptr;
    n.p = PtrInfo{.pointee = pointee, .addr_space = addr_space};
    const u32 id = push_(std::move(n));
    ptr_dedup_.emplace(k, id);
    return TypeRef{id};
}

TypeRef TypeArena::array_t(TypeRef elem, u32 count) {
    const u64 k = array_key(elem, count);
    if (auto it = array_dedup_.find(k); it != array_dedup_.end()) {
        return TypeRef{it->second};
    }
    TypeNode n; n.kind = TypeKind::Array;
    n.a = ArrayInfo{.elem = elem, .count = count};
    const u32 id = push_(std::move(n));
    array_dedup_.emplace(k, id);
    return TypeRef{id};
}

TypeRef TypeArena::func_t(TypeRef ret, std::vector<TypeRef> params,
                           bool varargs, Abi abi) {
    const u64 k = func_key(ret, params, varargs, abi);
    auto [lo, hi] = func_dedup_.equal_range(k);
    for (auto it = lo; it != hi; ++it) {
        if (func_equals(nodes_[it->second].fn, ret, params, varargs, abi)) {
            return TypeRef{it->second};
        }
    }
    TypeNode n; n.kind = TypeKind::Func;
    n.fn = FuncInfo{
        .ret = ret, .params = std::move(params),
        .varargs = varargs, .abi = abi,
    };
    const u32 id = push_(std::move(n));
    func_dedup_.emplace(k, id);
    return TypeRef{id};
}

TypeRef TypeArena::struct_t(StructInfo info) {
    if (auto it = struct_dedup_.find(info.name); it != struct_dedup_.end()) {
        return TypeRef{it->second};
    }
    const std::string name = info.name;
    TypeNode n; n.kind = TypeKind::Struct;
    n.s = std::move(info);
    const u32 id = push_(std::move(n));
    struct_dedup_.emplace(name, id);
    return TypeRef{id};
}

TypeRef TypeArena::meet(TypeRef a, TypeRef b) {
    if (a == b) return a;
    if (a.is_top()) return b;
    if (b.is_top()) return a;
    if (a.is_bottom() || b.is_bottom()) return bottom();

    const TypeKind ka = nodes_[a.id].kind;
    const TypeKind kb = nodes_[b.id].kind;
    if (ka != kb) return bottom();

    switch (ka) {
        case TypeKind::Void:
            return a;

        case TypeKind::Int: {
            const auto& ia = nodes_[a.id].i;
            const auto& ib = nodes_[b.id].i;
            if (ia.bits != ib.bits) return bottom();
            // Signedness: prefer the more refined one. If both claim
            // signedness and disagree, that's a conflict.
            bool sk = ia.sign_known || ib.sign_known;
            bool sg = ia.is_signed;
            if (ia.sign_known && ib.sign_known) {
                if (ia.is_signed != ib.is_signed) return bottom();
                sg = ia.is_signed;
            } else if (ib.sign_known) {
                sg = ib.is_signed;
            }
            return int_t(ia.bits, sk, sg);
        }

        case TypeKind::Float: {
            const auto& fa = nodes_[a.id].f;
            const auto& fb = nodes_[b.id].f;
            if (fa.bits != fb.bits) return bottom();
            return a;
        }

        case TypeKind::Ptr: {
            const auto& pa = nodes_[a.id].p;
            const auto& pb = nodes_[b.id].p;
            if (pa.addr_space != pb.addr_space) return bottom();
            const TypeRef pointee = meet(pa.pointee, pb.pointee);
            if (pointee.is_bottom()) return bottom();
            return ptr_t(pointee, pa.addr_space);
        }

        case TypeKind::Array: {
            const auto& aa = nodes_[a.id].a;
            const auto& ab = nodes_[b.id].a;
            // Unknown bound (count==0) yields to known.
            if (aa.count != 0 && ab.count != 0 && aa.count != ab.count) {
                return bottom();
            }
            const TypeRef elem = meet(aa.elem, ab.elem);
            if (elem.is_bottom()) return bottom();
            const u32 count = aa.count ? aa.count : ab.count;
            return array_t(elem, count);
        }

        case TypeKind::Struct:
        case TypeKind::Func:
            // Phase 1: by-identity only. Real unification lands with
            // Phase 3 (function sig IPA) and Phase 4 (struct discovery).
            return bottom();

        case TypeKind::Top:
        case TypeKind::Bottom:
            return bottom();  // unreachable — handled above
    }
    return bottom();
}

std::string TypeArena::format(TypeRef r, int depth) const {
    if (depth > 4) return "...";
    const auto& n = nodes_[r.id];
    switch (n.kind) {
        case TypeKind::Top:    return "top";
        case TypeKind::Bottom: return "bottom";
        case TypeKind::Void:   return "void";
        case TypeKind::Int: {
            const char prefix = n.i.sign_known ? (n.i.is_signed ? 's' : 'u') : 'i';
            return std::format("{}{}", prefix, n.i.bits);
        }
        case TypeKind::Float:
            return std::format("f{}", n.f.bits);
        case TypeKind::Ptr:
            return std::format("ptr({})", format(n.p.pointee, depth + 1));
        case TypeKind::Array:
            if (n.a.count == 0) {
                return std::format("array({})", format(n.a.elem, depth + 1));
            }
            return std::format("array({}, {})", format(n.a.elem, depth + 1), n.a.count);
        case TypeKind::Struct:
            return std::format("struct {}", n.s.name);
        case TypeKind::Func: {
            std::string s = "func(";
            for (std::size_t k = 0; k < n.fn.params.size(); ++k) {
                if (k) s += ", ";
                s += format(n.fn.params[k], depth + 1);
            }
            s += ") -> ";
            s += format(n.fn.ret, depth + 1);
            return s;
        }
    }
    return "?";
}

}  // namespace ember
