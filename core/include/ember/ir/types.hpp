#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/abi.hpp>

namespace ember {

// First-class types for the IR. Decoupled from the bit-width-only `IrType`
// every SSA value still carries; this lattice runs alongside as a
// refinement layer that Phase 2+ inference will populate. Phase 1 wires
// the lattice and arena only — no SSA value is annotated yet, so the
// effective type of every value is Top (unknown).
enum class TypeKind : u8 {
    Top,        // id == 0
    Bottom,     // id == 1 — irreconcilable conflict
    Void,
    Int,
    Float,
    Ptr,
    Struct,
    Array,
    Func,
};

[[nodiscard]] constexpr std::string_view type_kind_name(TypeKind k) noexcept {
    switch (k) {
        case TypeKind::Top:    return "top";
        case TypeKind::Bottom: return "bottom";
        case TypeKind::Void:   return "void";
        case TypeKind::Int:    return "int";
        case TypeKind::Float:  return "float";
        case TypeKind::Ptr:    return "ptr";
        case TypeKind::Struct: return "struct";
        case TypeKind::Array:  return "array";
        case TypeKind::Func:   return "func";
    }
    return "?";
}

// Opaque handle into a TypeArena. id 0 is always Top, id 1 is always
// Bottom; primitives (void, i1..i64, f32/f64) get stable ids assigned at
// arena construction.
struct TypeRef {
    u32 id = 0;

    [[nodiscard]] constexpr bool is_top()    const noexcept { return id == 0; }
    [[nodiscard]] constexpr bool is_bottom() const noexcept { return id == 1; }
    [[nodiscard]] constexpr bool operator==(const TypeRef&) const noexcept = default;
};

struct StructField {
    u32         offset = 0;
    TypeRef     type   = {};
    std::string name;
};

struct IntInfo    { u8 bits = 0; bool sign_known = false; bool is_signed = false; };
struct FloatInfo  { u8 bits = 0; };
struct PtrInfo    { TypeRef pointee = {}; u8 addr_space = 0; };
struct StructInfo { std::string name; std::vector<StructField> fields; u32 size = 0; u32 align = 0; };
struct ArrayInfo  { TypeRef elem = {}; u32 count = 0; };  // count==0 == unknown bound
struct FuncInfo   {
    TypeRef              ret = {};
    std::vector<TypeRef> params;
    bool                 varargs = false;
    Abi                  abi     = Abi::Unknown;
};

struct TypeNode {
    TypeKind   kind = TypeKind::Top;
    IntInfo    i;
    FloatInfo  f;
    PtrInfo    p;
    StructInfo s;
    ArrayInfo  a;
    FuncInfo   fn;
};

// Interned, content-addressed type pool. Cheap to construct; one per
// IrFunction (Phase 1) and eventually one per Binary for cross-function
// unification (Phase 3). All ids are stable for the arena's lifetime.
class TypeArena {
public:
    TypeArena();

    [[nodiscard]] TypeRef top()    const noexcept { return TypeRef{0}; }
    [[nodiscard]] TypeRef bottom() const noexcept { return TypeRef{1}; }
    [[nodiscard]] TypeRef void_t() const noexcept { return void_id_; }

    [[nodiscard]] TypeRef int_t(u8 bits, bool sign_known = false,
                                bool is_signed = false);
    [[nodiscard]] TypeRef float_t(u8 bits);

    [[nodiscard]] TypeRef ptr_t(TypeRef pointee, u8 addr_space = 0);
    [[nodiscard]] TypeRef array_t(TypeRef elem, u32 count = 0);
    [[nodiscard]] TypeRef func_t(TypeRef ret, std::vector<TypeRef> params,
                                  bool varargs = false, Abi abi = Abi::Unknown);
    // Structs intern by name. Anonymous structs need a synthesized name
    // (Phase 4 will hash field shape into one); Phase 1 callers shouldn't
    // need this directly.
    [[nodiscard]] TypeRef struct_t(StructInfo info);

    [[nodiscard]] const TypeNode& node(TypeRef r) const noexcept {
        return nodes_[r.id];
    }
    [[nodiscard]] TypeKind kind(TypeRef r) const noexcept {
        return nodes_[r.id].kind;
    }
    [[nodiscard]] std::size_t size() const noexcept { return nodes_.size(); }

    // Greatest-lower-bound: combines two pieces of evidence about the
    // same value. Top is identity, Bottom is absorbing; mismatched
    // primitives → Bottom; pointer pointees recurse.
    [[nodiscard]] TypeRef meet(TypeRef a, TypeRef b);

    [[nodiscard]] std::string format(TypeRef r, int depth = 0) const;

private:
    std::vector<TypeNode> nodes_;

    std::unordered_map<u64, u32>         int_dedup_;
    std::unordered_map<u8,  u32>         float_dedup_;
    std::unordered_map<u64, u32>         ptr_dedup_;
    std::unordered_map<u64, u32>         array_dedup_;
    std::unordered_map<std::string, u32> struct_dedup_;
    std::unordered_map<u64, u32>         func_dedup_;

    TypeRef void_id_ = {};

    [[nodiscard]] u32 push_(TypeNode n);
};

}  // namespace ember
