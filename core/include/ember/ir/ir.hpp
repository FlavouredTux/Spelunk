#pragma once

#include <array>
#include <cstddef>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <ember/analysis/function.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/types.hpp>

namespace ember {

enum class IrType : u8 {
    I1,
    I8,
    I16,
    I32,
    I64,
    // 128-bit register-shaped value. Used for XMM/SSE dataflow so the upper
    // 64 bits of a vector aren't silently truncated through the F64 surrogate
    // the lifter used to fall back on. Interpretation (packed-int vs packed-fp)
    // is carried by the named SIMD intrinsic, not the IR type tag — the type
    // just guarantees the bit-width is preserved across SSA / cleanup / emit.
    // Constant folding doesn't apply (no I128 immediates); arithmetic at this
    // width only happens through Intrinsic nodes.
    I128,
    F32,
    F64,
};

[[nodiscard]] constexpr unsigned type_bits(IrType t) noexcept {
    switch (t) {
        case IrType::I1:   return 1;
        case IrType::I8:   return 8;
        case IrType::I16:  return 16;
        case IrType::I32:  return 32;
        case IrType::I64:  return 64;
        case IrType::I128: return 128;
        case IrType::F32:  return 32;
        case IrType::F64:  return 64;
    }
    return 0;
}

[[nodiscard]] constexpr bool is_float_type(IrType t) noexcept {
    return t == IrType::F32 || t == IrType::F64;
}

[[nodiscard]] constexpr IrType type_for_bits(unsigned bits) noexcept {
    switch (bits) {
        case 1:   return IrType::I1;
        case 8:   return IrType::I8;
        case 16:  return IrType::I16;
        case 32:  return IrType::I32;
        case 64:  return IrType::I64;
        case 128: return IrType::I128;
        default:  return IrType::I64;
    }
}

[[nodiscard]] constexpr std::string_view type_name(IrType t) noexcept {
    switch (t) {
        case IrType::I1:   return "i1";
        case IrType::I8:   return "i8";
        case IrType::I16:  return "i16";
        case IrType::I32:  return "i32";
        case IrType::I64:  return "i64";
        case IrType::I128: return "i128";
        case IrType::F32:  return "f32";
        case IrType::F64:  return "f64";
    }
    return "?";
}

enum class Flag : u8 { Zf, Sf, Cf, Of };

[[nodiscard]] constexpr std::string_view flag_name(Flag f) noexcept {
    switch (f) {
        case Flag::Zf: return "zf";
        case Flag::Sf: return "sf";
        case Flag::Cf: return "cf";
        case Flag::Of: return "of";
    }
    return "?";
}

enum class IrValueKind : u8 { None, Reg, Temp, Imm, Flag };

struct IrValue {
    IrValueKind      kind    = IrValueKind::None;
    IrType           type    = IrType::I64;
    Reg              reg     = Reg::None;
    u32              temp    = 0;
    i64              imm     = 0;
    ember::Flag   flag    = Flag::Zf;
    u32              version = 0;   // SSA version; 0 = pre-SSA or live-in

    [[nodiscard]] static IrValue make_reg(Reg r, IrType t) noexcept {
        IrValue v; v.kind = IrValueKind::Reg; v.type = t; v.reg = r; return v;
    }
    [[nodiscard]] static IrValue make_temp(u32 id, IrType t) noexcept {
        IrValue v; v.kind = IrValueKind::Temp; v.type = t; v.temp = id; return v;
    }
    [[nodiscard]] static IrValue make_imm(i64 v, IrType t) noexcept {
        IrValue r; r.kind = IrValueKind::Imm; r.type = t; r.imm = v; return r;
    }
    [[nodiscard]] static IrValue make_flag(ember::Flag f) noexcept {
        IrValue v; v.kind = IrValueKind::Flag; v.type = IrType::I1; v.flag = f; return v;
    }
};

enum class IrOp : u16 {
    Nop,

    Assign,
    Load,
    Store,

    Add, Sub, Mul, Div, Mod,
    And, Or, Xor,
    Neg, Not,
    Shl, Lshr, Ashr,

    // Ternary select: srcs[0] is an i1 condition, srcs[1] is the value when
    // true, srcs[2] is the value when false. Used to lift CMOVcc as a clean
    // dataflow node so the emitter can render `(cond ? a : b)` instead of
    // an opaque intrinsic.
    Select,

    CmpEq, CmpNe,
    CmpUlt, CmpUle, CmpUgt, CmpUge,
    CmpSlt, CmpSle, CmpSgt, CmpSge,

    ZExt, SExt, Trunc,

    AddCarry, SubBorrow,
    AddOverflow, SubOverflow,

    Branch, BranchIndirect,
    CondBranch,
    Call, CallIndirect,
    Return, Unreachable,

    Phi,
    Clobber,   // dst becomes undefined — models caller-saved regs across calls.
               // Non-side-effecting; DCE removes it if the new SSA value is unused.

    Intrinsic,
};

[[nodiscard]] std::string_view op_name(IrOp op) noexcept;

[[nodiscard]] constexpr bool is_terminator(IrOp op) noexcept {
    switch (op) {
        case IrOp::Branch:
        case IrOp::BranchIndirect:
        case IrOp::CondBranch:
        case IrOp::Return:
        case IrOp::Unreachable:
            return true;
        default:
            return false;
    }
}

struct IrInst {
    IrOp                    op          = IrOp::Nop;
    IrValue                 dst         = {};
    std::array<IrValue, 3>  srcs        = {};
    u8                      src_count   = 0;
    addr_t                  source_addr = 0;
    addr_t                  target1     = 0;
    addr_t                  target2     = 0;
    Reg                     segment     = Reg::None;
    std::string             name;
    std::vector<IrValue>    phi_operands;
    std::vector<addr_t>     phi_preds;
};

struct IrBlock {
    addr_t               start = 0;
    addr_t               end   = 0;
    std::vector<IrInst>  insts;
    BlockKind            kind  = BlockKind::Fallthrough;
    std::vector<addr_t>  successors;
    std::vector<addr_t>  predecessors;
    // Switch-block metadata mirrored from BasicBlock. Parallel to the first
    // N entries of `successors`; if `has_default`, `successors.back()` is
    // the default target (not in case_values).
    std::vector<i64>     case_values;
    bool                 has_default  = false;
    Reg                  switch_index = Reg::None;
};

// Pack an SSA value's identity into a single key for the value_types
// side table. Distinct from ssa.hpp's `ssa_key` (which returns a tuple
// for SSA-conversion bookkeeping) — this one is just a hash key.
[[nodiscard]] inline u64 value_type_key(const IrValue& v) noexcept {
    auto pack = [](IrValueKind kind, u32 id, u32 version) -> u64 {
        return (static_cast<u64>(static_cast<u8>(kind)) << 56)
             | (static_cast<u64>(id) << 32)
             |  static_cast<u64>(version);
    };
    switch (v.kind) {
        case IrValueKind::Reg:
            return pack(v.kind, static_cast<u32>(v.reg), v.version);
        case IrValueKind::Temp:
            return pack(v.kind, v.temp, v.version);
        case IrValueKind::Flag:
            return pack(v.kind, static_cast<u32>(v.flag), v.version);
        default:
            return 0;
    }
}

struct IrFunction {
    addr_t                            start = 0;
    addr_t                            end   = 0;
    std::string                       name;
    std::vector<IrBlock>              blocks;
    std::map<addr_t, std::size_t>     block_at;
    u32                               next_temp_id = 0;

    // Phase 1 type lattice: every SSA value defaults to Top (unknown).
    // value_types is sparse — a missing entry means Top, so the lifter
    // doesn't have to populate anything for the no-inference baseline.
    // Phase 2 inference will start writing entries here.
    TypeArena                         types;
    std::unordered_map<u64, TypeRef>  value_types;

    [[nodiscard]] TypeRef type_of(const IrValue& v) const noexcept {
        const u64 k = value_type_key(v);
        if (k == 0) return TypeRef{};  // Imm / None — typed by IrValue.type
        auto it = value_types.find(k);
        return it == value_types.end() ? TypeRef{} : it->second;
    }
};

[[nodiscard]] std::string format_ir_value(const IrValue& v);
[[nodiscard]] std::string format_ir_inst(const IrInst& inst);
[[nodiscard]] std::string format_ir_function(const IrFunction& fn);

}  // namespace ember
