#pragma once

// Shared analysis state and the individual cleanup passes. Private to the
// passes*.cpp translation units.

#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <span>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include <spelunk/ir/passes.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/ir/ssa.hpp>

namespace spelunk::ir_passes {

[[nodiscard]] i64 mask_signed(i64 v, IrType t) noexcept;

[[nodiscard]] u64 mask_unsigned(i64 v, IrType t) noexcept;

// ============================================================================
// Iterate over value references in an instruction
// ============================================================================
template <class F>
void for_each_use(IrInst& inst, F f) {
    if (inst.op == IrOp::Phi) {
        for (auto& v : inst.phi_operands) f(v);
    } else {
        for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
            f(inst.srcs[k]);
        }
    }
}

template <class F>
void for_each_use(const IrInst& inst, F f) {
    if (inst.op == IrOp::Phi) {
        for (const auto& v : inst.phi_operands) f(v);
    } else {
        for (u8 k = 0; k < inst.src_count && k < inst.srcs.size(); ++k) {
            f(inst.srcs[k]);
        }
    }
}

// ============================================================================
// AnalysisManager - lazy, invalidatable function-wide analyses
// ============================================================================
//
// Today there's just one cached analysis: a `SsaKey -> (block, inst)` map of
// every instruction's SSA-keyed dst. cast_simplify, trivial_phi, and dce all
// used to rebuild this independently each call; the manager builds it once
// per fixpoint iteration and only rebuilds after a pass that mutates dst
// locations (currently just DCE, which deletes instructions).
struct DefLoc { u32 block; u32 inst; };

// SsaKey is std::tuple<u8, u32, u32>; the standard library doesn't auto-
// hash tuples, so the cleanup pipeline historically stored its lookups
// in std::map<SsaKey, …> (red-black tree, every probe = O(log N) plus
// a heap-allocated node per insert). Profiling on spelunk-on-itself
// identified copy_prop, trivial_phi, and the def-map cache as hot - all
// of them are hash-shaped lookups by their nature. A simple mix of the
// three fields is enough; all SsaKeys with kind != 3 (Imm) have the
// version field 0 most of the time, so we make sure it's mixed in too.
struct SsaKeyHash {
    [[nodiscard]] std::size_t operator()(const SsaKey& k) const noexcept {
        const auto [kind, id, ver] = k;
        u64 h = static_cast<u64>(id) * 0x9E3779B97F4A7C15ull;
        h ^= static_cast<u64>(ver) * 0xBF58476D1CE4E5B9ull;
        h ^= static_cast<u64>(kind) * 0x94D049BB133111EBull;
        h ^= h >> 30;
        return static_cast<std::size_t>(h);
    }
};

template <typename V>
using SsaMap = std::unordered_map<SsaKey, V, SsaKeyHash>;

class AnalysisManager {
public:
    void invalidate_defs() noexcept { def_map_.reset(); }

    const SsaMap<DefLoc>& defs(const IrFunction& fn) {
        if (!def_map_) {
            SsaMap<DefLoc> m;
            // Reserve up-front so the rehash storm during construction
            // turns into a single allocation. ~1 entry per IR inst is a
            // safe upper bound (only insts with stable dsts contribute).
            std::size_t reserve = 0;
            for (const auto& bb : fn.blocks) reserve += bb.insts.size();
            m.reserve(reserve);
            for (u32 bi = 0; bi < fn.blocks.size(); ++bi) {
                const auto& bb = fn.blocks[bi];
                for (u32 ii = 0; ii < bb.insts.size(); ++ii) {
                    if (auto k = ssa_key(bb.insts[ii].dst); k) {
                        m[*k] = {bi, ii};
                    }
                }
            }
            def_map_ = std::move(m);
        }
        return *def_map_;
    }

private:
    std::optional<SsaMap<DefLoc>> def_map_;
};

// Walk either a caller-supplied block list or all blocks. Pass entries use
// this so the same body handles both first-iteration full sweeps and
// subsequent dirty-only sweeps.
template <class F>
void for_blocks(IrFunction& fn, std::span<const u32> blocks, F f) {
    for (u32 bi : blocks) f(bi, fn.blocks[bi]);
}

[[nodiscard]] std::optional<IrValue>
try_fold(const IrInst& inst) noexcept;

[[nodiscard]] std::size_t pass_constant_fold(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_copy_prop(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_trivial_phi(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched);

[[nodiscard]] bool is_side_effect(IrOp op) noexcept;

// ============================================================================
// Pass: local GVN (intra-block value numbering)
// ============================================================================
//
// Collapses duplicate pure computations within a block into a single temp,
// so that downstream consumers (including memory_forward) see stable SSA
// identities for equivalent expressions like `rsp - 0x14`, which the lifter
// emits afresh every time it computes an effective address.
struct GvnOp {
    u8                                               op;      // IrOp cast
    u8                                               type;    // dst IrType
    std::array<std::optional<SsaKey>, 3>             src_keys;
    std::array<i64, 3>                               imm_vals;
    std::array<u8,  3>                               src_forms;  // 0=None, 1=Imm, 2=Key

    bool operator<(const GvnOp& o) const noexcept {
        if (op    != o.op)    return op    < o.op;
        if (type  != o.type)  return type  < o.type;
        for (std::size_t i = 0; i < 3; ++i) {
            if (src_forms[i] != o.src_forms[i]) return src_forms[i] < o.src_forms[i];
            if (src_forms[i] == 1) {
                if (imm_vals[i] != o.imm_vals[i]) return imm_vals[i] < o.imm_vals[i];
            } else if (src_forms[i] == 2) {
                if (src_keys[i] != o.src_keys[i]) return src_keys[i] < o.src_keys[i];
            }
        }
        return false;
    }
};

[[nodiscard]] bool gvn_eligible(IrOp op) noexcept;

[[nodiscard]] std::optional<GvnOp> gvn_key_of(const IrInst& inst) noexcept;

enum class AddressClass : u8 { Unknown, Absolute, Stack };

struct AddressForm {
    AddressClass cls = AddressClass::Unknown;
    i64 offset = 0;
};

[[nodiscard]] AddressForm resolve_address_form(
    const IrFunction& fn, const SsaMap<DefLoc>& defs,
    IrValue value, unsigned depth = 0) noexcept;

[[nodiscard]] bool definitely_no_alias(AddressForm a, std::size_t a_size,
                                       AddressForm b, std::size_t b_size) noexcept;

[[nodiscard]] bool same_address(const IrValue& a, AddressForm af,
                                const IrValue& b, AddressForm bf) noexcept;

[[nodiscard]] std::size_t memory_width(IrType type) noexcept;

[[nodiscard]] std::size_t pass_local_gvn(
    IrFunction& fn, AnalysisManager& /*am*/,
    std::span<const u32> dirty, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_dead_store_elim(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_memory_forward(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_cast_simplify(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched);

[[nodiscard]] std::size_t pass_dce(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> /*dirty*/, std::vector<u32>& touched);

const IrInst* strip_assigns_to_def(const IrFunction& fn,
                                   const SsaMap<DefLoc>& defs,
                                   IrValue v, int max_hops = 8);

const IrValue* match_sign_extend_shift(const IrFunction& fn,
                                       const SsaMap<DefLoc>& defs,
                                       const IrValue& v);

const IrValue* match_sign_mask(const IrFunction& fn,
                               const SsaMap<DefLoc>& defs,
                               const IrValue& v);

struct IdiomRewrite {
    std::size_t insert_before;
    IrInst replacement;
    std::vector<IrInst> helpers;
};

[[nodiscard]] std::size_t pass_idiom_recognize(
    IrFunction& fn, AnalysisManager& am,
    std::span<const u32> dirty, std::vector<u32>& touched);

std::size_t pass_msvc_security_cookie_return(IrFunction& fn,
                                             AnalysisManager& am);

CleanupStats run_pipeline(IrFunction& fn);

}  // namespace spelunk::ir_passes
