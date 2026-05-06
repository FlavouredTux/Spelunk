#pragma once

#include <string>
#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

// Symbolic expression materialized from an SSA value. Leaves are
// parameters (live-in arg regs), constants, opaque call results, or
// truly unknown values; interior nodes are loads, arithmetic, and
// comparisons. Phi nodes only appear when the chosen path didn't
// uniquely select an incoming version (path-relative phi resolution
// usually collapses them away).
struct ForgeExpr {
    enum class Kind : u8 {
        Unknown,
        Param,
        Imm,
        Load,
        BinOp,
        Cmp,
        Phi,
        Call,
    };

    Kind                   kind        = Kind::Unknown;
    Reg                    param_reg   = Reg::None;
    int                    param_index = -1;            // 0-based ABI slot
    i64                    imm         = 0;
    IrOp                   op          = IrOp::Nop;     // BinOp / Cmp / Phi
    IrType                 width       = IrType::I64;
    std::vector<ForgeExpr> children;
    addr_t                 call_target = 0;             // Call kind only
};

[[nodiscard]] std::string format_forge_expr(const ForgeExpr& e);

// One conditional decision the chosen path traversed. `went_taken`
// records which CondBranch successor the path used; the formatter
// inverts the comparison when reporting `pretty` for the not-taken
// case so the predicate always reads as the constraint that holds.
struct BranchDecision {
    addr_t      branch_va        = 0;
    addr_t      taken_target     = 0;
    addr_t      not_taken_target = 0;
    bool        went_taken       = false;
    addr_t      in_function      = 0;        // entry of the fn this branch lives in
    ForgeExpr   condition;
    std::string pretty;
};

// A constraint extracted from comparing a load chain rooted at a
// function parameter against another expression. `offset_chain` is
// the sequence of dereferences from outermost: `{0x138, 0x60}` means
// the constraint touches `*(*(arg + 0x138) + 0x60)`. An empty offset
// chain is a constraint on the parameter itself.
struct FieldRequirement {
    int                  param_index   = -1;
    Reg                  param_reg     = Reg::None;
    std::vector<i64>     offset_chain;
    IrType               access_width  = IrType::I64;
    IrOp                 cmp_op        = IrOp::Nop;
    ForgeExpr            rhs;
    bool                 lhs_is_field  = true;
    bool                 must_be_taken = false;
    addr_t               site_va       = 0;
    addr_t               in_function   = 0;
};

struct ForgeSpec {
    addr_t                        entry_va        = 0;
    addr_t                        target_va       = 0;
    bool                          reachable       = false;
    std::string                   entry_name;
    std::string                   target_fn_name;
    // Entry-to-target call chain (entry first, target's containing fn last).
    std::vector<addr_t>           call_chain;
    std::vector<BranchDecision>   branches;
    std::vector<FieldRequirement> fields;
    std::vector<std::string>      warnings;
};

// Compute the minimum struct-field map and branch-decision sequence
// that a single representative call chain from `entry_va` to
// `target_va` requires. Intra-procedural and chosen path is the
// shortest CFG path through each function on the chain — by design
// this is one *witness* for reachability, not the meet of all
// possible reaching paths. Loops are unrolled at most once. Live-in
// arg regs are interpreted as parameters using the binary's ABI.
[[nodiscard]] Result<ForgeSpec>
infer_forge_spec(const Binary& b, addr_t entry_va, addr_t target_va);

[[nodiscard]] std::string format_forge_spec(const ForgeSpec& spec);
[[nodiscard]] std::string format_forge_spec_json(const ForgeSpec& spec);

}  // namespace ember
