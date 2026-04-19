#pragma once

#include <memory>
#include <string>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

enum class RegionKind : u8 {
    Empty,
    Block,
    Seq,
    IfThen,
    IfElse,
    While,      // while (cond) { body }  — condition tested at top
    DoWhile,    // do { body } while (cond)  — condition tested after body
    For,        // for (; cond; update) { body } — induction-var pattern
    Loop,       // for (;;) { … }  — no recognized exit condition
    Switch,
    Return,
    Unreachable,
    Break,
    Continue,
    Goto,
};

struct Region {
    RegionKind                           kind        = RegionKind::Empty;
    addr_t                               block_start = 0;
    IrValue                              condition   = {};
    bool                                 invert      = false;
    addr_t                               target      = 0;
    std::vector<std::unique_ptr<Region>> children;
    // For Switch: case_values is parallel to the first N children (case bodies);
    // if has_default, children.back() is the default region.
    std::vector<i64>                     case_values;
    bool                                 has_default = false;
    // For Switch: the register whose value selects the case (display-only).
    Reg                                  switch_index = Reg::None;
    // For For: location of the update statement in the IR, so the emitter
    // can render it in the for-header and suppress it in the body. Only
    // meaningful when kind == For.
    addr_t                               update_block  = 0;
    u32                                  update_inst   = 0;
    bool                                 has_update    = false;
};

struct StructuredFunction {
    const IrFunction*        ir = nullptr;
    std::unique_ptr<Region>  body;
};

[[nodiscard]] std::string format_structured(const StructuredFunction& sf);

}  // namespace ember
