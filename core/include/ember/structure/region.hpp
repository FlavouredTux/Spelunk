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
    While,
    Loop,
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
};

struct StructuredFunction {
    const IrFunction*        ir = nullptr;
    std::unique_ptr<Region>  body;
};

[[nodiscard]] std::string format_structured(const StructuredFunction& sf);

}  // namespace ember
