#pragma once

#include <cstddef>
#include <map>
#include <string>
#include <vector>

#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember {

enum class BlockKind : u8 {
    Fallthrough,
    Conditional,
    Unconditional,
    Return,
    IndirectJmp,
    Switch,
    // Terminating jmp to a known function entry — treated as
    // `call target; return rax;` at the IR level.
    TailCall,
};

[[nodiscard]] constexpr std::string_view block_kind_name(BlockKind k) noexcept {
    switch (k) {
        case BlockKind::Fallthrough:   return "fallthrough";
        case BlockKind::Conditional:   return "conditional";
        case BlockKind::Unconditional: return "unconditional";
        case BlockKind::Return:        return "return";
        case BlockKind::IndirectJmp:   return "indirect";
        case BlockKind::Switch:        return "switch";
        case BlockKind::TailCall:      return "tail-call";
    }
    return "?";
}

struct BasicBlock {
    addr_t                   start        = 0;
    addr_t                   end          = 0;
    std::vector<Instruction> instructions;
    BlockKind                kind         = BlockKind::Fallthrough;
    // For Switch kind: successors = [case0, case1, ..., caseN-1, default?]
    // case_values[i] corresponds to successors[i] for i < case_values.size().
    // If has_default, successors.back() is the default target (not in case_values).
    std::vector<addr_t>      successors;
    std::vector<addr_t>      predecessors;
    std::vector<i64>         case_values;
    bool                     has_default  = false;
    // The register whose value selects the case (for the emitter).
    Reg                      switch_index = Reg::None;
};

struct Function {
    addr_t                           start = 0;
    addr_t                           end   = 0;
    std::string                      name;
    std::vector<BasicBlock>          blocks;
    std::map<addr_t, std::size_t>    block_at;
    std::vector<addr_t>              call_targets;

    [[nodiscard]] std::size_t edge_count() const noexcept {
        std::size_t n = 0;
        for (const auto& b : blocks) n += b.successors.size();
        return n;
    }
};

}  // namespace ember
