#pragma once

// Private state and phase boundaries shared by the CFG builder implementation
// units. This is deliberately kept under src/: none of these details are part
// of CfgBuilder's public API.

#include <map>
#include <optional>
#include <set>
#include <unordered_set>
#include <vector>

#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>
#include <spelunk/disasm/register.hpp>

namespace spelunk {

class Binary;
class Decoder;
struct Function;

namespace cfg_builder_detail {

struct JumpTable {
    std::vector<addr_t>  targets;
    std::vector<i64>     values;  // parallel to targets (0, 1, 2, …)
    std::optional<addr_t> default_tgt;
    Reg                  index_reg = Reg::None;
};

struct WalkState {
    std::map<addr_t, Instruction> insns;
    std::set<addr_t>              leaders;
    std::unordered_set<addr_t>    call_seen;
    std::vector<addr_t>           calls;
    // Direct calls known not to return. Partition treats these as terminal
    // blocks so cleanup/cold bytes after stack-fail/abort paths do not get
    // pulled into the normal fallthrough CFG.
    std::set<addr_t>              noreturn_calls;
    // Switch tables, keyed by the address of the indirect jmp that reads them.
    std::map<addr_t, JumpTable>   tables;
    // Addresses of `jmp`s that are tail calls (target is a known function
    // entry or PLT stub). Partition converts these into TailCall blocks.
    std::set<addr_t>              tail_calls;
    // Resolved targets for register-indirect PPC branches such as
    // `lis/ori/mtctr/bctrl` where the local instruction window proves CTR.
    std::map<addr_t, addr_t>      resolved_indirect;
};

[[nodiscard]] std::optional<JumpTable>
detect_jump_table(const Binary& binary, const WalkState& state, addr_t jmp_addr);

[[nodiscard]] std::optional<addr_t>
resolve_ppc_ctr_target(const Binary& binary, const WalkState& state,
                       addr_t branch_addr);

void walk_from(const Binary& binary, const Decoder& decoder, WalkState& state,
               addr_t entry, const std::unordered_set<addr_t>& known_entries,
               addr_t owner_begin, addr_t owner_end);

void partition(const Binary& binary, const WalkState& state, Function& function);

void compute_predecessors(Function& function);

}  // namespace cfg_builder_detail
}  // namespace spelunk
