#pragma once

#include <string>
#include <vector>

#include <ember/analysis/symtable.hpp>
#include <ember/binary/binary.hpp>
#include <ember/common/error.hpp>
#include <ember/common/types.hpp>

namespace ember::analysis {

// One reference site: an instruction at `callsite` that takes the
// address of (or otherwise references) the string at `string_va`.
struct SymUseSite {
    addr_t       callsite  = 0;
    addr_t       string_va = 0;
    std::string  name;
};

// One row of the per-function aggregated view. `sites` is sorted by
// callsite address. `walks_full_table` is set when the function has
// access to the table base - either by direct rip-rel ref to it or
// by reading a slot whose value is the table base. Loose-scope rows
// have non-empty `base_load_sites`; that's the diagnostic signal for
// "we admitted this fn into the scope because it loads the base via
// imm64-stored / relocated slot".
struct SymUseRow {
    addr_t                  fn_addr          = 0;
    std::string             fn_name;
    std::vector<SymUseSite> sites;
    bool                    walks_full_table = false;
    std::vector<addr_t>     base_load_sites;
};

struct SymUses {
    SymtableWalk           walk;
    std::vector<SymUseRow> rows;     // sorted by descending unique-symbol count
    // Diagnostic counters: how the scope was constructed. Surfaced by
    // the CLI as `# scope: N candidates from refs-to-loose` so the
    // operator can sanity-check the heuristic on an unfamiliar binary.
    std::size_t scope_fn_count        = 0;
    std::size_t scope_imm64_slots     = 0;
    std::size_t scope_relocated_slots = 0;
};

struct SymUseOptions {
    // When true, drop the lightweight register-taint walker and emit
    // every IMM operand in candidate fns that lands on an exact entry
    // offset. Bumps recall but spikes false positives - `0x10` is a
    // common struct-field constant and matches `_ITM_*` on a typical
    // ELF table. Diagnostic only.
    bool no_taint = false;
};

// Walk the string table at `table_va`, then for each entry surface
// every function whose body references it. Three discovery paths:
//   (1) direct rip-rel / abs-mem refs to the entry VA
//       (the `lea reg, [rip+entry_va]` shape)
//   (2) imm64-stored slots - readable-section qwords that hold
//       `table_va`; functions that read those slots are admitted
//   (3) ELF R_*_RELATIVE relocations whose addend == table_va
// For paths (2)/(3), each candidate fn is re-decoded under a tiny
// register-taint walker that propagates the table-base register
// through `mov reg, src_reg`, emits offsets at `add tainted, IMM`
// and `lea reg, [tainted + disp]` (no index), and clears taint on
// branches / calls / generic writes. Errors only on an unmapped
// `table_va`.
[[nodiscard]] Result<SymUses>
collect_symbol_uses(const Binary& b, addr_t table_va,
                    SymUseOptions opts = {});

}  // namespace ember::analysis
