#pragma once

#include <map>
#include <optional>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// An exception-handler landing pad the unwinder will jump to when a call
// inside the associated function throws. `lp_addr == 0` is a "cleanup"
// landing pad — always runs during unwind; doesn't catch a specific type.
// `action_index` points into the LSDA action table (1-based); we don't
// decode actions yet, so 0 means "no typed catch information available".
struct LandingPad {
    addr_t lp_addr      = 0;
    u64    action_index = 0;
};

// Map from call-site instruction address to its landing pad, aggregated
// across all FDEs in the binary's __eh_frame / .eh_frame section.
// Empty map = no EH data present (or format not yet supported).
using LpMap = std::map<addr_t, LandingPad>;

// Parse the binary's DWARF CFI (__eh_frame / .eh_frame) and per-function
// LSDAs (__gcc_except_tab / .gcc_except_table) to build the call-site →
// landing-pad map. Mach-O and ELF share the same CFI/LSDA format; PE/COFF
// uses a different scheme and is not handled yet.
[[nodiscard]] LpMap parse_landing_pads(const Binary& b);

// Convenience lookup. Returns nullopt if no landing pad is registered for
// `call_site` or if the map is empty.
[[nodiscard]] inline std::optional<LandingPad>
landing_pad_for(const LpMap& m, addr_t call_site) {
    auto it = m.find(call_site);
    if (it == m.end()) return std::nullopt;
    return it->second;
}

}  // namespace ember
