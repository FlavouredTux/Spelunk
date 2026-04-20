#pragma once

#include <vector>

#include <ember/binary/binary.hpp>
#include <ember/common/types.hpp>

namespace ember {

// One RUNTIME_FUNCTION entry from a PE image's `.pdata` section. Addresses
// are absolute VAs (image_base + RVA), consistent with everything else
// Ember exposes. Always sorted ascending by `begin`, duplicates removed.
struct PeUnwindEntry {
    addr_t begin;
    addr_t end;
    // UnwindInfoAddress as an absolute VA. Zero for chained entries and
    // when the .xdata can't be reached. v1 doesn't consume the unwind
    // codes themselves — this field is kept so future passes (prologue
    // recognition, frame-pointer inference) can pick it up without
    // re-parsing the .pdata table.
    addr_t unwind_info;
};

// Walk IMAGE_DIRECTORY_ENTRY_EXCEPTION on a PE binary and return every
// RUNTIME_FUNCTION entry. Returns empty for non-PE binaries or when the
// directory is absent. x86-64 entries only; ARM64 uses a variable-length
// packed format that this parser does not handle.
[[nodiscard]] std::vector<PeUnwindEntry>
parse_pe_pdata(const Binary& b);

}  // namespace ember
