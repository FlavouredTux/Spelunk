#pragma once

#include <vector>

#include <ember/common/types.hpp>

namespace ember {

class Binary;

// Vtable slot harvest. Walks Itanium and MSVC RTTI (whichever applies
// to the binary's format), returns each method-slot address that
// already lands in an executable section. Cheap — RTTI parsing is
// already required for naming.
[[nodiscard]] std::vector<addr_t> discover_from_vtables(const Binary& b);

// Linear-sweep `.text` for x64 function prologue byte patterns. Each
// candidate is validated by decoding two instructions; the address is
// rejected if either fails, and skipped if it falls inside a section
// flagged as encrypted (high entropy). Designed to recover stripped
// commercial binaries where `.pdata` is missing or zeroed and only
// the entry-point function is in the symbol table.
[[nodiscard]] std::vector<addr_t> discover_from_prologues(const Binary& b);

}  // namespace ember
