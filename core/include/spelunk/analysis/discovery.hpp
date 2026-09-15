#pragma once

#include <vector>

#include <spelunk/common/types.hpp>

namespace spelunk {

class Binary;
struct Section;

// Canonical code-address predicate for analysis passes. Accepts sections
// with the executable flag or a recognized text-section name.
[[nodiscard]] bool addr_in_code_section(const Binary& b, addr_t a) noexcept;

// Linear-sweep `.text`/code sections for architecture-specific function
// prologue patterns. Each candidate is validated by decoding nearby
// instructions; the address is rejected if validation fails, and skipped
// if it falls inside a section flagged as encrypted (high entropy).
// Designed to recover stripped commercial binaries where stronger
// metadata is missing or zeroed and only the entry-point function is in
// the symbol table.
//
// `lo`/`hi`: when `hi > lo`, the per-section sweep clips its byte
// range to the intersection of the section and [lo, hi). On a
// minidump that's mostly wine-DLL pages this turns a 200MB linear
// sweep into the ~16MB the user actually cares about.
[[nodiscard]] std::vector<addr_t>
discover_from_prologues(const Binary& b, addr_t lo = 0, addr_t hi = 0);

}  // namespace spelunk
