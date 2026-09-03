#pragma once

// Shared between strings.cpp (the scanner) and the analyses layered on
// it: string_names.cpp and log_categories.cpp.

#include <cstddef>
#include <span>
#include <vector>

#include <ember/analysis/pipeline.hpp>
#include <ember/analysis/strings.hpp>
#include <ember/binary/binary.hpp>

namespace ember {

inline constexpr std::size_t kMinStringLen = 4;
inline constexpr std::size_t kMaxStringLen = 1024;

[[nodiscard]] inline bool is_string_byte(unsigned char c) noexcept {
    if (c == '\t' || c == '\n' || c == '\r') return true;
    return c >= 0x20 && c <= 0x7e;
}

// Extract printable strings from a single section. Each NUL terminator
// ends the current run; overlapping/adjacent runs are independent entries
// (one per start offset).
void scan_section(const Section& sec, std::vector<StringEntry>& out,
                  const StringScanOptions& options);

// Callers that already discovered functions pass them in so the scan can
// attribute references without repeating discovery.
[[nodiscard]] std::vector<StringEntry>
scan_strings_impl(const Binary& b, const StringScanOptions& options,
                  std::span<const DiscoveredFunction> discovered_functions,
                  bool have_discovered_functions);

}  // namespace ember
