#pragma once

#include <cstddef>
#include <span>

namespace ember {

struct Binary;
struct Section;

// Shannon entropy over the byte distribution. Range [0.0, 8.0]. Uniform
// random bytes sit at ~7.99; ASCII text and typical x86 code sit around
// 4.5–6.5; encrypted / compressed payloads sit at 7.5+.
[[nodiscard]] double section_entropy(std::span<const std::byte> data) noexcept;

// True when a section's bytes look encrypted/packed — high entropy and
// large enough that the entropy estimate is meaningful (tiny sections
// are noisy).
[[nodiscard]] bool section_looks_encrypted(const Section& s) noexcept;

// True when the binary as a whole looks packed (Byfron / VMProtect /
// Themida style). Uses geometric heuristics — entry in non-exec
// section, large code-shaped section without exec flag, or any
// executable section that's encrypted.
[[nodiscard]] bool binary_looks_packed(const Binary& b) noexcept;

}  // namespace ember
