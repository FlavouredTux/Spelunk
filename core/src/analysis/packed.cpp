#include <ember/analysis/packed.hpp>

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

#include <ember/binary/binary.hpp>
#include <ember/binary/section.hpp>

namespace ember {

namespace {

// Anything below this is too small to give a stable entropy estimate.
// 4 KiB is a single page — comfortably above the noise floor while
// still flagging tiny encrypted stubs.
constexpr std::size_t kMinEntropyBytes = 4 * 1024;

// 7.5/8.0 cleanly separates plain x86 code (~5–6.5) from
// compressed/encrypted blobs (~7.9). Lower thresholds start
// false-positiving on dense .rdata.
constexpr double kEncryptedEntropy = 7.5;

// A section "looks like code" if its name matches the canonical text
// section across our supported formats. Used in the packed-binary
// heuristic: a `.text`-shaped section without the executable bit is
// the classic packer giveaway (the real code lives somewhere else,
// usually filled in at runtime).
[[nodiscard]] bool name_is_code_shaped(std::string_view name) noexcept {
    return name == ".text" || name == "__text" || name == "CODE";
}

// 64 KiB — small enough to catch toy obfuscated samples, large enough
// to ignore the rare legitimate non-exec `.text` (data tables emitted
// into the code section by some toolchains).
constexpr std::uint64_t kCodeShapedMinSize = 64 * 1024;

}  // namespace

double section_entropy(std::span<const std::byte> data) noexcept {
    if (data.empty()) return 0.0;
    std::array<std::uint64_t, 256> hist{};
    for (auto b : data) ++hist[static_cast<std::uint8_t>(b)];
    const double n = static_cast<double>(data.size());
    double h = 0.0;
    for (auto c : hist) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

bool section_looks_encrypted(const Section& s) noexcept {
    if (s.data.size() < kMinEntropyBytes) return false;
    return section_entropy(s.data) > kEncryptedEntropy;
}

bool binary_looks_packed(const Binary& b) noexcept {
    const addr_t entry = b.entry_point();
    bool entry_in_exec = false;
    for (const auto& s : b.sections()) {
        if (!s.flags.executable) continue;
        if (entry >= s.vaddr && entry < s.vaddr + s.size) {
            entry_in_exec = true;
            break;
        }
    }
    // Heuristic 1: entry point not in any executable section. Classic
    // unpacker stub — runtime decrypts the real code first.
    if (entry != 0 && !entry_in_exec) return true;

    for (const auto& s : b.sections()) {
        // Heuristic 2: a code-shaped section with the exec bit
        // stripped. Means the loader will fix up permissions at
        // runtime after unpacking.
        if (name_is_code_shaped(s.name)
            && s.size >= kCodeShapedMinSize
            && !s.flags.executable) {
            return true;
        }
        // Heuristic 3: any executable section that's encrypted.
        // Catches packers that leave the section header looking
        // normal but the bytes are ciphertext until runtime.
        if (s.flags.executable && section_looks_encrypted(s)) {
            return true;
        }
    }
    return false;
}

}  // namespace ember
