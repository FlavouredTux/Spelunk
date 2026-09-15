#pragma once

#include <cstddef>
#include <span>

#include <spelunk/disasm/decoder.hpp>

namespace spelunk {

// ARM (A32 / ARMv7-A) instruction decoder. 32-bit fixed-length,
// little-endian. Thumb (T16/T32) is a separate mode not handled here - it
// requires per-address ARM/Thumb state selection (mapping symbols), which
// the stateless Decoder interface doesn't carry yet.
class Arm32Decoder final : public Decoder {
public:
    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;
};

}  // namespace spelunk
