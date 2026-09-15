#pragma once

#include <cstddef>
#include <span>

#include <spelunk/disasm/decoder.hpp>

namespace spelunk {

class Arm64Decoder final : public Decoder {
public:
    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;
};

}  // namespace spelunk
