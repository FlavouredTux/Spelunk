#pragma once

#include <cstddef>
#include <span>

#include <spelunk/disasm/decoder.hpp>

namespace spelunk {

class X64Decoder final : public Decoder {
public:
    X64Decoder() = default;

    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;
};

}  // namespace spelunk
