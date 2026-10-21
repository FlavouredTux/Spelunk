#pragma once

#include <cstddef>
#include <span>

#include <spelunk/disasm/decoder.hpp>

namespace spelunk {

class X64Decoder final : public Decoder {
public:
    X64Decoder() = default;
    // Legacy protected mode shares opcode tables with long mode, but has
    // different register, address, branch and stack operand widths.
    explicit X64Decoder(bool mode64) noexcept : mode64_(mode64) {}

    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;
private:
    bool mode64_ = true;
};

}  // namespace spelunk
