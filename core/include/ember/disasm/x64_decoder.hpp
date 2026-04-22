#pragma once

#include <cstddef>
#include <span>

#include <ember/disasm/decoder.hpp>

namespace ember {

class X64Decoder final : public Decoder {
public:
    X64Decoder() = default;

    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;
};

}  // namespace ember
