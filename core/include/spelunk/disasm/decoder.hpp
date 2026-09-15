#pragma once

#include <cstddef>
#include <memory>
#include <span>

#include <spelunk/common/error.hpp>
#include <spelunk/common/types.hpp>
#include <spelunk/disasm/instruction.hpp>

namespace spelunk {

class Binary;

class Decoder {
public:
    virtual ~Decoder() = default;

    [[nodiscard]] virtual Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept = 0;
};

[[nodiscard]] Result<std::unique_ptr<Decoder>>
make_decoder(const Binary& b);

}  // namespace spelunk
