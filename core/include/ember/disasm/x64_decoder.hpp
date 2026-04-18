#pragma once

#include <cstddef>
#include <span>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/instruction.hpp>

namespace ember {

class X64Decoder {
public:
    X64Decoder() = default;

    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept;
};

}  // namespace ember
