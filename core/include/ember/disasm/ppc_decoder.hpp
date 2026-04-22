#pragma once

#include <cstddef>
#include <span>

#include <ember/binary/arch.hpp>
#include <ember/disasm/decoder.hpp>

namespace ember {

class PpcDecoder final : public Decoder {
public:
    explicit PpcDecoder(Endian endian) noexcept : endian_(endian) {}

    [[nodiscard]] Result<Instruction>
    decode(std::span<const std::byte> code, addr_t addr) const noexcept override;

private:
    Endian endian_ = Endian::Big;
};

}  // namespace ember
