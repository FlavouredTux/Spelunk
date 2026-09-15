#pragma once

// Private mnemonic-name dispatch shared by the instruction implementation
// units. This header remains under src/ because it is not part of the public
// disassembly API.

#include <string_view>

#include <spelunk/disasm/instruction.hpp>

namespace spelunk::instruction_detail {

[[nodiscard]] std::string_view arm_mnemonic_name(Mnemonic m) noexcept;

}  // namespace spelunk::instruction_detail
