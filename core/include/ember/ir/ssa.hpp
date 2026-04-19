#pragma once

#include <optional>
#include <tuple>

#include <ember/common/error.hpp>
#include <ember/common/types.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

[[nodiscard]] Reg canonical_reg(Reg r) noexcept;

// Stable identity for an SSA value. (kind, id, version)
//   kind 0 = Reg (id = canonical reg index,  version = SSA version)
//   kind 1 = Flag (id = flag index,          version = SSA version)
//   kind 2 = Temp (id = temp id,             version = 0)
//   kind 3 = Imm  (id = low 32, version = high 32 of the immediate value)
// Returning std::nullopt means the value has no stable key (e.g. IrValueKind::None).
using SsaKey = std::tuple<u8, u32, u32>;

[[nodiscard]] std::optional<SsaKey> ssa_key(const IrValue& v) noexcept;
[[nodiscard]] bool same_ssa_value(const IrValue& a, const IrValue& b) noexcept;

class SsaBuilder {
public:
    SsaBuilder() = default;

    [[nodiscard]] Result<void> convert(IrFunction& fn) const;
};

}  // namespace ember
