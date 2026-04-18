#pragma once

#include <ember/common/error.hpp>
#include <ember/disasm/register.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

[[nodiscard]] Reg canonical_reg(Reg r) noexcept;

class SsaBuilder {
public:
    SsaBuilder() = default;

    [[nodiscard]] Result<void> convert(IrFunction& fn) const;
};

}  // namespace ember
