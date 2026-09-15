#pragma once

#include <spelunk/common/error.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/structure/region.hpp>

namespace spelunk {

class Structurer {
public:
    Structurer() = default;

    [[nodiscard]] Result<StructuredFunction> structure(const IrFunction& fn) const;
};

}  // namespace spelunk
