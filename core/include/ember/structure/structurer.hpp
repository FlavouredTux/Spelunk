#pragma once

#include <ember/common/error.hpp>
#include <ember/ir/ir.hpp>
#include <ember/structure/region.hpp>

namespace ember {

class Structurer {
public:
    Structurer() = default;

    [[nodiscard]] Result<StructuredFunction> structure(const IrFunction& fn) const;
};

}  // namespace ember
