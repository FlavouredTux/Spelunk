#pragma once

#include <ember/analysis/function.hpp>
#include <ember/common/error.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

class X64Lifter {
public:
    X64Lifter() = default;

    [[nodiscard]] Result<IrFunction> lift(const Function& fn) const;
};

}  // namespace ember
