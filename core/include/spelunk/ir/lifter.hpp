#pragma once

#include <memory>

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>

namespace spelunk {

class Binary;

class Lifter {
public:
    virtual ~Lifter() = default;

    [[nodiscard]] virtual Abi abi() const noexcept = 0;
    [[nodiscard]] virtual Result<IrFunction> lift(const Function& fn) const = 0;
};

[[nodiscard]] Result<std::unique_ptr<Lifter>>
make_lifter(const Binary& b);

}  // namespace spelunk
