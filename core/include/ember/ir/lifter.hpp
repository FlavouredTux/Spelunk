#pragma once

#include <memory>

#include <ember/analysis/function.hpp>
#include <ember/common/error.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>

namespace ember {

class Binary;

class Lifter {
public:
    virtual ~Lifter() = default;

    [[nodiscard]] virtual Abi abi() const noexcept = 0;
    [[nodiscard]] virtual Result<IrFunction> lift(const Function& fn) const = 0;
};

[[nodiscard]] Result<std::unique_ptr<Lifter>>
make_lifter(const Binary& b);

}  // namespace ember
