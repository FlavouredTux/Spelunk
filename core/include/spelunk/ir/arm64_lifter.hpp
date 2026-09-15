#pragma once

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>

namespace spelunk {

class Arm64Lifter final : public Lifter {
public:
    explicit Arm64Lifter(Abi abi) noexcept : abi_(abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }

    [[nodiscard]] Result<IrFunction>
    lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::Aapcs64;
};

}  // namespace spelunk
