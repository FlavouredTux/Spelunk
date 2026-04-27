#pragma once

#include <ember/analysis/function.hpp>
#include <ember/common/error.hpp>
#include <ember/ir/abi.hpp>
#include <ember/ir/ir.hpp>
#include <ember/ir/lifter.hpp>

namespace ember {

class Arm64Lifter final : public Lifter {
public:
    explicit Arm64Lifter(Abi abi) noexcept : abi_(abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }

    [[nodiscard]] Result<IrFunction>
    lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::Aapcs64;
};

}  // namespace ember
