#pragma once

#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/lifter.hpp>

namespace spelunk {

class PpcLifter final : public Lifter {
public:
    explicit PpcLifter(Abi abi) noexcept : abi_(abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }
    [[nodiscard]] Result<IrFunction> lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::Ppc64ElfV2Le;
};

}  // namespace spelunk
