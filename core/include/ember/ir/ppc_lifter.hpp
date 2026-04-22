#pragma once

#include <ember/ir/abi.hpp>
#include <ember/ir/lifter.hpp>

namespace ember {

class PpcLifter final : public Lifter {
public:
    explicit PpcLifter(Abi abi) noexcept : abi_(abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }
    [[nodiscard]] Result<IrFunction> lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::Ppc64ElfV2Le;
};

}  // namespace ember
