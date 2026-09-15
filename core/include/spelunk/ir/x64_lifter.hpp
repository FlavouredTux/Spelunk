#pragma once

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>

namespace spelunk {

class X64Lifter final : public Lifter {
public:
    // The default ABI is SysV - matches historical behaviour so any
    // call site that hasn't been updated still works on ELF/Mach-O
    // binaries. Callers lifting PE x86_64 must construct with
    // `X64Lifter{Abi::Win64}` so the emitted IR models the right
    // argument-passing and caller-saved sets.
    X64Lifter() = default;
    explicit X64Lifter(Abi abi) noexcept : abi_(abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }

    [[nodiscard]] Result<IrFunction> lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::SysVAmd64;
};

}  // namespace spelunk
