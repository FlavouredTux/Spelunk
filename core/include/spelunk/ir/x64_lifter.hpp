#pragma once

#include <spelunk/analysis/function.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/ir.hpp>
#include <spelunk/ir/lifter.hpp>

namespace spelunk {
class Binary;

class X64Lifter final : public Lifter {
public:
    // The default ABI is SysV - matches historical behaviour so any
    // call site that hasn't been updated still works on ELF/Mach-O
    // binaries. Callers lifting PE x86_64 must construct with
    // `X64Lifter{Abi::Win64}` so the emitted IR models the right
    // argument-passing and caller-saved sets.
    X64Lifter() = default;
    explicit X64Lifter(Abi abi) noexcept : abi_(abi) {}
    // x86 needs the image for per-function conventions and callee stack
    // cleanup. The convention analysis itself lifts with
    // resolve_function_abi off: it is computing that convention.
    X64Lifter(Abi abi, const Binary* binary, bool resolve_function_abi = true) noexcept
        : abi_(abi), binary_(binary), resolve_function_abi_(resolve_function_abi) {}

    [[nodiscard]] Abi abi() const noexcept override { return abi_; }

    [[nodiscard]] Result<IrFunction> lift(const Function& fn) const override;

private:
    Abi abi_ = Abi::SysVAmd64;
    const Binary* binary_ = nullptr;
    bool resolve_function_abi_ = true;
};

}  // namespace spelunk
