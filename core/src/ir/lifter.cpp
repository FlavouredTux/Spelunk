#include <spelunk/ir/lifter.hpp>

#include <expected>
#include <format>
#include <memory>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/extension/lifter_registry.hpp>
#include <spelunk/ir/abi.hpp>
#include <spelunk/ir/arm32_lifter.hpp>
#include <spelunk/ir/arm64_lifter.hpp>
#include <spelunk/ir/ppc_lifter.hpp>
#include <spelunk/ir/x64_lifter.hpp>

namespace spelunk {

Result<std::unique_ptr<Lifter>>
make_lifter(const Binary& b) {
    const Abi abi = abi_for(b.format(), b.arch(), b.endian());
    switch (b.arch()) {
        case Arch::X86_64:
            return std::unique_ptr<Lifter>(std::make_unique<X64Lifter>(abi));
        case Arch::Ppc32:
        case Arch::Ppc64:
            if (abi == Abi::Unknown) break;
            return std::unique_ptr<Lifter>(std::make_unique<PpcLifter>(abi));
        case Arch::Arm64:
            return std::unique_ptr<Lifter>(std::make_unique<Arm64Lifter>(
                abi == Abi::Unknown ? Abi::Aapcs64 : abi));
        case Arch::Arm:
            return std::unique_ptr<Lifter>(std::make_unique<Arm32Lifter>(
                abi == Abi::Unknown ? Abi::AapcsArm32 : abi));
        default:
            break;
    }
    if (auto factory = ext::get_lifter_factory(b.arch())) {
        return factory(b, abi);
    }
    return std::unexpected(Error::unsupported(std::format(
        "no lifter for arch {}", arch_name(b.arch()))));
}

}  // namespace spelunk
