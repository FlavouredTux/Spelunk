#include <ember/ir/lifter.hpp>

#include <format>

#include <ember/binary/binary.hpp>
#include <ember/ir/arm64_lifter.hpp>
#include <ember/ir/ppc_lifter.hpp>
#include <ember/ir/x64_lifter.hpp>

namespace ember {

Result<std::unique_ptr<Lifter>>
make_lifter(const Binary& b) {
    const Abi abi = abi_for(b.format(), b.arch(), b.endian());
    switch (b.arch()) {
        case Arch::X86_64:
            return std::unique_ptr<Lifter>(std::make_unique<X64Lifter>(abi));
        case Arch::Ppc64:
            if (abi == Abi::Unknown) break;
            return std::unique_ptr<Lifter>(std::make_unique<PpcLifter>(abi));
        case Arch::Arm64:
            return std::unique_ptr<Lifter>(std::make_unique<Arm64Lifter>(
                abi == Abi::Unknown ? Abi::Aapcs64 : abi));
        default:
            break;
    }
    return std::unexpected(Error::unsupported(std::format(
        "no lifter for arch {}", arch_name(b.arch()))));
}

}  // namespace ember
