#include <spelunk/disasm/decoder.hpp>

#include <expected>
#include <format>
#include <memory>

#include <spelunk/binary/arch.hpp>
#include <spelunk/binary/binary.hpp>
#include <spelunk/common/error.hpp>
#include <spelunk/disasm/arm32_decoder.hpp>
#include <spelunk/disasm/arm64_decoder.hpp>
#include <spelunk/disasm/ppc_decoder.hpp>
#include <spelunk/disasm/x64_decoder.hpp>
#include <spelunk/extension/decoder_registry.hpp>

namespace spelunk {

Result<std::unique_ptr<Decoder>>
make_decoder(const Binary& b) {
    switch (b.arch()) {
        case Arch::X86_64:
            return std::unique_ptr<Decoder>(std::make_unique<X64Decoder>());
        case Arch::Ppc32:
        case Arch::Ppc64:
            return std::unique_ptr<Decoder>(std::make_unique<PpcDecoder>(b.endian()));
        case Arch::Arm64:
            return std::unique_ptr<Decoder>(std::make_unique<Arm64Decoder>());
        case Arch::Arm:
            return std::unique_ptr<Decoder>(std::make_unique<Arm32Decoder>());
        default:
            break;
    }
    if (auto factory = ext::get_decoder_factory(b.arch())) {
        return factory(b);
    }
    return std::unexpected(Error::unsupported(std::format(
        "no decoder for arch {}", arch_name(b.arch()))));
}

}  // namespace spelunk
