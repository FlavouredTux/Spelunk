#include <ember/disasm/decoder.hpp>

#include <format>

#include <ember/binary/binary.hpp>
#include <ember/disasm/ppc_decoder.hpp>
#include <ember/disasm/x64_decoder.hpp>

namespace ember {

Result<std::unique_ptr<Decoder>>
make_decoder(const Binary& b) {
    switch (b.arch()) {
        case Arch::X86_64:
            return std::unique_ptr<Decoder>(std::make_unique<X64Decoder>());
        case Arch::Ppc32:
        case Arch::Ppc64:
            return std::unique_ptr<Decoder>(std::make_unique<PpcDecoder>(b.endian()));
        default:
            return std::unexpected(Error::unsupported(std::format(
                "no decoder for arch {}", arch_name(b.arch()))));
    }
}

}  // namespace ember
