// libFuzzer harness for one instruction decoder. EMBER_FUZZ_DECODER names
// the class (X64Decoder, Arm64Decoder, Arm32Decoder, PpcDecoder) and
// EMBER_FUZZ_DECODER_ARGS its constructor arguments, if any. The input
// is decoded linearly, advancing by the decoded length or one byte,
// so every offset of the input gets used as an instruction start.

#include <cstddef>
#include <cstdint>
#include <span>

#include <ember/disasm/arm32_decoder.hpp>
#include <ember/disasm/arm64_decoder.hpp>
#include <ember/disasm/ppc_decoder.hpp>
#include <ember/disasm/x64_decoder.hpp>

#ifndef EMBER_FUZZ_DECODER
#error "define EMBER_FUZZ_DECODER to the decoder class under test"
#endif
#ifndef EMBER_FUZZ_DECODER_ARGS
#define EMBER_FUZZ_DECODER_ARGS
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const ember::EMBER_FUZZ_DECODER decoder EMBER_FUZZ_DECODER_ARGS;
    const std::span<const std::byte> code(reinterpret_cast<const std::byte*>(data), size);
    ember::addr_t pc = 0x1000;
    std::size_t off = 0;
    while (off < size) {
        auto insn = decoder.decode(code.subspan(off), pc);
        const std::size_t step = (insn && insn->length != 0) ? insn->length : 1;
        off += step;
        pc += step;
    }
    return 0;
}
