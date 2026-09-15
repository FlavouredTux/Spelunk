// libFuzzer harness for one instruction decoder. SPELUNK_FUZZ_DECODER names
// the class (X64Decoder, Arm64Decoder, Arm32Decoder, PpcDecoder) and
// SPELUNK_FUZZ_DECODER_ARGS its constructor arguments, if any. The input
// is decoded linearly, advancing by the decoded length or one byte,
// so every offset of the input gets used as an instruction start.

#include <cstddef>
#include <cstdint>
#include <span>

#include <spelunk/disasm/arm32_decoder.hpp>
#include <spelunk/disasm/arm64_decoder.hpp>
#include <spelunk/disasm/ppc_decoder.hpp>
#include <spelunk/disasm/x64_decoder.hpp>

#ifndef SPELUNK_FUZZ_DECODER
#error "define SPELUNK_FUZZ_DECODER to the decoder class under test"
#endif
#ifndef SPELUNK_FUZZ_DECODER_ARGS
#define SPELUNK_FUZZ_DECODER_ARGS
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const spelunk::SPELUNK_FUZZ_DECODER decoder SPELUNK_FUZZ_DECODER_ARGS;
    const std::span<const std::byte> code(reinterpret_cast<const std::byte*>(data), size);
    spelunk::addr_t pc = 0x1000;
    std::size_t off = 0;
    while (off < size) {
        auto insn = decoder.decode(code.subspan(off), pc);
        const std::size_t step = (insn && insn->length != 0) ? insn->length : 1;
        off += step;
        pc += step;
    }
    volatile const spelunk::addr_t decoded_end = pc;
    (void)decoded_end;
    return 0;
}
