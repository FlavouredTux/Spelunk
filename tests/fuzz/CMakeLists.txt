# libFuzzer targets. Configure with clang, EMBER_SANITIZE=ON (so the core
# is instrumented too) and EMBER_BUILD_FUZZERS=ON; scripts/ci.sh fuzz builds
# and runs every target against a corpus seeded from the test fixtures.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "EMBER_BUILD_FUZZERS needs clang (libFuzzer)")
endif()
if(NOT EMBER_SANITIZE)
    message(FATAL_ERROR "EMBER_BUILD_FUZZERS needs EMBER_SANITIZE=ON")
endif()

function(ember_fuzzer name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE ember::core ember::flags)
    target_compile_definitions(${name} PRIVATE ${ARGN})
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

# The harness runtime alone is not enough: instrument the parser/library code
# too, while leaving the final libFuzzer runtime to each executable below.
target_compile_options(ember_core PRIVATE -fsanitize=fuzzer-no-link)

ember_fuzzer(fuzz_elf      fuzz_load.cpp   EMBER_FUZZ_LOADER=ElfBinary)
ember_fuzzer(fuzz_pe       fuzz_load.cpp   EMBER_FUZZ_LOADER=PeBinary)
ember_fuzzer(fuzz_macho    fuzz_load.cpp   EMBER_FUZZ_LOADER=MachOBinary)
ember_fuzzer(fuzz_minidump fuzz_load.cpp   EMBER_FUZZ_LOADER=MinidumpBinary)
ember_fuzzer(fuzz_dol      fuzz_load.cpp   EMBER_FUZZ_LOADER=DolBinary)
ember_fuzzer(fuzz_rel      fuzz_rel.cpp)
ember_fuzzer(fuzz_pdb      fuzz_pdb.cpp    EMBER_FUZZ_PDB=1)
ember_fuzzer(fuzz_x64      fuzz_decode.cpp EMBER_FUZZ_DECODER=X64Decoder)
ember_fuzzer(fuzz_arm64    fuzz_decode.cpp EMBER_FUZZ_DECODER=Arm64Decoder)
ember_fuzzer(fuzz_arm32    fuzz_decode.cpp EMBER_FUZZ_DECODER=Arm32Decoder)
ember_fuzzer(fuzz_ppc      fuzz_decode.cpp EMBER_FUZZ_DECODER=PpcDecoder
                                           "EMBER_FUZZ_DECODER_ARGS=(ember::Endian::Big)")
ember_fuzzer(fuzz_ppc_le   fuzz_decode.cpp EMBER_FUZZ_DECODER=PpcDecoder
                                           "EMBER_FUZZ_DECODER_ARGS=(ember::Endian::Little)")
