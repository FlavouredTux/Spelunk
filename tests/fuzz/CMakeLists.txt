# libFuzzer targets. Configure with clang, SPELUNK_SANITIZE=ON (so the core
# is instrumented too) and SPELUNK_BUILD_FUZZERS=ON; scripts/ci.sh fuzz builds
# and runs every target against a corpus seeded from the test fixtures.
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "SPELUNK_BUILD_FUZZERS needs clang (libFuzzer)")
endif()
if(NOT SPELUNK_SANITIZE)
    message(FATAL_ERROR "SPELUNK_BUILD_FUZZERS needs SPELUNK_SANITIZE=ON")
endif()

function(spelunk_fuzzer name source)
    add_executable(${name} ${source})
    target_link_libraries(${name} PRIVATE spelunk::core spelunk::flags)
    target_compile_definitions(${name} PRIVATE ${ARGN})
    target_compile_options(${name} PRIVATE -fsanitize=fuzzer)
    target_link_options(${name} PRIVATE -fsanitize=fuzzer)
endfunction()

# The harness runtime alone is not enough: instrument the parser/library code
# too, while leaving the final libFuzzer runtime to each executable below.
target_compile_options(spelunk_core PRIVATE -fsanitize=fuzzer-no-link)

spelunk_fuzzer(fuzz_elf      fuzz_load.cpp   SPELUNK_FUZZ_LOADER=ElfBinary)
spelunk_fuzzer(fuzz_pe       fuzz_load.cpp   SPELUNK_FUZZ_LOADER=PeBinary)
spelunk_fuzzer(fuzz_macho    fuzz_load.cpp   SPELUNK_FUZZ_LOADER=MachOBinary)
spelunk_fuzzer(fuzz_minidump fuzz_load.cpp   SPELUNK_FUZZ_LOADER=MinidumpBinary)
spelunk_fuzzer(fuzz_dol      fuzz_load.cpp   SPELUNK_FUZZ_LOADER=DolBinary)
spelunk_fuzzer(fuzz_rel      fuzz_rel.cpp)
spelunk_fuzzer(fuzz_pdb      fuzz_pdb.cpp    SPELUNK_FUZZ_PDB=1)
spelunk_fuzzer(fuzz_x64      fuzz_decode.cpp SPELUNK_FUZZ_DECODER=X64Decoder)
spelunk_fuzzer(fuzz_arm64    fuzz_decode.cpp SPELUNK_FUZZ_DECODER=Arm64Decoder)
spelunk_fuzzer(fuzz_arm32    fuzz_decode.cpp SPELUNK_FUZZ_DECODER=Arm32Decoder)
spelunk_fuzzer(fuzz_ppc      fuzz_decode.cpp SPELUNK_FUZZ_DECODER=PpcDecoder
                                           "SPELUNK_FUZZ_DECODER_ARGS=(spelunk::Endian::Big)")
spelunk_fuzzer(fuzz_ppc_le   fuzz_decode.cpp SPELUNK_FUZZ_DECODER=PpcDecoder
                                           "SPELUNK_FUZZ_DECODER_ARGS=(spelunk::Endian::Little)")
