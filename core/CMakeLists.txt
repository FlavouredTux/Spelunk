add_library(ember_core STATIC
    src/binary/elf.cpp
    src/binary/macho.cpp
    src/binary/loader.cpp
    src/disasm/register.cpp
    src/disasm/instruction.cpp
    src/disasm/x64/decoder.cpp
    src/analysis/cfg_builder.cpp
    src/analysis/cfg_util.cpp
    src/analysis/arity.cpp
    src/analysis/strings.cpp
    src/analysis/pipeline.cpp
    src/analysis/fingerprint.cpp
    src/analysis/demangle.cpp
    src/analysis/sig_inference.cpp
    src/analysis/eh_frame.cpp
    src/analysis/objc.cpp
    src/analysis/libcxx_string.cpp
    src/common/annotations.cpp
    src/common/cache.cpp
    src/ir/ir.cpp
    src/ir/x64_lifter.cpp
    src/ir/ssa.cpp
    src/ir/passes.cpp
    src/structure/structurer.cpp
    src/decompile/emitter.cpp
    src/script/runtime.cpp
)
add_library(ember::core ALIAS ember_core)

target_include_directories(ember_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(ember_core PUBLIC cxx_std_23)
target_link_libraries(ember_core
    PRIVATE ember::flags
    PUBLIC  ember::quickjs
)

set_target_properties(ember_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
