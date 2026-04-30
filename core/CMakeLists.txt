add_library(ember_core STATIC
    src/binary/elf.cpp
    src/binary/macho.cpp
    src/binary/pe.cpp
    src/binary/pdb.cpp
    src/binary/minidump.cpp
    src/binary/raw_regions.cpp
    src/binary/loader.cpp
    src/disasm/decoder.cpp
    src/disasm/register.cpp
    src/disasm/instruction.cpp
    src/disasm/x64/decoder.cpp
    src/disasm/ppc/decoder.cpp
    src/disasm/arm/decoder.cpp
    src/analysis/cfg_builder.cpp
    src/analysis/cfg_util.cpp
    src/analysis/arity.cpp
    src/analysis/syscalls.cpp
    src/analysis/strings.cpp
    src/analysis/data_xrefs.cpp
    src/analysis/pipeline.cpp
    src/analysis/fingerprint.cpp
    src/analysis/demangle.cpp
    src/analysis/msvc_demangle.cpp
    src/analysis/sig_inference.cpp
    src/analysis/ir_cache.cpp
    src/analysis/import_sigs.cpp
    src/analysis/indirect_calls.cpp
    src/analysis/type_infer_local.cpp
    src/analysis/eh_frame.cpp
    src/analysis/cfi.cpp
    src/analysis/objc.cpp
    src/analysis/pe_unwind.cpp
    src/analysis/vm_detect.cpp
    src/analysis/packed.cpp
    src/analysis/discovery.cpp
    src/analysis/frame.cpp
    src/analysis/sigs.cpp
    src/analysis/libcxx_string.cpp
    src/analysis/rtti.cpp
    src/analysis/msvc_rtti.cpp
    src/common/annotations.cpp
    src/common/cache.cpp
    src/ir/abi.cpp
    src/ir/ir.cpp
    src/ir/types.cpp
    src/ir/lifter.cpp
    src/ir/ppc_lifter.cpp
    src/ir/x64_lifter.cpp
    src/ir/arm64_lifter.cpp
    src/ir/ssa.cpp
    src/ir/passes.cpp
    src/structure/structurer.cpp
    src/decompile/emitter.cpp
    src/decompile/emitter_helpers.cpp
    src/decompile/emitter_tables.cpp
    src/script/declarative.cpp
    src/debug/target.cpp
    src/debug/unwind_rbp.cpp
    src/debug/unwind_eh.cpp
)
add_library(ember::core ALIAS ember_core)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    target_sources(ember_core PRIVATE
        src/debug/linux/ptrace_target.cpp
        src/debug/linux/ptrace_proc.cpp
        src/debug/linux/ptrace_mem.cpp
        src/debug/linux/ptrace_regs.cpp
        src/debug/linux/ptrace_break.cpp
        src/debug/linux/ptrace_watch.cpp
        src/debug/linux/ptrace_event.cpp
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" AND
       CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    target_sources(ember_core PRIVATE
        src/debug/macos/mach_target.cpp
        src/debug/macos/mach_proc.cpp
        src/debug/macos/mach_mem.cpp
        src/debug/macos/mach_regs.cpp
        src/debug/macos/mach_break.cpp
        src/debug/macos/mach_event.cpp
    )
endif()

target_include_directories(ember_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

target_compile_features(ember_core PUBLIC cxx_std_23)
target_link_libraries(ember_core
    PRIVATE ember::flags
)

set_target_properties(ember_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
