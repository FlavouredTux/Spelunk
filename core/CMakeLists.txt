add_library(ember_core STATIC
    src/binary/elf.cpp
    src/binary/elf_cafe.cpp
    src/binary/elf_cafe_link.cpp
    src/binary/elf_phdr.cpp
    src/binary/elf_symbols.cpp
    src/binary/dol.cpp
    src/binary/rel.cpp
    src/binary/ppc32_relocation.cpp
    src/binary/dtk_project.cpp
    src/binary/macho.cpp
    src/binary/macho_dyld.cpp
    src/binary/macho_metadata.cpp
    src/binary/pe.cpp
    src/binary/pe_tables.cpp
    src/binary/pdb.cpp
    src/binary/pdb_msf.cpp
    src/binary/pdb_tpi.cpp
    src/binary/dwarf.cpp
    src/binary/kismet_bundle.cpp
    src/binary/minidump.cpp
    src/binary/raw_regions.cpp
    src/binary/binary.cpp
    src/binary/loader.cpp
    src/extension/registry.cpp
    src/disasm/decoder.cpp
    src/disasm/register.cpp
    src/disasm/instruction.cpp
    src/disasm/instruction_format.cpp
    src/disasm/instruction_mnemonic_arm.cpp
    src/disasm/x64/decoder.cpp
    src/disasm/x64/decoder_operands.cpp
    src/disasm/x64/decoder_tables.cpp
    src/disasm/x64/decoder_x87.cpp
    src/disasm/ppc/decoder.cpp
    src/disasm/ppc/decoder_branch.cpp
    src/disasm/ppc/decoder_floating.cpp
    src/disasm/ppc/decoder_integer.cpp
    src/disasm/ppc/decoder_paired_single.cpp
    src/disasm/arm/decoder.cpp
    src/disasm/arm/decoder32.cpp
    src/analysis/cfg_builder.cpp
    src/analysis/cfg_builder_decode.cpp
    src/analysis/cfg_builder_flow.cpp
    src/analysis/cfg_util.cpp
    src/analysis/arity.cpp
    src/analysis/syscalls.cpp
    src/analysis/strings.cpp
    src/analysis/string_names.cpp
    src/analysis/string_names_candidates.cpp
    src/analysis/string_names_anchors.cpp
    src/analysis/string_names_itanium.cpp
    src/analysis/log_categories.cpp
    src/analysis/app_surface.cpp
    src/analysis/graphics.cpp
    src/analysis/symtable.cpp
    src/analysis/symresolve.cpp
    src/analysis/symuses.cpp
    src/analysis/data_xrefs.cpp
    src/analysis/pipeline.cpp
    src/analysis/pipeline_callgraph.cpp
    src/analysis/pipeline_discovery.cpp
    src/analysis/pipeline_names.cpp
    src/analysis/pipeline_resolve.cpp
    src/analysis/name_resolver.cpp
    src/analysis/fingerprint.cpp
    src/analysis/teef.cpp
    src/analysis/teef_corpus.cpp
    src/analysis/teef_recognize.cpp
    src/analysis/egraph.cpp
    src/analysis/teef_orbit.cpp
    src/analysis/teef_behav.cpp
    src/analysis/teef_behav_interpreter.cpp
    src/analysis/demangle.cpp
    src/analysis/demangle_itanium.cpp
    src/analysis/demangle_simplify.cpp
    src/analysis/msvc_demangle.cpp
    src/analysis/sig_inference.cpp
    src/analysis/ir_cache.cpp
    src/analysis/import_sigs.cpp
    src/analysis/indirect_calls.cpp
    src/analysis/ssa_cleanup.cpp
    src/analysis/type_infer_local.cpp
    src/analysis/forge_spec.cpp
    src/analysis/eh_frame.cpp
    src/analysis/cfi.cpp
    src/analysis/objc.cpp
    src/analysis/pe_unwind.cpp
    src/analysis/recover_imports.cpp
    src/analysis/int3_resolver.cpp
    src/analysis/packed.cpp
    src/analysis/discovery.cpp
    src/analysis/frame.cpp
    src/analysis/sigs.cpp
    src/analysis/identify.cpp
    src/analysis/kismet.cpp
    src/analysis/rtti.cpp
    src/analysis/msvc_rtti.cpp
    src/analysis/vtables.cpp
    src/common/annotations.cpp
    src/common/cache.cpp
    src/common/text.cpp
    src/ir/abi.cpp
    src/ir/ir.cpp
    src/ir/types.cpp
    src/ir/lifter.cpp
    src/ir/ppc_lifter.cpp
    src/ir/ppc_lifter_control.cpp
    src/ir/ppc_lifter_fp.cpp
    src/ir/ppc_lifter_operands.cpp
    src/ir/ppc_lifter_ps.cpp
    src/ir/x64_lifter.cpp
    src/ir/x64_lifter_alu.cpp
    src/ir/x64_lifter_control.cpp
    src/ir/x64_lifter_data.cpp
    src/ir/x64_lifter_flags.cpp
    src/ir/x64_lifter_operands.cpp
    src/ir/x64_lifter_simd.cpp
    src/ir/arm64_lifter.cpp
    src/ir/arm32_lifter.cpp
    src/ir/ssa.cpp
    src/ir/passes.cpp
    src/ir/passes_fold.cpp
    src/ir/passes_idiom.cpp
    src/ir/passes_memory.cpp
    src/ir/passes_simplify.cpp
    src/structure/structurer.cpp
    src/structure/structurer_build.cpp
    src/structure/structurer_cfg.cpp
    src/decompile/emitter.cpp
    src/decompile/emitter_abi.cpp
    src/decompile/emitter_virtual.cpp
    src/decompile/emitter_analyze.cpp
    src/decompile/emitter_block.cpp
    src/decompile/emitter_calls.cpp
    src/decompile/emitter_document.cpp
    src/decompile/emitter_expr.cpp
    src/decompile/emitter_flags.cpp
    src/decompile/emitter_infer.cpp
    src/decompile/emitter_inline.cpp
    src/decompile/emitter_leaf.cpp
    src/decompile/emitter_mem.cpp
    src/decompile/emitter_phi.cpp
    src/decompile/emitter_noise.cpp
    src/decompile/emitter_objc.cpp
    src/decompile/emitter_records.cpp
    src/decompile/emitter_regions.cpp
    src/decompile/emitter_setup.cpp
    src/decompile/emitter_ssa_use_index.cpp
    src/decompile/emitter_strings.cpp
    src/decompile/emitter_tables.cpp
    src/decompile/emitter_text.cpp
    src/decompile/emitter_text_ppc.cpp
    src/decompile/emitter_types.cpp
    src/script/declarative.cpp
    src/debug/target.cpp
    src/debug/unwind_rbp.cpp
    src/debug/unwind_eh.cpp
    src/debug/unwind_scavenge.cpp
)
add_library(ember::core ALIAS ember_core)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
   CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    target_sources(ember_core PRIVATE
        src/debug/linux/proc_mem.cpp
        src/debug/linux/proc_utils.cpp
        src/debug/linux/ptrace_target.cpp
        src/debug/linux/ptrace_proc.cpp
        src/debug/linux/ptrace_mem.cpp
        src/debug/linux/ptrace_regs.cpp
        src/debug/linux/ptrace_break.cpp
        src/debug/linux/ptrace_watch.cpp
        src/debug/linux/ptrace_catch.cpp
        src/debug/linux/ptrace_event.cpp
        src/debug/linux/perf_target.cpp
        src/debug/linux/perf_proc.cpp
        src/debug/linux/perf_mem.cpp
        src/debug/linux/perf_regs.cpp
        src/debug/linux/perf_break.cpp
        src/debug/linux/perf_watch.cpp
        src/debug/linux/perf_event.cpp
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

option(EMBER_WITH_ZLIB "Enable Wii U RPX/RPL section decompression when zlib is available" ON)
set(EMBER_ZLIB_ENABLED OFF PARENT_SCOPE)
if(EMBER_WITH_ZLIB)
    find_package(ZLIB QUIET)
    if(ZLIB_FOUND)
        target_link_libraries(ember_core PRIVATE ZLIB::ZLIB)
        target_compile_definitions(ember_core PRIVATE EMBER_HAS_ZLIB=1)
        set(EMBER_ZLIB_ENABLED ON PARENT_SCOPE)
    else()
        message(STATUS "zlib not found: compressed Wii U RPX/RPL sections disabled")
    endif()
endif()
