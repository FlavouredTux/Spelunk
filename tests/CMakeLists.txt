# Golden-output tests for the ember decompilation pipeline.
#
# Each fixture is a small C program compiled with known flags (-O2 -g) into
# an executable whose path is handed to ember. We then run ember at several
# pipeline stages (-p pseudo-C, -i --ssa IR, -c CFG) and diff the output
# against a checked-in golden file.
#
# Goldens live in tests/golden/. To regenerate after an intentional output
# change:
#
#     UPDATE_GOLDEN=1 ctest --test-dir build -V
#
# Tests are only wired when building on Linux with gcc/clang available
# (ASM output would drift across compilers).

# Toolchain-independent unit tests run anywhere. Compiled-fixture golden
# tests are pinned to the gcc:16 toolchain (see ci.yml) so they only
# wire up on Linux.
add_executable(ember_demangle_test demangle_test.cpp)
target_link_libraries(ember_demangle_test PRIVATE ember::core ember::flags)
add_test(NAME demangle_unit COMMAND ember_demangle_test)

add_executable(ember_annotations_resolver_test annotations_resolver_test.cpp)
target_link_libraries(ember_annotations_resolver_test
    PRIVATE ember::core ember::flags)
add_test(NAME annotations_resolver_unit
         COMMAND ember_annotations_resolver_test)

# Unit test for FLIRT-style signature matching (`--pat`). Self-contained:
# uses an in-process MockBinary so the test doesn't depend on which
# version of gcc compiled the C fixtures.
add_executable(ember_sigs_test sigs_test.cpp)
target_link_libraries(ember_sigs_test PRIVATE ember::core ember::flags)
add_test(NAME sigs_unit COMMAND ember_sigs_test)

# Unit tests for the .ember declarative scripting format. Self-contained:
# a synthetic MockBinary with one defined function and a rodata string
# the function references, so the [from-strings] path has a real
# string→xref→containing-fn pipeline to walk.
add_executable(ember_declarative_test declarative_test.cpp)
target_link_libraries(ember_declarative_test PRIVATE ember::core ember::flags)
add_test(NAME declarative_unit COMMAND ember_declarative_test)

# Unit test for PDB ingestion. Builds a synthetic v7 MSF in-memory
# (superblock, directory, DBI header, S_PUB32 records) so the parser
# round-trip is exercised without depending on a real Microsoft toolchain.
add_executable(ember_pdb_test pdb_test.cpp)
target_link_libraries(ember_pdb_test PRIVATE ember::core ember::flags)
add_test(NAME pdb_unit COMMAND ember_pdb_test)

add_executable(ember_pe_reloc_test pe_reloc_test.cpp)
target_link_libraries(ember_pe_reloc_test PRIVATE ember::core ember::flags)
add_test(NAME pe_reloc_unit COMMAND ember_pe_reloc_test)

add_executable(ember_msvc_rtti_test msvc_rtti_test.cpp)
target_link_libraries(ember_msvc_rtti_test PRIVATE ember::core ember::flags)
add_test(NAME msvc_rtti_unit COMMAND ember_msvc_rtti_test)

# Unit test for the AArch64 decoder. Hand-encoded 4-byte instructions
# cover ALU immediate / shifted-register, move-wide, branches (B/BL/Bcc/
# CBZ/RET), loads/stores (immediate offset + LDP), and aliases (MOV/MUL/
# CMP). No fixture binary required - the encodings are derived directly
# from ARM ARM Table C4-x.
add_executable(ember_arm64_decoder_test arm64_decoder_test.cpp)
target_link_libraries(ember_arm64_decoder_test PRIVATE ember::core ember::flags)
add_test(NAME arm64_decoder_unit COMMAND ember_arm64_decoder_test)

add_executable(ember_arm32_decoder_test arm32_decoder_test.cpp)
target_link_libraries(ember_arm32_decoder_test PRIVATE ember::core ember::flags)
add_test(NAME arm32_decoder_unit COMMAND ember_arm32_decoder_test)

add_executable(ember_x64_decoder_test x64_decoder_test.cpp)
target_link_libraries(ember_x64_decoder_test PRIVATE ember::core ember::flags)
add_test(NAME x64_decoder_unit COMMAND ember_x64_decoder_test)

add_executable(ember_ppc_decoder_test ppc_decoder_test.cpp)
target_link_libraries(ember_ppc_decoder_test PRIVATE ember::core ember::flags)
add_test(NAME ppc_decoder_unit COMMAND ember_ppc_decoder_test)

add_executable(ember_arity_test arity_test.cpp)
target_link_libraries(ember_arity_test PRIVATE ember::core ember::flags)
add_test(NAME arity_unit COMMAND ember_arity_test)

# Unit tests for the e-graph saturation engine that backs TEEF v6's L3
# orbit-class fingerprint. Self-contained: builds e-graphs from synthetic
# terms, no IR involved.
add_executable(ember_egraph_test egraph_test.cpp)
target_link_libraries(ember_egraph_test PRIVATE ember::core ember::flags)
add_test(NAME egraph_unit COMMAND ember_egraph_test)

# Unit test for the int3 resolver. Self-contained: a MockBinary with
# hand-placed 0xCC bytes so the classifier is exercised without a
# compiled C fixture.
add_executable(ember_int3_resolver_test int3_resolver_test.cpp)
target_link_libraries(ember_int3_resolver_test PRIVATE ember::core ember::flags)
add_test(NAME int3_resolver_unit COMMAND ember_int3_resolver_test)

# Unit test for the forge-spec inferencer. Self-contained: a MockBinary
# with hand-encoded x86-64 bytes for an `if (p->magic == 0x1234)` shape,
# so the constraint extractor is exercised without depending on the
# fixture C compiler. Compiler drift can't move addresses around
# because the bytes are hand-laid.
add_executable(ember_forge_spec_test forge_spec_test.cpp)
target_link_libraries(ember_forge_spec_test PRIVATE ember::core ember::flags)
add_test(NAME forge_spec_unit COMMAND ember_forge_spec_test)

add_executable(ember_resolve_function_test resolve_function_test.cpp)
target_link_libraries(ember_resolve_function_test PRIVATE ember::core ember::flags)
add_test(NAME resolve_function_unit COMMAND ember_resolve_function_test)

add_executable(ember_raw_regions_test raw_regions_test.cpp)
target_link_libraries(ember_raw_regions_test PRIVATE ember::core ember::flags)
add_test(NAME raw_regions_unit COMMAND ember_raw_regions_test)

add_executable(ember_recover_imports_test recover_imports_test.cpp)
target_link_libraries(ember_recover_imports_test PRIVATE ember::core ember::flags)
add_test(NAME recover_imports_unit COMMAND ember_recover_imports_test)

add_executable(ember_ir_cleanup_test ir_cleanup_test.cpp)
target_link_libraries(ember_ir_cleanup_test PRIVATE ember::core ember::flags)
add_test(NAME ir_cleanup_unit COMMAND ember_ir_cleanup_test)

add_executable(ember_loader_robustness_test loader_robustness_test.cpp)
target_link_libraries(ember_loader_robustness_test PRIVATE ember::core ember::flags)
add_test(NAME loader_robustness_unit COMMAND ember_loader_robustness_test)

add_executable(ember_dtk_project_test dtk_project_test.cpp)
target_link_libraries(ember_dtk_project_test PRIVATE ember::core ember::flags)
add_test(NAME dtk_project_unit COMMAND ember_dtk_project_test)

add_executable(ember_discovery_test discovery_test.cpp)
target_link_libraries(ember_discovery_test PRIVATE ember::core ember::flags)
add_test(NAME discovery_unit COMMAND ember_discovery_test)

# Unit test for the structurer's drop-block diagnostic. Builds a
# synthetic IrFunction with one reachable Return plus a disconnected
# block carrying a Call, runs the structurer, and asserts the
# pseudo-C output contains a STRUCTURER_FAIL marker for the dropped
# block instead of silently omitting it.
add_executable(ember_structurer_fail_test structurer_fail_test.cpp)
target_link_libraries(ember_structurer_fail_test
    PRIVATE ember::core ember::flags)
add_test(NAME structurer_fail_unit COMMAND ember_structurer_fail_test)

# Unit tests for the TeefCorpus loader/recognizer. Synthesizes tiny
# F/C/S/T-row TSVs in-memory, writes them to a temp file, loads via
# the public API, and asserts recognize() returns the expected
# matches. Covers basic L2 exact, sub_* drop, multi-TSV merge name
# interning, distinct-name guard, T-row runtime transitions,
# 24-field back-compat, L1 prefix-exact, chunk-vote, and the
# string-anchor filter - all paths previously had zero coverage.
add_executable(ember_teef_corpus_test teef_corpus_test.cpp)
target_link_libraries(ember_teef_corpus_test
    PRIVATE ember::core ember::flags)
add_test(NAME teef_corpus_unit COMMAND ember_teef_corpus_test)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "ember tests: fixture goldens skipped (Linux only)")
    return()
endif()

# Fixture-based golden tests shell out to the CLI; skip them entirely
# when the CLI is opted out of (e.g. the macOS Apple Clang job, where
# the CLI's `<print>` usage isn't yet portable).
if(NOT TARGET ember_cli)
    message(STATUS "ember tests: fixture goldens skipped (ember_cli not built)")
    return()
endif()

# Build each fixture from .c → binary with deterministic flags. We drive it
# through add_custom_command so CTest depends on a real file target.
set(_fixture_dir "${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
set(_golden_dir  "${CMAKE_CURRENT_SOURCE_DIR}/golden")
set(_build_dir   "${CMAKE_CURRENT_BINARY_DIR}/fixtures")
file(MAKE_DIRECTORY "${_build_dir}")

# For fixtures whose goldens record absolute addresses or function sizes,
# any gcc point-release codegen drift breaks the test even though ember's
# behaviour is unchanged. `ember_use_prebuilt_fixture` copies a pre-built
# binary checked into `tests/fixtures/<name>.prebuilt` into the same build
# location `ember_build_fixture` would produce, so downstream test rules
# don't need to know which path produced it. Use this for tests that
# depend on exact compiled bytes; everything else stays compiled-on-build.
function(ember_use_prebuilt_fixture name)
    set(_src "${_fixture_dir}/${name}.prebuilt")
    set(_out "${_build_dir}/${name}")
    if(NOT EXISTS "${_src}")
        message(FATAL_ERROR
            "ember_use_prebuilt_fixture: ${_src} is missing. "
            "Build it once with the canonical toolchain and check it in.")
    endif()
    add_custom_command(
        OUTPUT "${_out}"
        COMMAND ${CMAKE_COMMAND} -E copy "${_src}" "${_out}"
        COMMAND chmod +x "${_out}"
        DEPENDS "${_src}"
        COMMENT "Staging prebuilt fixture ${name}"
        VERBATIM
    )
    add_custom_target(ember_fixture_${name} ALL DEPENDS "${_out}")
    set(EMBER_FIXTURE_${name}_PATH "${_out}" PARENT_SCOPE)
endfunction()

function(ember_build_fixture name)
    cmake_parse_arguments(F "PIE" "OPT;PROTECTOR;SRC;FP" "EXTRA_LDFLAGS" ${ARGN})
    if(NOT F_OPT)
        set(F_OPT "-O2")
    endif()
    if(NOT F_PROTECTOR)
        set(F_PROTECTOR "-fno-stack-protector")
    endif()
    if(F_PIE)
        set(_pie_flags "-fPIE" "-pie")
    else()
        set(_pie_flags "-no-pie")
    endif()
    if(F_FP STREQUAL "omit")
        set(_fp_flag "-fomit-frame-pointer")
    elseif(F_FP STREQUAL "keep")
        set(_fp_flag "-fno-omit-frame-pointer")
    else()
        set(_fp_flag "")
    endif()
    if(F_SRC)
        set(_src "${_fixture_dir}/${F_SRC}")
    else()
        set(_src "${_fixture_dir}/${name}.c")
    endif()
    set(_out "${_build_dir}/${name}")
    add_custom_command(
        OUTPUT "${_out}"
        COMMAND ${CMAKE_C_COMPILER} ${F_OPT} -g ${F_PROTECTOR}
                ${_pie_flags} ${_fp_flag} ${F_EXTRA_LDFLAGS}
                -o "${_out}" "${_src}"
        DEPENDS "${_src}"
        COMMENT "Compiling fixture ${name} (${F_OPT} ${F_PROTECTOR})"
        VERBATIM
    )
    add_custom_target(ember_fixture_${name} ALL DEPENDS "${_out}")
    set(EMBER_FIXTURE_${name}_PATH "${_out}" PARENT_SCOPE)
endfunction()

function(ember_build_stripped_fixture name source_name)
    set(_src "${EMBER_FIXTURE_${source_name}_PATH}")
    if(NOT _src)
        message(FATAL_ERROR "ember_build_stripped_fixture: source fixture '${source_name}' is not defined")
    endif()
    set(_out "${_build_dir}/${name}")
    add_custom_command(
        OUTPUT "${_out}"
        COMMAND ${CMAKE_COMMAND} -E copy "${_src}" "${_out}"
        COMMAND ${CMAKE_STRIP} --strip-all "${_out}"
        DEPENDS "${_src}"
        COMMENT "Stripping fixture ${source_name} -> ${name}"
        VERBATIM
    )
    add_custom_target(ember_fixture_${name} ALL DEPENDS "${_out}")
    set(EMBER_FIXTURE_${name}_PATH "${_out}" PARENT_SCOPE)
endfunction()

# Need a C compiler for fixtures.
enable_language(C)

ember_build_fixture(switch_basic)
ember_build_fixture(partial_reg)
ember_build_fixture(return_value)
# Compile at -O0 so the compiler spills every local; this is the shape
# where memory-forwarding has maximum leverage.
ember_build_fixture(mem_forward OPT "-O0")
# Goldens for `imports` record absolute addresses, function sizes, and
# data-xref offsets - every one of which shifts on a gcc point-release
# even when imports.c is unchanged. We've burned multiple commits
# regenerating against successive GCC point releases; pinning a prebuilt
# binary against the canonical toolchain is the only stable answer.
# Source still lives at imports.c - kept for traceability and so the
# binary can be rebuilt with `gcc -O2 -g -fno-stack-protector -no-pie
# -nostartfiles -Wl,-e,main -o tests/fixtures/imports.prebuilt
# tests/fixtures/imports.c` when an intentional behaviour change wants
# new bytes (regen the imports.* goldens in the same commit).
ember_use_prebuilt_fixture(imports)
ember_build_fixture(decoder_misc)
ember_build_fixture(tail_call)
ember_build_fixture(indirect_tail)
ember_build_fixture(indirect_trace)
ember_build_fixture(string_cmp)
# Resolver-pattern fixture: packed string table + writable fnptr table
# + a function that fills the fnptr table with N consecutive stride-8
# constant stores. The symuses goldens bake in xref sites from the
# compiled function bodies, so pin the bytes rather than chasing
# gcc-image drift. Rebuild with:
#   gcc -O0 -g -fno-stack-protector -no-pie -nostartfiles -Wl,-e,main \
#       -o tests/fixtures/symresolve_demo.prebuilt \
#       tests/fixtures/symresolve_demo.c
ember_use_prebuilt_fixture(symresolve_demo)
# Multi-resolver: two functions populating disjoint slot ranges of one
# fnptr table - the iterative detector has to find both, the merged
# output has to attribute every slot to the right resolver.
ember_build_fixture(symresolve_multi
    OPT "-O0"
    EXTRA_LDFLAGS "-nostartfiles" "-Wl,-e,main")
# Base+offset access pattern: functions never reference individual
# entry VAs directly, only `lea reg, [rip+table_base]` followed by
# arithmetic with constant offsets. -O1 so the optimizer keeps the
# base in a register and emits a real `lea reg, [reg+disp]` rather
# than the -O0 spill-everything-to-stack shape.
ember_build_fixture(symuses_indirect
    OPT "-O1"
    EXTRA_LDFLAGS "-nostartfiles" "-Wl,-e,main")
# imm64-stored slot pattern: the table base is reached only via a
# qword in .data, the way obfuscated loaders typically stash it. The
# strict data_xref scan returns zero hits for the table base VA;
# the loose-scope path has to find the slot and admit its readers.
ember_build_fixture(symuses_imm64
    OPT "-O1"
    EXTRA_LDFLAGS "-nostartfiles" "-Wl,-e,main")
# Mixes legit base+offset access with decoy arithmetic on an unrelated
# counter using the same constants as string-table entry offsets.
# Default --symuses (taint on) must produce exactly one row; --no-taint
# must surface the decoys too.
ember_build_fixture(symuses_noise
    OPT "-O1"
    EXTRA_LDFLAGS "-nostartfiles" "-Wl,-e,main")
# -O0 so the compiler literally emits every redundant store; at -O2 the
# compiler would DSE itself and leave nothing for us to test.
ember_build_fixture(dead_store OPT "-O0")
ember_build_fixture(fp_scalar)
ember_build_fixture(printf_noise)
ember_build_fixture(low_byte_flag)
# Stack-protector on so the canary prologue/epilogue actually get emitted.
ember_build_fixture(canary PROTECTOR "-fstack-protector-strong")
ember_build_fixture(noreturn_import)
ember_build_fixture(assert_name OPT "-O0")
ember_build_stripped_fixture(assert_name_stripped assert_name)
ember_build_fixture(mangled_string_name OPT "-O0")
ember_build_stripped_fixture(mangled_string_name_stripped mangled_string_name)
ember_build_fixture(surface_inventory OPT "-O0")
set(_surface_app_root "${_build_dir}/SurfaceInventory.app")
set(_surface_app_exe "${_surface_app_root}/Contents/MacOS/surface_inventory")
set(_surface_app_vmprotect "${_surface_app_root}/Contents/MacOS/libVMProtectSDK.dylib")
set(_surface_app_mimalloc "${_surface_app_root}/Contents/MacOS/libmimalloc.3.dylib")
set(_surface_app_metal "${_surface_app_root}/Contents/Resources/default.metallib")
set(_surface_app_glsl "${_surface_app_root}/Contents/Resources/shaders/shaders_glsl3.pack")
set(_surface_app_cert "${_surface_app_root}/Contents/Resources/ssl/cacert.pem")
set(_surface_app_locale "${_surface_app_root}/Contents/Resources/en.lproj/Localizable.strings")
add_custom_command(
    OUTPUT "${_surface_app_exe}"
           "${_surface_app_vmprotect}"
           "${_surface_app_mimalloc}"
           "${_surface_app_metal}"
           "${_surface_app_glsl}"
           "${_surface_app_cert}"
           "${_surface_app_locale}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${_surface_app_root}/Contents/MacOS"
            "${_surface_app_root}/Contents/Resources/shaders"
            "${_surface_app_root}/Contents/Resources/ssl"
            "${_surface_app_root}/Contents/Resources/en.lproj"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${EMBER_FIXTURE_surface_inventory_PATH}" "${_surface_app_exe}"
    COMMAND ${CMAKE_COMMAND} -E touch
            "${_surface_app_vmprotect}"
            "${_surface_app_mimalloc}"
            "${_surface_app_metal}"
            "${_surface_app_glsl}"
            "${_surface_app_cert}"
            "${_surface_app_locale}"
    DEPENDS "${EMBER_FIXTURE_surface_inventory_PATH}"
    COMMENT "Staging surface inventory app bundle"
    VERBATIM
)
add_custom_target(ember_fixture_surface_inventory_app ALL
    DEPENDS "${_surface_app_exe}"
            "${_surface_app_vmprotect}"
            "${_surface_app_mimalloc}"
            "${_surface_app_metal}"
            "${_surface_app_glsl}"
            "${_surface_app_cert}"
            "${_surface_app_locale}")
set(EMBER_FIXTURE_surface_inventory_app_PATH "${_surface_app_exe}")
set(_surface_text_app_root "${_build_dir}/SurfaceTextOnly.app")
set(_surface_text_app_exe "${_surface_text_app_root}/Contents/MacOS/not_binary")
set(_surface_text_app_metal "${_surface_text_app_root}/Contents/Resources/default.metallib")
add_custom_command(
    OUTPUT "${_surface_text_app_exe}" "${_surface_text_app_metal}"
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "${_surface_text_app_root}/Contents/MacOS"
            "${_surface_text_app_root}/Contents/Resources"
    COMMAND ${CMAKE_COMMAND} -E touch
            "${_surface_text_app_exe}"
            "${_surface_text_app_metal}"
    COMMENT "Staging text-only surface app bundle"
    VERBATIM
)
add_custom_target(ember_fixture_surface_text_app ALL
    DEPENDS "${_surface_text_app_exe}" "${_surface_text_app_metal}")
set(EMBER_FIXTURE_surface_text_app_PATH "${_surface_text_app_exe}")
# -O0 so the explicit gotos survive for the tail-duplication test.
ember_build_fixture(gotos OPT "-O0")
ember_build_stripped_fixture(gotos_stripped gotos)
# -O0 so the `%` operator survives as a real IDIV (and the IR Mod op),
# and the do-while body keeps its conditional structure intact.
ember_build_fixture(arith OPT "-O0")
# -O2 so gcc emits the branchless abs patterns (sign-mask, two's-complement)
# that the idiom-recognition pass should match and simplify.
ember_build_fixture(arith_idiom OPT "-O2")
# 24-byte 3-pointer struct shaped like libstdc++ / libc++ / MSVC STL
# std::vector<T> for the looks_like_vector predicate to fire on.
ember_build_fixture(vector_like)
ember_build_fixture(struct_fields)
ember_build_fixture(global_resolution)
# -O0 so dbg_marker stays a real function (no inlining, no tail-call
# fold) and gets a stable symbol address the smoke test can set a
# software breakpoint at. Built once non-PIE (dbg_target) and once
# PIE (dbg_target_pie) so the smoke tests cover both load shapes -
# slide-aware breakpoint resolution flows through the same path for
# both, with the slide degenerating to 0 in the non-PIE case.
ember_build_fixture(dbg_target     OPT "-O0")
ember_build_fixture(dbg_target_pie OPT "-O0" PIE SRC "dbg_target.c")
# -O2 + -fomit-frame-pointer: RBP-walk fails past frame 0 because the
# call to dbg_marker doesn't preserve RBP. The .eh_frame unwinder
# must still produce a multi-frame trace.
ember_build_fixture(dbg_target_ofp OPT "-O2" FP "omit" SRC "dbg_target.c")
# Parent/child pair for the exec-persistence smoke test. -O0 keeps
# preexec_marker / child_writer as real symbols so the test can
# anchor breakpoints by name.
ember_build_fixture(dbg_exec_parent OPT "-O0")
ember_build_fixture(dbg_exec_child  OPT "-O0")

# Debugger smoke test: launches the dbg_target fixture under the
# Linux ptrace backend, sets a breakpoint at `dbg_marker`, asserts
# the bp fires and the process exits with code 42. Runs against
# both fixtures so the slide-correction path is exercised. Linux /
# x86-64 only - matches the backend's CMake gate. yama ptrace_scope
# is irrelevant for child tracees so any sysctl works.
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    add_executable(ember_dbg_smoke_test dbg_smoke_test.cpp)
    target_link_libraries(ember_dbg_smoke_test
        PRIVATE ember::core ember::flags)
    add_dependencies(ember_dbg_smoke_test
        ember_fixture_dbg_target ember_fixture_dbg_target_pie)
    add_test(NAME dbg_smoke
             COMMAND ember_dbg_smoke_test "${EMBER_FIXTURE_dbg_target_PATH}")
    add_test(NAME dbg_smoke_pie
             COMMAND ember_dbg_smoke_test "${EMBER_FIXTURE_dbg_target_pie_PATH}")
    set_tests_properties(dbg_smoke dbg_smoke_pie
        PROPERTIES SKIP_RETURN_CODE 77)

    # Same fixture run through the perf_event_open backend. Skips at
    # runtime (exit 77) when the kernel denies perf_event_open due to
    # /proc/sys/kernel/perf_event_paranoid >= 2 without CAP_PERFMON,
    # so the test passes uniformly across paranoid and permissive
    # CI environments.
    add_executable(ember_dbg_perf_smoke_test dbg_perf_smoke_test.cpp)
    target_link_libraries(ember_dbg_perf_smoke_test
        PRIVATE ember::core ember::flags)
    add_dependencies(ember_dbg_perf_smoke_test ember_fixture_dbg_target)
    add_test(NAME dbg_perf_smoke
             COMMAND ember_dbg_perf_smoke_test "${EMBER_FIXTURE_dbg_target_PATH}")
    set_tests_properties(dbg_perf_smoke PROPERTIES SKIP_RETURN_CODE 77)

    # .eh_frame unwinder vs RBP-walk on -fomit-frame-pointer.
    add_executable(ember_dbg_eh_unwind_test dbg_eh_unwind_test.cpp)
    target_link_libraries(ember_dbg_eh_unwind_test
        PRIVATE ember::core ember::flags)
    add_dependencies(ember_dbg_eh_unwind_test ember_fixture_dbg_target_ofp)
    add_test(NAME dbg_eh_unwind
             COMMAND ember_dbg_eh_unwind_test "${EMBER_FIXTURE_dbg_target_ofp_PATH}")
    set_tests_properties(dbg_eh_unwind PROPERTIES SKIP_RETURN_CODE 77)

    # Persisted breakpoints/watchpoints across exec(2). Parent arms a
    # write-watch on `marker`, execve's into the child, expects the
    # watch to fire on the child's child_writer store.
    add_executable(ember_dbg_exec_persist_test dbg_exec_persist_test.cpp)
    target_link_libraries(ember_dbg_exec_persist_test
        PRIVATE ember::core ember::flags)
    add_dependencies(ember_dbg_exec_persist_test
        ember_fixture_dbg_exec_parent ember_fixture_dbg_exec_child)
    add_test(NAME dbg_exec_persist
             COMMAND ember_dbg_exec_persist_test
                     "${EMBER_FIXTURE_dbg_exec_parent_PATH}"
                     "${EMBER_FIXTURE_dbg_exec_child_PATH}")
    set_tests_properties(dbg_exec_persist PROPERTIES SKIP_RETURN_CODE 77)
endif()

# Register one golden test. ARGS is a |-separated list (translated to ';' by
# the driver script), because CTest's own quoting gets ugly with ";" in
# a -D argument.
function(ember_golden_test)
    cmake_parse_arguments(T "" "NAME;FIXTURE;GOLDEN;ARGS" "" ${ARGN})
    if(NOT T_NAME OR NOT T_FIXTURE OR NOT T_GOLDEN)
        message(FATAL_ERROR "ember_golden_test: NAME/FIXTURE/GOLDEN required")
    endif()
    add_test(
        NAME ${T_NAME}
        COMMAND ${CMAKE_COMMAND}
            -DEMBER=$<TARGET_FILE:ember_cli>
            -DBINARY=${EMBER_FIXTURE_${T_FIXTURE}_PATH}
            -DARGS=${T_ARGS}
            -DGOLDEN=${_golden_dir}/${T_GOLDEN}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_golden.cmake
    )
    set_tests_properties(${T_NAME} PROPERTIES
        DEPENDS ember_cli
        LABELS golden
    )
endfunction()

function(ember_expect_fail_test)
    cmake_parse_arguments(T "" "NAME;FIXTURE;ERR_SUBSTR;ARGS" "" ${ARGN})
    if(NOT T_NAME OR NOT T_FIXTURE OR NOT T_ERR_SUBSTR)
        message(FATAL_ERROR "ember_expect_fail_test: NAME/FIXTURE/ERR_SUBSTR required")
    endif()
    add_test(
        NAME ${T_NAME}
        COMMAND ${CMAKE_COMMAND}
            -DEMBER=$<TARGET_FILE:ember_cli>
            -DBINARY=${EMBER_FIXTURE_${T_FIXTURE}_PATH}
            -DARGS=${T_ARGS}
            -DERR_SUBSTR=${T_ERR_SUBSTR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_cli_expect_fail.cmake
    )
    set_tests_properties(${T_NAME} PROPERTIES
        DEPENDS ember_cli
        LABELS golden
    )
endfunction()

# --dump-types: type-lattice self-test. Doesn't read the binary, but the
# golden harness wants a fixture path slot, so we pass any existing one.
ember_golden_test(
    NAME    types_basic_dump
    FIXTURE switch_basic
    ARGS    "--dump-types|__BINARY__"
    GOLDEN  types_basic.dump.txt
)

# ---- switch_basic -----------------------------------------------------------

ember_golden_test(
    NAME    switch_basic_describe_pseudo
    FIXTURE switch_basic
    ARGS    "-p|-s|describe"
    GOLDEN  switch_basic.describe.pseudo.txt
)

ember_golden_test(
    NAME    switch_basic_describe_cfg
    FIXTURE switch_basic
    ARGS    "-c|-s|describe"
    GOLDEN  switch_basic.describe.cfg.txt
)

# ---- partial_reg ------------------------------------------------------------
#
# These goldens are the central regression bait for the partial-register
# soundness fix. Any change in how the lifter models sub-register writes
# will show up here and demand review.

ember_golden_test(
    NAME    partial_reg_zext_pseudo
    FIXTURE partial_reg
    ARGS    "-p|-s|zero_extend_via_eax"
    GOLDEN  partial_reg.zero_extend_via_eax.pseudo.txt
)

ember_golden_test(
    NAME    partial_reg_zext_ssa
    FIXTURE partial_reg
    ARGS    "-i|--ssa|-s|zero_extend_via_eax"
    GOLDEN  partial_reg.zero_extend_via_eax.ssa.txt
)

ember_golden_test(
    NAME    partial_reg_al_pseudo
    FIXTURE partial_reg
    ARGS    "-p|-s|preserve_upper_via_al"
    GOLDEN  partial_reg.preserve_upper_via_al.pseudo.txt
)

# ---- return_value -----------------------------------------------------------
#
# Guards against a regression where Ret didn't read rax, leading DCE to kill
# the entire computation and emit an empty function body.

ember_golden_test(
    NAME    return_value_add32_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|add32"
    GOLDEN  return_value.add32.pseudo.txt
)

ember_golden_test(
    NAME    return_value_compound_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|compound"
    GOLDEN  return_value.compound.pseudo.txt
)

ember_golden_test(
    NAME    return_value_big_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|big"
    GOLDEN  return_value.big.pseudo.txt
)

ember_golden_test(
    NAME    return_value_branch32_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|branch32"
    GOLDEN  return_value.branch32.pseudo.txt
)

ember_golden_test(
    NAME    return_value_main_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|main"
    GOLDEN  return_value.main.pseudo.txt
)

# Signature + body-substitution: with the hand-written annotations file
# below, `big` renders as `add_mix(a, b, c)` and rdi/rsi/rdx inside the
# body become a/b/c. Locks in that --annotations flows all the way through
# the emitter, not just into the function header.
ember_golden_test(
    NAME    return_value_big_signed_pseudo
    FIXTURE return_value
    ARGS    "-p|-s|big|--annotations|${_fixture_dir}/return_value.ann"
    GOLDEN  return_value.big.signed.pseudo.txt
)

# Sidecar auto-load: drop `<binary>.ember-annotations` next to a copy of
# the fixture and expect `-p -s big` to pick up the same renames as the
# --annotations-explicit test above, without any flag. We build the
# sidecar against a separate binary path so this test can't accidentally
# poison `return_value_big_pseudo` (which expects the unannotated form).
set(_rv_sidecar "${_build_dir}/return_value_sidecar")
add_custom_command(
    OUTPUT  "${_rv_sidecar}"
            "${_rv_sidecar}.ember-annotations"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${EMBER_FIXTURE_return_value_PATH}" "${_rv_sidecar}"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${_fixture_dir}/return_value.ann"
            "${_rv_sidecar}.ember-annotations"
    DEPENDS "${EMBER_FIXTURE_return_value_PATH}"
            "${_fixture_dir}/return_value.ann"
    COMMENT "Staging sidecar annotations for return_value_sidecar"
    VERBATIM
)
add_custom_target(ember_fixture_return_value_sidecar ALL
    DEPENDS "${_rv_sidecar}" "${_rv_sidecar}.ember-annotations")
set(EMBER_FIXTURE_return_value_sidecar_PATH "${_rv_sidecar}")

ember_golden_test(
    NAME    return_value_big_sidecar_pseudo
    FIXTURE return_value_sidecar
    ARGS    "-p|-s|big"
    GOLDEN  return_value.big.signed.pseudo.txt
)

# ---- imports (ELF PLT/GOT resolution) --------------------------------------
#
# Guards the import-name rendering pipeline. Without PLT/GOT resolution
# these calls would degrade to `sub_XXXX(...)` / `(**(u64*)(0x...))(...)`.

ember_golden_test(
    NAME    imports_use_imports_pseudo
    FIXTURE imports
    ARGS    "-p|-s|use_imports"
    GOLDEN  imports.use_imports.pseudo.txt
)

# Fingerprint stability: the address-independent content hash per function.
# If this drifts, the rename TSV stops matching old databases - bump
# the "v1" schema token in fingerprint.cpp when that's intentional, and
# regenerate goldens.
ember_golden_test(
    NAME    imports_fingerprints
    FIXTURE imports
    ARGS    "--no-cache|--fingerprints"
    GOLDEN  imports.fingerprints.txt
)

# --functions: flat TSV of every discovered function (defined symbols ∪
# CFG-walked call targets). Guards the shape of the list surface the UI
# Sidebar consumes, so a change here rippling into the Sidebar is
# immediately visible.
ember_golden_test(
    NAME    imports_functions
    FIXTURE imports
    ARGS    "--no-cache|--functions"
    GOLDEN  imports.functions.txt
)

# --data-xrefs: rip-relative / absolute memory references that resolve to a
# loaded non-executable section. Catches breakage in the operand-shape walk
# and the read/write/lea classification.
ember_golden_test(
    NAME    imports_data_xrefs
    FIXTURE imports
    ARGS    "--no-cache|--data-xrefs"
    GOLDEN  imports.data_xrefs.txt
)

# Same flag with a substring filter. Locks case-insensitive name-column
# matching. `__BINARY__` is needed so the pattern lands *after* the binary
# positional - parse_args only treats the second positional as the
# filter pattern.
ember_golden_test(
    NAME    imports_functions_filtered
    FIXTURE imports
    ARGS    "--no-cache|--functions|__BINARY__|main"
    GOLDEN  imports.functions.main.txt
)

# --collisions: every name and every fingerprint bound to >1 address.
# The imports fixture has the deliberate `twin_a` / `twin_b` pair so a
# regression in collect_collisions either drops them or invents new
# ones - both shapes the golden catches immediately.
ember_golden_test(
    NAME    imports_collisions
    FIXTURE imports
    ARGS    "--no-cache|--collisions"
    GOLDEN  imports.collisions.txt
)

# --validate NAME on a uniquely-shaped function: locks the STRONG
# verdict path (single bound, no near-matches) and the bound-row TSV
# format that downstream tooling parses.
ember_golden_test(
    NAME    imports_validate_main
    FIXTURE imports
    ARGS    "--no-cache|--validate|main"
    GOLDEN  imports.validate.main.txt
)

# --symtable: walks .dynstr (a real packed NUL-terminated string table)
# at its known fixture VA. Locks the table-walk semantics (leading empty
# entry, internal NUL handling, non-printable termination) and the
# keyword-bucketed `# categories:` bonus block - `getenv` here lands in
# the env bucket. The fixture's pinned bytes mean these offsets / VAs
# don't drift unless imports.prebuilt is regenerated.
ember_golden_test(
    NAME    imports_symtable_dynstr
    FIXTURE imports
    ARGS    "--symtable|0x400410"
    GOLDEN  imports.symtable.dynstr.txt
)

ember_expect_fail_test(
    NAME       imports_symtable_unmapped_va
    FIXTURE    imports
    ARGS       "--symtable|0x999999"
    ERR_SUBSTR "not in any loadable segment"
)

# --symresolve: pairs the string table at g_names with the fnptr table
# (g_fns) and per-slot callsites. Locks (a) the resolver-detection
# heuristic - longest stride-8 write run picks `resolver` correctly
# when no other function emits a comparable run - and (b) the per-row
# callsite counts (alpha=1, charlie=2, others=0). The fixture is built
# at -O0 so each slot store is a separate `mov qword [rip+disp], imm`
# rather than a vectorized 16-byte block, which is what a real
# hand-written resolver loop emits anyway.
ember_golden_test(
    NAME    symresolve_demo_basic
    FIXTURE symresolve_demo
    ARGS    "--symresolve|0x402000"
    GOLDEN  symresolve_demo.basic.txt
)

# Multi-resolver: locks the iterative detector - picks resolver_tail
# (5 slots) first, then resolver_head (3 slots) on the second pass,
# merges them in base_va order so slot 0 attributes to head and slot 3
# attributes to tail. Coverage = 8/8 = 100% goes to stderr (not in
# golden, which captures stdout only).
ember_golden_test(
    NAME    symresolve_multi_basic
    FIXTURE symresolve_multi
    ARGS    "--symresolve|0x402000"
    GOLDEN  symresolve_multi.basic.txt
)

# --symuses: pure xref scan, surfaces every function that holds a
# `lea reg, [rip+g_names+N]`-style reference into the table, deduped
# per row and sorted by descending unique-symbol count. Locks (a)
# touch_alpha_and_delta sorting first with 2 uses, (b) the
# walks_table function being marked <full_table_walker> off its single
# lea-to-base hit, (c) the deterministic ordering of single-use rows
# (by ascending fn address as the tie-breaker).
ember_golden_test(
    NAME    symresolve_demo_symuses
    FIXTURE symresolve_demo
    ARGS    "--symuses|0x402000"
    GOLDEN  symresolve_demo.uses.txt
)

# --symuses --verbose: one row per callsite. Demonstrates the
# table-base reference rendering as <table_base> on walks_table.
ember_golden_test(
    NAME    symresolve_demo_symuses_verbose
    FIXTURE symresolve_demo
    ARGS    "--symuses|0x402000|--verbose"
    GOLDEN  symresolve_demo.uses.verbose.txt
)

# --symuses --min-uses 2: drops every row below the cutoff, including
# the <full_table_walker> row (whose lea-to-base count of 1 is a low
# bound - same threshold rule as for symbol rows).
ember_golden_test(
    NAME    symresolve_demo_symuses_min2
    FIXTURE symresolve_demo
    ARGS    "--symuses|0x402000|--min-uses|2"
    GOLDEN  symresolve_demo.uses.min2.txt
)

# --symuses against the base+offset access pattern. The consumers
# never reference entry VAs directly - they hold the table base in a
# register and add a constant offset before each use. Locks (a) the
# scope-scan path correctly attributing the `add reg, IMM`
# displacements to the right entries (alpha at 0x1, delta at 0x15,
# charlie at 0xd) and (b) the touches_base_only function still
# surfacing as <full_table_walker> when its body has no offset hits.
ember_golden_test(
    NAME    symuses_indirect_basic
    FIXTURE symuses_indirect
    ARGS    "--symuses|0x402000"
    GOLDEN  symuses_indirect.txt
)

# Verbose form: confirms the per-site rendering of base-load events
# as <table_base> and per-offset hits as the matched symbol name.
ember_golden_test(
    NAME    symuses_indirect_verbose
    FIXTURE symuses_indirect
    ARGS    "--symuses|0x402000|--verbose"
    GOLDEN  symuses_indirect.verbose.txt
)

# imm64-stored slot path. The strict data_xref scan would find zero
# refs to g_str_table itself - the only static evidence the table is
# in use is `mov rax, [rip+g_table_ptr]` followed by `add rax, IMM`.
# Locks the loose-scope path: walk readable sections for qwords ==
# table_va, admit slot-readers as scope candidates, then run the
# per-fn IMM scan over those.
ember_golden_test(
    NAME    symuses_imm64_basic
    FIXTURE symuses_imm64
    ARGS    "--symuses|0x402000"
    GOLDEN  symuses_imm64.txt
)

ember_golden_test(
    NAME    refs_to_loose_verbose_site_context
    FIXTURE symuses_imm64
    ARGS    "--refs-to-loose|0x402000|--verbose"
    GOLDEN  symuses_imm64.refs_to_loose.verbose.txt
)

# Taint-walker FP suppression. Default mode emits exactly one row
# (the real charlie consumer); --no-taint surfaces the three decoy
# adds (alpha / bravo / delta) on the unrelated counters too. Locks
# the regression: removing or weakening the taint propagation would
# reintroduce the noise on the default form.
ember_golden_test(
    NAME    symuses_noise_taint
    FIXTURE symuses_noise
    ARGS    "--symuses|0x402000"
    GOLDEN  symuses_noise.txt
)
ember_golden_test(
    NAME    symuses_noise_no_taint
    FIXTURE symuses_noise
    ARGS    "--symuses|0x402000|--no-taint"
    GOLDEN  symuses_noise.no_taint.txt
)

# ---- decoder_misc (coverage of formerly-unhandled opcodes) -----------------
#
# Every function here hits a decoder/lifter path that previously produced
# `not_implemented` or wrong IR: setcc, cmovcc, bswap, rep movsq, rotates,
# carry-flag control/rotates, LAHF/SAHF flag snapshots, PUSHFQ/POPFQ flag
# save-restore, and scalar/XMM transfers. If any regresses, the function stops
# decompiling or the golden diverges.

ember_golden_test(
    NAME    decoder_misc_setswap_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|set_and_swap"
    GOLDEN  decoder_misc.set_and_swap.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_blockcopy_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|block_copy"
    GOLDEN  decoder_misc.block_copy.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_sse_memclr_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|sse_memclr"
    GOLDEN  decoder_misc.sse_memclr.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_rotate_mix_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|rotate_mix"
    GOLDEN  decoder_misc.rotate_mix.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_carry_seed_add_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|carry_seed_add"
    GOLDEN  decoder_misc.carry_seed_add.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_carry_rotate_one_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|carry_rotate_one"
    GOLDEN  decoder_misc.carry_rotate_one.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_carry_rotate_mix_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|carry_rotate_mix"
    GOLDEN  decoder_misc.carry_rotate_mix.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_lahf_snapshot_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|lahf_snapshot"
    GOLDEN  decoder_misc.lahf_snapshot.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_sahf_parity_select_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|sahf_parity_select"
    GOLDEN  decoder_misc.sahf_parity_select.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_pushf_popf_carry_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|pushf_popf_carry"
    GOLDEN  decoder_misc.pushf_popf_carry.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_movd_gpr_roundtrip_ssa
    FIXTURE decoder_misc
    ARGS    "-i|--ssa|-s|movd_gpr_roundtrip"
    GOLDEN  decoder_misc.movd_gpr_roundtrip.ssa.txt
)

ember_golden_test(
    NAME    decoder_misc_movd_extract_high_word_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|movd_extract_high_word"
    GOLDEN  decoder_misc.movd_extract_high_word.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_movq_gpr_roundtrip_disasm
    FIXTURE decoder_misc
    ARGS    "-d|-s|movq_gpr_roundtrip"
    GOLDEN  decoder_misc.movq_gpr_roundtrip.disasm.txt
)

ember_golden_test(
    NAME    decoder_misc_movq_gpr_roundtrip_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|movq_gpr_roundtrip"
    GOLDEN  decoder_misc.movq_gpr_roundtrip.pseudo.txt
)

ember_golden_test(
    NAME    decoder_misc_vector_word_roundtrip_pseudo
    FIXTURE decoder_misc
    ARGS    "-p|-s|vector_word_roundtrip"
    GOLDEN  decoder_misc.vector_word_roundtrip.pseudo.txt
)

# ---- tail_call (jmp-to-function as return) --------------------------------

ember_golden_test(
    NAME    tail_call_wrap_strlen_pseudo
    FIXTURE tail_call
    ARGS    "-p|-s|wrap_strlen"
    GOLDEN  tail_call.wrap_strlen.pseudo.txt
)


# ---- indirect_tail (jmp [reg/mem] as return) ------------------------------
#
# Each of these once rendered as `__unreachable();` because the lifter
# treated indirect jmps as opaque control-flow instead of indirect tail-
# calls. Locks in the canonical x86-64 indirect-tail-call shapes:
# fn-pointer table, struct-field fn-pointer, named global fn-pointer.

ember_golden_test(
    NAME    indirect_tail_table_pseudo
    FIXTURE indirect_tail
    ARGS    "-p|-s|via_table"
    GOLDEN  indirect_tail.via_table.pseudo.txt
)

ember_golden_test(
    NAME    indirect_tail_member_pseudo
    FIXTURE indirect_tail
    ARGS    "-p|-s|via_member"
    GOLDEN  indirect_tail.via_member.pseudo.txt
)

ember_golden_test(
    NAME    indirect_tail_global_pseudo
    FIXTURE indirect_tail
    ARGS    "-p|-s|via_global"
    GOLDEN  indirect_tail.via_global.pseudo.txt
)

ember_golden_test(
    NAME    indirect_tail_absolute_pseudo
    FIXTURE indirect_tail
    ARGS    "-p|-s|via_absolute"
    GOLDEN  indirect_tail.via_absolute.pseudo.txt
)

ember_golden_test(
    NAME    indirect_trace_call_fp_pseudo
    FIXTURE indirect_trace
    ARGS    "--trace|${_fixture_dir}/indirect_trace.trace|--resolve-calls|-p|-s|call_fp"
    GOLDEN  indirect_trace.call_fp.pseudo.txt
)

ember_golden_test(
    NAME    string_cmp_cmp_marker_pseudo
    FIXTURE string_cmp
    ARGS    "-p|-s|cmp_marker"
    GOLDEN  string_cmp.cmp_marker.pseudo.txt
)

ember_golden_test(
    NAME    string_cmp_print_marker_pseudo
    FIXTURE string_cmp
    ARGS    "-p|-s|print_marker"
    GOLDEN  string_cmp.print_marker.pseudo.txt
)

# printf/fprintf - variadic arg trimming driven by format-string parsing.
ember_golden_test(
    NAME    printf_one_arg_pseudo
    FIXTURE printf_noise
    ARGS    "-p|-s|one_arg"
    GOLDEN  printf_noise.one_arg.pseudo.txt
)
ember_golden_test(
    NAME    printf_two_args_pseudo
    FIXTURE printf_noise
    ARGS    "-p|-s|two_args"
    GOLDEN  printf_noise.two_args.pseudo.txt
)
ember_golden_test(
    NAME    printf_no_args_pseudo
    FIXTURE printf_noise
    ARGS    "-p|-s|no_args"
    GOLDEN  printf_noise.no_args.pseudo.txt
)
ember_golden_test(
    NAME    printf_width_star_pseudo
    FIXTURE printf_noise
    ARGS    "-p|-s|width_star"
    GOLDEN  printf_noise.width_star.pseudo.txt
)
# Exercises argv-style pointer indexing: *(u64*)(a2+8) → a2[1].
ember_golden_test(
    NAME    printf_main_argv_pseudo
    FIXTURE printf_noise
    ARGS    "-p|-s|main"
    GOLDEN  printf_noise.main.pseudo.txt
)
ember_golden_test(
    NAME    low_byte_flag_merge_pseudo
    FIXTURE low_byte_flag
    ARGS    "-p|-s|low_byte_flag_merge"
    GOLDEN  low_byte_flag.low_byte_flag_merge.pseudo.txt
)

# Stack-canary prologue+check suppression (-fstack-protector-strong).
ember_golden_test(
    NAME    canary_uses_buffer_pseudo
    FIXTURE canary
    ARGS    "-p|-s|uses_buffer"
    GOLDEN  canary.uses_buffer.pseudo.txt
)
ember_golden_test(
    NAME    noreturn_import_assert_fail_pseudo
    FIXTURE noreturn_import
    ARGS    "-p|-s|assert_fail_path"
    GOLDEN  noreturn_import.assert_fail_path.pseudo.txt
)
ember_golden_test(
    NAME    assert_name_stripped_infer_pseudo
    FIXTURE assert_name_stripped
    ARGS    "--infer-string-names|-p|-s|recovered_assert_name"
    GOLDEN  assert_name.recovered_assert_name.pseudo.txt
)
ember_golden_test(
    NAME    mangled_string_name_stripped_infer_pseudo
    FIXTURE mangled_string_name_stripped
    ARGS    "--infer-string-names|-p|-s|Example::Worker::run"
    GOLDEN  mangled_string_name.recovered.pseudo.txt
)
ember_golden_test(
    NAME    surface_inventory_summary
    FIXTURE surface_inventory
    ARGS    "-q|--no-cache|--surfaces"
    GOLDEN  surface_inventory.surfaces.txt
)
ember_golden_test(
    NAME    surface_inventory_script_vm_evidence
    FIXTURE surface_inventory
    ARGS    "-q|--no-cache|--surfaces|--surface|script_vm|--surface-row-type|evidence"
    GOLDEN  surface_inventory.script_vm_evidence.txt
)
ember_golden_test(
    NAME    surface_inventory_json
    FIXTURE surface_inventory
    ARGS    "-q|--no-cache|--surfaces|--json"
    GOLDEN  surface_inventory.surfaces.json.txt
)
ember_golden_test(
    NAME    surface_inventory_bundle_summary
    FIXTURE surface_inventory_app
    ARGS    "-q|--no-cache|--surfaces"
    GOLDEN  surface_inventory.bundle.surfaces.txt
)
ember_golden_test(
    NAME    surface_inventory_bundle_anti_tamper
    FIXTURE surface_inventory_app
    ARGS    "-q|--no-cache|--surfaces|--surface|anti_tamper|--surface-kind|bundle_file|--surface-row-type|evidence"
    GOLDEN  surface_inventory.bundle.anti_tamper.txt
)
ember_golden_test(
    NAME    surface_inventory_bundle_shader_category
    FIXTURE surface_inventory_app
    ARGS    "-q|--no-cache|--surfaces|--surface|graphics_rendering|--surface-kind|bundle_file|--surface-category|artifact_shader|--surface-row-type|evidence"
    GOLDEN  surface_inventory.bundle.shader.txt
)
ember_golden_test(
    NAME    surface_inventory_bundle_category_rows
    FIXTURE surface_inventory_app
    ARGS    "-q|--no-cache|--surfaces|--surface-row-type|category"
    GOLDEN  surface_inventory.bundle.categories.txt
)
ember_golden_test(
    NAME    surface_inventory_bundle_artifact_rows
    FIXTURE surface_inventory_app
    ARGS    "-q|--no-cache|--surfaces|--surface-row-type|artifact|--surface-category|artifact_shader"
    GOLDEN  surface_inventory.bundle.artifacts.txt
)
ember_golden_test(
    NAME    surface_bundle_artifacts_without_binary_load
    FIXTURE surface_text_app
    ARGS    "-q|--no-cache|--surfaces|--surface|graphics_rendering|--surface-kind|bundle_file|--surface-row-type|evidence"
    GOLDEN  surface_text_app.bundle.graphics.txt
)

# Trivial-tail goto inlining: goto fail; ... fail: cleanup; return -1;
ember_golden_test(
    NAME    gotos_multi_exit_pseudo
    FIXTURE gotos
    ARGS    "-p|-s|multi_exit"
    GOLDEN  gotos.multi_exit.pseudo.txt
)
ember_golden_test(
    NAME    gotos_cleanup_on_fail_pseudo
    FIXTURE gotos
    ARGS    "-p|-s|cleanup_on_fail"
    GOLDEN  gotos.cleanup_on_fail.pseudo.txt
)
ember_golden_test(
    NAME    gotos_shared_tail_pseudo
    FIXTURE gotos
    ARGS    "-p|-s|shared_tail"
    GOLDEN  gotos.shared_tail.pseudo.txt
)
# ---- arith (IR Mod op + do-while structurer) -------------------------------
#
# Two regressions land here. First: `IrOp::Mod` was added in adffa81 and
# until now had no direct golden - divmod_runtime exercises a runtime
# `% b` (gcc emits `IDIV r/m32`, the lifter raises it to a Mod alongside
# the Div). Second: the structurer's do-while detection now accepts
# loops with multiple back-edge predecessors (one cond-and-exit tail
# plus inner unconditional jumps from skip arms) - dowhile_with_skip
# is the smallest such shape and locks the rendered output so a future
# regression that falls back to goto soup shows up as a clean diff.

ember_golden_test(
    NAME    arith_divmod_runtime_pseudo
    FIXTURE arith
    ARGS    "-p|-s|divmod_runtime"
    GOLDEN  arith.divmod_runtime.pseudo.txt
)

ember_golden_test(
    NAME    arith_signed_divmod_runtime_pseudo
    FIXTURE arith
    ARGS    "-p|-s|signed_divmod_runtime"
    GOLDEN  arith.signed_divmod_runtime.pseudo.txt
)

ember_golden_test(
    NAME    arith_dowhile_with_skip_pseudo
    FIXTURE arith
    ARGS    "-p|-s|dowhile_with_skip"
    GOLDEN  arith.dowhile_with_skip.pseudo.txt
)

# Idiom-recognition pass: branchless abs patterns compiled at -O2 should
# simplify from (x >> 31 & x) + x / xor+ashr forms to `x < 0 ? -x : x`.
ember_golden_test(
    NAME    arith_idiom_abs_i32_pseudo
    FIXTURE arith_idiom
    ARGS    "-p|-s|abs_i32"
    GOLDEN  arith_idiom.abs_i32.pseudo.txt
)

ember_golden_test(
    NAME    arith_idiom_abs_i64_pseudo
    FIXTURE arith_idiom
    ARGS    "-p|-s|abs_i64"
    GOLDEN  arith_idiom.abs_i64.pseudo.txt
)

ember_golden_test(
    NAME    arith_idiom_neg_i32_pseudo
    FIXTURE arith_idiom
    ARGS    "-p|-s|neg_i32"
    GOLDEN  arith_idiom.neg_i32.pseudo.txt
)

# Locks Phase 4a-2 vector-shape recognition: the 24-byte 3-pointer
# struct's accesses render as begin / end / capacity, and indexed
# reads through the begin pointer come out as `b[idx]`.
ember_golden_test(
    NAME    vector_like_sum_vec_pseudo
    FIXTURE vector_like
    ARGS    "-p|-s|sum_vec"
    GOLDEN  vector_like.sum_vec.pseudo.txt
)

ember_golden_test(
    NAME    struct_fields_inspect_packet_pseudo
    FIXTURE struct_fields
    ARGS    "-p|-s|inspect_packet|--annotations|${_fixture_dir}/struct_fields.ann"
    GOLDEN  struct_fields.inspect_packet.pseudo.txt
)

ember_golden_test(
    NAME    global_resolution_unsized_head_pseudo
    FIXTURE global_resolution
    ARGS    "-p|-s|read_unsized_head"
    GOLDEN  global_resolution.read_unsized_head.pseudo.txt
)
ember_golden_test(
    NAME    global_resolution_unsized_tail_pseudo
    FIXTURE global_resolution
    ARGS    "-p|-s|read_unsized_tail"
    GOLDEN  global_resolution.read_unsized_tail.pseudo.txt
)
ember_golden_test(
    NAME    global_resolution_after_pseudo
    FIXTURE global_resolution
    ARGS    "-p|-s|read_after"
    GOLDEN  global_resolution.read_after.pseudo.txt
)
ember_golden_test(
    NAME    global_resolution_addr_tail_pseudo
    FIXTURE global_resolution
    ARGS    "-p|-s|addr_unsized_tail"
    GOLDEN  global_resolution.addr_unsized_tail.pseudo.txt
)

ember_golden_test(
    NAME    tail_call_double_wrap_pseudo
    FIXTURE tail_call
    ARGS    "-p|-s|double_wrap"
    GOLDEN  tail_call.double_wrap.pseudo.txt
)

# --callees: direct (call inner, call strlen@PLT) and tail (jmp strlen@PLT)
# edges of the tail_call fixture. Addresses here share the same -no-pie
# baseline (0x401000) that other tail_call goldens bake in, so these are as
# stable as the existing golden set.
ember_golden_test(
    NAME    tail_call_main_callees
    FIXTURE tail_call
    ARGS    "--callees|main"
    GOLDEN  tail_call.main.callees.txt
)
ember_golden_test(
    NAME    tail_call_wrap_strlen_callees_json
    FIXTURE tail_call
    ARGS    "--callees|wrap_strlen|--json"
    GOLDEN  tail_call.wrap_strlen.callees.json.txt
)
# Leaf function with no calls - acceptance criterion: empty list, exit 0.
ember_golden_test(
    NAME    tail_call_inner_callees_empty
    FIXTURE tail_call
    ARGS    "--callees|inner"
    GOLDEN  tail_call.inner.callees.txt
)

# --apply --dry-run on a hand-written .ember fixture exercising
# [rename] / [note] / [signature] (deterministic sections; the
# pattern-rename / from-strings paths are unit-tested separately
# because their output set depends on the gcc-emitted sub_* layout
# which drifts across patch versions). Locks the parser, the resolver
# fallback (LHS by name resolves through the symbol table), the
# signature parser, and the to_text serializer all the way through
# the CLI's run_apply_ember pipeline.
ember_golden_test(
    NAME    return_value_apply_dry_run
    FIXTURE return_value
    ARGS    "--apply|${_fixture_dir}/return_value.ember|--dry-run|--no-cache|--quiet"
    GOLDEN  return_value.apply_dry_run.txt
)

# --containing-fn: resolve an address inside the body of `big` to its
# entry + name + offset-within. The fixture is compiled -no-pie so the
# VAs are stable; `big` lives at a known offset. Exercises both TSV and
# JSON output.
ember_golden_test(
    NAME    return_value_containing_fn
    FIXTURE return_value
    ARGS    "--containing-fn|0x401143"
    GOLDEN  return_value.containing_fn.txt
)
ember_golden_test(
    NAME    return_value_containing_fn_json
    FIXTURE return_value
    ARGS    "--containing-fn|0x401143|--json"
    GOLDEN  return_value.containing_fn.json.txt
)

ember_expect_fail_test(
    NAME       disasm_at_bad_count_rejected
    FIXTURE    return_value
    ARGS       "--disasm-at|0x401000|--count|2wat"
    ERR_SUBSTR "bad --count"
)

add_test(
    NAME disasm_at_json_unmapped_fails
    COMMAND ${CMAKE_COMMAND}
        -DEMBER=$<TARGET_FILE:ember_cli>
        -DBINARY=${EMBER_FIXTURE_return_value_PATH}
        "-DARGS=--disasm-at|0x999999|--json"
        "-DOUT_SUBSTR=\"error\":"
        -P ${CMAKE_CURRENT_SOURCE_DIR}/run_cli_json_expect_fail.cmake
)
set_tests_properties(disasm_at_json_unmapped_fails PROPERTIES
    DEPENDS ember_cli
    LABELS golden
)

ember_expect_fail_test(
    NAME       disasm_window_zero_count_rejected
    FIXTURE    return_value
    ARGS       "--disasm-window|0x401000|--count|0"
    ERR_SUBSTR "bad --count"
)

ember_golden_test(
    NAME    disasm_at_nonexec_section_warns
    FIXTURE symuses_imm64
    ARGS    "--disasm-at|0x402000|--count|2"
    GOLDEN  symuses_imm64.rodata_disasm_at.txt
)

ember_expect_fail_test(
    NAME       numeric_filter_bad_integer_rejected
    FIXTURE    return_value
    ARGS       "--min-fn-size|12wat|--functions"
    ERR_SUBSTR "--min-fn-size: bad integer"
)

ember_expect_fail_test(
    NAME       identify_threshold_suffix_rejected
    FIXTURE    return_value
    ARGS       "--identify-threshold|0.5junk|--identify"
    ERR_SUBSTR "--identify-threshold"
)

ember_expect_fail_test(
    NAME       recognize_threshold_nan_rejected
    FIXTURE    return_value
    ARGS       "--recognize-threshold|nan|--recognize"
    ERR_SUBSTR "--recognize-threshold"
)

# ---- dead_store (DSE on global-address stores) ----------------------------

ember_golden_test(
    NAME    dead_store_redundant_pseudo
    FIXTURE dead_store
    ARGS    "-p|-s|redundant"
    GOLDEN  dead_store.redundant.pseudo.txt
)

# ---- fp_scalar (scalar SSE float/double arithmetic) ----------------------
#
# Decoder+lifter handle scalar FP ops as real math instead of intrinsic
# calls. With the hand-written annotations file, param substitution also
# covers xmm-passed floating-point arguments (xmm0..xmm7 → declared names).

ember_golden_test(
    NAME    fp_scalar_sum_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|sum|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.sum.pseudo.txt
)

ember_golden_test(
    NAME    fp_scalar_poly_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|poly|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.poly.pseudo.txt
)

ember_golden_test(
    NAME    fp_scalar_mix_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|mix|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.mix.pseudo.txt
)

ember_golden_test(
    NAME    fp_scalar_single_sum_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|single_sum|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.single_sum.pseudo.txt
)

# Comparison-driven branches: ucomisd / comiss → ZF/CF/PF → jcc readouts as
# `if (a > b)` etc. instead of an opaque `ucomi(...)` plus stale-flag jcc.
ember_golden_test(
    NAME    fp_scalar_max_d_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|max_d|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.max_d.pseudo.txt
)
ember_golden_test(
    NAME    fp_scalar_clamp_f_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|clamp_f|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.clamp_f.pseudo.txt
)
# sqrt → libm-style intrinsic name, expression inlined into return.
ember_golden_test(
    NAME    fp_scalar_hypot2_pseudo
    FIXTURE fp_scalar
    ARGS    "-p|-s|hypot2|--annotations|${_fixture_dir}/fp_scalar.ann"
    GOLDEN  fp_scalar.hypot2.pseudo.txt
)

# ---- mem_forward (stack-slot load forwarding) ------------------------------
#
# Compiled at -O0 so every local round-trips the stack. The golden captures
# the post-forwarding pseudo-C - if the GVN/memory-forward passes regress,
# `return` here will stop referencing `y` via a forwarded temp and start
# reading from a stack-slot load again.

ember_golden_test(
    NAME    mem_forward_pseudo
    FIXTURE mem_forward
    ARGS    "-p|-s|forward_local"
    GOLDEN  mem_forward.forward_local.pseudo.txt
)

# ---- macho_tiny (hand-built Mach-O: header, segments, symtab, LC_MAIN,
#                  LC_FUNCTION_STARTS, underscore-stripped symbol names) -----
#
# Emitted by a Python generator at configure time so we don't need the Apple
# SDK or a Mac toolchain to run these. Guards the Mach-O loader end-to-end
# against regressions even on Linux CI.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    function(ember_build_python_macho_fixture name script)
        set(_out "${_build_dir}/${name}")
        set(_script "${_fixture_dir}/${script}")
        add_custom_command(
            OUTPUT "${_out}"
            COMMAND ${Python3_EXECUTABLE}
                    "${_script}"
                    ${ARGN}
                    "${_out}"
            DEPENDS "${_script}"
            COMMENT "Generating Mach-O fixture ${name}"
            VERBATIM
        )
        add_custom_target(ember_fixture_${name} ALL DEPENDS "${_out}")
        set(EMBER_FIXTURE_${name}_PATH "${_out}" PARENT_SCOPE)
    endfunction()

    ember_build_python_macho_fixture(macho_tiny make_macho_tiny.py)
    ember_build_python_macho_fixture(macho_unixthread make_macho_tiny.py
        --unixthread)
    ember_build_python_macho_fixture(macho_fat_tiny make_macho_tiny.py --fat)
    ember_build_python_macho_fixture(macho_exports_trie make_macho_tiny.py
        --exports-trie)
    ember_build_python_macho_fixture(macho_data_in_code make_macho_tiny.py
        --data-in-code)
    ember_build_python_macho_fixture(macho_x64_import make_macho_x64_import.py)
    ember_build_python_macho_fixture(
        macho_x64_dysymtab_import make_macho_x64_import.py --dysymtab)
    ember_build_python_macho_fixture(
        macho_x64_direct_import make_macho_x64_import.py --dysymtab-direct)
    ember_build_python_macho_fixture(
        macho_x64_weak_bind_import make_macho_x64_import.py --weak-bind)
    ember_build_python_macho_fixture(
        macho_x64_stack_guard make_macho_x64_import.py --stack-guard)
    ember_build_python_macho_fixture(
        macho_arm64e_import make_macho_arm64e_import.py)
    ember_build_python_macho_fixture(
        macho_arm64e_auth_rebase make_macho_arm64e_import.py --auth-rebase)
    ember_build_python_macho_fixture(
        macho_arm64e_import_addend make_macho_arm64e_import.py
        --import-addend)
    ember_build_python_macho_fixture(
        macho_arm64e_import_addend64 make_macho_arm64e_import.py
        --import-addend64)
    ember_build_python_macho_fixture(
        macho_compact_unwind make_macho_compact_unwind.py)
    ember_build_python_macho_fixture(
        macho_blocks make_macho_blocks.py)
    ember_build_python_macho_fixture(
        macho_dsym_primary make_macho_dsym_pair.py)
    ember_build_python_macho_fixture(
        macho_dsym_symbols make_macho_dsym_pair.py --dsym)
    set(_macho_dsym_bundle_file
        "${_build_dir}/macho_dsym_primary.dSYM/Contents/Resources/DWARF/macho_dsym_primary")
    add_custom_command(
        OUTPUT "${_macho_dsym_bundle_file}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
                "${_build_dir}/macho_dsym_primary.dSYM/Contents/Resources/DWARF"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${EMBER_FIXTURE_macho_dsym_symbols_PATH}"
                "${_macho_dsym_bundle_file}"
        DEPENDS ember_fixture_macho_dsym_symbols
        COMMENT "Staging Mach-O dSYM bundle macho_dsym_primary.dSYM"
        VERBATIM
    )
    add_custom_target(ember_fixture_macho_dsym_bundle ALL
        DEPENDS "${_macho_dsym_bundle_file}")
    ember_build_python_macho_fixture(
        macho_objc_relative make_macho_objc_relative.py)
    ember_build_python_macho_fixture(
        macho_string_names make_macho_string_names.py)
    ember_build_python_macho_fixture(
        macho_lua_reg make_macho_lua_reg.py)
    ember_build_python_macho_fixture(
        macho_graphics_strings make_macho_graphics_strings.py)
    ember_build_python_macho_fixture(
        macho_assert_rtn make_macho_assert_rtn.py)
    ember_build_python_macho_fixture(macho_objc_stret make_macho_objc_stret.py)
    ember_build_python_macho_fixture(
        macho_objc_stack_arg make_macho_objc_stack_arg.py)
    ember_build_python_macho_fixture(macho_objc_fpret make_macho_objc_fpret.py)
    ember_build_python_macho_fixture(macho_objc_super make_macho_objc_super.py)
    ember_build_python_macho_fixture(macho_cpp_rtti make_macho_cpp_rtti.py)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_rtti make_macho_cpp_rtti.py --metadata)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_local_rtti make_macho_cpp_rtti.py --metadata-local)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_nested_local_rtti make_macho_cpp_rtti.py --metadata-nested-local)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_nested_free_rtti make_macho_cpp_rtti.py --metadata-nested-free)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_dtor_rtti make_macho_cpp_rtti.py --metadata-dtor)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_ctor_rtti make_macho_cpp_rtti.py --metadata-ctor)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_operator_rtti make_macho_cpp_rtti.py --metadata-operator)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_conversion_rtti make_macho_cpp_rtti.py --metadata-conversion)
    ember_build_python_macho_fixture(
        macho_cpp_metadata_long_rtti make_macho_cpp_rtti.py --metadata-long)
    ember_build_python_macho_fixture(
        macho_cpp_shared_ptr_rtti make_macho_cpp_rtti.py --shared-ptr)
    ember_build_python_macho_fixture(macho_swift_types make_macho_swift_types.py)

    # ---- ppc32_reloc (hand-built ELF32 ET_REL with code/data relocations) --
    # Generated directly so this remains cross-toolchain-independent.
    set(_ppc32_reloc "${_build_dir}/ppc32_reloc.o")
    add_custom_command(
        OUTPUT "${_ppc32_reloc}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc32_reloc.py"
                "${_ppc32_reloc}"
        DEPENDS "${_fixture_dir}/make_ppc32_reloc.py"
        COMMENT "Generating ELF PPC32 relocatable fixture ppc32_reloc.o"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32_reloc ALL DEPENDS "${_ppc32_reloc}")
    set(EMBER_FIXTURE_ppc32_reloc_PATH "${_ppc32_reloc}")

    add_executable(ember_elf_ppc_reloc_test elf_ppc_reloc_test.cpp)
    target_link_libraries(ember_elf_ppc_reloc_test PRIVATE ember::core ember::flags)
    add_dependencies(ember_elf_ppc_reloc_test ember_fixture_ppc32_reloc)
    add_test(NAME elf_ppc_reloc_unit
        COMMAND ember_elf_ppc_reloc_test "${_ppc32_reloc}")

    # ---- wii_rel (version-3 module with self, DOL, and cross-REL edges) -----
    set(_wii_rel "${_build_dir}/wii_rel.rel")
    add_custom_command(
        OUTPUT "${_wii_rel}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_wii_rel.py"
                "${_wii_rel}"
        DEPENDS "${_fixture_dir}/make_wii_rel.py"
        COMMENT "Generating Wii REL fixture wii_rel.rel"
        VERBATIM
    )
    add_custom_target(ember_fixture_wii_rel ALL DEPENDS "${_wii_rel}")
    set(EMBER_FIXTURE_wii_rel_PATH "${_wii_rel}")

    add_executable(ember_rel_loader_test rel_loader_test.cpp)
    target_link_libraries(ember_rel_loader_test PRIVATE ember::core ember::flags)
    add_dependencies(ember_rel_loader_test ember_fixture_wii_rel)
    add_test(NAME rel_loader_unit
        COMMAND ember_rel_loader_test "${_wii_rel}"
                "${_fixture_dir}/wii_rel_symbols.txt")

    set(_wii_rel_link_source "${_build_dir}/wii_rel_link_source.rel")
    set(_wii_rel_link_peer "${_build_dir}/wii_rel_link_peer.rel")
    add_custom_command(
        OUTPUT "${_wii_rel_link_source}" "${_wii_rel_link_peer}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_wii_rel_pair.py"
                "${_wii_rel_link_source}" "${_wii_rel_link_peer}"
        DEPENDS "${_fixture_dir}/make_wii_rel_pair.py"
        COMMENT "Generating linked Wii REL pair fixtures"
        VERBATIM
    )
    add_custom_target(ember_fixture_wii_rel_pair ALL
        DEPENDS "${_wii_rel_link_source}" "${_wii_rel_link_peer}")

    add_executable(ember_rel_link_test rel_link_test.cpp)
    target_link_libraries(ember_rel_link_test PRIVATE ember::core ember::flags)
    add_dependencies(ember_rel_link_test ember_fixture_wii_rel_pair)
    add_test(NAME rel_link_unit
        COMMAND ember_rel_link_test
                "${_wii_rel_link_source}"
                "${_wii_rel_link_peer}"
                "${_fixture_dir}/wii_rel_link_source_symbols.txt"
                "${_fixture_dir}/wii_rel_link_peer_symbols.txt")

    ember_golden_test(
        NAME    wii_rel_prolog_disasm
        FIXTURE wii_rel
        ARGS    "-d|-s|_prolog"
        GOLDEN  wii_rel.prolog.disasm.txt
    )

    ember_golden_test(
        NAME    macho_tiny_main_pseudo
        FIXTURE macho_tiny
        ARGS    "-p|-s|main"
        GOLDEN  macho_tiny.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_tiny_add42_pseudo
        FIXTURE macho_tiny
        ARGS    "-p|-s|add42"
        GOLDEN  macho_tiny.add42.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_tiny_read_answer_pseudo
        FIXTURE macho_tiny
        ARGS    "-p|-s|read_answer"
        GOLDEN  macho_tiny.read_answer.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_unixthread_main_pseudo
        FIXTURE macho_unixthread
        ARGS    "-p|-s|main"
        GOLDEN  macho_tiny.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_fat_tiny_main_pseudo
        FIXTURE macho_fat_tiny
        ARGS    "-p|-s|main"
        GOLDEN  macho_tiny.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_exports_trie_exported_add42_pseudo
        FIXTURE macho_exports_trie
        ARGS    "-p|-s|exported_add42"
        GOLDEN  macho_exports_trie.exported_add42.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_data_in_code_data_guard_pseudo
        FIXTURE macho_data_in_code
        ARGS    "-p|-s|data_guard"
        GOLDEN  macho_data_in_code.data_guard.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_data_in_code_xrefs
        FIXTURE macho_data_in_code
        ARGS    "--xrefs"
        GOLDEN  macho_data_in_code.xrefs.txt
    )
    ember_golden_test(
        NAME    macho_x64_import_main_pseudo
        FIXTURE macho_x64_import
        ARGS    "-p|-s|main"
        GOLDEN  macho_x64_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_x64_dysymtab_import_main_pseudo
        FIXTURE macho_x64_dysymtab_import
        ARGS    "-p|-s|main"
        GOLDEN  macho_x64_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_x64_direct_import_main_pseudo
        FIXTURE macho_x64_direct_import
        ARGS    "-p|-s|main"
        GOLDEN  macho_x64_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_x64_weak_bind_import_main_pseudo
        FIXTURE macho_x64_weak_bind_import
        ARGS    "-p|-s|main"
        GOLDEN  macho_x64_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_x64_stack_guard_main_pseudo
        FIXTURE macho_x64_stack_guard
        ARGS    "-p|-s|main"
        GOLDEN  macho_x64_stack_guard.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_arm64e_import_main_pseudo
        FIXTURE macho_arm64e_import
        ARGS    "-p|-s|main"
        GOLDEN  macho_arm64e_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_arm64e_import_read_rebased_pseudo
        FIXTURE macho_arm64e_import
        ARGS    "-p|-s|read_rebased"
        GOLDEN  macho_arm64e_import.read_rebased.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_arm64e_auth_rebase_read_rebased_pseudo
        FIXTURE macho_arm64e_auth_rebase
        ARGS    "-p|-s|read_rebased"
        GOLDEN  macho_arm64e_import.read_rebased.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_arm64e_import_addend64_main_pseudo
        FIXTURE macho_arm64e_import_addend64
        ARGS    "-p|-s|main"
        GOLDEN  macho_arm64e_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_arm64e_import_addend_main_pseudo
        FIXTURE macho_arm64e_import_addend
        ARGS    "-p|-s|main"
        GOLDEN  macho_arm64e_import.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_compact_unwind_functions
        FIXTURE macho_compact_unwind
        ARGS    "--functions"
        GOLDEN  macho_compact_unwind.functions.txt
    )
    ember_golden_test(
        NAME    macho_blocks_functions
        FIXTURE macho_blocks
        ARGS    "--functions|__block_invoke"
        GOLDEN  macho_blocks.functions.txt
    )
    ember_golden_test(
        NAME    macho_blocks_inferred_functions
        FIXTURE macho_blocks
        ARGS    "__BINARY__|--no-cache|--infer-string-names|--functions|SampleWorker"
        GOLDEN  macho_blocks.inferred.functions.txt
    )
    ember_golden_test(
        NAME    macho_blocks_invoke_pseudo
        FIXTURE macho_blocks
        ARGS    "-p|-s|__block_invoke_100001006"
        GOLDEN  macho_blocks.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_dsym_overlay_hidden_pseudo
        FIXTURE macho_dsym_primary
        ARGS    "-p|-s|dsym_named_hidden|--dsym|${EMBER_FIXTURE_macho_dsym_symbols_PATH}|-q"
        GOLDEN  macho_dsym_overlay.hidden.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_dsym_auto_hidden_pseudo
        FIXTURE macho_dsym_primary
        ARGS    "-p|-s|dsym_named_hidden|-q"
        GOLDEN  macho_dsym_overlay.hidden.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_ping_pseudo
        FIXTURE macho_objc_relative
        ARGS    "-p|-s|-[Tiny ping]"
        GOLDEN  macho_objc_relative.ping.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_count_pseudo
        FIXTURE macho_objc_relative
        ARGS    "-p|-s|-[Tiny count]"
        GOLDEN  macho_objc_relative.count.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_objc_names
        FIXTURE macho_objc_relative
        ARGS    "--objc-names"
        GOLDEN  macho_objc_relative.objc_names.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_stack_block_functions
        FIXTURE macho_objc_relative
        ARGS    "--no-cache|--functions|Tiny_withCallback"
        GOLDEN  macho_objc_relative.stack_block.functions.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_block_capture_ivar_pseudo
        FIXTURE macho_objc_relative
        ARGS    "--no-cache|-p|-s|Tiny_withCallback_consumeBlock__block_invoke"
        GOLDEN  macho_objc_relative.block_capture_ivar.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_objc_protocols
        FIXTURE macho_objc_relative
        ARGS    "--objc-protocols"
        GOLDEN  macho_objc_relative.objc_protocols.txt
    )
    ember_golden_test(
        NAME    macho_objc_relative_objc_surfaces
        FIXTURE macho_objc_relative
        ARGS    "--objc-surfaces"
        GOLDEN  macho_objc_relative.objc_surfaces.txt
    )
    ember_golden_test(
        NAME    macho_string_names_recovered_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverName"
        GOLDEN  macho_string_names.recovered.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_pretty_function_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|recoverCachedValue"
        GOLDEN  macho_string_names.pretty_function.pseudo.txt
    )
    add_test(
        NAME macho_string_names_inferred_functions_cache
        COMMAND ${CMAKE_COMMAND}
            -DEMBER=$<TARGET_FILE:ember_cli>
            -DBINARY=${EMBER_FIXTURE_macho_string_names_PATH}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/run_functions_infer_cache.cmake
    )
    set_tests_properties(macho_string_names_inferred_functions_cache PROPERTIES
        DEPENDS ember_cli
        LABELS golden
    )
    ember_golden_test(
        NAME    macho_string_names_operator_function_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Example::Box::operator_eq"
        GOLDEN  macho_string_names.operator_function.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_destructor_function_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Example::Box::dtor_Box"
        GOLDEN  macho_string_names.destructor_function.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_clang_closure_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverClosureValue"
        GOLDEN  macho_string_names.clang_closure.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_shared_ptr_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverSharedStateFromControlBlock"
        GOLDEN  macho_string_names.shared_ptr_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_callable_traits_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverCallableTraitFromVeryLongCompilerMetadataArtifactNameThatSurvivesBinaryStripping"
        GOLDEN  macho_string_names.callable_traits_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_local_static_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|recoverFileLocalCompilerArtifact"
        GOLDEN  macho_string_names.local_static_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_anon_namespace_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|_GLOBAL__N_1::recoverAnonymousNamespaceThing"
        GOLDEN  macho_string_names.anon_namespace_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_free_function_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|recoverFreeFunctionArtifact"
        GOLDEN  macho_string_names.free_function_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_nested_free_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|recoverNestedFreeFunctionArtifact"
        GOLDEN  macho_string_names.nested_free_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_mangled_destructor_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::dtor_Player"
        GOLDEN  macho_string_names.mangled_destructor_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_mangled_constructor_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::ctor_Player"
        GOLDEN  macho_string_names.mangled_constructor_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_mangled_operator_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Example::Gadget::operator_eq"
        GOLDEN  macho_string_names.mangled_operator_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_mangled_conversion_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Example::Gate::operator_Core_Player_ptr"
        GOLDEN  macho_string_names.mangled_conversion_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_bind_adapter_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverBindCompilerBug"
        GOLDEN  macho_string_names.bind_adapter_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_async_state_parent_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|Core::Player::recoverAsyncCompilerBug"
        GOLDEN  macho_string_names.async_state_parent.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_role_identifier_anchor_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|string_anchor_SchedulerHeartbeatJob"
        GOLDEN  macho_string_names.role_identifier_anchor.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_script_vm_telemetry_anchor_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|script_vm_telemetry_bad_synchronize_call"
        GOLDEN  macho_string_names.script_vm_telemetry_anchor.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_engine_feature_anchor_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|feature_scene_graph_task_queue"
        GOLDEN  macho_string_names.engine_feature_anchor.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_engine_feature_network_anchor_pseudo
        FIXTURE macho_string_names
        ARGS    "-q|--infer-string-names|-p|-s|feature_network_job_use_parallel_for"
        GOLDEN  macho_string_names.engine_feature_network_anchor.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_string_names_compiler_artifact_surface
        FIXTURE macho_string_names
        ARGS    "-q|--no-cache|--surfaces|--surface|compiler_artifacts|--surface-row-type|evidence"
        GOLDEN  macho_string_names.compiler_artifacts.surface.txt
    )
    ember_golden_test(
        NAME    macho_string_names_log_categories
        FIXTURE macho_string_names
        ARGS    "--no-cache|--log-categories"
        GOLDEN  macho_string_names.log_categories.txt
    )
    ember_golden_test(
        NAME    macho_lua_reg_inferred_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|lua_cfunc_tick"
        GOLDEN  macho_lua_reg.inferred.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_mangled_prefix_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|Engine::ScriptHost::resume"
        GOLDEN  macho_lua_reg.mangled_prefix.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_mangled_const_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|Engine::ScriptHost::inspect"
        GOLDEN  macho_lua_reg.mangled_const.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_mangled_local_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|Engine::ScriptHost::dispatch"
        GOLDEN  macho_lua_reg.mangled_local.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_bound_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|reflection_ScriptHost_performAction_bound_func_argc_2"
        GOLDEN  macho_lua_reg.reflection_bound.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_event_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|reflection_ScriptHost_actionSignal_event"
        GOLDEN  macho_lua_reg.reflection_event.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_property_pseudo
        FIXTURE macho_lua_reg
        ARGS    "-q|--infer-string-names|-p|-s|reflection_ScriptHost_actionLevel_property"
        GOLDEN  macho_lua_reg.reflection_property.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_descriptor_surface
        FIXTURE macho_lua_reg
        ARGS    "-q|--no-cache|--surfaces|--surface|reflection_metadata|--surface-row-type|evidence|--surface-category|reflection_bound_function"
        GOLDEN  macho_lua_reg.reflection_descriptor.surface.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_owner_surface
        FIXTURE macho_lua_reg
        ARGS    "-q|--no-cache|--surfaces|--surface|reflection_metadata|--surface-row-type|owner"
        GOLDEN  macho_lua_reg.reflection_owner.surface.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_owner_filter_surface
        FIXTURE macho_lua_reg
        ARGS    "-q|--no-cache|--surfaces|--surface|reflection_metadata|--surface-row-type|owner|--surface-owner|ScriptHost"
        GOLDEN  macho_lua_reg.reflection_owner.surface.txt
    )
    ember_golden_test(
        NAME    macho_lua_reflection_descriptor_row_surface
        FIXTURE macho_lua_reg
        ARGS    "-q|--no-cache|--surfaces|--surface|reflection_metadata|--surface-row-type|descriptor|--surface-owner|ScriptHost"
        GOLDEN  macho_lua_reg.reflection_descriptor_row.surface.txt
    )
    ember_golden_test(
        NAME    macho_graphics_gl_pseudo
        FIXTURE macho_graphics_strings
        ARGS    "-q|--infer-string-names|-p|-s|graphics_gl_bind_buffer"
        GOLDEN  macho_graphics_strings.gl.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_graphics_vk_pseudo
        FIXTURE macho_graphics_strings
        ARGS    "-q|--infer-string-names|-p|-s|graphics_vk_create_swapchain_khr"
        GOLDEN  macho_graphics_strings.vk.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_graphics_glsl_pseudo
        FIXTURE macho_graphics_strings
        ARGS    "-q|--infer-string-names|-p|-s|graphics_glsl_shader_source"
        GOLDEN  macho_graphics_strings.glsl.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_graphics_shader_pack_pseudo
        FIXTURE macho_graphics_strings
        ARGS    "-q|--infer-string-names|-p|-s|graphics_shader_pack_load"
        GOLDEN  macho_graphics_strings.shader_pack.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_graphics_gl_proc_loader_pseudo
        FIXTURE macho_graphics_strings
        ARGS    "-q|--infer-string-names|-p|-s|graphics_gl_proc_loader"
        GOLDEN  macho_graphics_strings.gl_proc_loader.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_graphics_inventory
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics"
        GOLDEN  macho_graphics_strings.graphics.txt
    )
    ember_golden_test(
        NAME    macho_graphics_inventory_json
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--json"
        GOLDEN  macho_graphics_strings.graphics.json.txt
    )
    ember_golden_test(
        NAME    macho_graphics_api_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-api|glBindBuffer"
        GOLDEN  macho_graphics_strings.graphics.api_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_backend_domain_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-backend|opengl|--graphics-domain|buffer"
        GOLDEN  macho_graphics_strings.graphics.backend_domain_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_extension_family_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-api|glFramebufferTexture2D"
        GOLDEN  macho_graphics_strings.graphics.extension_family_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_extension_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-extension|ARB"
        GOLDEN  macho_graphics_strings.graphics.extension_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_row_type_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-row-type|extension"
        GOLDEN  macho_graphics_strings.graphics.row_type_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_category_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-category|proc_resolver"
        GOLDEN  macho_graphics_strings.graphics.category_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_constant_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-category|constant_name"
        GOLDEN  macho_graphics_strings.graphics.constant_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_extension_name_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-category|extension_name"
        GOLDEN  macho_graphics_strings.graphics.extension_name_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_role_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-role|proc_loader"
        GOLDEN  macho_graphics_strings.graphics.role_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_vulkan_role_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-backend|vulkan|--graphics-role|proc_loader"
        GOLDEN  macho_graphics_strings.graphics.vulkan_role_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_sdl_role_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-backend|sdl|--graphics-role|proc_loader"
        GOLDEN  macho_graphics_strings.graphics.sdl_role_filter.txt
    )
    ember_golden_test(
        NAME    macho_graphics_function_filter
        FIXTURE macho_graphics_strings
        ARGS    "-q|--no-cache|--graphics|--graphics-function|0x100001054"
        GOLDEN  macho_graphics_strings.graphics.function_filter.txt
    )
    ember_golden_test(
        NAME    macho_assert_rtn_recovered_pseudo
        FIXTURE macho_assert_rtn
        ARGS    "-q|--infer-string-names|-p|-s|MacPlayer::recoverFromAssert"
        GOLDEN  macho_assert_rtn.recovered.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_stret_main_pseudo
        FIXTURE macho_objc_stret
        ARGS    "-p|-s|main"
        GOLDEN  macho_objc_stret.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_stack_arg_main_pseudo
        FIXTURE macho_objc_stack_arg
        ARGS    "-p|-s|main"
        GOLDEN  macho_objc_stack_arg.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_fpret_main_pseudo
        FIXTURE macho_objc_fpret
        ARGS    "-p|-s|main"
        GOLDEN  macho_objc_fpret.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_objc_super_main_pseudo
        FIXTURE macho_objc_super
        ARGS    "-p|-s|main"
        GOLDEN  macho_objc_super.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_rtti_vfn0_pseudo
        FIXTURE macho_cpp_rtti
        ARGS    "-p|-s|Core::Player::vfn_0"
        GOLDEN  macho_cpp_rtti.vfn0.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_rtti_vfn1_pseudo
        FIXTURE macho_cpp_rtti
        ARGS    "-p|-s|Core::Player::vfn_1"
        GOLDEN  macho_cpp_rtti.vfn1.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_rtti_vfn0_pseudo
        FIXTURE macho_cpp_metadata_rtti
        ARGS    "-p|-s|Example::Worker::run::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_rtti.vfn0.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_rtti_dump
        FIXTURE macho_cpp_metadata_rtti
        ARGS    "--no-cache|--rtti"
        GOLDEN  macho_cpp_metadata_rtti.rtti.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_local_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_local_rtti
        ARGS    "-p|-s|recoverFileLocalCompilerArtifact::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_local_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_nested_local_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_nested_local_rtti
        ARGS    "-p|-s|Example::Worker::run::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_nested_local_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_nested_free_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_nested_free_rtti
        ARGS    "-p|-s|recoverNestedFreeFunctionArtifact::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_nested_free_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_dtor_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_dtor_rtti
        ARGS    "-p|-s|Core::Player::dtor_Player::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_dtor_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_ctor_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_ctor_rtti
        ARGS    "-p|-s|Core::Player::ctor_Player::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_ctor_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_operator_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_operator_rtti
        ARGS    "-p|-s|Example::Gadget::operator_eq::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_operator_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_conversion_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_conversion_rtti
        ARGS    "-p|-s|Example::Gate::operator_Core_Player_ptr::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_conversion_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_metadata_long_rtti_invoke_pseudo
        FIXTURE macho_cpp_metadata_long_rtti
        ARGS    "-p|-s|Core::Player::recoverCallableTraitFromVeryLongCompilerMetadataArtifactNameThatSurvivesRttiVtableFunctionNameRecoveryAndKeepsGoingPastTheOldOneHundredSixtyCharacterLimitForStrippedBuilds::lambda_0::invoke"
        GOLDEN  macho_cpp_metadata_long_rtti.invoke.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_cpp_shared_ptr_rtti_functions
        FIXTURE macho_cpp_shared_ptr_rtti
        ARGS    "--functions|on_zero_shared"
        GOLDEN  macho_cpp_shared_ptr_rtti.functions.txt
    )
    ember_golden_test(
        NAME    macho_swift_types_main_pseudo
        FIXTURE macho_swift_types
        ARGS    "-p|-s|main"
        GOLDEN  macho_swift_types.main.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_swift_types_field_name_pseudo
        FIXTURE macho_swift_types
        ARGS    "-p|-s|field_name"
        GOLDEN  macho_swift_types.field_name.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_swift_types_accessor_pseudo
        FIXTURE macho_swift_types
        ARGS    "-p|-s|swift_type_Widget_accessor"
        GOLDEN  macho_swift_types.accessor.pseudo.txt
    )
    ember_golden_test(
        NAME    macho_swift_types_field_symbol_validate
        FIXTURE macho_swift_types
        ARGS    "--validate|swift_field_Widget_title"
        GOLDEN  macho_swift_types.field_symbol.validate.txt
    )

    # ---- ppc64_tiny (hand-built ELF64, both endian modes) -----------------
    #
    # Synthetic fixtures so PPC64 loader + disasm coverage runs on Linux
    # without a cross compiler.
    set(_ppc64le_tiny "${_build_dir}/ppc64le_tiny")
    add_custom_command(
        OUTPUT "${_ppc64le_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                le
                "${_ppc64le_tiny}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating ELF PPC64LE fixture ppc64le_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc64le_tiny ALL DEPENDS "${_ppc64le_tiny}")
    set(EMBER_FIXTURE_ppc64le_tiny_PATH "${_ppc64le_tiny}")

    set(_ppc64be_tiny "${_build_dir}/ppc64be_tiny")
    add_custom_command(
        OUTPUT "${_ppc64be_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                be
                "${_ppc64be_tiny}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating ELF PPC64BE fixture ppc64be_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc64be_tiny ALL DEPENDS "${_ppc64be_tiny}")
    set(EMBER_FIXTURE_ppc64be_tiny_PATH "${_ppc64be_tiny}")

    set(_ppc64be_opd_tiny "${_build_dir}/ppc64be_opd_tiny")
    add_custom_command(
        OUTPUT "${_ppc64be_opd_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                be-opd
                "${_ppc64be_opd_tiny}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating ELF PPC64BE descriptor fixture ppc64be_opd_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc64be_opd_tiny ALL DEPENDS "${_ppc64be_opd_tiny}")
    set(EMBER_FIXTURE_ppc64be_opd_tiny_PATH "${_ppc64be_opd_tiny}")

    set(_ppc64be_ds "${_build_dir}/ppc64be_ds")
    add_custom_command(
        OUTPUT "${_ppc64be_ds}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                be-ds
                "${_ppc64be_ds}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating PPC64 DS-form fixture ppc64be_ds"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc64be_ds ALL DEPENDS "${_ppc64be_ds}")
    set(EMBER_FIXTURE_ppc64be_ds_PATH "${_ppc64be_ds}")

    ember_golden_test(
        NAME    ppc64le_tiny_disasm
        FIXTURE ppc64le_tiny
        ARGS    "-d"
        GOLDEN  ppc64le_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    ppc64be_tiny_disasm
        FIXTURE ppc64be_tiny
        ARGS    "-d"
        GOLDEN  ppc64be_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    ppc64le_tiny_ssa
        FIXTURE ppc64le_tiny
        ARGS    "-i|--ssa"
        GOLDEN  ppc64le_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    ppc64le_tiny_pseudo
        FIXTURE ppc64le_tiny
        ARGS    "-p"
        GOLDEN  ppc64le_tiny.pseudo.txt
    )
    ember_golden_test(
        NAME    ppc64be_tiny_ssa
        FIXTURE ppc64be_tiny
        ARGS    "-i|--ssa"
        GOLDEN  ppc64be_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    ppc64be_tiny_pseudo
        FIXTURE ppc64be_tiny
        ARGS    "-p"
        GOLDEN  ppc64be_tiny.pseudo.txt
    )
    ember_golden_test(
        NAME    ppc64be_opd_tiny_pseudo
        FIXTURE ppc64be_opd_tiny
        ARGS    "-p"
        GOLDEN  ppc64be_opd_tiny.pseudo.txt
    )
    ember_golden_test(
        NAME    ppc64be_ds_disasm
        FIXTURE ppc64be_ds
        ARGS    "-d"
        GOLDEN  ppc64be_ds.disasm.txt
    )
    ember_golden_test(
        NAME    ppc64be_ds_ssa
        FIXTURE ppc64be_ds
        ARGS    "-i|--ssa"
        GOLDEN  ppc64be_ds.ssa.txt
    )

    # ---- ppc32_tiny (hand-built ELF32, both endian modes) -----------------
    # Reuses the PPC decoder/lifter path with a 32-bit ABI so the same
    # minimal addi+blr program returns u32 rather than the PPC64 u64 shape.
    set(_ppc32le_tiny "${_build_dir}/ppc32le_tiny")
    add_custom_command(
        OUTPUT "${_ppc32le_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                32le
                "${_ppc32le_tiny}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating ELF PPC32LE fixture ppc32le_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32le_tiny ALL DEPENDS "${_ppc32le_tiny}")
    set(EMBER_FIXTURE_ppc32le_tiny_PATH "${_ppc32le_tiny}")

    set(_ppc32be_tiny "${_build_dir}/ppc32be_tiny")
    add_custom_command(
        OUTPUT "${_ppc32be_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                32be
                "${_ppc32be_tiny}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating ELF PPC32BE fixture ppc32be_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32be_tiny ALL DEPENDS "${_ppc32be_tiny}")
    set(EMBER_FIXTURE_ppc32be_tiny_PATH "${_ppc32be_tiny}")

    ember_golden_test(
        NAME    ppc32le_tiny_disasm
        FIXTURE ppc32le_tiny
        ARGS    "-d"
        GOLDEN  ppc32le_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    ppc32be_tiny_disasm
        FIXTURE ppc32be_tiny
        ARGS    "-d"
        GOLDEN  ppc32be_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    ppc32le_tiny_ssa
        FIXTURE ppc32le_tiny
        ARGS    "-i|--ssa"
        GOLDEN  ppc32le_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    ppc32le_tiny_pseudo
        FIXTURE ppc32le_tiny
        ARGS    "-p"
        GOLDEN  ppc32le_tiny.pseudo.txt
    )
    ember_golden_test(
        NAME    ppc32be_tiny_ssa
        FIXTURE ppc32be_tiny
        ARGS    "-i|--ssa"
        GOLDEN  ppc32be_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    ppc32be_tiny_pseudo
        FIXTURE ppc32be_tiny
        ARGS    "-p"
        GOLDEN  ppc32be_tiny.pseudo.txt
    )

    set(_ppc32be_scalar "${_build_dir}/ppc32be_scalar")
    add_custom_command(
        OUTPUT "${_ppc32be_scalar}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                32be-scalar
                "${_ppc32be_scalar}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating scalar ELF PPC32BE fixture ppc32be_scalar"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32be_scalar ALL DEPENDS "${_ppc32be_scalar}")
    set(EMBER_FIXTURE_ppc32be_scalar_PATH "${_ppc32be_scalar}")

    ember_golden_test(
        NAME    ppc32be_scalar_disasm
        FIXTURE ppc32be_scalar
        ARGS    "-d"
        GOLDEN  ppc32be_scalar.disasm.txt
    )
    ember_golden_test(
        NAME    ppc32be_scalar_ssa
        FIXTURE ppc32be_scalar
        ARGS    "-i|--ssa"
        GOLDEN  ppc32be_scalar.ssa.txt
    )
    ember_golden_test(
        NAME    ppc32be_scalar_pseudo
        FIXTURE ppc32be_scalar
        ARGS    "-p"
        GOLDEN  ppc32be_scalar.pseudo.txt
    )

    set(_ppc32be_fp "${_build_dir}/ppc32be_fp")
    add_custom_command(
        OUTPUT "${_ppc32be_fp}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                32be-fp
                "${_ppc32be_fp}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating scalar FP ELF PPC32BE fixture ppc32be_fp"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32be_fp ALL DEPENDS "${_ppc32be_fp}")
    set(EMBER_FIXTURE_ppc32be_fp_PATH "${_ppc32be_fp}")

    ember_golden_test(
        NAME    ppc32be_fp_disasm
        FIXTURE ppc32be_fp
        ARGS    "-d"
        GOLDEN  ppc32be_fp.disasm.txt
    )
    ember_golden_test(
        NAME    ppc32be_fp_ssa
        FIXTURE ppc32be_fp
        ARGS    "-i|--ssa"
        GOLDEN  ppc32be_fp.ssa.txt
    )

    set(_ppc32be_dol "${_build_dir}/ppc32be_dol.dol")
    set(_ppc32be_dol_map "${_ppc32be_dol}.map")
    add_custom_command(
        OUTPUT "${_ppc32be_dol}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_ppc64_tiny.py"
                dol-scalar
                "${_ppc32be_dol}"
        DEPENDS "${_fixture_dir}/make_ppc64_tiny.py"
        COMMENT "Generating scalar DOL PPC32BE fixture ppc32be_dol"
        VERBATIM
    )
    add_custom_command(
        OUTPUT "${_ppc32be_dol_map}"
        COMMAND ${CMAKE_COMMAND} -E copy
                "${_fixture_dir}/ppc32be_dol.map"
                "${_ppc32be_dol_map}"
        DEPENDS "${_fixture_dir}/ppc32be_dol.map"
        COMMENT "Staging DOL PPC32BE map ppc32be_dol.dol.map"
        VERBATIM
    )
    add_custom_target(ember_fixture_ppc32be_dol ALL
        DEPENDS "${_ppc32be_dol}" "${_ppc32be_dol_map}")
    set(EMBER_FIXTURE_ppc32be_dol_PATH "${_ppc32be_dol}")

    set(_dtk_project "${_build_dir}/dtk_project")
    set(_dtk_object "${_dtk_project}/orig/EU0/sys/main.dol")
    set(_dtk_config "${_dtk_project}/config/EU0/config.yml")
    set(_dtk_symbols "${_dtk_project}/config/EU0/symbols.txt")
    set(_dtk_rel_object "${_dtk_project}/orig/EU0/files/rel/test/nlzss")
    set(_dtk_rel_symbols "${_dtk_project}/config/EU0/test/symbols.txt")
    set(_dtk_link_source_object
        "${_dtk_project}/orig/EU0/files/rel/link_source/nlzss")
    set(_dtk_link_source_symbols
        "${_dtk_project}/config/EU0/link_source/symbols.txt")
    set(_dtk_link_peer_object
        "${_dtk_project}/orig/EU0/files/rel/link_peer/nlzss")
    set(_dtk_link_peer_symbols
        "${_dtk_project}/config/EU0/link_peer/symbols.txt")
    add_custom_command(
        OUTPUT "${_dtk_object}" "${_dtk_config}" "${_dtk_symbols}"
               "${_dtk_rel_object}" "${_dtk_rel_symbols}"
               "${_dtk_link_source_object}" "${_dtk_link_source_symbols}"
               "${_dtk_link_peer_object}" "${_dtk_link_peer_symbols}"
        COMMAND ${CMAKE_COMMAND} -E make_directory
                "${_dtk_project}/orig/EU0/sys"
                "${_dtk_project}/config/EU0"
                "${_dtk_project}/orig/EU0/files/rel/test"
                "${_dtk_project}/config/EU0/test"
                "${_dtk_project}/orig/EU0/files/rel/link_source"
                "${_dtk_project}/config/EU0/link_source"
                "${_dtk_project}/orig/EU0/files/rel/link_peer"
                "${_dtk_project}/config/EU0/link_peer"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_ppc32be_dol}" "${_dtk_object}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_fixture_dir}/dtk_project/config/EU0/config.yml" "${_dtk_config}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_fixture_dir}/dtk_project/config/EU0/symbols.txt" "${_dtk_symbols}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_wii_rel}" "${_dtk_rel_object}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_fixture_dir}/wii_rel_symbols.txt" "${_dtk_rel_symbols}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_wii_rel_link_source}" "${_dtk_link_source_object}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_fixture_dir}/wii_rel_link_source_symbols.txt"
                "${_dtk_link_source_symbols}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_wii_rel_link_peer}" "${_dtk_link_peer_object}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${_fixture_dir}/wii_rel_link_peer_symbols.txt"
                "${_dtk_link_peer_symbols}"
        DEPENDS
            "${_ppc32be_dol}"
            "${_wii_rel}"
            "${_wii_rel_link_source}"
            "${_wii_rel_link_peer}"
            "${_fixture_dir}/dtk_project/config/EU0/config.yml"
            "${_fixture_dir}/dtk_project/config/EU0/symbols.txt"
            "${_fixture_dir}/wii_rel_symbols.txt"
            "${_fixture_dir}/wii_rel_link_source_symbols.txt"
            "${_fixture_dir}/wii_rel_link_peer_symbols.txt"
        COMMENT "Staging DTK project fixture"
        VERBATIM
    )
    add_custom_target(ember_fixture_dtk_project ALL
        DEPENDS "${_dtk_object}" "${_dtk_config}" "${_dtk_symbols}"
                "${_dtk_rel_object}" "${_dtk_rel_symbols}"
                "${_dtk_link_source_object}" "${_dtk_link_source_symbols}"
                "${_dtk_link_peer_object}" "${_dtk_link_peer_symbols}")
    set(EMBER_FIXTURE_dtk_project_PATH "${_dtk_project}")

    ember_golden_test(
        NAME    ppc32be_dol_disasm
        FIXTURE ppc32be_dol
        ARGS    "-d"
        GOLDEN  ppc32be_dol.disasm.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_ssa
        FIXTURE ppc32be_dol
        ARGS    "-i|--ssa"
        GOLDEN  ppc32be_dol.ssa.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_pseudo
        FIXTURE ppc32be_dol
        ARGS    "-p"
        GOLDEN  ppc32be_dol.pseudo.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_functions
        FIXTURE ppc32be_dol
        ARGS    "--no-cache|--functions"
        GOLDEN  ppc32be_dol.functions.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_data_xrefs
        FIXTURE ppc32be_dol
        ARGS    "--no-cache|--data-xrefs"
        GOLDEN  ppc32be_dol.data_xrefs.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_xrefs
        FIXTURE ppc32be_dol
        ARGS    "--no-cache|--xrefs"
        GOLDEN  ppc32be_dol.xrefs.txt
    )
    ember_golden_test(
        NAME    ppc32be_dol_indexed_disasm
        FIXTURE ppc32be_dol
        ARGS    "-d|--disasm-at|0x80003160|--count|9"
        GOLDEN  ppc32be_dol.indexed_disasm.txt
    )
    ember_golden_test(
        NAME    dtk_project_pseudo_by_name
        FIXTURE dtk_project
        ARGS    "--dtk|__BINARY__|--version|EU0|-p|-s|marioReInit|-q"
        GOLDEN  dtk_project.pseudo.txt
    )
    ember_golden_test(
        NAME    dtk_project_functions
        FIXTURE dtk_project
        ARGS    "--dtk|__BINARY__|--version|EU0|--no-cache|--functions|-q"
        GOLDEN  dtk_project.functions.txt
    )
    ember_golden_test(
        NAME    dtk_rel_prolog_disasm
        FIXTURE dtk_project
        ARGS    "--dtk|__BINARY__|--version|EU0|--dtk-module|test|-d|-s|fixture_prolog|-q"
        GOLDEN  dtk_rel.prolog.disasm.txt
    )
    ember_golden_test(
        NAME    dtk_rel_cross_module_disasm
        FIXTURE dtk_project
        ARGS    "--dtk|__BINARY__|--version|EU0|--dtk-module|link_source|-d|-s|link_source_entry|-q"
        GOLDEN  dtk_rel_cross_module.disasm.txt
    )
    ember_golden_test(
        NAME    dtk_rel_peer_function_disasm
        FIXTURE dtk_project
        ARGS    "--dtk|__BINARY__|--version|EU0|--dtk-module|link_source|-d|-s|peer_entry|-q"
        GOLDEN  dtk_rel_peer_function.disasm.txt
    )

    # ---- arm64_tiny (hand-built ELF AArch64) ------------------------------
    #
    # Locks the AArch64 decoder + lifter + structurer + emitter pipeline
    # against regressions on Linux without needing an ARM cross compiler.
    # The function is `add x0, x0, #42; ret` - minimal but exercises ALU
    # immediate, the AAPCS64 return register, and ret-via-x30.
    set(_arm64_tiny "${_build_dir}/arm64_tiny")
    add_custom_command(
        OUTPUT "${_arm64_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_arm64_tiny.py"
                "${_arm64_tiny}"
        DEPENDS "${_fixture_dir}/make_arm64_tiny.py"
        COMMENT "Generating ELF AArch64 fixture arm64_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_arm64_tiny ALL DEPENDS "${_arm64_tiny}")
    set(EMBER_FIXTURE_arm64_tiny_PATH "${_arm64_tiny}")

    ember_golden_test(
        NAME    arm64_tiny_disasm
        FIXTURE arm64_tiny
        ARGS    "-d"
        GOLDEN  arm64_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    arm64_tiny_ssa
        FIXTURE arm64_tiny
        ARGS    "-i|--ssa"
        GOLDEN  arm64_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    arm64_tiny_pseudo
        FIXTURE arm64_tiny
        ARGS    "-p"
        GOLDEN  arm64_tiny.pseudo.txt
    )

    # ---- arm32_tiny (hand-built ELF ARM / ARMv7) --------------------------
    #
    # Locks the A32 decoder + lifter + structurer + emitter pipeline on Linux
    # without an ARM cross compiler. The function is
    # `add r0, r0, #42; lsl r0, r0, #1; bx lr` - exercising ALU immediate,
    # the barrel-shifter MOV alias, the AAPCS return register (r0), and the
    # bx-lr return shape.
    set(_arm32_tiny "${_build_dir}/arm32_tiny")
    add_custom_command(
        OUTPUT "${_arm32_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_arm32_tiny.py"
                "${_arm32_tiny}"
        DEPENDS "${_fixture_dir}/make_arm32_tiny.py"
        COMMENT "Generating ELF ARM fixture arm32_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_arm32_tiny ALL DEPENDS "${_arm32_tiny}")
    set(EMBER_FIXTURE_arm32_tiny_PATH "${_arm32_tiny}")

    ember_golden_test(
        NAME    arm32_tiny_disasm
        FIXTURE arm32_tiny
        ARGS    "-d"
        GOLDEN  arm32_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    arm32_tiny_ssa
        FIXTURE arm32_tiny
        ARGS    "-i|--ssa"
        GOLDEN  arm32_tiny.ssa.txt
    )
    ember_golden_test(
        NAME    arm32_tiny_pseudo
        FIXTURE arm32_tiny
        ARGS    "-p"
        GOLDEN  arm32_tiny.pseudo.txt
    )

    # ---- pe_tiny (hand-built PE32+: DOS + NT + COFF + optional header +
    #               .text/.rdata/.pdata, one IAT import, one export,
    #               Win64 prologue, RUNTIME_FUNCTION table) ------------------
    #
    # Same Python-generator approach as macho_tiny - no Windows toolchain
    # required, so tests run on Linux CI. Exercises the PE loader end-to-end:
    # headers, sections, IAT import resolution, named export, PDATA-driven
    # function-start discovery, and the Win64 ABI path in the lifter.
    set(_pe_tiny "${_build_dir}/pe_tiny")
    add_custom_command(
        OUTPUT "${_pe_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe_tiny.py"
                "${_pe_tiny}"
        DEPENDS "${_fixture_dir}/make_pe_tiny.py"
        COMMENT "Generating PE fixture pe_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe_tiny ALL DEPENDS "${_pe_tiny}")
    set(EMBER_FIXTURE_pe_tiny_PATH "${_pe_tiny}")

    ember_golden_test(
        NAME    pe_tiny_main_pseudo
        FIXTURE pe_tiny
        ARGS    "-p|-s|sub_140001000"
        GOLDEN  pe_tiny.main.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_tiny_add42_pseudo
        FIXTURE pe_tiny
        ARGS    "-p|-s|add42"
        GOLDEN  pe_tiny.add42.pseudo.txt
    )

    set(_pe_rich "${_build_dir}/pe_rich")
    add_custom_command(
        OUTPUT "${_pe_rich}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe_rich.py"
                "${_pe_rich}"
        DEPENDS "${_fixture_dir}/make_pe_rich.py"
        COMMENT "Generating PE fixture pe_rich"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe_rich ALL DEPENDS "${_pe_rich}")
    set(EMBER_FIXTURE_pe_rich_PATH "${_pe_rich}")

    ember_golden_test(
        NAME    pe_rich_main_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_180001000"
        GOLDEN  pe_rich.main.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_add7_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|add7"
        GOLDEN  pe_rich.add7.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_tls_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|tls_callback_0"
        GOLDEN  pe_rich.tls_callback_0.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_open_file_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_1800010c0"
        GOLDEN  pe_rich.open_file.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_wrap_add7_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_180001100"
        GOLDEN  pe_rich.wrap_add7.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_switch_cfg
        FIXTURE pe_rich
        ARGS    "--cfg|-s|sub_180001140"
        GOLDEN  pe_rich.switch.cfg.txt
    )
    ember_golden_test(
        NAME    pe_rich_switch_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_180001140"
        GOLDEN  pe_rich.switch.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_rich_debug_wrap_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_180001180"
        GOLDEN  pe_rich.debug_wrap.pseudo.txt
    )
    # MSVC two-table indexed switch (Pattern D): a small byte-wide index
    # table feeds into an absolute 8-byte jump table. Locks in the new
    # detector path in cfg_builder.cpp.
    ember_golden_test(
        NAME    pe_rich_switch_msvc_cfg
        FIXTURE pe_rich
        ARGS    "--cfg|-s|sub_1800011c0"
        GOLDEN  pe_rich.switch_msvc.cfg.txt
    )
    ember_golden_test(
        NAME    pe_rich_switch_msvc_pseudo
        FIXTURE pe_rich
        ARGS    "-p|-s|sub_1800011c0"
        GOLDEN  pe_rich.switch_msvc.pseudo.txt
    )

    # ---- pe_stackargs (hand-built PE32+: two functions with real
    #                    UNWIND_INFO records) ----------------------------
    #
    # Exercises Win64 argument passing in the emitter:
    #   - incoming stack-argument naming: stack_sum reads its 5th/6th args
    #     from the caller's stack; they must render as `a5`/`a6`, not raw
    #     `arg_<hex>` stack loads.
    #   - positional fp/int arg mapping: fp_pos(int, double, int) places its
    #     args in (rcx, xmm1, r8) under Win64's shared positional slots, so
    #     the 3rd param resolves to r8 - the independent-counter mapping
    #     used to misplace it at rdx.
    set(_pe_stackargs "${_build_dir}/pe_stackargs")
    add_custom_command(
        OUTPUT "${_pe_stackargs}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe_stackargs.py"
                "${_pe_stackargs}"
        DEPENDS "${_fixture_dir}/make_pe_stackargs.py"
        COMMENT "Generating PE fixture pe_stackargs"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe_stackargs ALL DEPENDS "${_pe_stackargs}")
    set(EMBER_FIXTURE_pe_stackargs_PATH "${_pe_stackargs}")

    ember_golden_test(
        NAME    pe_stackargs_stack_sum_pseudo
        FIXTURE pe_stackargs
        ARGS    "-p|-s|sub_140001000"
        GOLDEN  pe_stackargs.stack_sum.pseudo.txt
    )
    ember_golden_test(
        NAME    pe_stackargs_fp_pos_pseudo
        FIXTURE pe_stackargs
        ARGS    "-p|--annotations|${_fixture_dir}/pe_stackargs.anns|-s|fp_pos"
        GOLDEN  pe_stackargs.fp_pos.pseudo.txt
    )

    # ---- recover-imports (IAT reconstruction) ------------------------
    #
    # Two fixtures: a reference DLL (refdll.dll) carrying a small export
    # table, and a raw-region capture (iat_dump.regions) whose .rdata
    # holds bare IAT pointers at a load base different from the DLL's
    # preferred base. The test base-solves the harvested pointers back to
    # dll!func names and emits the slot-RVA → name JSON contract.
    set(_pe_refdll "${_build_dir}/refdll.dll")
    add_custom_command(
        OUTPUT "${_pe_refdll}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe_refdll.py"
                "${_pe_refdll}"
        DEPENDS "${_fixture_dir}/make_pe_refdll.py"
        COMMENT "Generating PE fixture refdll.dll"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe_refdll ALL DEPENDS "${_pe_refdll}")
    set(EMBER_FIXTURE_pe_refdll_PATH "${_pe_refdll}")

    set(_iat_dump "${_build_dir}/iat_dump.regions")
    add_custom_command(
        OUTPUT "${_iat_dump}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_iat_dump.py"
                "${_iat_dump}"
        DEPENDS "${_fixture_dir}/make_iat_dump.py"
        COMMENT "Generating raw-region fixture iat_dump.regions"
        VERBATIM
    )
    add_custom_target(ember_fixture_iat_dump ALL DEPENDS "${_iat_dump}")
    set(EMBER_FIXTURE_iat_dump_PATH "${_iat_dump}")

    ember_golden_test(
        NAME    recover_imports_json
        FIXTURE iat_dump
        ARGS    "--regions|__BINARY__|--recover-imports|--json|--dll|${_pe_refdll}|--image-base|0x140000000"
        GOLDEN  recover_imports.json.txt
    )

    set(_pe32_bad "${_build_dir}/pe32_bad")
    add_custom_command(
        OUTPUT "${_pe32_bad}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe32_bad.py"
                "${_pe32_bad}"
        DEPENDS "${_fixture_dir}/make_pe32_bad.py"
        COMMENT "Generating malformed PE32 fixture pe32_bad"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe32_bad ALL DEPENDS "${_pe32_bad}")
    set(EMBER_FIXTURE_pe32_bad_PATH "${_pe32_bad}")

    ember_expect_fail_test(
        NAME       pe32_rejected
        FIXTURE    pe32_bad
        ERR_SUBSTR "PE32 (32-bit) not supported"
    )

    # ---- minidump_tiny (hand-built MS minidump: header, SystemInfo,
    #                    Memory64List with one r-x range carrying tiny
    #                    x86_64 code, ModuleList with one fake module) ----
    #
    # Same Python-generator approach as macho_tiny / pe_tiny - runs on
    # Linux CI without a Windows toolchain. Exercises MinidumpBinary's
    # header + stream-directory parse, SystemInfo→arch mapping, and the
    # bytes_at(va) override. The decompile golden also locks in the
    # Format::Minidump → Win64 ABI mapping (a1 == rcx, not rdi).
    set(_minidump_tiny "${_build_dir}/minidump_tiny.dmp")
    add_custom_command(
        OUTPUT "${_minidump_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_minidump_tiny.py"
                "${_minidump_tiny}"
        DEPENDS "${_fixture_dir}/make_minidump_tiny.py"
        COMMENT "Generating minidump fixture minidump_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_minidump_tiny ALL DEPENDS "${_minidump_tiny}")
    set(EMBER_FIXTURE_minidump_tiny_PATH "${_minidump_tiny}")

    ember_golden_test(
        NAME    minidump_tiny_add42_pseudo
        FIXTURE minidump_tiny
        ARGS    "-p|-s|sub_7ff600001000"
        GOLDEN  minidump_tiny.add42.pseudo.txt
    )
    ember_golden_test(
        NAME    minidump_tiny_disasm
        FIXTURE minidump_tiny
        ARGS    "-d|--disasm-at|0x7ff600001000|--count|4"
        GOLDEN  minidump_tiny.disasm.txt
    )

    # ---- minidump_pe (minidump wrapping the pe_tiny PE image as one
    #                   in-memory module) ---------------------------------
    #
    # Drives the A2 per-module export/import recovery: MinidumpBinary
    # walks the in-memory PE headers of the wrapped module and lifts
    # `add42` (export) and `GetTickCount` (IAT import) out of them.
    set(_minidump_pe "${_build_dir}/minidump_pe.dmp")
    add_custom_command(
        OUTPUT "${_minidump_pe}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_minidump_pe.py"
                "${_pe_tiny}"
                "${_minidump_pe}"
        DEPENDS "${_fixture_dir}/make_minidump_pe.py" "${_pe_tiny}"
        COMMENT "Generating minidump fixture minidump_pe"
        VERBATIM
    )
    add_custom_target(ember_fixture_minidump_pe ALL DEPENDS "${_minidump_pe}")
    set(EMBER_FIXTURE_minidump_pe_PATH "${_minidump_pe}")

    ember_golden_test(
        NAME    minidump_pe_functions
        FIXTURE minidump_pe
        ARGS    "--functions"
        GOLDEN  minidump_pe.functions.txt
    )

    # ---- pe_pdb (minimal PE with a sidecar PDB v7) --------------------
    #
    # Locks the PE → CodeView (RSDS) → MSF → S_PUB32 → symbol-table flow
    # against regressions. The .exe and .pdb are emitted by a single
    # generator so their CodeView reference + (segment, offset) → VA
    # resolution stays in sync. ember discovers the PDB via the loader's
    # sidecar lookup (basename of the embedded RSDS path → next to the
    # binary) and merges the publics into the PE's symbol table.
    set(_pe_pdb_exe "${_build_dir}/pe_pdb")
    set(_pe_pdb_pdb "${_build_dir}/pe_pdb.pdb")
    add_custom_command(
        OUTPUT "${_pe_pdb_exe}" "${_pe_pdb_pdb}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_pe_pdb.py"
                "${_pe_pdb_exe}"
                "${_pe_pdb_pdb}"
        DEPENDS "${_fixture_dir}/make_pe_pdb.py"
        COMMENT "Generating PE+PDB fixture pe_pdb"
        VERBATIM
    )
    add_custom_target(ember_fixture_pe_pdb ALL
        DEPENDS "${_pe_pdb_exe}" "${_pe_pdb_pdb}")
    set(EMBER_FIXTURE_pe_pdb_PATH "${_pe_pdb_exe}")

    ember_golden_test(
        NAME    pe_pdb_functions
        FIXTURE pe_pdb
        ARGS    "--functions"
        GOLDEN  pe_pdb.functions.txt
    )

    # extracted_main has a real stack frame and the PDB's S_REGREL32
    # records name its two int locals "i" and "j" - this golden locks
    # the full path: TPI / module-stream / S_REGREL32 → PdbLocalHint
    # → frame layout merge → emitted declarations and body references.
    ember_golden_test(
        NAME    pe_pdb_extracted_main_pseudo
        FIXTURE pe_pdb
        ARGS    "-p|-s|extracted_main"
        GOLDEN  pe_pdb.extracted_main.pseudo.txt
    )

    # ---- raw_regions_tiny (manifest + a single 4-byte code blob) -------
    #
    # No magic bytes - loaded via `--regions <manifest>`. Stage the
    # source-tree fixture into the build dir so the manifest can use a
    # relative `code.bin` path that resolves at test-run time.
    set(_rr_src "${_fixture_dir}/raw_regions_tiny")
    set(_rr_dir "${_build_dir}/raw_regions_tiny")
    add_custom_command(
        OUTPUT "${_rr_dir}/regions.txt" "${_rr_dir}/code.bin"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${_rr_dir}"
        COMMAND ${CMAKE_COMMAND} -E copy
                "${_rr_src}/regions.txt" "${_rr_dir}/regions.txt"
        COMMAND ${CMAKE_COMMAND} -E copy
                "${_rr_src}/code.bin"    "${_rr_dir}/code.bin"
        DEPENDS "${_rr_src}/regions.txt" "${_rr_src}/code.bin"
        COMMENT "Staging raw-regions fixture raw_regions_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_raw_regions_tiny ALL
        DEPENDS "${_rr_dir}/regions.txt" "${_rr_dir}/code.bin")
    set(EMBER_FIXTURE_raw_regions_tiny_PATH "${_rr_dir}/regions.txt")

    # The "binary" passed to ember is the manifest path; --regions
    # consumes it via __BINARY__ substitution so no positional binary
    # gets appended by the test harness.
    ember_golden_test(
        NAME    raw_regions_tiny_pseudo
        FIXTURE raw_regions_tiny
        ARGS    "--regions|__BINARY__|-p|-s|sub_140001000"
        GOLDEN  raw_regions_tiny.add42.pseudo.txt
    )

    # ---- raw-bytes (no manifest, just one rwx region) -----------------
    #
    # Locks the --raw-bytes / --base-va shortcut. Fixture re-uses the
    # raw_regions_tiny code.bin file directly, so no extra build setup.
    set(EMBER_FIXTURE_raw_bytes_tiny_PATH "${_rr_dir}/code.bin")
    add_custom_target(ember_fixture_raw_bytes_tiny ALL
        DEPENDS "${_rr_dir}/code.bin")
    ember_golden_test(
        NAME    raw_bytes_tiny_pseudo
        FIXTURE raw_bytes_tiny
        ARGS    "--raw-bytes|__BINARY__|--base-va|0x140001000|-p|-s|sub_140001000"
        GOLDEN  raw_bytes_tiny.add42.pseudo.txt
    )
endif()
