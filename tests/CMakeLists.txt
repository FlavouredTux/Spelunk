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
# tests are pinned to the gcc:15 toolchain (see ci.yml) so they only
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

function(ember_build_fixture name)
    cmake_parse_arguments(F "" "OPT;PROTECTOR" "" ${ARGN})
    if(NOT F_OPT)
        set(F_OPT "-O2")
    endif()
    if(NOT F_PROTECTOR)
        set(F_PROTECTOR "-fno-stack-protector")
    endif()
    set(_src "${_fixture_dir}/${name}.c")
    set(_out "${_build_dir}/${name}")
    add_custom_command(
        OUTPUT "${_out}"
        COMMAND ${CMAKE_C_COMPILER} ${F_OPT} -g ${F_PROTECTOR}
                -no-pie -o "${_out}" "${_src}"
        DEPENDS "${_src}"
        COMMENT "Compiling fixture ${name} (${F_OPT} ${F_PROTECTOR})"
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
ember_build_fixture(imports)
ember_build_fixture(decoder_misc)
ember_build_fixture(tail_call)
# -O0 so the compiler literally emits every redundant store; at -O2 the
# compiler would DSE itself and leave nothing for us to test.
ember_build_fixture(dead_store OPT "-O0")
ember_build_fixture(fp_scalar)
ember_build_fixture(printf_noise)
# Stack-protector on so the canary prologue/epilogue actually get emitted.
ember_build_fixture(canary PROTECTOR "-fstack-protector-strong")
# -O0 so the explicit gotos survive for the tail-duplication test.
ember_build_fixture(gotos OPT "-O0")
# -O0 so the `%` operator survives as a real IDIV (and the IR Mod op),
# and the do-while body keeps its conditional structure intact.
ember_build_fixture(arith OPT "-O0")

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
# If this drifts, scripts/names.js (cross-version name carryover) stops
# matching old databases — bump the "v1" schema token in fingerprint.cpp
# when that's intentional, and regenerate goldens.
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
# positional — parse_args only treats the second positional as the
# filter pattern.
ember_golden_test(
    NAME    imports_functions_filtered
    FIXTURE imports
    ARGS    "--no-cache|--functions|__BINARY__|main"
    GOLDEN  imports.functions.main.txt
)

# --collisions: every name and every fingerprint bound to >1 address.
# The imports fixture has two real fingerprint collisions (the
# tm_clones twins and the _dl_relocate_static_pie / _fini stubs) so a
# regression in collect_collisions either drops them or invents new
# ones — both shapes the golden catches immediately.
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

# ---- decoder_misc (coverage of formerly-unhandled opcodes) -----------------
#
# Every function here hits a decoder path that previously produced
# `not_implemented`: setcc, cmovcc, bswap, rep movsq. If any of these
# regresses, the function stops decompiling (or the golden diverges).

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

# ---- tail_call (jmp-to-function as return) --------------------------------

ember_golden_test(
    NAME    tail_call_wrap_strlen_pseudo
    FIXTURE tail_call
    ARGS    "-p|-s|wrap_strlen"
    GOLDEN  tail_call.wrap_strlen.pseudo.txt
)

# printf/fprintf — variadic arg trimming driven by format-string parsing.
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

# Stack-canary prologue+check suppression (-fstack-protector-strong).
ember_golden_test(
    NAME    canary_uses_buffer_pseudo
    FIXTURE canary
    ARGS    "-p|-s|uses_buffer"
    GOLDEN  canary.uses_buffer.pseudo.txt
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
# until now had no direct golden — divmod_runtime exercises a runtime
# `% b` (gcc emits `IDIV r/m32`, the lifter raises it to a Mod alongside
# the Div). Second: the structurer's do-while detection now accepts
# loops with multiple back-edge predecessors (one cond-and-exit tail
# plus inner unconditional jumps from skip arms) — dowhile_with_skip
# is the smallest such shape and locks the rendered output so a future
# regression that falls back to goto soup shows up as a clean diff.

ember_golden_test(
    NAME    arith_divmod_runtime_pseudo
    FIXTURE arith
    ARGS    "-p|-s|divmod_runtime"
    GOLDEN  arith.divmod_runtime.pseudo.txt
)

ember_golden_test(
    NAME    arith_dowhile_with_skip_pseudo
    FIXTURE arith
    ARGS    "-p|-s|dowhile_with_skip"
    GOLDEN  arith.dowhile_with_skip.pseudo.txt
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
# Leaf function with no calls — acceptance criterion: empty list, exit 0.
ember_golden_test(
    NAME    tail_call_inner_callees_empty
    FIXTURE tail_call
    ARGS    "--callees|inner"
    GOLDEN  tail_call.inner.callees.txt
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

# ---- mem_forward (stack-slot load forwarding) ------------------------------
#
# Compiled at -O0 so every local round-trips the stack. The golden captures
# the post-forwarding pseudo-C — if the GVN/memory-forward passes regress,
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
    set(_macho_tiny "${_build_dir}/macho_tiny")
    add_custom_command(
        OUTPUT "${_macho_tiny}"
        COMMAND ${Python3_EXECUTABLE}
                "${_fixture_dir}/make_macho_tiny.py"
                "${_macho_tiny}"
        DEPENDS "${_fixture_dir}/make_macho_tiny.py"
        COMMENT "Generating Mach-O fixture macho_tiny"
        VERBATIM
    )
    add_custom_target(ember_fixture_macho_tiny ALL DEPENDS "${_macho_tiny}")
    set(EMBER_FIXTURE_macho_tiny_PATH "${_macho_tiny}")

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
        NAME    macho_tiny_script
        FIXTURE macho_tiny
        ARGS    "--script|${_fixture_dir}/macho_tiny_scan.js"
        GOLDEN  macho_tiny.script.txt
    )

    # Phase-2 scripting surface (analysis, xrefs, strings, project). The
    # project file is written into the build tree so re-runs overwrite it.
    set(_phase2_proj "${_build_dir}/macho_tiny_phase2.proj")
    ember_golden_test(
        NAME    macho_tiny_script_phase2
        FIXTURE macho_tiny
        ARGS    "--project|${_phase2_proj}|--script|${_fixture_dir}/macho_tiny_phase2.js"
        GOLDEN  macho_tiny.script.phase2.txt
    )

    # scripts/query.js — the omnibus RE query dispatcher. Each golden covers
    # one subcommand invoked through the dispatcher, which together pin the
    # argv→command plumbing end-to-end.
    set(_query_js "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/query.js")
    ember_golden_test(
        NAME    query_js_info
        FIXTURE macho_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|info"
        GOLDEN  query_js.info.txt
    )
    ember_golden_test(
        NAME    query_js_find_func
        FIXTURE macho_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|find-func|main"
        GOLDEN  query_js.find_func.txt
    )
    ember_golden_test(
        NAME    query_js_bytes
        FIXTURE macho_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|bytes|0x100001000|6"
        GOLDEN  query_js.bytes.txt
    )
    ember_golden_test(
        NAME    query_js_find_bytes
        FIXTURE macho_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|find-bytes|b8 2a ?? ?? ?? c3"
        GOLDEN  query_js.find_bytes.txt
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

    ember_golden_test(
        NAME    ppc64le_tiny_info
        FIXTURE ppc64le_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|info"
        GOLDEN  ppc64le_tiny.info.txt
    )
    ember_golden_test(
        NAME    ppc64le_tiny_disasm
        FIXTURE ppc64le_tiny
        ARGS    "-d"
        GOLDEN  ppc64le_tiny.disasm.txt
    )
    ember_golden_test(
        NAME    ppc64be_tiny_info
        FIXTURE ppc64be_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|info"
        GOLDEN  ppc64be_tiny.info.txt
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
        NAME    ppc64be_opd_tiny_info
        FIXTURE ppc64be_opd_tiny
        ARGS    "--script|${_query_js}|__BINARY__|--|info"
        GOLDEN  ppc64be_opd_tiny.info.txt
    )
    ember_golden_test(
        NAME    ppc64be_opd_tiny_pseudo
        FIXTURE ppc64be_opd_tiny
        ARGS    "-p"
        GOLDEN  ppc64be_opd_tiny.pseudo.txt
    )

    # ---- pe_tiny (hand-built PE32+: DOS + NT + COFF + optional header +
    #               .text/.rdata/.pdata, one IAT import, one export,
    #               Win64 prologue, RUNTIME_FUNCTION table) ------------------
    #
    # Same Python-generator approach as macho_tiny — no Windows toolchain
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
    ember_golden_test(
        NAME    pe_tiny_script
        FIXTURE pe_tiny
        ARGS    "--script|${_fixture_dir}/pe_tiny_scan.js"
        GOLDEN  pe_tiny.script.txt
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
    ember_golden_test(
        NAME    pe_rich_script
        FIXTURE pe_rich
        ARGS    "--script|${_fixture_dir}/pe_rich_scan.js"
        GOLDEN  pe_rich.script.txt
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
    # Same Python-generator approach as macho_tiny / pe_tiny — runs on
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

    # ---- raw_regions_tiny (manifest + a single 4-byte code blob) -------
    #
    # No magic bytes — loaded via `--regions <manifest>`. Stage the
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
endif()
