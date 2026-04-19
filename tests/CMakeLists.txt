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

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(STATUS "ember tests: skipping (Linux only for now)")
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

ember_golden_test(
    NAME    tail_call_double_wrap_pseudo
    FIXTURE tail_call
    ARGS    "-p|-s|double_wrap"
    GOLDEN  tail_call.double_wrap.pseudo.txt
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
endif()
