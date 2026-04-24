# Golden-output test runner.
#
# Required vars on the CMake invocation:
#   EMBER    — path to the ember CLI executable
#   BINARY   — path to the compiled fixture binary
#   ARGS     — semicolon-separated list of args to pass (before BINARY)
#   GOLDEN   — path to the expected-output file
#
# Behavior:
#   Runs "$EMBER $ARGS $BINARY", captures stdout, and compares against GOLDEN.
#   If UPDATE_GOLDEN is set in the environment, the captured output is written
#   back to GOLDEN (for intentional updates) and the test passes.
#   Otherwise, a mismatch prints a unified diff and fails.

if(NOT EMBER OR NOT BINARY OR NOT GOLDEN)
    message(FATAL_ERROR "run_golden.cmake: missing EMBER/BINARY/GOLDEN")
endif()

set(_args "")
set(_has_binary_placeholder FALSE)
if(ARGS)
    # `__BINARY__` inside ARGS is substituted with the fixture path in place,
    # and the trailing BINARY argument is suppressed. Use this when the script
    # needs args AFTER the binary (e.g. `-- <subcommand>` syntax).
    string(FIND "${ARGS}" "__BINARY__" _bp)
    if(NOT _bp EQUAL -1)
        set(_has_binary_placeholder TRUE)
        string(REPLACE "__BINARY__" "${BINARY}" ARGS "${ARGS}")
    endif()
    string(REPLACE "|" ";" _args "${ARGS}")
endif()

# Per-test cache dir isolates the run from the developer's ~/.cache/ember
# state (otherwise a stray sidecar / cached annotations file from a prior
# session could bleed into goldens). Created under the build tree so it
# dies with `cmake --build --target clean`.
set(_test_cache "${CMAKE_CURRENT_BINARY_DIR}/.ember_test_cache")
file(MAKE_DIRECTORY "${_test_cache}")

if(_has_binary_placeholder)
    execute_process(
        COMMAND "${EMBER}" --cache-dir "${_test_cache}" ${_args}
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE  _err
        RESULT_VARIABLE _rc
    )
else()
    execute_process(
        COMMAND "${EMBER}" --cache-dir "${_test_cache}" ${_args} "${BINARY}"
        OUTPUT_VARIABLE _out
        ERROR_VARIABLE  _err
        RESULT_VARIABLE _rc
    )
endif()
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "ember exited with ${_rc}:\n${_err}\n--- stdout ---\n${_out}")
endif()

# Normalize trailing whitespace / final newline for stable comparison.
string(REGEX REPLACE "[ \t]+\n" "\n" _out "${_out}")

if(DEFINED ENV{UPDATE_GOLDEN})
    file(WRITE "${GOLDEN}" "${_out}")
    message(STATUS "Updated golden: ${GOLDEN}")
    return()
endif()

if(NOT EXISTS "${GOLDEN}")
    message(FATAL_ERROR
        "Missing golden file: ${GOLDEN}\n"
        "Re-run with UPDATE_GOLDEN=1 to create it.\n"
        "--- produced output ---\n${_out}")
endif()

file(READ "${GOLDEN}" _expected)
string(REGEX REPLACE "[ \t]+\n" "\n" _expected "${_expected}")

if(NOT _out STREQUAL _expected)
    # Write the produced output to a side file and invoke diff for a readable
    # failure message.
    set(_produced "${CMAKE_CURRENT_BINARY_DIR}/.golden_out")
    file(WRITE "${_produced}" "${_out}")
    execute_process(
        COMMAND diff -u "${GOLDEN}" "${_produced}"
        OUTPUT_VARIABLE _diff
        RESULT_VARIABLE _diff_rc
    )
    message(FATAL_ERROR
        "Golden mismatch for ${GOLDEN}:\n${_diff}\n"
        "Run with UPDATE_GOLDEN=1 to accept.")
endif()
