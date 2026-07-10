if(NOT EMBER OR NOT BINARY OR NOT OUT_SUBSTR)
    message(FATAL_ERROR
        "run_cli_json_expect_fail.cmake: missing EMBER/BINARY/OUT_SUBSTR")
endif()

set(_args "")
if(ARGS)
    string(REPLACE "|" ";" _args "${ARGS}")
endif()

execute_process(
    COMMAND "${EMBER}" ${_args} "${BINARY}"
    OUTPUT_VARIABLE _out
    ERROR_VARIABLE  _err
    RESULT_VARIABLE _rc
)

if(_rc EQUAL 0)
    message(FATAL_ERROR
        "Expected JSON failure but ember exited 0\n--- stdout ---\n${_out}")
endif()

string(FIND "${_out}" "${OUT_SUBSTR}" _hit)
if(_hit EQUAL -1)
    message(FATAL_ERROR
        "stdout did not contain expected JSON error\nexpected: ${OUT_SUBSTR}\n"
        "--- stdout ---\n${_out}\n--- stderr ---\n${_err}")
endif()
