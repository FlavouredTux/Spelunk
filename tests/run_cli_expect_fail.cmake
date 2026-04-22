if(NOT EMBER OR NOT BINARY OR NOT ERR_SUBSTR)
    message(FATAL_ERROR "run_cli_expect_fail.cmake: missing EMBER/BINARY/ERR_SUBSTR")
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
        "Expected failure but ember exited 0\n--- stdout ---\n${_out}\n--- stderr ---\n${_err}")
endif()

string(FIND "${_err}" "${ERR_SUBSTR}" _hit)
if(_hit EQUAL -1)
    message(FATAL_ERROR
        "stderr did not contain expected substring\nexpected: ${ERR_SUBSTR}\n--- stderr ---\n${_err}")
endif()
