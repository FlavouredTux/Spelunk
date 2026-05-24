if(NOT EMBER OR NOT BINARY)
    message(FATAL_ERROR "run_functions_infer_cache.cmake: missing EMBER/BINARY")
endif()

set(_test_cache "${CMAKE_CURRENT_BINARY_DIR}/.ember_functions_infer_cache")
file(REMOVE_RECURSE "${_test_cache}")
file(MAKE_DIRECTORY "${_test_cache}")

execute_process(
    COMMAND "${EMBER}" --cache-dir "${_test_cache}" "${BINARY}" --functions recoverCachedValue
    OUTPUT_VARIABLE _plain_out
    ERROR_VARIABLE  _plain_err
    RESULT_VARIABLE _plain_rc
)
if(NOT _plain_rc EQUAL 0)
    message(FATAL_ERROR "plain --functions exited with ${_plain_rc}:\n${_plain_err}")
endif()
if(_plain_out MATCHES "recoverCachedValue")
    message(FATAL_ERROR "plain --functions unexpectedly found inferred name:\n${_plain_out}")
endif()

execute_process(
    COMMAND "${EMBER}" --cache-dir "${_test_cache}" "${BINARY}" --infer-string-names --functions recoverCachedValue
    OUTPUT_VARIABLE _infer_out
    ERROR_VARIABLE  _infer_err
    RESULT_VARIABLE _infer_rc
)
if(NOT _infer_rc EQUAL 0)
    message(FATAL_ERROR "inferred --functions exited with ${_infer_rc}:\n${_infer_err}")
endif()
if(NOT _infer_out MATCHES "recoverCachedValue")
    message(FATAL_ERROR
        "inferred --functions reused the plain cache or missed the name.\n"
        "--- stderr ---\n${_infer_err}\n--- stdout ---\n${_infer_out}")
endif()
