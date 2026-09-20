add_executable(spelunk_cli
    src/args.cpp
    src/builders.cpp
    src/builders_graphics.cpp
    src/builders_surfaces.cpp
    src/builders_surfaces_model.cpp
    src/fingerprint.cpp
    src/header_import.cpp
    src/header_import_model.cpp
    src/info.cpp
    src/main.cpp
    src/patches.cpp
    src/util.cpp
    src/commands/annotations.cpp
    src/commands/common.cpp
    src/commands/disasm.cpp
    src/commands/explain.cpp
    src/commands/functions.cpp
    src/commands/identify.cpp
    src/commands/inventory.cpp
    src/commands/metadata.cpp
    src/commands/state.cpp
    src/commands/symbols.cpp
    src/commands/views.cpp
)

# Header/type import is optional at build time. The CLI keeps a useful error
# path on machines without libclang rather than making core Spelunk depend on it.
find_path(SPELUNK_LIBCLANG_INCLUDE_DIR clang-c/Index.h)
find_library(SPELUNK_LIBCLANG_LIBRARY NAMES clang libclang)
if (SPELUNK_LIBCLANG_INCLUDE_DIR AND SPELUNK_LIBCLANG_LIBRARY)
    target_include_directories(spelunk_cli PRIVATE ${SPELUNK_LIBCLANG_INCLUDE_DIR})
    target_link_libraries(spelunk_cli PRIVATE ${SPELUNK_LIBCLANG_LIBRARY})
    target_compile_definitions(spelunk_cli PRIVATE SPELUNK_HAVE_LIBCLANG=1)
endif()

set_target_properties(spelunk_cli PROPERTIES
    OUTPUT_NAME spelunk
)
target_compile_definitions(spelunk_cli PRIVATE
    SPELUNK_VERSION_STRING="${PROJECT_VERSION}"
)

execute_process(
    COMMAND git rev-parse --short=12 HEAD
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    OUTPUT_VARIABLE SPELUNK_GIT_REVISION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
    RESULT_VARIABLE SPELUNK_GIT_RESULT)
if(NOT SPELUNK_GIT_RESULT EQUAL 0 OR SPELUNK_GIT_REVISION STREQUAL "")
    set(SPELUNK_GIT_REVISION "unknown")
else()
    execute_process(
        COMMAND git status --porcelain --untracked-files=no
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        OUTPUT_VARIABLE SPELUNK_GIT_DIRTY
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
    if(NOT SPELUNK_GIT_DIRTY STREQUAL "")
        string(APPEND SPELUNK_GIT_REVISION "-dirty")
    endif()
endif()
target_compile_definitions(spelunk_cli PRIVATE
    SPELUNK_GIT_REVISION="${SPELUNK_GIT_REVISION}")

find_package(Threads REQUIRED)
target_link_libraries(spelunk_cli PRIVATE
    Threads::Threads
    spelunk::core
    spelunk::flags
)
