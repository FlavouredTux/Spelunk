add_executable(ember_cli
    src/args.cpp
    src/builders.cpp
    src/dbg.cpp
    src/fingerprint.cpp
    src/header_import.cpp
    src/info.cpp
    src/kismet.cpp
    src/main.cpp
    src/patches.cpp
    src/util.cpp
    src/subcommands.cpp
)

# Header/type import is optional at build time. The CLI keeps a useful error
# path on machines without libclang rather than making core Ember depend on it.
find_path(EMBER_LIBCLANG_INCLUDE_DIR clang-c/Index.h)
find_library(EMBER_LIBCLANG_LIBRARY NAMES clang libclang)
if (EMBER_LIBCLANG_INCLUDE_DIR AND EMBER_LIBCLANG_LIBRARY)
    target_include_directories(ember_cli PRIVATE ${EMBER_LIBCLANG_INCLUDE_DIR})
    target_link_libraries(ember_cli PRIVATE ${EMBER_LIBCLANG_LIBRARY})
    target_compile_definitions(ember_cli PRIVATE EMBER_HAVE_LIBCLANG=1)
endif()

set_target_properties(ember_cli PROPERTIES
    OUTPUT_NAME ember
)
target_compile_definitions(ember_cli PRIVATE
    EMBER_VERSION_STRING="${PROJECT_VERSION}"
)

target_link_libraries(ember_cli PRIVATE
    ember::core
    ember::flags
)
