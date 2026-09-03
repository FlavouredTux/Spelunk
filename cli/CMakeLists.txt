add_executable(ember_cli
    src/args.cpp
    src/builders.cpp
    src/builders_graphics.cpp
    src/builders_surfaces.cpp
    src/dbg.cpp
    src/dbg_breakpoints.cpp
    src/dbg_inspect.cpp
    src/dbg_process.cpp
    src/dbg_resolve.cpp
    src/fingerprint.cpp
    src/header_import.cpp
    src/header_import_model.cpp
    src/info.cpp
    src/kismet.cpp
    src/main.cpp
    src/patches.cpp
    src/util.cpp
    src/commands/annotations.cpp
    src/commands/common.cpp
    src/commands/disasm.cpp
    src/commands/explain.cpp
    src/commands/functions.cpp
    src/commands/inventory.cpp
    src/commands/metadata.cpp
    src/commands/state.cpp
    src/commands/symbols.cpp
    src/commands/teef.cpp
    src/commands/teef_recognize.cpp
    src/commands/views.cpp
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
