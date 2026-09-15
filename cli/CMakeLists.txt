add_executable(spelunk_cli
    src/args.cpp
    src/builders.cpp
    src/builders_graphics.cpp
    src/builders_surfaces.cpp
    src/builders_surfaces_model.cpp
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

target_link_libraries(spelunk_cli PRIVATE
    spelunk::core
    spelunk::flags
)
