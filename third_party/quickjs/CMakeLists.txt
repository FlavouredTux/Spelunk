# Vendored QuickJS-NG 0.10.1. We only need the interpreter core — not the
# -libc module (which adds std/os APIs we deliberately don't expose to
# scripts).

add_library(ember_quickjs STATIC
    quickjs.c
    cutils.c
    libregexp.c
    libunicode.c
    xsum.c
)
add_library(ember::quickjs ALIAS ember_quickjs)

target_include_directories(ember_quickjs SYSTEM PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)

# QuickJS self-identifies its version via a macro the build normally passes
# on the command line. Provide a stable value so the source compiles.
target_compile_definitions(ember_quickjs PRIVATE
    CONFIG_VERSION="2024-01-13-ember"
)

# On MSVC, cutils.c includes <windows.h> directly while cutils.h includes
# <winsock2.h> ahead of <windows.h>. Without WIN32_LEAN_AND_MEAN the
# old winsock1 from windows.h defines sockaddr et al, which then redefine
# when cutils.h later pulls in winsock2 — hundreds of C2011/C2375 errors.
if(WIN32)
    target_compile_definitions(ember_quickjs PRIVATE
        WIN32_LEAN_AND_MEAN
    )
endif()

# QuickJS is performance-sensitive C; suppress pedantic warnings that would
# drown out Ember's own diagnostics. We don't link it to ember::flags.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ember_quickjs PRIVATE
        -Wno-everything
    )
endif()

set_target_properties(ember_quickjs PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    POSITION_INDEPENDENT_CODE ON
)
