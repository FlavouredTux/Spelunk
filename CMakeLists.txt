cmake_minimum_required(VERSION 3.28)

project(spelunk
    VERSION 2.0.0
    DESCRIPTION "Spelunk - reverse engineering toolkit"
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

option(SPELUNK_WERROR    "Treat warnings as errors"     ON)
option(SPELUNK_SANITIZE  "Enable AddressSanitizer+UBSan" OFF)
option(SPELUNK_BUILD_CLI "Build the command-line tool"  ON)
option(SPELUNK_BUILD_GUI "Build the Qt 6 desktop front end" OFF)
option(SPELUNK_BUILD_FUZZERS "Build the libFuzzer targets (clang + SPELUNK_SANITIZE)" OFF)
option(SPELUNK_COMPILE_FIXTURES
    "Compile test fixtures from source instead of staging the committed binaries" OFF)

add_library(spelunk_flags INTERFACE)
add_library(spelunk::flags ALIAS spelunk_flags)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(spelunk_flags INTERFACE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wsign-conversion
        -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Woverloaded-virtual -Wnull-dereference
        -Wdouble-promotion -Wformat=2
        -Wmisleading-indentation
    )
    if(SPELUNK_WERROR)
        target_compile_options(spelunk_flags INTERFACE -Werror)
    endif()
    if(SPELUNK_SANITIZE)
        target_compile_options(spelunk_flags INTERFACE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(spelunk_flags INTERFACE
            -fsanitize=address,undefined)
        # gcc's maybe-uninitialized heuristic misfires inside <regex> once
        # the sanitizer instrumentation is in; the sanitizers themselves
        # catch real uninitialized reads at run time.
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
            target_compile_options(spelunk_flags INTERFACE -Wno-maybe-uninitialized)
        endif()
    endif()
elseif(MSVC)
    target_compile_options(spelunk_flags INTERFACE /W4 /permissive- /Zc:preprocessor)
    # MSVC's CRT deprecates standard C functions (getenv, sprintf, ...) in
    # favour of its _s variants; with /WX every getenv call would be a
    # build failure. We use the standard names deliberately for portability.
    target_compile_definitions(spelunk_flags INTERFACE
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
    )
    if(SPELUNK_WERROR)
        target_compile_options(spelunk_flags INTERFACE /WX)
    endif()
endif()

include(CTest)
add_subdirectory(core)
if(SPELUNK_BUILD_CLI)
    add_subdirectory(cli)
endif()
if(SPELUNK_BUILD_GUI)
    add_subdirectory(gui)
endif()
if(BUILD_TESTING)
    # Toolchain-independent unit tests don't need the CLI. Fixture-based
    # golden tests inside tests/CMakeLists.txt gate themselves on the
    # spelunk_cli target so they no-op when SPELUNK_BUILD_CLI=OFF.
    add_subdirectory(tests)
endif()
if(SPELUNK_BUILD_FUZZERS)
    add_subdirectory(tests/fuzz)
endif()
