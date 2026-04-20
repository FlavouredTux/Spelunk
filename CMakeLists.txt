cmake_minimum_required(VERSION 3.28)

project(ember
    VERSION 0.1.2
    DESCRIPTION "Ember — reverse engineering toolkit"
    HOMEPAGE_URL "https://example.invalid/ember"
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

option(EMBER_WERROR    "Treat warnings as errors"     ON)
option(EMBER_SANITIZE  "Enable AddressSanitizer+UBSan" OFF)
option(EMBER_BUILD_CLI "Build the command-line tool"  ON)

add_library(ember_flags INTERFACE)
add_library(ember::flags ALIAS ember_flags)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(ember_flags INTERFACE
        -Wall -Wextra -Wpedantic
        -Wshadow -Wconversion -Wsign-conversion
        -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Woverloaded-virtual -Wnull-dereference
        -Wdouble-promotion -Wformat=2
        -Wmisleading-indentation
    )
    if(EMBER_WERROR)
        target_compile_options(ember_flags INTERFACE -Werror)
    endif()
    if(EMBER_SANITIZE)
        target_compile_options(ember_flags INTERFACE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(ember_flags INTERFACE
            -fsanitize=address,undefined)
    endif()
elseif(MSVC)
    target_compile_options(ember_flags INTERFACE /W4 /permissive- /Zc:preprocessor)
    # MSVC's CRT deprecates standard C functions (getenv, sprintf, ...) in
    # favour of its _s variants; with /WX every getenv call would be a
    # build failure. We use the standard names deliberately for portability.
    target_compile_definitions(ember_flags INTERFACE
        _CRT_SECURE_NO_WARNINGS
        _CRT_NONSTDC_NO_WARNINGS
    )
    if(EMBER_WERROR)
        target_compile_options(ember_flags INTERFACE /WX)
    endif()
endif()

include(CTest)
add_subdirectory(third_party/quickjs)
add_subdirectory(core)
if(EMBER_BUILD_CLI)
    add_subdirectory(cli)
endif()
if(BUILD_TESTING AND EMBER_BUILD_CLI)
    add_subdirectory(tests)
endif()
