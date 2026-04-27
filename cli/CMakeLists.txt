add_executable(ember_cli
    src/args.cpp
    src/builders.cpp
    src/fingerprint.cpp
    src/info.cpp
    src/main.cpp
    src/patches.cpp
    src/subcommands.cpp
    src/util.cpp
)

set_target_properties(ember_cli PROPERTIES
    OUTPUT_NAME ember
)

target_link_libraries(ember_cli PRIVATE
    ember::core
    ember::flags
)
