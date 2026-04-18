add_executable(ember_cli src/main.cpp)

set_target_properties(ember_cli PROPERTIES
    OUTPUT_NAME ember
)

target_link_libraries(ember_cli PRIVATE
    ember::core
    ember::flags
)
