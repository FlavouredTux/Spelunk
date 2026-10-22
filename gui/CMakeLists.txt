# Qt 6 desktop front end. Opt-in (SPELUNK_BUILD_GUI) so the core and CLI
# keep building on machines without Qt. Links spelunk::core in-process;
# there is no IPC or JSON layer between the widgets and the pipeline.
find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

add_executable(spelunk_gui
    src/main.cpp
    src/main_window.cpp
    src/session.cpp
    src/function_model.cpp
    src/code_view.cpp
    src/graph_layout.cpp
    src/graph_view.cpp
    src/hex_view.cpp
    src/highlighters.cpp
    src/nav_band.cpp
    src/chooser.cpp
)

set_target_properties(spelunk_gui PROPERTIES
    OUTPUT_NAME spelunk-gui
)

target_link_libraries(spelunk_gui PRIVATE
    spelunk::core
    spelunk::flags
    Qt6::Widgets
)

target_compile_definitions(spelunk_gui PRIVATE
    SPELUNK_GUI_VERSION="${PROJECT_VERSION}"
)

if(BUILD_TESTING)
    find_package(Qt6 REQUIRED COMPONENTS Test)
    # The window sources minus main.cpp, driven by QtTest key presses.
    add_executable(spelunk_gui_keymap_test
        tests/keymap_test.cpp
        src/main_window.cpp
        src/session.cpp
        src/function_model.cpp
        src/code_view.cpp
        src/graph_layout.cpp
        src/graph_view.cpp
        src/hex_view.cpp
        src/highlighters.cpp
        src/nav_band.cpp
        src/chooser.cpp
    )
    target_link_libraries(spelunk_gui_keymap_test PRIVATE spelunk::core spelunk::flags Qt6::Widgets Qt6::Test)
    add_test(NAME gui_ida_keymap
             COMMAND spelunk_gui_keymap_test "${CMAKE_SOURCE_DIR}/tests/fixtures/pointer_walk.prebuilt"
                     "${CMAKE_SOURCE_DIR}/tests/fixtures/printf_noise.prebuilt")
    set_tests_properties(gui_ida_keymap PROPERTIES TIMEOUT 120 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

if(BUILD_TESTING)
    # The graph layout has no Qt dependency; check its invariants directly.
    add_executable(spelunk_gui_graph_layout_test tests/graph_layout_test.cpp src/graph_layout.cpp)
    target_link_libraries(spelunk_gui_graph_layout_test PRIVATE spelunk::flags)
    add_test(NAME gui_graph_layout COMMAND spelunk_gui_graph_layout_test)
endif()
