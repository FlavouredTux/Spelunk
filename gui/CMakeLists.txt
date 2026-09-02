# Qt 6 desktop front end. Opt-in (EMBER_BUILD_GUI) so the core and CLI
# keep building on machines without Qt. Links ember::core in-process;
# there is no IPC or JSON layer between the widgets and the pipeline.
find_package(Qt6 REQUIRED COMPONENTS Widgets)
qt_standard_project_setup()

add_executable(ember_gui
    src/main.cpp
    src/main_window.cpp
    src/session.cpp
    src/function_model.cpp
    src/code_view.cpp
    src/highlighters.cpp
    src/nav_band.cpp
)

set_target_properties(ember_gui PROPERTIES
    OUTPUT_NAME ember-gui
)

target_link_libraries(ember_gui PRIVATE
    ember::core
    ember::flags
    Qt6::Widgets
)

target_compile_definitions(ember_gui PRIVATE
    EMBER_GUI_VERSION="${PROJECT_VERSION}"
)
