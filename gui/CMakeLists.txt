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
    src/hex_view.cpp
    src/highlighters.cpp
    src/nav_band.cpp
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
