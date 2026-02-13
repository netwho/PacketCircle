# CMakeLists.txt for PacketCircle plugin (Wireshark 4.6.x compatible)
# This plugin creates a custom window showing communication pairs in a circle visualization

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(packetcircle 0 2 2 0)

# Enable Qt MOC and resource compilation
SET(CMAKE_AUTOMOC ON)
SET(CMAKE_AUTORCC ON)

# Find required packages
if(USE_qt6)
    set(qtver "6")
else()
    set(qtver "5")
endif()

find_package(Qt${qtver} REQUIRED COMPONENTS Core Widgets Gui)

# Plugin name
set(PLUGIN_NAME packetcircle)

# Source files - dissector/analysis sources
set(DISSECTOR_SRC
    packet_analyzer.c
    circle_plugin.c
    circle_widget.c
    ui_main_window.c
    ui_bridge.cpp
)

# Set C++ for Qt source files (.c files that are actually C++)
set_source_files_properties(
    circle_widget.c
    ui_main_window.c
    ui_bridge.cpp
    PROPERTIES LANGUAGE CXX
)

# Qt resource files
set(PLUGIN_RESOURCES
    packetcircle.qrc
)

# All plugin files
set(PLUGIN_FILES
    plugin.c
    ${DISSECTOR_SRC}
    ${PLUGIN_RESOURCES}
)

set(PLUGIN_HEADERS
    packet_analyzer.h
    circle_widget.h
    circle_plugin.h
    ui_main_window.h
    ui_bridge.h
)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Enable C++ for Qt
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Disable Qt version tagging so the plugin can load with any Qt 6.x runtime
# (Wireshark.app bundles its own Qt which may differ from the build-time Qt)
add_definitions(-DQT_NO_VERSION_TAGGING)

# Version is set by set_module_info(packetcircle 0 2 2 0) above

# Set source file properties for plugin.c
set_source_files_properties(
    plugin.c
    PROPERTIES
    SKIP_AUTOGEN ON
    LANGUAGE C
)

set_source_files_properties(
    ${PLUGIN_FILES}
    PROPERTIES
    COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

# Register plugin files (required for Wireshark 4.6.x epan plugin type)
register_plugin_files(plugin.c
    plugin
    ${DISSECTOR_SRC}
)

# Create Wireshark plugin library (epan type for 4.6.x)
add_wireshark_plugin_library(${PLUGIN_NAME} epan)

# Link libraries
target_link_libraries(${PLUGIN_NAME}
    epan
    wiretap
    Qt${qtver}::Core
    Qt${qtver}::Widgets
    Qt${qtver}::Gui
)

# Install plugin
install_plugin(${PLUGIN_NAME} epan)
