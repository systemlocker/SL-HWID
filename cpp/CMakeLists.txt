cmake_minimum_required(VERSION 3.20)

project(SLHwid VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SLHWID_STATIC "Build SL-HWID as a static library" ON)

if(SLHWID_STATIC)
    set(SLHWID_LIBRARY_TYPE STATIC)
else()
    set(SLHWID_LIBRARY_TYPE SHARED)
endif()

add_library(slhwid ${SLHWID_LIBRARY_TYPE}
    src/slhwid.cpp
    src/slhwid_platform.cpp
)
add_library(SLHwid::slhwid ALIAS slhwid)
set_target_properties(slhwid PROPERTIES EXPORT_NAME slhwid)

target_include_directories(slhwid
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(NOT SLHWID_STATIC)
    target_compile_definitions(slhwid PUBLIC SLHWID_SHARED PRIVATE SLHWID_BUILDING)
endif()

if(WIN32)
    target_link_libraries(slhwid PRIVATE bcrypt)
endif()

if(MSVC)
    target_compile_options(slhwid PRIVATE /W4 /permissive- /EHsc)
    if(NOT SLHWID_STATIC)
        target_compile_options(slhwid PRIVATE /wd4251)
    endif()
else()
    target_compile_options(slhwid PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS slhwid
    EXPORT SLHwidTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT SLHwidTargets
    FILE SLHwidTargets.cmake
    NAMESPACE SLHwid::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SLHwid
)
configure_package_config_file(
    cmake/SLHwidConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/SLHwidConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SLHwid
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/SLHwidConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/SLHwidConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/SLHwidConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SLHwid
)
