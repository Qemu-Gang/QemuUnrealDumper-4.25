cmake_minimum_required(VERSION 3.9)
project(unrealdumper CXX)

set (CMAKE_CXX_STANDARD 20)

# load memflow project
include(ExternalProject)
set_directory_properties(PROPERTIES EP_PREFIX ${CMAKE_BINARY_DIR}/rs)
ExternalProject_Add(
        memflow
        GIT_REPOSITORY "https://github.com/memflow/memflow"
        GIT_SHALLOW true
        GIT_PROGRESS true
        GIT_TAG "0.1.5"
        CONFIGURE_COMMAND ""
        BUILD_COMMAND cargo build --all-features --workspace
        COMMAND cargo build --release --all-features --workspace
        BINARY_DIR "${CMAKE_BINARY_DIR}/rs/src/memflow"
        INSTALL_COMMAND ""
        LOG_BUILD ON)

find_package(Threads)

include_directories(
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_BINARY_DIR}/rs/src/memflow/memflow-ffi"
        "${CMAKE_BINARY_DIR}/rs/src/memflow/memflow-win32-ffi"
)

add_executable( unrealdumper
        src/sigscanner.cpp
        src/engine.cpp
        src/generic.cpp
        src/main.cpp
        src/wrappers.cpp
        src/memory.cpp
        src/fmt/format.cc
        )

add_dependencies( unrealdumper
        memflow
)

target_link_libraries(unrealdumper m dl pthread rt)
target_link_libraries(unrealdumper ${CMAKE_BINARY_DIR}/rs/src/memflow/target/release/libmemflow_win32_ffi.a)
target_link_libraries(unrealdumper ${CMAKE_BINARY_DIR}/rs/src/memflow/target/release/libmemflow_ffi.a)

