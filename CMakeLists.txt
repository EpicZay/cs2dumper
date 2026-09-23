cmake_minimum_required(VERSION 3.25)
project(cs2_dumper VERSION 0.1.0 LANGUAGES CXX)

add_library(cs2core
    src/core/pe.cpp
    src/core/pattern.cpp
    src/core/process.cpp
    src/database/database.cpp
    src/source2/collect.cpp
    src/generators/generator.cpp
)
target_compile_features(cs2core PUBLIC cxx_std_20)
target_include_directories(cs2core PUBLIC src external)
if(MSVC)
    target_compile_options(cs2core PRIVATE /W4 /permissive-)
else()
    target_compile_options(cs2core PRIVATE -Wall -Wextra -Wpedantic)
endif()

add_executable(cs2-dumper src/main.cpp)
target_link_libraries(cs2-dumper PRIVATE cs2core)

include(CTest)
if(BUILD_TESTING)
    add_executable(cs2-tests tests/tests.cpp)
    target_link_libraries(cs2-tests PRIVATE cs2core)
    add_test(NAME cs2-tests COMMAND cs2-tests)
endif()
