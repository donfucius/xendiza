cmake_minimum_required(VERSION 4.2)
project(xendiza)

set(CMAKE_CXX_STANDARD 20)

option(XENDIZA_BENCH_WITH_CAPSTONE "Build benchmark with Capstone comparison" OFF)
option(XENDIZA_BENCH_WITH_ZYDIS "Build benchmark with Zydis comparison" OFF)

add_library(xendiza STATIC xendiza.cpp xendiza_x64.cpp xendiza_x86.cpp)

find_package(Microsoft.GSL CONFIG REQUIRED)
target_link_libraries(xendiza PRIVATE Microsoft.GSL::GSL)

if(MSVC)
    target_compile_options(xendiza PRIVATE /Zc:preprocessor)
endif()

# Tests
enable_testing()

find_package(GTest CONFIG REQUIRED)

add_executable(xendiza_tests
    test/test_basic_instructions.cpp
    test/test_x86_basic.cpp
    test/test_2byte_opcodes.cpp
    test/test_x86_2byte_opcodes.cpp
    test/test_opcode_extensions.cpp
    test/test_x87_opcodes.cpp
    test/test_public_api.cpp
    test/test_no_operands.cpp
    test/test_system_opcodes.cpp
)

target_link_libraries(xendiza_tests PRIVATE xendiza GTest::gtest GTest::gtest_main Microsoft.GSL::GSL)
target_include_directories(xendiza_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(xendiza_tests PRIVATE /Zc:preprocessor)
endif()

include(GoogleTest)
gtest_discover_tests(xendiza_tests)

# Example
add_executable(xendiza_example
    example/example.cpp
)

target_link_libraries(xendiza_example PRIVATE xendiza Microsoft.GSL::GSL)
target_include_directories(xendiza_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(xendiza_example PRIVATE /Zc:preprocessor)
endif()

# Benchmark
add_executable(xendiza_bench
    bench/bench_disasm.cpp
)

target_link_libraries(xendiza_bench PRIVATE xendiza Microsoft.GSL::GSL)
target_include_directories(xendiza_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(xendiza_bench PRIVATE /Zc:preprocessor)
endif()

if(XENDIZA_BENCH_WITH_CAPSTONE)
    find_path(CAPSTONE_INCLUDE_DIR capstone/capstone.h)
    find_library(CAPSTONE_LIBRARY NAMES capstone)
    if(CAPSTONE_INCLUDE_DIR AND CAPSTONE_LIBRARY)
        target_compile_definitions(xendiza_bench PRIVATE XENDIZA_BENCH_WITH_CAPSTONE=1)
        target_include_directories(xendiza_bench PRIVATE ${CAPSTONE_INCLUDE_DIR})
        target_link_libraries(xendiza_bench PRIVATE ${CAPSTONE_LIBRARY})
    else()
        message(WARNING "Capstone requested but not found; benchmark will build without Capstone")
    endif()
endif()

if(XENDIZA_BENCH_WITH_ZYDIS)
    find_package(Zydis CONFIG QUIET)
    if(TARGET Zydis::Zydis)
        target_compile_definitions(xendiza_bench PRIVATE XENDIZA_BENCH_WITH_ZYDIS=1)
        target_link_libraries(xendiza_bench PRIVATE Zydis::Zydis)
    else()
        message(WARNING "Zydis requested but not found; benchmark will build without Zydis")
    endif()
endif()
