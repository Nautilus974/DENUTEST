cmake_minimum_required(VERSION 3.16)
project(at_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra)

# Core library with the reusable primitives.
add_library(at_core STATIC
  src/integrity.cpp
  src/anti_debug.cpp
  src/vm_mini.cpp)
target_include_directories(at_core PUBLIC ${CMAKE_SOURCE_DIR}/src)

# End-to-end demo program.
add_executable(at_demo src/demo_main.cpp)
target_link_libraries(at_demo PRIVATE at_core)

# Benchmark.
add_executable(bench_vm bench/bench_vm.cpp)
target_link_libraries(bench_vm PRIVATE at_core)

# Tests.
enable_testing()
add_executable(test_integrity tests/test_integrity.cpp)
target_link_libraries(test_integrity PRIVATE at_core)
add_test(NAME integrity COMMAND test_integrity)

add_executable(test_anti_debug tests/test_anti_debug.cpp)
target_link_libraries(test_anti_debug PRIVATE at_core)
add_test(NAME anti_debug COMMAND test_anti_debug)

# The demo should exit 0 clean and non-zero when tamper is simulated.
add_test(NAME demo_clean COMMAND at_demo)
add_test(NAME demo_tamper COMMAND at_demo --tamper)
set_tests_properties(demo_tamper PROPERTIES WILL_FAIL TRUE)
