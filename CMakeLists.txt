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
  src/vm_mini.cpp
  src/exe_inspect.cpp
  src/env_checks.cpp
  src/protection_model.cpp
  src/timing_probe.cpp)
target_include_directories(at_core PUBLIC ${CMAKE_SOURCE_DIR}/src)

# End-to-end demo program.
add_executable(at_demo src/demo_main.cpp)
target_link_libraries(at_demo PRIVATE at_core)

# Read-only static executable inspector (CLI).
add_executable(exe_inspect src/exe_inspect_main.cpp)
target_link_libraries(exe_inspect PRIVATE at_core)

# Independent principles-study demo (integrity + anti-debug + env + VM).
add_executable(lab_demo src/lab_demo_main.cpp)
target_link_libraries(lab_demo PRIVATE at_core)

# Timing-detection experiment (prints real measured cycle costs on this host).
add_executable(timing_experiment src/timing_experiment_main.cpp)
target_link_libraries(timing_experiment PRIVATE at_core)

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

add_executable(test_exe_inspect tests/test_exe_inspect.cpp)
target_link_libraries(test_exe_inspect PRIVATE at_core)
add_test(NAME exe_inspect COMMAND test_exe_inspect)

add_executable(test_env_checks tests/test_env_checks.cpp)
target_link_libraries(test_env_checks PRIVATE at_core)
add_test(NAME env_checks COMMAND test_env_checks)

add_executable(test_security_properties tests/test_security_properties.cpp)
target_link_libraries(test_security_properties PRIVATE at_core)
add_test(NAME security_properties COMMAND test_security_properties)

add_executable(test_protection_model tests/test_protection_model.cpp)
target_link_libraries(test_protection_model PRIVATE at_core)
add_test(NAME protection_model COMMAND test_protection_model)

add_executable(test_timing_probe tests/test_timing_probe.cpp)
target_link_libraries(test_timing_probe PRIVATE at_core)
add_test(NAME timing_probe COMMAND test_timing_probe)

# The lab demo must exit 0 clean and non-zero only under a real tamper.
add_test(NAME lab_demo_clean COMMAND lab_demo)
add_test(NAME lab_demo_tamper COMMAND lab_demo --tamper)
set_tests_properties(lab_demo_tamper PROPERTIES WILL_FAIL TRUE)

# The demo should exit 0 clean and non-zero when tamper is simulated.
add_test(NAME demo_clean COMMAND at_demo)
add_test(NAME demo_tamper COMMAND at_demo --tamper)
set_tests_properties(demo_tamper PROPERTIES WILL_FAIL TRUE)
