cmake_minimum_required(VERSION 3.16)
project(secret_sharing_cpp
    VERSION 0.1.0
    LANGUAGES CXX
    DESCRIPTION "Bit-compatible C++ port of secret-sharing")

# C++20 (with std::span, std::optional, designated initialisers,
# concepts). C++23 features used selectively via __has_cpp_attribute.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compile-database for clang-tidy and infer.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Aggressive warnings — every supported warning except the ones that
# fight modern style.
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    add_compile_options(
        -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion
        -Wshadow -Wnon-virtual-dtor -Wold-style-cast -Wcast-align
        -Wunused -Woverloaded-virtual -Wmisleading-indentation
        -Wnull-dereference -Wdouble-promotion -Wformat=2
        -Wimplicit-fallthrough -Wno-missing-field-initializers)
endif()

# Sanitiser preset — `cmake -B build-asan -DSANITISE=address`.
set(SANITISE "" CACHE STRING "Sanitiser to enable: address, undefined, address-undefined, thread, memory")
if(SANITISE)
    string(REPLACE "-" "," _san "${SANITISE}")
    add_compile_options(-fsanitize=${_san} -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=${_san})
endif()

# Sources for the library.
add_library(secret_sharing STATIC
    src/bigint.cpp
    src/csprng.cpp
    src/field.cpp
    src/poly.cpp
    src/shamir.cpp)
target_include_directories(secret_sharing PUBLIC include)
target_compile_features(secret_sharing PUBLIC cxx_std_20)

# Production build: -O3 + LTO. Override with `-DCMAKE_BUILD_TYPE=Debug`.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
include(CheckIPOSupported)
check_ipo_supported(RESULT _ipo_ok)
if(_ipo_ok AND CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(secret_sharing PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

# Tests + fuzz are opt-in via cache flags so a downstream `add_subdirectory`
# can pull in the library without GoogleTest or libFuzzer dependencies.
option(SECRET_SHARING_BUILD_TESTS "Build GoogleTest unit tests" ON)
option(SECRET_SHARING_BUILD_FUZZ  "Build libFuzzer harnesses (clang only)" OFF)
option(SECRET_SHARING_BUILD_BENCH "Build the pilot-bench dispatch binary" ON)

if(SECRET_SHARING_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(SECRET_SHARING_BUILD_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "libFuzzer harnesses require clang")
    endif()
    add_subdirectory(fuzz)
endif()

if(SECRET_SHARING_BUILD_BENCH)
    add_executable(pilot_ss_cpp src/pilot_ss.cpp)
    target_link_libraries(pilot_ss_cpp PRIVATE secret_sharing)
    add_executable(bench_field_mul_cpp src/bench_field_mul.cpp)
    target_link_libraries(bench_field_mul_cpp PRIVATE secret_sharing)
endif()
