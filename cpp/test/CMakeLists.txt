include(FetchContent)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(secret_sharing_tests
    test_bigint.cpp
    test_bigint_differential.cpp
    test_csprng.cpp
    test_field.cpp
    test_poly.cpp
    test_shamir.cpp
    test_compat.cpp)
target_link_libraries(secret_sharing_tests PRIVATE secret_sharing GTest::gtest_main)
target_compile_features(secret_sharing_tests PRIVATE cxx_std_20)

include(GoogleTest)
gtest_discover_tests(secret_sharing_tests)

# Keep allocation fault injection separate from the GoogleTest allocator.
add_executable(division_wipe_test test_division_wipe.cpp)
target_link_libraries(division_wipe_test PRIVATE secret_sharing)
add_test(NAME big_uint.division_wipes_scratch COMMAND division_wipe_test)
