# libFuzzer requires clang. The parent CMakeLists already enforced
# this; here we add per-fuzz-target executables linked against the
# library with `-fsanitize=fuzzer,address,undefined` so that any
# memory-safety / UB issue trips immediately.

set(FUZZ_FLAGS -fsanitize=fuzzer,address,undefined -g -O1)

add_executable(fuzz_bigint fuzz_bigint.cpp)
target_link_libraries(fuzz_bigint PRIVATE secret_sharing)
target_compile_options(fuzz_bigint PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_bigint PRIVATE ${FUZZ_FLAGS})

add_executable(fuzz_field fuzz_field.cpp)
target_link_libraries(fuzz_field PRIVATE secret_sharing)
target_compile_options(fuzz_field PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_field PRIVATE ${FUZZ_FLAGS})

add_executable(fuzz_shamir fuzz_shamir.cpp)
target_link_libraries(fuzz_shamir PRIVATE secret_sharing)
target_compile_options(fuzz_shamir PRIVATE ${FUZZ_FLAGS})
target_link_options(fuzz_shamir PRIVATE ${FUZZ_FLAGS})
