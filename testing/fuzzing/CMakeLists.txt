# For coverage tests
target_compile_definitions(toxcore_static PUBLIC "FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION")

# Override network and random functions
add_library(fuzz_support func_conversion.h fuzz_support.cc fuzz_support.h)

set(LIBFUZZER_LINKER_FLAGS)
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(LIBFUZZER_LINKER_FLAGS "-fsanitize=fuzzer")
else()
  message(SEND_ERROR "Compiler must be Clang to build fuzz targets")
endif()

# Fuzzes the toxsave API
add_executable(toxsave_fuzzer toxsave_harness.cc)
target_link_libraries(toxsave_fuzzer PRIVATE toxcore_static fuzz_support ${LIBFUZZER_LINKER_FLAGS})

# Fuzzes the bootstrap process
add_executable(bootstrap_fuzzer bootstrap_harness.cc)
target_link_libraries(bootstrap_fuzzer PRIVATE toxcore_static fuzz_support ${LIBFUZZER_LINKER_FLAGS})

add_executable(DHT_fuzz_test ../../toxcore/DHT_fuzz_test.cc)
target_link_libraries(DHT_fuzz_test PRIVATE toxcore_static fuzz_support ${LIBFUZZER_LINKER_FLAGS})

add_executable(tox_events_fuzz_test ../../toxcore/tox_events_fuzz_test.cc)
target_link_libraries(tox_events_fuzz_test PRIVATE toxcore_static fuzz_support ${LIBFUZZER_LINKER_FLAGS})
