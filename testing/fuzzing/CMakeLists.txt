# Override network and random functions
add_library(fuzz_support func_conversion.h fuzz_support.cc fuzz_support.h)

set(LIBFUZZER_LINKER_FLAGS)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(LIBFUZZER_LINKER_FLAGS "-fsanitize=fuzzer")
else()
  message(SEND_ERROR "Compiler must be Clang to build fuzz targets")
endif()

function(fuzz_test target source_dir)
  set(${target}_CORPUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/toktok-fuzzer/corpus/${target}_fuzz_test)
  file(GLOB ${target}_fuzz_CORPUS "${${target}_CORPUS_DIR}/*")
  add_executable(${target}_fuzz_test ${source_dir}/${target}_fuzz_test.cc)
  target_link_libraries(${target}_fuzz_test PRIVATE toxcore_fuzz fuzz_support ${LIBFUZZER_LINKER_FLAGS})
  if(${target}_fuzz_CORPUS)
    add_test(NAME ${target}_fuzz COMMAND ${CROSSCOMPILING_EMULATOR} ${target}_fuzz_test -max_total_time=10 ${${target}_fuzz_CORPUS})
  endif()
endfunction()

# Fuzzes the toxsave API
add_executable(toxsave_fuzzer toxsave_harness.cc)
target_link_libraries(toxsave_fuzzer PRIVATE toxcore_fuzz fuzz_support ${LIBFUZZER_LINKER_FLAGS})

# Fuzzes the bootstrap process
add_executable(bootstrap_fuzzer bootstrap_harness.cc)
target_link_libraries(bootstrap_fuzzer PRIVATE toxcore_fuzz fuzz_support ${LIBFUZZER_LINKER_FLAGS})

fuzz_test(DHT              ../../toxcore)
fuzz_test(forwarding       ../../toxcore)
fuzz_test(group_announce   ../../toxcore)
fuzz_test(group_moderation ../../toxcore)
fuzz_test(tox_events       ../../toxcore)
