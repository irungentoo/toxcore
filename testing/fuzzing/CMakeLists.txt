# Override network and random functions
add_library(fuzz_support func_conversion.hh fuzz_support.cc fuzz_support.hh)

set(LIBFUZZER_LINKER_FLAGS)
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
  set(LIBFUZZER_LINKER_FLAGS "-fsanitize=fuzzer")
else()
  message(SEND_ERROR "Compiler must be Clang to build fuzz targets")
endif()

function(fuzz_test target source_dir)
  set(CORPUS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/toktok-fuzzer/corpus/${target}_fuzz_test)
  file(GLOB CORPUS "${CORPUS_DIR}/*")
  add_executable(${target}_fuzz_test ${source_dir}/${target}_fuzz_test.cc)
  target_link_libraries(${target}_fuzz_test PRIVATE fuzz_support test_util toxcore_fuzz ${LIBFUZZER_LINKER_FLAGS})
  if(CORPUS)
    add_test(NAME ${target}_fuzz COMMAND ${CROSSCOMPILING_EMULATOR} ${target}_fuzz_test -max_total_time=10 ${CORPUS})
    set_property(TEST ${target}_fuzz PROPERTY ENVIRONMENT "LLVM_PROFILE_FILE=${target}.profraw;srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
  endif()
endfunction()

fuzz_test(bootstrap        .)  # Fuzzes the bootstrap process
fuzz_test(toxsave          .)  # Fuzzes the bootstrap process

fuzz_test(DHT              ../../toxcore)
fuzz_test(forwarding       ../../toxcore)
fuzz_test(group_announce   ../../toxcore)
fuzz_test(group_moderation ../../toxcore)
fuzz_test(tox_events       ../../toxcore)
