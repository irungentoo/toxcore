# Find and compile the GTest library.

message(STATUS "Checking for gtest")

# Look for the sources.
find_file(GTEST_ALL_CC gtest-all.cc PATHS
  ${CMAKE_SOURCE_DIR}/third_party/googletest/googletest/src
  /usr/src/gtest/src
  NO_DEFAULT_PATH
)

if(GTEST_ALL_CC)
  # ../.. from the source file is the source root.
  get_filename_component(GTEST_SRC_DIR ${GTEST_ALL_CC} DIRECTORY)
  get_filename_component(GTEST_SRC_ROOT ${GTEST_SRC_DIR} DIRECTORY)

  # Look for the header file.
  include(CheckIncludeFileCXX)
  include_directories(SYSTEM ${GTEST_SRC_ROOT}/include)
  check_include_file_cxx("gtest/gtest.h" HAVE_GTEST_GTEST_H)

  if(HAVE_GTEST_GTEST_H)
    message(STATUS "Found gtest: ${GTEST_SRC_ROOT}")

    add_library(gtest
      ${GTEST_SRC_DIR}/gtest-all.cc
      ${GTEST_SRC_DIR}/gtest_main.cc)
    target_include_directories(gtest PRIVATE ${GTEST_SRC_ROOT})

    # Ignore all warnings for gtest. We don't care about their implementation.
    check_cxx_compiler_flag("-w" HAVE_CXX_W QUIET)
    if(HAVE_CXX_W)
      set_target_properties(gtest PROPERTIES COMPILE_FLAGS "-w")
    endif()

    set(HAVE_GTEST TRUE)
    set(TEST_CXX_FLAGS "")

    check_cxx_compiler_flag("-Wno-global-constructors" HAVE_CXX_W_NO_GLOBAL_CONSTRUCTORS QUIET)
    if(HAVE_CXX_W_NO_GLOBAL_CONSTRUCTORS)
      set(TEST_CXX_FLAGS "${TEST_CXX_FLAGS} -Wno-global-constructors")
    endif()

    check_cxx_compiler_flag("-Wno-zero-as-null-pointer-constant" HAVE_CXX_W_NO_ZERO_AS_NULL_POINTER_CONSTANT QUIET)
    if(HAVE_CXX_W_NO_ZERO_AS_NULL_POINTER_CONSTANT)
      set(TEST_CXX_FLAGS "${TEST_CXX_FLAGS} -Wno-zero-as-null-pointer-constant")
    endif()
  endif()
endif()

function(unit_test subdir target)
  if(HAVE_GTEST)
    add_executable(unit_${target}_test ${subdir}/${target}_test.cpp)
    target_link_modules(unit_${target}_test toxcore gtest)
    set_target_properties(unit_${target}_test PROPERTIES COMPILE_FLAGS "${TEST_CXX_FLAGS}")
    add_test(NAME ${target} COMMAND ${CROSSCOMPILING_EMULATOR} unit_${target}_test)
  endif()
endfunction()
