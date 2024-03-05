#!/bin/bash

set -eu

NPROC=$(nproc)

. ".github/scripts/flags-gcc.sh"

# Allows wine to display source code file names and line numbers on crash in
# its backtrace.
add_flag -gdwarf-2

# Fix invalid register for .seh_savexmm error
add_flag -fno-asynchronous-unwind-tables

docker run \
  -e ALLOW_TEST_FAILURE=true \
  -e ENABLE_ARCH_i686="$i686" \
  -e ENABLE_ARCH_x86_64="$x86_64" \
  -e ENABLE_TEST=true \
  -e EXTRA_CMAKE_FLAGS="-DBOOTSTRAP_DAEMON=OFF -DMIN_LOGGER_LEVEL=DEBUG -DTEST_TIMEOUT_SECONDS=90 -DAUTOTEST=ON -DUSE_IPV6=OFF" \
  -e CMAKE_C_FLAGS="$C_FLAGS" \
  -e CMAKE_CXX_FLAGS="$CXX_FLAGS" \
  -e CMAKE_EXE_LINKER_FLAGS="$LD_FLAGS" \
  -e CMAKE_SHARED_LINKER_FLAGS="$LD_FLAGS" \
  -v "$PWD:/toxcore" \
  -v "$PWD/result:/prefix" \
  --rm \
  -t \
  --pull never \
  "toxchat/windows:$WINDOWS_ARCH"
