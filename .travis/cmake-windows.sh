#!/bin/bash

ACTION="$1"

set -eu

CACHEDIR="$HOME/cache"
NPROC=$(nproc)

travis_install() {
  cd other/docker/windows

  docker build \
    --build-arg SUPPORT_ARCH_i686="$i686" \
    --build-arg SUPPORT_ARCH_x86_64="$x86_64" \
    --build-arg SUPPORT_TEST=true \
    -t toxcore-"$WINDOWS_ARCH" \
    .
}

travis_script() {
  . ".travis/flags-$CC.sh"

  # Allows wine to display source code file names and line numbers on crash in
  # its backtrace.
  add_flag -gdwarf-2

  docker run \
    -e ALLOW_TEST_FAILURE=true \
    -e ENABLE_ARCH_i686="$i686" \
    -e ENABLE_ARCH_x86_64="$x86_64" \
    -e ENABLE_TEST=true \
    -e EXTRA_CMAKE_FLAGS="-DBOOTSTRAP_DAEMON=OFF -DMIN_LOGGER_LEVEL=DEBUG -DTEST_TIMEOUT_SECONDS=90 -DAUTOTEST=ON" \
    -e CMAKE_C_FLAGS="$C_FLAGS" \
    -e CMAKE_CXX_FLAGS="$CXX_FLAGS" \
    -e CMAKE_EXE_LINKER_FLAGS="$LD_FLAGS" \
    -e CMAKE_SHARED_LINKER_FLAGS="$LD_FLAGS" \
    -v "$PWD:/toxcore" \
    -v "$PWD/result:/prefix" \
    --rm \
    toxcore-"$WINDOWS_ARCH"
}

if [ "-z" "$ACTION" ]; then
  "travis_script"
else
  "travis_$ACTION"
fi
