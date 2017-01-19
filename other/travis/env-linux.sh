#!/bin/sh

CMAKE=cmake
CMAKE_EXTRA_FLAGS="$CMAKE_EXTRA_FLAGS -DFORMAT_TEST=ON"
NPROC=`nproc`
CURDIR=$PWD
RUN_TESTS=true

RUN() {
  "$@"
}

TESTS() {
  # Keep running tests until they eventually succeed or Travis times out after
  # 50 minutes. This cuts down on the time lost when tests fail, because we no
  # longer need to manually restart the build and wait for compilation.
  "$@" || TESTS "$@"
}
