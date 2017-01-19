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
  COUNT="$1"; shift
  "$@" || {
    if [ $COUNT -gt 1 ]; then
      TESTS `expr $COUNT - 1` "$@"
    fi
  }
}
