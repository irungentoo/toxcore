#!/bin/sh

CMAKE=cmake
CMAKE_EXTRA_FLAGS="$CMAKE_EXTRA_FLAGS"
NPROC=`sysctl -n hw.ncpu`
CURDIR=$PWD

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
