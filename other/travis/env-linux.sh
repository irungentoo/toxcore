#!/bin/sh

CMAKE=cmake
CMAKE_EXTRA_FLAGS="-DFORMAT_TEST=ON"
NPROC=`nproc`
CURDIR=$PWD

RUN() {
  "$@"
}

TESTS() {
  "$@"
}
