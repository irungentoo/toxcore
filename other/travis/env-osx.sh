#!/bin/sh

CMAKE=cmake
CMAKE_EXTRA_FLAGS=""
NPROC=`sysctl -n hw.ncpu`
CURDIR=$PWD

RUN() {
  "$@"
}

TESTS() {
  "$@"
}
