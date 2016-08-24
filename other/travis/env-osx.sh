#!/bin/sh

CMAKE=cmake
NPROC=`sysctl -n hw.ncpu`
CURDIR=$PWD

RUN() {
  "$@"
}

TESTS() {
  "$@"
}
