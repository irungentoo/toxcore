#!/bin/sh

CMAKE=cmake
NPROC=`nproc`
CURDIR=$PWD
TESTS=true

RUN() {
  "$@"
}
