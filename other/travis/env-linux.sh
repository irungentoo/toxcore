#!/bin/sh

export PATH=/opt/ghc/7.8.4/bin:/opt/cabal/1.18/bin:/opt/alex/3.1.7/bin:/opt/happy/1.19.5/bin:$PATH
export PATH=$HOME/.cabal/bin:$PATH

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
    else
      false
    fi
  }
}
