#!/bin/sh

. other/travis/env.sh

RUN() {
  "$@"
}
export CMAKE=cmake
export MAKE=make
export PREFIX=$PWD/_install
