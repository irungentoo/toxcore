#!/bin/sh

CMAKE=cmake
# Asan is disabled because it's currently broken in FreeBSD 11.
# We should try enabling it in the next FreeBSD release and see if it works.
CMAKE_EXTRA_FLAGS="$CMAKE_EXTRA_FLAGS -DASAN=OFF"
NPROC=`nproc`
CURDIR=/root
RUN_TESTS=true
MAKE=gmake

SCREEN_SESSION=freebsd
SSH_PORT=10022

RUN() {
  ssh -t -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no root@localhost -p $SSH_PORT "$@"
}

TESTS() {
  COUNT="$1"; shift
  RUN "$@" || {
    if [ $COUNT -gt 1 ]; then
      TESTS `expr $COUNT - 1` "$@"
    else
      false
    fi
  }
}
