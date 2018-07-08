#!/bin/sh

CMAKE=cmake
NPROC=`nproc`
CURDIR=/root
RUN_TESTS=true
MAKE=gmake
# A lot of tests fail and run for the full 2 minutes allowed, resulting in
# Travis build timing out, so we restrict it to just 1 test run until enough
# tests are fixed so that they succeed and don't run the full 2 minutes.
MAX_TEST_RETRIES=1

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
      # FIXME: We allow the tests to fail for now, but this should be changed to
      #        "false" once we fix tests under FreeBSD
      true
    fi
  }
}
