#!/usr/bin/env bash

set -eux

TEST=${1:-conference_test}
OUTPUT="/work/c-toxcore/test.perf"

readarray -t FLAGS <<<"$(pkg-config --cflags --libs libsodium opus vpx | sed -e 's/ /\n/g')"
readarray -t SRCS <<<"$(find /work/c-toxcore/tox* -name "*.c")"

gcc -pthread -g \
  -o "/work/$TEST" -O3 -fno-omit-frame-pointer \
  "${SRCS[@]}" \
  /work/c-toxcore/auto_tests/auto_test_support.c \
  /work/c-toxcore/testing/misc_tools.c \
  "/work/c-toxcore/auto_tests/$TEST.c" \
  -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE \
  "${FLAGS[@]}"

time perf record -g --call-graph dwarf --freq=max "/work/$TEST" /work/c-toxcore/auto_tests/
perf report | head -n50
perf script -F +pid >"$OUTPUT"
chown 1000:100 "$OUTPUT"
