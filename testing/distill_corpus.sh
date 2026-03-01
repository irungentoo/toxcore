#!/bin/sh

HARNESS_BIN="../_afl_build/bootstrap_fuzz_test"
COV_BIN="../_cov_build/bootstrap_fuzz_test"
# move to repo root
cd ../

cd _afl_out/

# Perform corpus minimization
mkdir -p corpus-cmin
rm corpus-cmin/*

afl-cmin -i fuzz0/queue/ -o corpus-cmin/ -- "$HARNESS_BIN"

# Minimize each testcase
mkdir -p corpus-tmin
rm corpus-tmin/*

# afl-tmin is VERY slow
# massive parallel bash piping for the rescue
find corpus-cmin/ -maxdepth 1 -type f |
  parallel --bar --joblog ./parallel.log afl-tmin -i ./corpus-cmin/{/} -o ./corpus-tmin/{/} -- "$HARNESS_BIN"

# in case the tmin-process was aborted, just copy non-minimized files
cp -n ./corpus-cmin/* ./corpus-tmin

# hack to let afl-cov run code coverage on our minimal corpus

rm -R corpus-cov
mkdir -p corpus-cov/queue

cp corpus-tmin/* corpus-cov/queue

# Run code coverage only on minized corpus to save time
afl-cov --cover-corpus -d ./corpus-cov --overwrite --coverage-cmd "$COV_BIN @@" --code-dir ../
