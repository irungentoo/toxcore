#!/bin/sh

# Move to repo root
cd ../

# Run code coverage only on minized corpus to save time
afl-cov --cover-corpus -d ./_afl_out --overwrite --live --coverage-cmd "_cov_build/bootstrap_fuzz_test @@" --code-dir ../
