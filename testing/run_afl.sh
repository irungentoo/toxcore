#! /bin/sh

# move to repo root
cd ../
rm -R _afl_build
mkdir _afl_build
cd _afl_build

# build c-toxcore using afl instrumentation
cmake -DCMAKE_C_COMPILER=afl-clang -DBUILD_MISC_TESTS=ON ..
make

# start fuzzing
afl-fuzz -i ../testing/afl_testdata/tox_saves/ -o afl_out/ ./afl_toxsave @@
