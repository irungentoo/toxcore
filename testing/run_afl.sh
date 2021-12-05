#!/bin/sh

COMMON_CMAKE_OPTIONS="-DCMAKE_C_COMPILER=afl-clang-lto -DCMAKE_CXX_COMPILER=afl-clang-lto++ -DBUILD_TOXAV=OFF -DENABLE_SHARED=NO -DBUILD_FUZZ_TESTS=ON -DDHT_BOOTSTRAP=OFF -DBOOTSTRAP_DAEMON=OFF"

# move to repo root
cd ../

# build fuzzer target UBSAN
mkdir -p _afl_build_ubsan
cd _afl_build_ubsan

export AFL_USE_UBSAN=1

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

unset AFL_USE_UBSAN

cd ..

# build fuzzer target MSAN
mkdir -p _afl_build_msan
cd _afl_build_msan

export AFL_USE_MSAN=1

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

unset AFL_USE_MSAN

cd ..

# build fuzzer target ASAN
mkdir -p _afl_build_asan
cd _afl_build_asan

export AFL_USE_ASAN=1

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

unset AFL_USE_ASAN

cd ..

# build fuzzer target without sanitizers for afl-tmin
mkdir -p _afl_build
cd _afl_build

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

cd ..

# build fuzzer target with CmpLog
mkdir -p _afl_build_cmplog
cd _afl_build_cmplog

export AFL_LLVM_CMPLOG=1

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

unset AFL_LLVM_CMPLOG

cd ..

# build fuzzer target for code coverage
mkdir -p _cov_build
cd _cov_build

# build c-toxcore using afl instrumentation
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-fprofile-arcs -ftest-coverage" -DCMAKE_C_FLAGS="-fprofile-arcs -ftest-coverage" -DCMAKE_VERBOSE_MAKEFILE=ON "$COMMON_CMAKE_OPTIONS" ..

# build fuzzer target
cmake --build ./ --target bootstrap_fuzzer

# back to repo root
cd ../

# Create fuzzer working directory

mkdir -p _afl_out

AFL_ARGS='-i testing/afl_testdata/tox_bootstraps/ -o _afl_out'

export AFL_IMPORT_FIRST=1
export AFL_AUTORESUME=1

# faster startup
export AFL_FAST_CAL=1

echo "connect to the fuzzers using: screen -x fuzz"
echo "if fuzzing doesn't start execute the following as root:"
echo ""
echo "echo core >/proc/sys/kernel/core_pattern"
echo "echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor"

# Main fuzzer, keeps complete corpus
screen -dmS fuzz afl-fuzz -M fuzz0 "$AFL_ARGS" -c ./_afl_build_cmplog/bootstrap_fuzzer ./_afl_build/bootstrap_fuzzer
sleep 10s

# Secondary fuzzers
screen -S fuzz -X screen afl-fuzz -S fuzz1 "$AFL_ARGS" -- ./_afl_build_msan/bootstrap_fuzzer
sleep 1s

screen -S fuzz -X screen afl-fuzz -S fuzz2 "$AFL_ARGS" ./_afl_build_ubsan/bootstrap_fuzzer
sleep 1s

screen -S fuzz -X screen afl-fuzz -S fuzz3 "$AFL_ARGS" ./_afl_build_asan/bootstrap_fuzzer
