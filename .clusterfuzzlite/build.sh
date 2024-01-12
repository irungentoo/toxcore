#!/bin/bash -eu

FUZZ_TARGETS="bootstrap_fuzz_test toxsave_fuzz_test"

# out of tree build
cd "$WORK"

ls /usr/local/lib/

# Debug build for asserts
cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$LIB_FUZZING_ENGINE" \
  -DBUILD_TOXAV=OFF -DENABLE_SHARED=NO -DBUILD_FUZZ_TESTS=ON \
  -DDHT_BOOTSTRAP=OFF -DBOOTSTRAP_DAEMON=OFF "$SRC"/c-toxcore

for TARGET in $FUZZ_TARGETS; do
  # build fuzzer target
  cmake --build ./ --target "$TARGET"

  # copy to output files
  cp "$WORK/testing/fuzzing/$TARGET" "$OUT"/
done
