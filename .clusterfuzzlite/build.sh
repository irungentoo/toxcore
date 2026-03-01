#!/bin/bash -eu

FUZZ_TARGETS=(
  DHT_fuzz_test
  bootstrap_fuzz_test
  # e2e_fuzz_test
  forwarding_fuzz_test
  group_announce_fuzz_test
  group_moderation_fuzz_test
  net_crypto_fuzz_test
  tox_events_fuzz_test
  toxsave_fuzz_test
)

# out of tree build
cd "$WORK"

ls /usr/local/lib/

# Debug build for asserts
cmake -GNinja \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
  -DBUILD_TOXAV=OFF \
  -DENABLE_SHARED=OFF \
  -DBUILD_FUZZ_TESTS=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  "$SRC"/c-toxcore

for TARGET in "${FUZZ_TARGETS[@]}"; do
  # build fuzzer target
  cmake --build ./ --target "$TARGET"

  # copy to output files
  cp "$WORK/testing/fuzzing/$TARGET" "$OUT"/
done
