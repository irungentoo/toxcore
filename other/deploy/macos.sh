#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$1"

if [ -n "${CI-}" ]; then
  brew install bash coreutils ninja yasm
fi

"$SCRIPT_DIR/deps.sh" macos "$ARCH"

export PKG_CONFIG_PATH="$PWD/deps-prefix-macos-$ARCH/lib/pkgconfig"

BUILD_DIR="_build-macos-$ARCH"

# Build for macOS
cmake \
  -B "$BUILD_DIR" \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-macos-$ARCH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=OFF \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DSTRICT_ABI=ON \
  -DMIN_LOGGER_LEVEL=TRACE \
  -DEXPERIMENTAL_API=ON \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15

cmake --build "$BUILD_DIR"
cmake --install "$BUILD_DIR"
