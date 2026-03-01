#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

ARCH="$1"
"$SCRIPT_DIR/deps.sh" linux "$ARCH"

export PKG_CONFIG_PATH="$PWD/deps-prefix-linux-$ARCH/lib/pkgconfig"

# Build
cmake \
  -B _build \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-linux-$ARCH" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_STATIC=OFF \
  -DENABLE_SHARED=ON \
  -DMUST_BUILD_TOXAV=ON \
  -DDHT_BOOTSTRAP=OFF \
  -DBOOTSTRAP_DAEMON=OFF \
  -DUNITTEST=OFF \
  -DSTRICT_ABI=ON \
  -DMIN_LOGGER_LEVEL=TRACE \
  -DEXPERIMENTAL_API=ON

cmake --build _build
cmake --install _build
