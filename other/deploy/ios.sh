#!/usr/bin/env bash

set -eux -o pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TARGET="$1"

if [ -n "${CI-}" ]; then
  brew install bash coreutils ninja yasm
fi

SYSTEM="${TARGET%%-*}"
ARCH="${TARGET#*-}"

"$SCRIPT_DIR/deps.sh" "$SYSTEM" "$ARCH"

export PKG_CONFIG_PATH="$PWD/deps-prefix-$SYSTEM-$ARCH/lib/pkgconfig"

if [ "$SYSTEM" = "ios" ]; then
  XC_SDK="iphoneos"
  TARGET_IPHONE_SIMULATOR=OFF
  IOS_FLAGS="-miphoneos-version-min=10.0 -arch $ARCH"
elif [ "$SYSTEM" = "iphonesimulator" ]; then
  XC_SDK="iphonesimulator"
  TARGET_IPHONE_SIMULATOR=ON
  IOS_FLAGS="-arch $ARCH"
else
  echo "Unexpected system $SYSTEM"
  exit 1
fi

BUILD_DIR="_build-$SYSTEM-$ARCH"

# Build for iOS 10
cmake \
  -B "$BUILD_DIR" \
  -G Ninja \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-$SYSTEM-$ARCH" \
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
  -DCMAKE_C_FLAGS="$IOS_FLAGS" \
  -DCMAKE_CXX_FLAGS="$IOS_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$IOS_FLAGS" \
  -DCMAKE_OSX_SYSROOT="$(xcrun --sdk "$XC_SDK" --show-sdk-path)" \
  -DCMAKE_OSX_ARCHITECTURES="$ARCH"

cmake --build "$BUILD_DIR"
cmake --install "$BUILD_DIR"
