#!/bin/bash

set -eu

if [ -n "${CI-}" ]; then
  sudo apt-get install -y --no-install-recommends ninja-build yasm
fi

# Set up environment
NDK=$ANDROID_NDK_HOME

ABI=${1:-"armeabi-v7a"}

case $ABI in
  armeabi-v7a)
    TARGET=armv7a-linux-androideabi
    NDK_API=21
    ANDROID_VPX_ABI=armv7-android-gcc
    ;;
  arm64-v8a)
    TARGET=aarch64-linux-android
    NDK_API=21
    ANDROID_VPX_ABI=arm64-android-gcc
    ;;
  x86)
    TARGET=i686-linux-android
    NDK_API=21
    ANDROID_VPX_ABI=x86-android-gcc
    ;;
  x86_64)
    TARGET=x86_64-linux-android
    NDK_API=21
    ANDROID_VPX_ABI=x86_64-android-gcc
    ;;
  *)
    exit 1
    ;;
esac

PREFIX="$PWD/deps-prefix-android-$ABI"

TOOLCHAIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64"
SYSROOT="$TOOLCHAIN/sysroot"

export CC="$TOOLCHAIN/bin/$TARGET$NDK_API-clang"
export CXX="$TOOLCHAIN/bin/$TARGET$NDK_API-clang++"
export LDFLAGS=-static-libstdc++
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# Build libsodium
if [ ! -f "$PREFIX/lib/libsodium.a" ]; then
  tar zxf <(wget -O- https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz)
  pushd libsodium-1.0.20
  ./configure --prefix="$PREFIX" --host="$TARGET" --with-sysroot="$SYSROOT" --disable-shared --disable-pie
  make -j"$(nproc)" install
  popd
  rm -rf libsodium-1.0.20
fi

# Build opus
if [ ! -f "$PREFIX/lib/libopus.a" ]; then
  tar zxf <(wget -O- https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz)
  pushd opus-1.5.2
  CFLAGS="-fPIC" ./configure --prefix="$PREFIX" --host="$TARGET" --with-sysroot="$SYSROOT" --disable-shared
  make "-j$(nproc)"
  make install
  popd
  rm -rf opus-1.5.2
fi

# Build libvpx
if [ ! -f "$PREFIX/lib/libvpx.a" ]; then
  tar zxf <(wget -O- https://github.com/webmproject/libvpx/archive/refs/tags/v1.15.0.tar.gz)
  pushd libvpx-1.15.0
  ./configure --prefix="$PREFIX" --libc="$SYSROOT" --target="$ANDROID_VPX_ABI" --disable-examples --disable-unit-tests --enable-pic ||
    (cat config.log && exit 1)
  sed -i -e "s!^AS=as!AS=$CC -c!" ./*.mk
  sed -i -e "s!^STRIP=strip!STRIP=$TOOLCHAIN/bin/llvm-strip!" ./*.mk
  make "-j$(nproc)"
  make install
  popd
  rm -rf libvpx-1.15.0
fi

# Build c-toxcore
rm -rf _build
cmake -B _build -G Ninja \
  -DANDROID_ABI="$ABI" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DCMAKE_INSTALL_PREFIX="$PWD/toxcore-android-$ABI" \
  -DCMAKE_PREFIX_PATH="$PREFIX" \
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
