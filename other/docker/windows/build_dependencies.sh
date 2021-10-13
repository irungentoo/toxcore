#!/usr/bin/env sh

# disable on Cygwin otherwise some builds fail
if [ "$CROSS_COMPILE" = "true" ]; then
  set -e -x
fi

#=== Cross-Compile Dependencies ===

build() {
  ARCH=${1}

  echo "Building for $ARCH architecture"

  # set some things
  WINDOWS_TOOLCHAIN=$ARCH-w64-mingw32

  # prefix that we will copy to the user
  PREFIX_DIR="/root/prefix/$ARCH"
  rm -rf "$PREFIX_DIR"
  mkdir -p "$PREFIX_DIR"

  export MAKEFLAGS=j"$(nproc)"
  export CFLAGS=-O3

  CURL_OPTIONS="-L --connect-timeout 10"

  cd /tmp
  rm -rf /tmp/*

  echo
  echo "=== Building Sodium $VERSION_SODIUM $ARCH ==="
  curl $CURL_OPTIONS -O "https://download.libsodium.org/libsodium/releases/libsodium-$VERSION_SODIUM.tar.gz"
  tar -xf "libsodium-$VERSION_SODIUM.tar.gz"
  cd "libsodium-$VERSION_SODIUM"
  ./configure --host="$WINDOWS_TOOLCHAIN" --prefix="$PREFIX_DIR" --disable-shared --enable-static
  make
  make install
  cd ..

  echo
  echo "=== Building Opus $VERSION_OPUS $ARCH ==="
  curl $CURL_OPTIONS -O "https://archive.mozilla.org/pub/opus/opus-$VERSION_OPUS.tar.gz"
  tar -xf "opus-$VERSION_OPUS.tar.gz"
  cd "opus-$VERSION_OPUS"
  ./configure --host="$WINDOWS_TOOLCHAIN" --prefix="$PREFIX_DIR" --disable-extra-programs --disable-doc --disable-shared --enable-static
  make
  make install
  cd ..

  echo
  echo "=== Building VPX $VERSION_VPX $ARCH ==="
  LIB_VPX_TARGET=""
  if [ "$ARCH" = "i686" ]; then
    LIB_VPX_TARGET=x86-win32-gcc
    LIB_VPX_CFLAGS=""
  else
    LIB_VPX_TARGET=x86_64-win64-gcc
    # There is a bug in gcc that breaks avx512 on 64-bit Windows https://gcc.gnu.org/bugzilla/show_bug.cgi?id=54412
    # VPX fails to build due to it.
    # This is a workaround as suggested in https://stackoverflow.com/questions/43152633
    LIB_VPX_CFLAGS="-fno-asynchronous-unwind-tables"
  fi
  curl $CURL_OPTIONS "https://github.com/webmproject/libvpx/archive/v$VERSION_VPX.tar.gz" -o "libvpx-$VERSION_VPX.tar.gz"
  tar -xf "libvpx-$VERSION_VPX.tar.gz"
  cd "libvpx-$VERSION_VPX"
  CFLAGS="$LIB_VPX_CFLAGS" CROSS="$WINDOWS_TOOLCHAIN"- ./configure --target="$LIB_VPX_TARGET" --prefix="$PREFIX_DIR" --disable-examples --disable-unit-tests --disable-shared --enable-static
  make
  make install
  cd ..

  rm -rf /tmp/*
}

if [ "$SUPPORT_ARCH_i686" = "true" ]; then
  build i686
fi

if [ "$SUPPORT_ARCH_x86_64" = "true" ]; then
  build x86_64
fi

tree /root

echo
echo "Built dependencies successfully!"
echo
