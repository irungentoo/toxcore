#!/usr/bin/env bash

# disable on Cygwin otherwise some builds fail
if [ "$CROSS_COMPILE" = "true" ]; then
  set -e -x
fi

#=== Cross-Compile Dependencies ===

. ./check_sha256.sh

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
  export CFLAGS="-O3 -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -ftrivial-auto-var-init=zero -fPIE -pie -fstack-protector-strong -fstack-clash-protection -fcf-protection=full"

  CURL_OPTIONS=(-L --connect-timeout 10)

  cd /tmp
  rm -rf /tmp/*

  echo "
        SET(CMAKE_SYSTEM_NAME Windows)

        SET(CMAKE_C_COMPILER   $WINDOWS_TOOLCHAIN-gcc)
        SET(CMAKE_CXX_COMPILER $WINDOWS_TOOLCHAIN-g++)
        SET(CMAKE_RC_COMPILER  $WINDOWS_TOOLCHAIN-windres)

        SET(CMAKE_FIND_ROOT_PATH /usr/$WINDOWS_TOOLCHAIN $DEP_PREFIX_DIR)
    " >windows_toolchain.cmake

  echo
  echo "=== Building Sodium $VERSION_SODIUM $ARCH ==="
  curl "${CURL_OPTIONS[@]}" -O "https://github.com/jedisct1/libsodium/releases/download/$VERSION_SODIUM-RELEASE/libsodium-$VERSION_SODIUM.tar.gz"
  check_sha256 "018d79fe0a045cca07331d37bd0cb57b2e838c51bc48fd837a1472e50068bbea" "libsodium-$VERSION_SODIUM.tar.gz"
  tar -xf "libsodium-$VERSION_SODIUM.tar.gz"
  cd "libsodium-stable"
  ./configure \
    --host="$WINDOWS_TOOLCHAIN" \
    --prefix="$PREFIX_DIR" \
    --disable-shared \
    --enable-static
  make
  make install
  cd ..

  echo
  echo "=== Building Opus $VERSION_OPUS $ARCH ==="
  if [ "$ARCH" = "i686" ]; then
    LIB_OPUS_CFLAGS=""
  else
    # This makes the build work with -fstack-clash-protection, as otherwise it crashes with:
    # silk/float/encode_frame_FLP.c: In function 'silk_encode_frame_FLP':
    # silk/float/encode_frame_FLP.c:379:1: internal compiler error: in i386_pe_seh_unwind_emit, at config/i386/winnt.cc:1274
    # Should get patched in a future gcc version: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90458
    LIB_OPUS_CFLAGS="-fno-asynchronous-unwind-tables"
  fi

  curl "${CURL_OPTIONS[@]}" -O "https://ftp.osuosl.org/pub/xiph/releases/opus/opus-$VERSION_OPUS.tar.gz"
  check_sha256 "c9b32b4253be5ae63d1ff16eea06b94b5f0f2951b7a02aceef58e3a3ce49c51f" "opus-$VERSION_OPUS.tar.gz"
  tar -xf "opus-$VERSION_OPUS.tar.gz"
  cd "opus-$VERSION_OPUS"
  CFLAGS="$CFLAGS $LIB_OPUS_CFLAGS" \
    ./configure \
    --host="$WINDOWS_TOOLCHAIN" \
    --prefix="$PREFIX_DIR" \
    --disable-extra-programs \
    --disable-doc \
    --disable-shared \
    --enable-static
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
  curl "${CURL_OPTIONS[@]}" "https://github.com/webmproject/libvpx/archive/v$VERSION_VPX.tar.gz" -o "libvpx-$VERSION_VPX.tar.gz"
  check_sha256 "5f21d2db27071c8a46f1725928a10227ae45c5cd1cad3727e4aafbe476e321fa" "libvpx-$VERSION_VPX.tar.gz"
  tar -xf "libvpx-$VERSION_VPX.tar.gz"
  cd "libvpx-$VERSION_VPX"
  CFLAGS="$CFLAGS $LIB_VPX_CFLAGS" \
    CROSS="$WINDOWS_TOOLCHAIN"- \
    ./configure \
    --target="$LIB_VPX_TARGET" \
    --prefix="$PREFIX_DIR" \
    --disable-examples \
    --disable-unit-tests \
    --disable-tools \
    --disable-shared \
    --enable-static
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
