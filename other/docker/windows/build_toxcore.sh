#!/bin/sh

set -e -x

#=== Cross-Compile Toxcore ===

build() {
  ARCH=${1}

  echo "Building for $ARCH architecture"

  # set some things

  WINDOWS_TOOLCHAIN=$ARCH-w64-mingw32

  # toxcore dependencies that we will copy to the user for static build of toxcore (e.g. vpx, opus, sodium)
  DEP_PREFIX_DIR="/root/prefix/$ARCH"

  # where to put the result of this particular build
  RESULT_PREFIX_DIR="/prefix/$ARCH"
  rm -rf "$RESULT_PREFIX_DIR"
  mkdir -p "$RESULT_PREFIX_DIR"

  rm -rf /tmp/*

  # where to install static/shared toxcores before deciding whether they should be copied over to the user
  STATIC_TOXCORE_PREFIX_DIR="/tmp/static_prefix"
  SHARED_TOXCORE_PREFIX_DIR="/tmp/shared_prefix"
  mkdir -p "$STATIC_TOXCORE_PREFIX_DIR" "$SHARED_TOXCORE_PREFIX_DIR"

  export MAKEFLAGS=j"$(nproc)"
  export CFLAGS=-O3

  echo
  echo "=== Building toxcore $ARCH ==="
  export PKG_CONFIG_PATH="$DEP_PREFIX_DIR/lib/pkgconfig"

  if [ "$CROSS_COMPILE" = "true" ]; then
    TOXCORE_DIR="/toxcore"
  else
    # get Toxcore root
    cd "$(cd "$(dirname -- "$0")" >/dev/null 2>&1 && pwd)"
    cd ../../../
    TOXCORE_DIR="$PWD"
  fi

  cp -a "$TOXCORE_DIR" /tmp/toxcore
  cd /tmp/toxcore/build

  echo "
        SET(CMAKE_SYSTEM_NAME Windows)

        SET(CMAKE_C_COMPILER   $WINDOWS_TOOLCHAIN-gcc)
        SET(CMAKE_CXX_COMPILER $WINDOWS_TOOLCHAIN-g++)
        SET(CMAKE_RC_COMPILER  $WINDOWS_TOOLCHAIN-windres)

        SET(CMAKE_FIND_ROOT_PATH /usr/$WINDOWS_TOOLCHAIN $DEP_PREFIX_DIR)
    " > windows_toolchain.cmake

  if [ "$ENABLE_TEST" = "true" ]; then
    echo "SET(CROSSCOMPILING_EMULATOR /usr/bin/wine)" >> windows_toolchain.cmake
  fi

  cmake -DCMAKE_TOOLCHAIN_FILE=windows_toolchain.cmake \
    -DCMAKE_INSTALL_PREFIX="$STATIC_TOXCORE_PREFIX_DIR" \
    -DENABLE_SHARED=OFF \
    -DENABLE_STATIC=ON \
    -DCMAKE_C_FLAGS="$CMAKE_C_FLAGS" \
    -DCMAKE_CXX_FLAGS="$CMAKE_CXX_FLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="$CMAKE_EXE_LINKER_FLAGS -fstack-protector" \
    -DCMAKE_SHARED_LINKER_FLAGS="$CMAKE_SHARED_LINKER_FLAGS" \
    $EXTRA_CMAKE_FLAGS \
    ..
  cmake --build . --target install -- -j"$(nproc)"

  if [ "$ENABLE_TEST" = "true" ]; then
    rm -rf /root/.wine

    # setup wine
    if [ "$ARCH" = "i686" ]; then
      export WINEARCH=win32
    else
      export WINEARCH=win64
    fi

    winecfg
    export CTEST_OUTPUT_ON_FAILURE=1
    # add libgcc_s_sjlj-1.dll libwinpthread-1.dll into PATH env var of wine
    export WINEPATH="$(
      cd /usr/lib/gcc/"$WINDOWS_TOOLCHAIN"/*posix/
      winepath -w "$PWD"
    )"\;"$(winepath -w /usr/"$WINDOWS_TOOLCHAIN"/lib/)"

    if [ "$ALLOW_TEST_FAILURE" = "true" ]; then
      set +e
    fi
    cmake --build . --target test -- ARGS="-j50"
    if [ "$ALLOW_TEST_FAILURE" = "true" ]; then
      set -e
    fi
  fi

  # move static dependencies
  cp -a "$STATIC_TOXCORE_PREFIX_DIR"/* "$RESULT_PREFIX_DIR"
  cp -a "$DEP_PREFIX_DIR"/* "$RESULT_PREFIX_DIR"

  # make libtox.dll
  cd "$SHARED_TOXCORE_PREFIX_DIR"
  for archive in "$STATIC_TOXCORE_PREFIX_DIR"/lib/libtox*.a; do
    "$WINDOWS_TOOLCHAIN"-ar xv "$archive"
  done

  if [ "$CROSS_COMPILE" = "true" ]; then
    LIBWINPTHREAD="/usr/$WINDOWS_TOOLCHAIN/lib/libwinpthread.a"
  else
    LIBWINPTHREAD="/usr/$WINDOWS_TOOLCHAIN/sys-root/mingw/lib/libwinpthread.a"
  fi

  "$WINDOWS_TOOLCHAIN"-gcc -Wl,--export-all-symbols \
    -Wl,--out-implib=libtox.dll.a \
    -shared \
    -o libtox.dll \
    *.obj \
    "$STATIC_TOXCORE_PREFIX_DIR"/lib/*.a \
    "$DEP_PREFIX_DIR"/lib/*.a \
    "$LIBWINPTHREAD" \
    -liphlpapi \
    -lws2_32 \
    -static-libgcc \
    -lssp
  cp libtox.dll.a "$RESULT_PREFIX_DIR"/lib
  mkdir -p "$RESULT_PREFIX_DIR"/bin
  cp libtox.dll "$RESULT_PREFIX_DIR"/bin

  rm -rf /tmp/*

  # remove everything from include directory except tox headers
  mv "$RESULT_PREFIX_DIR"/include/tox "$RESULT_PREFIX_DIR"/tox
  rm -rf "$RESULT_PREFIX_DIR"/include/*
  mv "$RESULT_PREFIX_DIR"/tox "$RESULT_PREFIX_DIR"/include/tox

  sed -i "s|^prefix=.*|prefix=$RESULT_PREFIX_DIR|g" "$RESULT_PREFIX_DIR"/lib/pkgconfig/*.pc
  sed -i "s|^libdir=.*|libdir=$RESULT_PREFIX_DIR/lib|g" "$RESULT_PREFIX_DIR"/lib/*.la
}

#=== Test Supported vs. Enabled ===

if [ "$ENABLE_ARCH_i686" != "true" ] && [ "$ENABLE_ARCH_x86_64" != "true" ]; then
  echo "Error: No architecture specified. Set either ENABLE_ARCH_i686 or ENABLE_ARCH_x86_64 or both."
  exit 1
fi

if [ "$ENABLE_ARCH_i686" = "true" ] && [ "$SUPPORT_ARCH_i686" != "true" ]; then
  echo "Error: Can't build for i686 architecture because the image was created without SUPPORT_ARCH_i686 set"
  exit 1
fi

if [ "$ENABLE_ARCH_x86_64" = "true" ] && [ "$SUPPORT_ARCH_x86_64" != "true" ]; then
  echo "Error: Can't build for x86_64 architecture because the image was created without SUPPORT_ARCH_x86_64 set"
  exit 1
fi

if [ "$ENABLE_TEST" = "true" ] && [ "$SUPPORT_TEST" != "true" ]; then
  echo "Error: Can't build with tests because the image was created without SUPPORT_TEST set"
  exit 1
fi

#=== Build ===

if [ "$ENABLE_ARCH_i686" = "true" ]; then
  build i686
fi

if [ "$ENABLE_ARCH_x86_64" = "true" ]; then
  build x86_64
fi

tree -h /prefix

echo
echo "Built toxcore successfully!"
echo

# since we are building as root
if [ "$CROSS_COMPILE" = "true" ]; then
  chmod 777 /prefix -R
fi
