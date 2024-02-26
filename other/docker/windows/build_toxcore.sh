#!/usr/bin/env bash

set -e -x

# Note: when modifying this script, don't forget to update the appropriate
#       parts of the cross-compilation section of the INSTALL.md.

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

  export MAKEFLAGS=j"$(nproc)"
  export CFLAGS="-D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS -ftrivial-auto-var-init=zero -fPIE -pie -fstack-protector-strong -fstack-clash-protection -fcf-protection=full"

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
    " >windows_toolchain.cmake

  if [ "$ENABLE_TEST" = "true" ]; then
    echo "SET(CROSSCOMPILING_EMULATOR /usr/bin/wine)" >>windows_toolchain.cmake
  fi

  if [ "$ARCH" = "i686" ]; then
    TOXCORE_CFLAGS=""
  else
    # This makes the build work with -fstack-clash-protection, as otherwise it crashes with:
    #/tmp/toxcore/toxcore/logger.c: In function 'logger_abort':
    #/tmp/toxcore/toxcore/logger.c:124:1: internal compiler error: in seh_emit_stackalloc, at config/i386/winnt.cc:1055
    # Should get patched in a future gcc version: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90458
    TOXCORE_CFLAGS="-fno-asynchronous-unwind-tables"
  fi

  # Patch CMakeLists.txt to make cracker.exe statically link against OpenMP. For some reason
  # -DCMAKE_EXE_LINKER_FLAGS="-static" doesn't do it.
  sed -i "s|OpenMP::OpenMP_C)|$(realpath -- /usr/lib/gcc/"$WINDOWS_TOOLCHAIN"/*-win32/libgomp.a) \${CMAKE_THREAD_LIBS_INIT})\ntarget_compile_options(cracker PRIVATE -fopenmp)|g" ../other/fun/CMakeLists.txt

  # Silly way to bypass a shellharden check
  read -ra EXTRA_CMAKE_FLAGS_ARRAY <<<"$EXTRA_CMAKE_FLAGS"
  CFLAGS="$CFLAGS $TOXCORE_CFLAGS" \
    cmake \
    -DCMAKE_TOOLCHAIN_FILE=windows_toolchain.cmake \
    -DCMAKE_INSTALL_PREFIX="$RESULT_PREFIX_DIR" \
    -DCMAKE_BUILD_TYPE="Release" \
    -DENABLE_SHARED=ON \
    -DENABLE_STATIC=ON \
    -DSTRICT_ABI=ON \
    -DEXPERIMENTAL_API=ON \
    -DBUILD_FUN_UTILS=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-static" \
    -DCMAKE_SHARED_LINKER_FLAGS="-static" \
    "${EXTRA_CMAKE_FLAGS_ARRAY[@]}" \
    -S ..
  cmake --build . --target install --parallel "$(nproc)"
  # CMake doesn't install fun utils, so do it manually
  cp -a other/fun/*.exe "$RESULT_PREFIX_DIR/bin/"

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
    # we don't have to do this since autotests are statically compiled now,
    # but just in case add MinGW-w64 dll locations to the PATH anyway
    export WINEPATH="$(
      cd /usr/lib/gcc/"$WINDOWS_TOOLCHAIN"/*win32/
      winepath -w "$PWD"
      cd -
    )"\;"$(winepath -w /usr/"$WINDOWS_TOOLCHAIN"/lib/)"

    if [ "$ALLOW_TEST_FAILURE" = "true" ]; then
      set +e
    fi
    cmake --build . --target test -- ARGS="-j50"
    if [ "$ALLOW_TEST_FAILURE" = "true" ]; then
      set -e
    fi
  fi

  # generate def, lib and exp as they supposedly help with linking against the dlls,
  # especially the lib is supposed to be of great help when linking on msvc.
  # cd in order to keep the object names inside .lib and .dll.a short
  cd "$RESULT_PREFIX_DIR"/bin/
  for TOX_DLL in *.dll; do
    gendef - "$TOX_DLL" >"${TOX_DLL%.*}.def"
    # we overwrite the CMake-generated .dll.a for the better
    # compatibility with the .lib being generated here
    "$WINDOWS_TOOLCHAIN"-dlltool \
      --input-def "${TOX_DLL%.*}.def" \
      --output-lib "${TOX_DLL%.*}.lib" \
      --output-exp "${TOX_DLL%.*}.exp" \
      --output-delaylib "../lib/${TOX_DLL%.*}.dll.a" \
      --dllname "$TOX_DLL"
  done
  cd -

  # copy over the deps
  if [ "$CROSS_COMPILE" = "true" ]; then
    LIBWINPTHREAD="/usr/$WINDOWS_TOOLCHAIN/lib/libwinpthread.a"
    cd /usr/lib/gcc/"$WINDOWS_TOOLCHAIN"/*win32/
    LIBSSP="$PWD/libssp.a"
    cd -
  else
    LIBWINPTHREAD="/usr/$WINDOWS_TOOLCHAIN/sys-root/mingw/lib/libwinpthread.a"
    LIBSSP="/usr/$WINDOWS_TOOLCHAIN/sys-root/mingw/lib/libssp.a"
  fi
  cp -a "$LIBWINPTHREAD" "$LIBSSP" "$RESULT_PREFIX_DIR/lib/"
  for STATIC_LIB in "$DEP_PREFIX_DIR"/lib/*.a; do
    [[ "$STATIC_LIB" == *.dll.a ]] && continue
    cp -a "$STATIC_LIB" "$RESULT_PREFIX_DIR/lib/"
  done
  cp "$DEP_PREFIX_DIR"/lib/pkgconfig/* "$RESULT_PREFIX_DIR/lib/pkgconfig/"

  # strip everything
  set +e
  "$WINDOWS_TOOLCHAIN"-strip --strip-unneeded "$RESULT_PREFIX_DIR"/bin/*.* "$RESULT_PREFIX_DIR"/lib/*.*
  set -e

  rm -rf /tmp/*

  sed -i "s|^prefix=.*|prefix=$RESULT_PREFIX_DIR|g" "$RESULT_PREFIX_DIR"/lib/pkgconfig/*.pc
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
