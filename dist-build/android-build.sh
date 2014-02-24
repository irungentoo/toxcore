#!/bin/sh

if [ -z "$ANDROID_NDK_HOME" ]; then
    echo "You should probably set ANDROID_NDK_HOME to the directory containing"
    echo "the Android NDK"
    exit
fi

if [ -z "$SODIUM_HOME" ]; then
    echo "You should probably set SODIUM_HOME to the directory containing root sodium sources"
    exit
fi

if [[ -z $TARGET_ARCH ]] || [[ -z $HOST_COMPILER ]]; then
    echo "You shouldn't use android-build.sh directly, use android-[arch].sh instead"
    exit 1
fi

if [ ! -f ./configure ]; then
	echo "Can't find ./configure. Wrong directory or haven't run autogen.sh?"
	exit 1
fi

if [ -z "$TOOLCHAIN_DIR" ]; then
  export TOOLCHAIN_DIR="$(pwd)/android-toolchain-${TARGET_ARCH}"
  export MAKE_TOOLCHAIN="${ANDROID_NDK_HOME}/build/tools/make-standalone-toolchain.sh"
  
  if [ -z "$MAKE_TOOLCHAIN" ]; then
    echo "Cannot find a make-standalone-toolchain.sh in ndk dir, interrupt..."
    exit 1
  fi
  
  $MAKE_TOOLCHAIN --platform="${NDK_PLATFORM:-android-14}" \
                  --arch="${TARGET_ARCH}" \
                  --toolchain="${TOOLCHAIN_NAME:-arm-linux-androideabi-4.8}" \
                  --install-dir="${TOOLCHAIN_DIR}"
fi

export PREFIX="$(pwd)/toxcore-android-${TARGET_ARCH}"
export SYSROOT="${TOOLCHAIN_DIR}/sysroot"
export PATH="${PATH}:${TOOLCHAIN_DIR}/bin"

# Clean up before build
rm -rf "${PREFIX}"

export CFLAGS="${CFLAGS} --sysroot=${SYSROOT} -I${SYSROOT}/usr/include"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS} -L${SYSROOT}/usr/lib"

./configure --host="${HOST_COMPILER}" \
            --with-sysroot="${SYSROOT}" \
            --with-libsodium-headers="${SODIUM_HOME}/libsodium-android-${TARGET_ARCH}/include" \
            --with-libsodium-libs="${SODIUM_HOME}/libsodium-android-${TARGET_ARCH}/lib" \
            --disable-soname-versions \
            --disable-av \
            --disable-ntox \
            --disable-daemon \
            --disable-phone \
            --prefix="${PREFIX}" && \

make clean && \
make -j3 install && \
echo "libtoxcore has been installed into ${PREFIX}"
