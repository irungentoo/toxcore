#!/bin/sh

[ -f android.settings ] && source ./android.settings

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
  
  if [ ! -f "$MAKE_TOOLCHAIN" ]; then
    echo "Cannot find a make-standalone-toolchain.sh in ndk dir, interrupt..."
    exit 1
  fi
  
  $MAKE_TOOLCHAIN --platform="${NDK_PLATFORM:-android-14}" \
                  --arch="${TARGET_ARCH}" \
                  --toolchain="${TOOLCHAIN_NAME:-arm-linux-androideabi-4.8}" \
                  --install-dir="${TOOLCHAIN_DIR}"
fi

export PREFIX="$(pwd)/toxcore-android-${TARGET_ARCH}"
export SYSROOT=${SYSROOT-${TOOLCHAIN_DIR}/sysroot}
export PATH="${PATH}:${TOOLCHAIN_DIR}/bin"

# Clean up before build
rm -rf "${PREFIX}"

export CFLAGS="${CFLAGS} --sysroot=${SYSROOT} -I${SYSROOT}/usr/include"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS} -L${SYSROOT}/usr/lib"

# here SODIUM_ARCH must be armv6, while TARGET_ARCH is arm
# permit override...
SODIUM_ARCH=${SODIUM_ARCH-${TARGET_ARCH}}

SODIUM_PREFIX="${SODIUM_HOME}/libsodium-android-${SODIUM_ARCH}"
SODIUM_HDR=${SODIUM_HDR---with-libsodium-headers="${SODIUM_PREFIX}/include"}
SODIUM_LIB=${SODIUM_LIB---with-libsodium-libs="${SODIUM_PREFIX}/lib"}

builddir="build-${TARGET_ARCH}"
mkdir -p $builddir
cd $builddir

../configure --host="${HOST_COMPILER}" \
            --with-sysroot="${SYSROOT}" \
            "${SODIUM_HDR}" \
            "${SODIUM_LIB}" \
            --disable-av \
            --prefix=/ && \

make clean && \
make -j3 install DESTDIR=${PREFIX} && \
echo "libtoxcore has been installed into ${PREFIX}"
