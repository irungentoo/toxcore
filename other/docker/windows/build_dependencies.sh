#!/usr/bin/env sh

set -e -x

#=== Cross-Compile Dependencies ===

build()
{
    ARCH=${1}

    echo "Building for ${ARCH} architecture"

    # set some things
    WINDOWS_TOOLCHAIN=${ARCH}-w64-mingw32

    # prefix that we will copy to the user
    PREFIX_DIR="/root/prefix/${ARCH}"
    # prefix for things that shouldn't be copied to the user
    EXTRA_PREFIX_DIR="/root/extra-prefix/${ARCH}"
    mkdir -p "${PREFIX_DIR}" "${EXTRA_PREFIX_DIR}"

    export MAKEFLAGS=j$(nproc)
    export CFLAGS=-O3

    cd /tmp

    echo
    echo "=== Building Sodium ${VERSION_SODIUM} ${ARCH} ==="
    git clone --depth=1 --branch="${VERSION_SODIUM}" https://github.com/jedisct1/libsodium
    cd libsodium
    ./autogen.sh
    ./configure --host="${WINDOWS_TOOLCHAIN}" --prefix="${PREFIX_DIR}" --disable-shared --enable-static
    make
    make install
    cd ..

    echo
    echo "=== Building Opus ${VERSION_OPUS} ${ARCH} ==="
    git clone --depth=1 --branch="${VERSION_OPUS}" https://github.com/xiph/opus
    cd opus
    ./autogen.sh
    ./configure --host="${WINDOWS_TOOLCHAIN}" --prefix="${PREFIX_DIR}" --disable-extra-programs --disable-doc --disable-shared --enable-static
    make
    make install
    cd ..

    echo
    echo "=== Building VPX ${VERSION_VPX} ${ARCH} ==="
    LIB_VPX_TARGET=""
    if [ "${ARCH}" = "i686" ]; then
        LIB_VPX_TARGET=x86-win32-gcc
    else
        LIB_VPX_TARGET=x86_64-win64-gcc
    fi
    git clone --depth=1 --branch="${VERSION_VPX}" https://github.com/webmproject/libvpx
    cd libvpx
    CROSS="${WINDOWS_TOOLCHAIN}"- ./configure --target="${LIB_VPX_TARGET}" --prefix="${PREFIX_DIR}" --disable-examples --disable-unit-tests --disable-shared --enable-static
    make
    make install
    cd ..

    if [ "${SUPPORT_TEST}" = "true" ]; then
        echo
        echo "=== Building Check ${VERSION_CHECK} ${ARCH} ==="
        git clone --depth=1 --branch="${VERSION_CHECK}" https://github.com/libcheck/check
        cd check
        autoreconf --install
        ./configure --host="${WINDOWS_TOOLCHAIN}" --prefix="${EXTRA_PREFIX_DIR}"
        make
        make install
        cd ..
    fi

    rm -rf /tmp/*
}

if [ "${SUPPORT_ARCH_i686}" = "true" ]; then
    build i686
fi

if [ "${SUPPORT_ARCH_x86_64}" = "true" ]; then
    build x86_64
fi

tree /root

echo
echo "Built dependencies successfully!"
echo
