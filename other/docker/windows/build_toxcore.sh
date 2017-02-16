#!/usr/bin/env sh

set -e -x

#=== Cross-Compile Toxcore ===

build()
{
    ARCH=${1}

    echo "Building for ${ARCH} architecture"

    # set some things

    WINDOWS_TOOLCHAIN=${ARCH}-w64-mingw32

    # toxcore dependencies that we will copy to the user for static build of toxcore (e.g. vpx, opus, sodium)
    DEP_PREFIX_DIR="/root/prefix/${ARCH}"

    # toxcore dependencies that user doesn't need in build result (e.g. libcheck used for testing toxcore)
    EXTRA_DEP_PREFIX_DIR="/root/extra-prefix/${ARCH}"
    mkdir -p "${EXTRA_DEP_PREFIX_DIR}"

    # where to put the result of this particular build
    RESULT_PREFIX_DIR="/prefix/${ARCH}"
    mkdir -p "${RESULT_PREFIX_DIR}"

    # where to install static/shared toxcores before deciding whether they should be copied over to the user
    STATIC_TOXCORE_PREFIX_DIR="/tmp/static_prefix"
    SHARED_TOXCORE_PREFIX_DIR="/tmp/shared_prefix"
    mkdir -p "${STATIC_TOXCORE_PREFIX_DIR}" "${SHARED_TOXCORE_PREFIX_DIR}"

    export MAKEFLAGS=j$(nproc)
    export CFLAGS=-O3

    echo
    echo "=== Building toxcore ${ARCH} ==="
    export PKG_CONFIG_PATH="${DEP_PREFIX_DIR}/lib/pkgconfig:${EXTRA_DEP_PREFIX_DIR}/lib/pkgconfig"

    cp /toxcore /tmp/toxcore -R
    cd /tmp/toxcore/build
    echo "
        SET(CMAKE_SYSTEM_NAME Windows)

        SET(CMAKE_C_COMPILER   ${WINDOWS_TOOLCHAIN}-gcc)
        SET(CMAKE_CXX_COMPILER ${WINDOWS_TOOLCHAIN}-g++)
        SET(CMAKE_RC_COMPILER  ${WINDOWS_TOOLCHAIN}-windres)

        SET(CMAKE_FIND_ROOT_PATH /usr/${WINDOWS_TOOLCHAIN} ${DEP_PREFIX_DIR} ${EXTRA_DEP_PREFIX_DIR})
    " > windows_toolchain.cmake

    if [ "${ENABLE_TEST}" = "true" ]; then
        echo "SET(CROSSCOMPILING_EMULATOR /usr/bin/wine)" >> windows_toolchain.cmake
    fi

    cmake -DCMAKE_TOOLCHAIN_FILE=windows_toolchain.cmake \
        -DCMAKE_INSTALL_PREFIX="${STATIC_TOXCORE_PREFIX_DIR}" \
        -DENABLE_SHARED=OFF \
        -DENABLE_STATIC=ON \
        ${EXTRA_CMAKE_FLAGS} \
        ..
    cmake --build . --target install

    if [ "${ENABLE_TEST}" = "true" ]; then
        rm -rf /root/.wine

        # setup wine
        if [ "${ARCH}" = "i686" ]; then
            export WINEARCH=win32
        else
            export WINEARCH=win64
        fi

        winecfg
        export CTEST_OUTPUT_ON_FAILURE=1
        # add libgcc_s_sjlj-1.dll libwinpthread-1.dll libcheck-0.dll into PATH env var of wine
        export WINEPATH=`cd /usr/lib/gcc/${WINDOWS_TOOLCHAIN}/*posix/ ; winepath -w $(pwd)`\;`winepath -w /usr/${WINDOWS_TOOLCHAIN}/lib/`\;`winepath -w ${EXTRA_DEP_PREFIX_DIR}/bin`

        if [ "${ALLOW_TEST_FAILURE}" = "true" ]; then
            set +e
        fi
        cmake --build . --target test
        if [ "${ALLOW_TEST_FAILURE}" = "true" ]; then
            set -e
        fi
    fi

    # move static dependencies
    cp "${STATIC_TOXCORE_PREFIX_DIR}"/* "${RESULT_PREFIX_DIR}" -R
    cp "${DEP_PREFIX_DIR}"/* "${RESULT_PREFIX_DIR}" -R

    # make libtox.dll
    cd "${SHARED_TOXCORE_PREFIX_DIR}"
    for archive in ${STATIC_TOXCORE_PREFIX_DIR}/lib/libtox*.a
    do
        ${WINDOWS_TOOLCHAIN}-ar xv ${archive}
    done
    ${WINDOWS_TOOLCHAIN}-gcc -Wl,--export-all-symbols \
                             -Wl,--out-implib=libtox.dll.a \
                             -shared \
                             -o libtox.dll \
                             *.obj \
                             ${STATIC_TOXCORE_PREFIX_DIR}/lib/*.a \
                             ${DEP_PREFIX_DIR}/lib/*.a \
                             /usr/${WINDOWS_TOOLCHAIN}/lib/libwinpthread.a \
                             -liphlpapi \
                             -lws2_32 \
                             -static-libgcc
    cp libtox.dll.a ${RESULT_PREFIX_DIR}/lib
    mkdir -p ${RESULT_PREFIX_DIR}/bin
    cp libtox.dll ${RESULT_PREFIX_DIR}/bin

    rm -rf /tmp/*

    # remove everything from include directory except tox headers
    mv ${RESULT_PREFIX_DIR}/include/tox ${RESULT_PREFIX_DIR}/tox
    rm -rf ${RESULT_PREFIX_DIR}/include/*
    mv ${RESULT_PREFIX_DIR}/tox ${RESULT_PREFIX_DIR}/include/tox

    sed -i "s|^prefix=.*|prefix=${RESULT_PREFIX_DIR}|g" ${RESULT_PREFIX_DIR}/lib/pkgconfig/*.pc
    sed -i "s|^libdir=.*|libdir=${RESULT_PREFIX_DIR}/lib|g" ${RESULT_PREFIX_DIR}/lib/*.la
}

#=== Test Supported vs. Enabled ===

if [ "${ENABLE_ARCH_i686}" != "true" ] && [ "${ENABLE_ARCH_x86_64}" != "true" ]; then
    echo "Error: No architecture specified. Set either ENABLE_ARCH_i686 or ENABLE_ARCH_x86_64 or both."
    exit 1
fi

if [ "${ENABLE_ARCH_i686}" = "true" ] && [ "${SUPPORT_ARCH_i686}" != "true" ]; then
    echo "Error: Can't build for i686 architecture because the image was created without SUPPORT_ARCH_i686 set"
    exit 1
fi

if [ "${ENABLE_ARCH_x86_64}" = "true" ] && [ "${SUPPORT_ARCH_x86_64}" != "true" ]; then
    echo "Error: Can't build for x86_64 architecture because the image was created without SUPPORT_ARCH_x86_64 set"
    exit 1
fi

if [ "${ENABLE_TEST}" = "true" ] && [ "${SUPPORT_TEST}" != "true" ]; then
    echo "Error: Can't build with tests because the image was created without SUPPORT_TEST set"
    exit 1
fi

#=== Build ===

if [ "${ENABLE_ARCH_i686}" = "true" ]; then
    build i686
fi

if [ "${ENABLE_ARCH_x86_64}" = "true" ]; then
    build x86_64
fi


tree -h /prefix

echo
echo "Built toxcore successfully!"
echo

# since we are building as root
chmod 777 /prefix -R
