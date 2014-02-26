#!/bin/sh
export CFLAGS="-Ofast"
TARGET_ARCH=mips TOOLCHAIN_NAME=mipsel-linux-android-4.8 HOST_COMPILER=mipsel-linux-android "$(dirname "$0")/android-build.sh"
