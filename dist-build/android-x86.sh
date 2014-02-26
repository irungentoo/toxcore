#!/bin/sh
export CFLAGS="-Ofast"
TARGET_ARCH=x86 TOOLCHAIN_NAME=x86-4.8 HOST_COMPILER=i686-linux-android "$(dirname "$0")/android-build.sh"
