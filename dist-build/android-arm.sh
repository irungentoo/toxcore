#!/bin/sh
export CFLAGS="-Ofast -mthumb -marm -march=armv6"
TARGET_ARCH=arm TOOLCHAIN_NAME=arm-linux-androideabi-4.8 HOST_COMPILER=arm-linux-androideabi "$(dirname "$0")/android-build.sh"
