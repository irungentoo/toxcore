#!/bin/sh

export VERSION_SODIUM="1.0.18"
export VERSION_OPUS="v1.2.1"
export VERSION_VPX="v1.6.1"

export SUPPORT_TEST=false
export SUPPORT_ARCH_i686=true
export SUPPORT_ARCH_x86_64=true
export CROSS_COMPILE=false

sh ./other/docker/windows/build_dependencies.sh

export ENABLE_TEST=false
export ALLOW_TEST_FAILURE=false
export ENABLE_ARCH_i686=true
export ENABLE_ARCH_x86_64=true
export EXTRA_CMAKE_FLAGS="-DTEST_TIMEOUT_SECONDS=90"

sh ./other/docker/windows/build_toxcore.sh
