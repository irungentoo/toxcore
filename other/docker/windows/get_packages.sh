#!/usr/bin/env sh

set -e -x

#=== Install Packages ===

apt-get update

# Arch-independent packages required for building toxcore's dependencies and toxcore itself
apt-get install -y \
  autoconf \
  automake \
  ca-certificates \
  cmake \
  curl \
  libtool \
  libc-dev \
  make \
  pkg-config \
  tree \
  yasm

# Arch-dependent packages required for building toxcore's dependencies and toxcore itself
if [ "$SUPPORT_ARCH_i686" = "true" ]; then
  apt-get install -y \
    g++-mingw-w64-i686 \
    gcc-mingw-w64-i686
fi

if [ "$SUPPORT_ARCH_x86_64" = "true" ]; then
  apt-get install -y \
    g++-mingw-w64-x86-64 \
    gcc-mingw-w64-x86-64
fi

# Packages needed for running toxcore tests
if [ "$SUPPORT_TEST" = "true" ]; then
  apt-get install -y \
    texinfo

  dpkg --add-architecture i386
  apt-get update
  apt-get install -y \
    wine \
    wine32 \
    wine64
fi

# Clean up to reduce image size
apt-get clean
rm -rf \
  /var/lib/apt/lists/* \
  /tmp/* \
  /var/tmp/*
