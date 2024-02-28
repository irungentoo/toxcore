#!/usr/bin/env bash

set -e -x

#=== Install Packages ===

apt-get update
apt-get upgrade -y

# Arch-independent packages required for building toxcore's dependencies and toxcore itself
apt-get install -y \
  autoconf \
  automake \
  ca-certificates \
  cmake \
  curl \
  libc-dev \
  libtool \
  make \
  mingw-w64-tools \
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

  CURL_OPTIONS=(-L --connect-timeout 10)

  # While we would prefer to use Debian's Wine packages, use WineHQ's packages
  # instead as Debian Bookworm's Wine crashes when creating a 64-bit prefix.
  # see https://github.com/TokTok/c-toxcore/pull/2713#issuecomment-1967319113
  # for the crash details
  curl "${CURL_OPTIONS[@]}" -o /etc/apt/keyrings/winehq-archive.key \
    https://dl.winehq.org/wine-builds/winehq.key
  curl "${CURL_OPTIONS[@]}" -O --output-dir /etc/apt/sources.list.d/ \
    https://dl.winehq.org/wine-builds/debian/dists/bookworm/winehq-bookworm.sources

  . ./check_sha256.sh
  check_sha256 "78b185fabdb323971d13bd329fefc8038e08559aa51c4996de18db0639a51df6" \
    "/etc/apt/keyrings/winehq-archive.key"
  check_sha256 "8dd8ef66c749d56e798646674c1c185a99b3ed6727ca0fbb5e493951e66c0f9e" \
    "/etc/apt/sources.list.d/winehq-bookworm.sources"

  dpkg --add-architecture i386
  apt-get update
  apt-get install -y \
    winehq-stable
fi

# Clean up to reduce image size
apt-get clean
rm -rf \
  /var/lib/apt/lists/* \
  /tmp/* \
  /var/tmp/*
