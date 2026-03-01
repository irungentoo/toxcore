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
  # instead as Debian Trixie's Wine crashes when creating a 64-bit prefix.
  # see https://github.com/TokTok/c-toxcore/pull/2713#issuecomment-1967319113
  # for the crash details
  curl "${CURL_OPTIONS[@]}" -o /etc/apt/keyrings/winehq-archive.key \
    https://dl.winehq.org/wine-builds/winehq.key
  curl "${CURL_OPTIONS[@]}" -O --output-dir /etc/apt/sources.list.d/ \
    https://dl.winehq.org/wine-builds/debian/dists/trixie/winehq-trixie.sources

  . ./check_sha256.sh
  check_sha256 "d965d646defe94b3dfba6d5b4406900ac6c81065428bf9d9303ad7a72ee8d1b8" \
    "/etc/apt/keyrings/winehq-archive.key"
  check_sha256 "d10fb49718b5ceda9cc9c2f8f52b076772396b4b3563a1aad2ab6503414dcee7" \
    "/etc/apt/sources.list.d/winehq-trixie.sources"

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
