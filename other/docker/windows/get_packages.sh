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
    git \
    libtool \
    libc-dev \
    make \
    pkg-config \
    tree \
    yasm

# Arch-dependent packages required for building toxcore's dependencies and toxcore itself
if [ "${SUPPORT_ARCH_i686}" = "true" ]; then
    apt-get install -y \
        g++-mingw-w64-i686 \
        gcc-mingw-w64-i686
fi

if [ "${SUPPORT_ARCH_x86_64}" = "true" ]; then
    apt-get install -y \
        g++-mingw-w64-x86-64 \
        gcc-mingw-w64-x86-64
fi

# Pacakges needed for running toxcore tests
if [ "${SUPPORT_TEST}" = "true" ]; then
    apt-get install -y \
        apt-transport-https \
        curl \
        gnupg \
        texinfo

    # Add Wine package repository to use the latest Wine
    echo "deb https://dl.winehq.org/wine-builds/debian/ stretch main" >> /etc/apt/sources.list
    curl -o Release.key https://dl.winehq.org/wine-builds/Release.key
    apt-key add Release.key

    dpkg --add-architecture i386
    apt-get update
    apt-get install -y \
        wine-devel \
        wine-devel-amd64 \
        wine-devel-dbg \
        winehq-devel
fi

# Clean up to reduce image size
apt-get clean
rm -rf \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*
