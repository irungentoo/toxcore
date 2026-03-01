# c-toxcore Clusterfuzzlite build environment

# We want to use the latest tools always
FROM gcr.io/oss-fuzz-base/base-builder:latest

RUN apt-get update \
 && apt-get -y install --no-install-suggests --no-install-recommends \
 cmake \
 ninja-build \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# Static builds of dependencies

# libsodium
RUN tar zxf <(curl -L https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz) \
 && cd libsodium-* \
 && ./configure --enable-shared=no \
 && make install \
 && cd ..

# Copy your project's source code.
COPY . $SRC/c-toxcore
# Working directory for build.sh.
WORKDIR $SRC/c-toxcore
RUN git submodule update --init --recursive
# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
