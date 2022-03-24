FROM ubuntu:20.04

ENV DEBIAN_FRONTEND="noninteractive"

# Install dependencies.
RUN apt-get update && apt-get install --no-install-recommends -y \
 autoconf \
 automake \
 ca-certificates \
 cmake \
 curl \
 git \
 libtool \
 make \
 ninja-build \
 pkg-config \
 python3 \
 unzip \
 wget \
 xz-utils \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work/emsdk
RUN git clone --depth=1 https://github.com/emscripten-core/emsdk /work/emsdk \
 && ./emsdk install 3.1.3 \
 && ./emsdk activate 3.1.3

# Build libsodium.
RUN . "/work/emsdk/emsdk_env.sh" \
 && git clone --depth=1 --branch=1.0.18 https://github.com/jedisct1/libsodium /work/libsodium \
 && cd /work/libsodium \
 && autoreconf -fi \
 && emconfigure ./configure --disable-shared \
  --without-pthreads \
  --disable-ssp --disable-asm --disable-pie \
 && emmake make install -j8

# Build an unused libsodium binding first so emcc caches all the system
# libraries. This makes rebuilds of toxcore below much faster.
RUN . "/work/emsdk/emsdk_env.sh" \
 && mkdir -p /work/wasm \
 && emcc -O3 -flto \
 --closure=1 \
 -s ALLOW_UNIMPLEMENTED_SYSCALLS=1 \
 -s EXPORT_NAME=libtoxcore \
 -s IGNORE_MISSING_MAIN=1 \
 -s MAIN_MODULE=1 \
 -s MALLOC=emmalloc \
 -s MODULARIZE=1 \
 -s STRICT=1 \
 -s WEBSOCKET_URL=wss:// \
 /usr/local/lib/libsodium.a \
 -o /work/wasm/libsodium.js

# Build c-toxcore.
COPY . /work/c-toxcore
RUN . "/work/emsdk/emsdk_env.sh" \
 && cd /work/c-toxcore \
 && emcmake cmake -B_build -H. -GNinja \
 -DCMAKE_INSTALL_PREFIX:PATH="/usr/local" \
 -DCMAKE_C_FLAGS="-O3 -flto -fPIC" \
 -DBUILD_TOXAV=OFF \
 -DENABLE_SHARED=OFF \
 -DBOOTSTRAP_DAEMON=OFF \
 -DMIN_LOGGER_LEVEL=DEBUG \
 && emmake cmake --build _build --parallel 8 --target install

# Build wasm bindings.
RUN . "/work/emsdk/emsdk_env.sh" \
 && mkdir -p /work/wasm \
 && emcc -O3 -flto \
 --closure=1 \
 -s ALLOW_UNIMPLEMENTED_SYSCALLS=1 \
 -s EXPORT_NAME=libtoxcore \
 -s IGNORE_MISSING_MAIN=1 \
 -s MAIN_MODULE=1 \
 -s MALLOC=emmalloc \
 -s MODULARIZE=1 \
 -s STRICT=1 \
 -s WEBSOCKET_URL=wss:// \
 /usr/local/lib/libsodium.a \
 /usr/local/lib/libtoxcore.a \
 -o /work/wasm/libtoxcore.js
