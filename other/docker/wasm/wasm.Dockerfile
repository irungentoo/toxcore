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
 && ./emsdk install 4.0.3 \
 && ./emsdk activate 4.0.3

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
WORKDIR /work

# Build libsodium.
RUN . "/work/emsdk/emsdk_env.sh" \
 && tar zxf <(curl -L https://github.com/jedisct1/libsodium/releases/download/1.0.20-RELEASE/libsodium-1.0.20.tar.gz) \
 && cd /work/libsodium-* \
 && emconfigure ./configure \
 --prefix=/wasm \
 --enable-static \
 --disable-shared \
 --without-pthreads \
 --disable-ssp \
 --disable-asm \
 --disable-pie \
 && emmake make -j"$(nproc)" \
 && emmake make install \
 && rm -rf /work/libsodium-*

# Build libvpx.
RUN . "/work/emsdk/emsdk_env.sh" \
 && tar zxf <(curl -L https://github.com/webmproject/libvpx/archive/v1.15.0.tar.gz) \
 && cd /work/libvpx-* \
 && emconfigure ./configure \
 --prefix=/wasm \
 --enable-static \
 --disable-shared \
 --target=generic-gnu \
 --disable-examples \
 --disable-tools \
 --disable-docs \
 --disable-unit-tests \
 --enable-pic \
 && emmake make -j"$(nproc)" \
 && emmake make install \
 && rm -rf /work/libvpx-*

# Build opus.
RUN . "/work/emsdk/emsdk_env.sh" \
 && tar zxf <(curl -L https://github.com/xiph/opus/releases/download/v1.5.2/opus-1.5.2.tar.gz) \
 && cd /work/opus-* \
 && emconfigure ./configure \
 --prefix=/wasm \
 --enable-static \
 --disable-shared \
 --host wasm32-unknown-emscripten \
 --disable-extra-programs \
 --disable-doc \
 CFLAGS="-O3 -flto -fPIC" \
 && emmake make -j"$(nproc)" \
 && emmake make install \
 && rm -rf /work/opus-*

# Build an unused binding without toxcore first so emcc caches all the system
# libraries. This makes rebuilds of toxcore below much faster.
RUN . "/work/emsdk/emsdk_env.sh" \
 && mkdir -p /wasm/bin \
 && emcc -O3 -flto \
 -s EXPORT_NAME=libtoxcore \
 -s MAIN_MODULE=1 \
 -s MALLOC=emmalloc \
 -s MODULARIZE=1 \
 -s STRICT=1 \
 -s WEBSOCKET_URL=ws:// \
 --no-entry \
 /wasm/lib/libopus.a \
 /wasm/lib/libsodium.a \
 /wasm/lib/libvpx.a \
 -o /wasm/bin/libtoxcore.js

ENV PKG_CONFIG_PATH="/wasm/lib/pkgconfig"

# Build c-toxcore.
COPY . /work/c-toxcore
RUN . "/work/emsdk/emsdk_env.sh" \
 && cd /work/c-toxcore \
 && emcmake cmake \
 -B_build \
 -GNinja \
 -DCMAKE_INSTALL_PREFIX="/wasm" \
 -DCMAKE_C_FLAGS="-O3 -flto -fPIC" \
 -DCMAKE_UNITY_BUILD=ON \
 -DMUST_BUILD_TOXAV=ON \
 -DENABLE_SHARED=OFF \
 -DBOOTSTRAP_DAEMON=OFF \
 -DMIN_LOGGER_LEVEL=TRACE \
 . \
 && emmake cmake --build _build \
 && emmake cmake --install _build

# Link together all the libraries.
RUN . "/work/emsdk/emsdk_env.sh" \
 && mkdir -p /wasm/bin \
 && emcc -O3 -flto \
 -s EXPORT_NAME=libtoxcore \
 -s EXPORTED_RUNTIME_METHODS='["HEAPU8", "wasmExports"]' \
 -s MAIN_MODULE=1 \
 -s MALLOC=emmalloc \
 -s MODULARIZE=1 \
 -s STRICT=1 \
 -s WEBSOCKET_URL=ws:// \
 --no-entry \
 /wasm/lib/libopus.a \
 /wasm/lib/libsodium.a \
 /wasm/lib/libvpx.a \
 /wasm/lib/libtoxcore.a \
 -o /wasm/bin/libtoxcore.js
RUN ls -lh /wasm/bin/libtoxcore.js /wasm/bin/libtoxcore.wasm
