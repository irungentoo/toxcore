# c-toxcore Clusterfuzzlite build environment

# We want to use the latest tools always
FROM gcr.io/oss-fuzz-base/base-builder:latest

RUN apt-get update && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    cmake libtool autoconf automake pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


RUN git clone --depth 1 --branch 1.0.18 https://github.com/jedisct1/libsodium libsodium
WORKDIR $SRC/libsodium
RUN ./autogen.sh && ./configure --enable-shared=no && make install

# Copy your project's source code.
COPY . $SRC/c-toxcore
# Working directory for build.sh.
WORKDIR $SRC/c-toxcore
# Copy build.sh into $SRC dir.
COPY ./.clusterfuzzlite/build.sh $SRC/
