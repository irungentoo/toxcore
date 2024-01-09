################################################
# cmake-asan
FROM ubuntu:20.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 clang \
 cmake \
 libconfig-dev \
 libgmock-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 llvm-dev \
 ninja-build \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /
RUN ["chmod", "755", "/entrypoint.sh"]

WORKDIR /home/builder
RUN groupadd -r -g 1000 builder \
 && useradd --no-log-init -r -g builder -u 1000 builder \
 && chown builder:builder /home/builder
USER builder

ENV CC=clang CXX=clang++
ENTRYPOINT ["/entrypoint.sh"]
