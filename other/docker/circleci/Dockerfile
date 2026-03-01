################################################
# cmake-asan
FROM ubuntu:24.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 clang \
 cmake \
 libclang-rt-dev \
 libconfig-dev \
 libgmock-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 ninja-build \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /
RUN ["chmod", "755", "/entrypoint.sh"]

WORKDIR /home/builder
RUN groupadd -r -g 987 builder \
 && useradd --no-log-init -r -g builder -u 987 builder \
 && chown builder:builder /home/builder
USER builder

ENV CC=clang CXX=clang++
ENTRYPOINT ["/entrypoint.sh"]
