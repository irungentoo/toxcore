FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 gcc \
 git \
 libc-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 make \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work/slimcc
RUN ["git", "clone", "--depth=1", "https://github.com/fuhsnn/slimcc", "/work/slimcc"]
RUN ["make", "CFLAGS=-O3"]

WORKDIR /work/c-toxcore
COPY --from=sources /src/ /work/c-toxcore
COPY other/docker/slimcc/Makefile /work/c-toxcore/
RUN ["make"]

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN ./send_message_test | grep "tox clients connected"
