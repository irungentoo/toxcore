################################################
# autotools-linux
FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 autoconf \
 automake \
 ca-certificates \
 curl \
 libconfig-dev \
 libopus-dev \
 libsodium-dev \
 libtool \
 libvpx-dev \
 make \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 builder \
 && useradd -m --no-log-init -r -g builder -u 1000 builder
USER builder

WORKDIR /home/builder

# Copy the sources and run the build.
COPY --chown=builder:builder . /home/builder/c-toxcore/
WORKDIR /home/builder/c-toxcore
RUN CC=gcc .github/scripts/autotools-linux
