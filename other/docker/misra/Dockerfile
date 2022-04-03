FROM ubuntu:20.04

RUN apt-get update && apt-get install --no-install-recommends -y \
 ca-certificates \
 cppcheck \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 make \
 wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY toxav/ /src/workspace/c-toxcore/toxav/
COPY toxcore/ /src/workspace/c-toxcore/toxcore/
COPY toxencryptsave/ /src/workspace/c-toxcore/toxencryptsave/
COPY third_party/cmp/cmp.h /src/workspace/c-toxcore/third_party/cmp/cmp.h
COPY other/docker/misra/Makefile /src/workspace/
WORKDIR /src/workspace
RUN ["make"]
