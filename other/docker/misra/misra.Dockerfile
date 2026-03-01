FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:20.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 cppcheck \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 make \
 wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY --from=sources /src/ /src/workspace/c-toxcore/
COPY other/docker/misra/Makefile /src/workspace/
WORKDIR /src/workspace
RUN ["make"]
