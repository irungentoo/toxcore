FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 creduce \
 g++ \
 gcc \
 git \
 libc-dev \
 libopus-dev \
 libsodium-dev \
 libsqlite3-dev \
 libssl-dev \
 libvpx-dev \
 llvm-dev \
 make \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work/smatch
RUN git clone --depth=1 https://repo.or.cz/smatch.git /work/smatch
COPY other/docker/sparse/local.mk /work/smatch/local.mk
RUN make install -j4 PREFIX=/usr/local

WORKDIR /work/c-toxcore
COPY --from=sources /src/ /work/c-toxcore
#COPY other/make_single_file /work/c-toxcore/other/
#RUN other/make_single_file auto_tests/tox_new_test.c > crash.c
#RUN sparsec $(pkg-config --cflags --libs libsodium opus vpx) crash.c

COPY other/docker/sparse/Makefile /work/c-toxcore/
RUN make -j4
