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

# Uncomment this to find bugs in slimcc using creduce.
#RUN apt-get update && \
# DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
# creduce \
# && apt-get clean \
# && rm -rf /var/lib/apt/lists/*

WORKDIR /work/slimcc
RUN ["git", "clone", "https://github.com/fuhsnn/slimcc", "/work/slimcc"]
# Comment this to checkout master (e.g. to find bugs using creduce).
RUN ["git", "checkout", "ac9ddf4d39642e6b4880b1a73e19c6f2769d857e"]
RUN ["make", "CFLAGS=-O3", "-j4"]

WORKDIR /work/c-toxcore
COPY --from=sources /src/ /work/c-toxcore

# Uncomment this to find bugs in slimcc using creduce.
#COPY other/docker/slimcc/creduce.sh /work/c-toxcore/other/docker/slimcc/
#RUN cp toxcore/ccompat.h crash.c \
# && other/docker/slimcc/creduce.sh \
# && creduce other/docker/slimcc/creduce.sh crash.c

COPY other/docker/slimcc/Makefile /work/c-toxcore/
RUN ["make"]

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN ./send_message_test | grep "tox clients connected"
