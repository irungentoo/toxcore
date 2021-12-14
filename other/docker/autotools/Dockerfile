################################################
# autotools-linux
FROM ubuntu:20.04

RUN apt-get update && apt-get install --no-install-recommends -y \
 autoconf \
 automake \
 ca-certificates \
 curl \
 libconfig-dev \
 libopus-dev \
 libtool \
 libvpx-dev \
 make \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd -r -g 1000 builder \
 && useradd -m --no-log-init -r -g builder -u 1000 builder
USER builder

# Copy minimal files to run "autotools-linux install", so we can avoid
# rebuilding nacl and other things when only source files change.
RUN mkdir -p /home/builder/build/c-toxcore /home/builder/cache
WORKDIR /home/builder/build/c-toxcore
COPY --chown=builder:builder .travis/ /home/builder/build/c-toxcore/.travis/
RUN .travis/autotools-linux install

# Now copy the rest of the sources and run the build.
COPY --chown=builder:builder . /home/builder/build/c-toxcore/
RUN CC=gcc .travis/autotools-linux script
