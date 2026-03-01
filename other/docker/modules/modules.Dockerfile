FROM alpine:3.23.0

RUN ["apk", "add", "--no-cache", \
 "bash", \
 "benchmark-dev", \
 "clang", \
 "gmock", \
 "gtest-dev", \
 "libc++-dev", \
 "libc++-static", \
 "libconfig-dev", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "opus-dev", \
 "pkgconfig", \
 "python3"]

WORKDIR /work
COPY . /work/

COPY toxcore/BUILD.bazel /work/toxcore/
COPY other/docker/modules/check /work/other/docker/modules/
RUN ["other/docker/modules/check"]
