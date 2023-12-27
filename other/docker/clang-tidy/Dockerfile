FROM alpine:3.19.0

RUN ["apk", "add", "--no-cache", \
 "bash", \
 "clang", \
 "clang-extra-tools", \
 "cmake", \
 "colordiff", \
 "libconfig-dev", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "opus-dev", \
 "pkgconfig", \
 "samurai"]

ENV CC=clang CXX=clang++

COPY . /c-toxcore/
WORKDIR /c-toxcore
RUN other/analysis/run-clang-tidy
