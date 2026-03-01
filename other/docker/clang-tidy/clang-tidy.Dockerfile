FROM toxchat/c-toxcore:sources AS sources
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

COPY --from=sources /src/ /c-toxcore/
COPY other/analysis/run-clang-tidy other/analysis/variants.sh /c-toxcore/other/analysis/
COPY .clang-tidy /c-toxcore/
WORKDIR /c-toxcore
RUN other/analysis/run-clang-tidy
