FROM alpine:3.19.0

RUN ["apk", "add", "--no-cache", \
 "bash", \
 "cppcheck", \
 "findutils", \
 "libconfig-dev", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "make", \
 "opus-dev"]

COPY other/bootstrap_daemon/ /src/workspace/c-toxcore/other/bootstrap_daemon/
COPY other/bootstrap_node_packets.* /src/workspace/c-toxcore/other/
COPY other/fun/ /src/workspace/c-toxcore/other/fun/
COPY auto_tests/check_compat.h /src/workspace/c-toxcore/auto_tests/
COPY testing/ /src/workspace/c-toxcore/testing/
COPY toxav/ /src/workspace/c-toxcore/toxav/
COPY toxcore/ /src/workspace/c-toxcore/toxcore/
COPY toxencryptsave/ /src/workspace/c-toxcore/toxencryptsave/
COPY third_party/cmp/cmp.h /src/workspace/c-toxcore/third_party/cmp/
COPY other/analysis/run-cppcheck \
     other/analysis/gen-file.sh \
     other/analysis/variants.sh \
     /src/workspace/c-toxcore/other/analysis/
COPY other/docker/cppcheck/toxcore.cfg \
     /src/workspace/c-toxcore/other/docker/cppcheck/
WORKDIR /src/workspace/c-toxcore
RUN ["other/analysis/run-cppcheck"]
