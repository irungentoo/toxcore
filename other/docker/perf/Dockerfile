FROM alpine:3.14.0

RUN ["apk", "add", "--no-cache", \
 "bash", \
 "gcc", \
 "linux-headers", \
 "musl-dev", \
 "libsodium-dev", \
 "libvpx-dev", \
 "opus-dev", \
 "perf"]

WORKDIR /work
COPY other/docker/perf/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
