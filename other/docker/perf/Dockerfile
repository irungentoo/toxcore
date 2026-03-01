FROM alpine:3.14.0

RUN ["apk", "add", "--no-cache", \
 "bash", \
 "gcc", \
 "libsodium-dev", \
 "libvpx-dev", \
 "linux-headers", \
 "musl-dev", \
 "opus-dev", \
 "perf"]

WORKDIR /work
COPY other/docker/perf/entrypoint.sh /
ENTRYPOINT ["/entrypoint.sh"]
