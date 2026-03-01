FROM toxchat/c-toxcore:sources AS sources
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

COPY --from=sources /src/ /src/workspace/c-toxcore/
COPY other/analysis/run-cppcheck \
     other/analysis/gen-file.sh \
     other/analysis/variants.sh \
     /src/workspace/c-toxcore/other/analysis/
COPY other/docker/cppcheck/toxcore.cfg \
     /src/workspace/c-toxcore/other/docker/cppcheck/
WORKDIR /src/workspace/c-toxcore
RUN ["other/analysis/run-cppcheck"]
