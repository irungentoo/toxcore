FROM ghcr.io/goblint/analyzer:latest

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 libsodium-dev \
 tcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY auto_tests/ /work/auto_tests/
COPY testing/ /work/testing/
COPY toxav/ /work/toxav/
COPY toxcore/ /work/toxcore/
COPY toxencryptsave/ /work/toxencryptsave/
COPY third_party/ /work/third_party/

COPY other/make_single_file /work/other/
COPY other/docker/goblint/sodium.c /work/other/docker/goblint/

RUN other/make_single_file -core auto_tests/tox_new_test.c other/docker/goblint/sodium.c > analysis.c
# Try compiling+linking just to make sure we have all the fake functions.
RUN tcc analysis.c

COPY other/docker/goblint/analysis.json /work/other/docker/goblint/
RUN /opt/goblint/analyzer/bin/goblint --conf /work/other/docker/goblint/analysis.json analysis.c
