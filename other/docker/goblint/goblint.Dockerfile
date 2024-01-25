FROM toxchat/c-toxcore:sources AS sources
FROM ghcr.io/goblint/analyzer:latest

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 libsodium-dev \
 tcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=sources /src/ /work/

COPY other/make_single_file /work/other/

RUN other/make_single_file -core auto_tests/tox_new_test.c other/docker/goblint/sodium.c > analysis.c
# Try compiling+linking just to make sure we have all the fake functions.
RUN tcc analysis.c

COPY other/docker/goblint/analysis.json /work/other/docker/goblint/
RUN /opt/goblint/analyzer/bin/goblint --conf /work/other/docker/goblint/analysis.json analysis.c
