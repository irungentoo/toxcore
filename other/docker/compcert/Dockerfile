FROM toxchat/compcert:latest

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 gdb \
 make \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY auto_tests/ /work/auto_tests/
COPY testing/ /work/testing/
COPY toxav/ /work/toxav/
COPY toxcore/ /work/toxcore/
COPY toxencryptsave/ /work/toxencryptsave/
COPY third_party/ /work/third_party/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

COPY other/docker/compcert/Makefile /work/
RUN make "-j$(nproc)"
RUN ./send_message_test #| grep 'tox clients connected'
