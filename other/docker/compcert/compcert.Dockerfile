FROM toxchat/c-toxcore:sources AS sources
FROM toxchat/compcert:latest

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 gdb \
 make \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY --from=sources /src/ /work/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN git clone --depth=1 https://github.com/jedisct1/libsodium /work/libsodium
COPY other/docker/compcert/Makefile /work/
RUN make "-j$(nproc)"
RUN ./send_message_test | grep 'tox clients connected'
