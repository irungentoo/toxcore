FROM toxchat/haskell:hs-tokstyle AS tokstyle
FROM ubuntu:20.04

RUN apt-get update && apt-get install --no-install-recommends -y \
 ca-certificates \
 gcc \
 git \
 libmsgpack-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tokstyle /bin/check-c /bin/
RUN ["git", "clone", "--depth=1", "https://github.com/TokTok/hs-tokstyle", "/src/workspace/hs-tokstyle"]

COPY toxav/ /src/workspace/c-toxcore/toxav/
COPY toxcore/ /src/workspace/c-toxcore/toxcore/
COPY toxencryptsave/ /src/workspace/c-toxcore/toxencryptsave/
RUN /bin/check-c $(find /src/workspace/c-toxcore -name "*.c")
