FROM toxchat/haskell:hs-tokstyle AS tokstyle
FROM ubuntu:20.04

RUN apt-get update && apt-get install --no-install-recommends -y \
 ca-certificates \
 gcc \
 git \
 libmsgpack-dev \
 libsodium-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tokstyle /bin/check-c /bin/
RUN ["git", "clone", "--depth=1", "https://github.com/TokTok/hs-tokstyle", "/src/workspace/hs-tokstyle"]

COPY toxcore/ /src/workspace/c-toxcore/toxcore/
COPY toxencryptsave/ /src/workspace/c-toxcore/toxencryptsave/
RUN /bin/check-c /src/workspace/c-toxcore/toxcore/*.c
