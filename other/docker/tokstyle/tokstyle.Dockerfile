FROM toxchat/c-toxcore:sources AS sources
FROM toxchat/haskell:hs-tokstyle AS tokstyle
FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 clang \
 git \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tokstyle /bin/check-c /bin/
RUN ["git", "clone", "--depth=1", "https://github.com/TokTok/hs-tokstyle", "/src/workspace/hs-tokstyle"]

COPY --from=sources /src/ /src/workspace/c-toxcore/
RUN /bin/check-c $(find /src/workspace/c-toxcore -name "*.c" \
 -and -not -wholename "*/auto_tests/*" \
 -and -not -wholename "*/other/*" \
 -and -not -wholename "*/super_donators/*" \
 -and -not -wholename "*/testing/*" \
 -and -not -wholename "*/third_party/cmp/examples/*" \
 -and -not -wholename "*/third_party/cmp/test/*")
