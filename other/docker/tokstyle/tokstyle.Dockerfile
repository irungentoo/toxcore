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

COPY --from=tokstyle /bin/check-c /bin/check-cimple /bin/
RUN ["git", "clone", "--depth=1", "https://github.com/TokTok/hs-tokstyle", "/src/workspace/hs-tokstyle"]
RUN ln -s /usr/include/opus /src/workspace/hs-tokstyle/include/opus \
 && ln -s /usr/include/sodium.h /src/workspace/hs-tokstyle/include/sodium.h \
 && ln -s /usr/include/sodium /src/workspace/hs-tokstyle/include/sodium \
 && ln -s /usr/include/vpx /src/workspace/hs-tokstyle/include/vpx

COPY --from=sources /src/ /src/workspace/c-toxcore/
RUN /bin/check-cimple $(find /src/workspace/c-toxcore -name "*.[ch]" \
 -and -not -wholename "*/auto_tests/*" \
 -and -not -wholename "*/other/*" \
 -and -not -wholename "*/super_donators/*" \
 -and -not -wholename "*/testing/*" \
 -and -not -wholename "*/third_party/cmp/examples/*" \
 -and -not -wholename "*/third_party/cmp/test/*") \
 -Wno-boolean-return \
 -Wno-callback-names \
 -Wno-callgraph \
 -Wno-enum-from-int \
 -Wno-nullability \
 -Wno-ownership-decls \
 -Wno-tagged-union \
 -Wno-type-check
RUN /bin/check-c $(find /src/workspace/c-toxcore -name "*.c" \
 -and -not -wholename "*/auto_tests/*" \
 -and -not -wholename "*/other/*" \
 -and -not -wholename "*/super_donators/*" \
 -and -not -wholename "*/testing/*" \
 -and -not -wholename "*/third_party/cmp/examples/*" \
 -and -not -wholename "*/third_party/cmp/test/*") \
 -Wno-borrow-check \
 -Wno-callback-discipline \
 -Wno-strict-typedef
