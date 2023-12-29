FROM toxchat/c-toxcore:sources AS src
FROM ubuntu:20.04 AS build

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 clang \
 cmake \
 curl \
 gcc \
 git \
 golang-1.18 \
 libconfig-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 llvm-dev \
 make \
 ninja-build \
 pkg-config \
 python3-lxml \
 python3-pip \
 python3-pygments \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir gcovr
# strip gtest so it doesn't end up in stack traces. This speeds up the
# mallocfail run below by a lot.
RUN ["strip", "-g",\
 "/usr/lib/x86_64-linux-gnu/libgtest.a",\
 "/usr/lib/x86_64-linux-gnu/libgtest_main.a"]
RUN ["curl", "-s", "https://codecov.io/bash", "-o", "/usr/local/bin/codecov"]
RUN ["chmod", "+x", "/usr/local/bin/codecov"]

ENV CC=clang \
    CXX=clang++ \
    PYTHONUNBUFFERED=1 \
    PATH=$PATH:/usr/lib/go-1.18/bin
SHELL ["/bin/bash", "-c"]

WORKDIR /work
COPY --from=src /src/ /work/
RUN source .github/scripts/flags-coverage.sh \
 && go version \
 && (cd other/proxy && go get github.com/things-go/go-socks5 && go build proxy_server.go) \
 && cmake -B_build -H. -GNinja \
 -DCMAKE_C_FLAGS="$C_FLAGS" \
 -DCMAKE_CXX_FLAGS="$CXX_FLAGS" \
 -DCMAKE_EXE_LINKER_FLAGS="$LD_FLAGS" \
 -DCMAKE_UNITY_BUILD=ON \
 -DENABLE_SHARED=OFF \
 -DMIN_LOGGER_LEVEL=TRACE \
 -DMUST_BUILD_TOXAV=ON \
 -DNON_HERMETIC_TESTS=OFF \
 -DSTRICT_ABI=ON \
 -DAUTOTEST=ON \
 -DPROXY_TEST=ON \
 -DUSE_IPV6=OFF \
 -DTEST_TIMEOUT_SECONDS=40 \
 && cmake --build _build --parallel 8 --target install

WORKDIR /work/_build
RUN /work/other/proxy/proxy_server \
 & (ctest -j50 --output-on-failure --rerun-failed --repeat until-pass:6 || \
    ctest -j50 --output-on-failure --rerun-failed --repeat until-pass:6)

WORKDIR /work/mallocfail
RUN ["git", "clone", "--depth=1", "https://github.com/ralight/mallocfail", "/work/mallocfail"]
COPY other/docker/coverage/syscall_funcs.c src/
RUN gcc -fPIC -shared -O2 -g3 -Wall -Ideps/uthash -Ideps/sha3 deps/*/*.c src/*.c -o mallocfail.so -ldl -lbacktrace \
 && install mallocfail.so /usr/local/lib/mallocfail.so

WORKDIR /work/_build
COPY other/docker/coverage/run_mallocfail /usr/local/bin/
RUN ["run_mallocfail", "--ctest=2", "--jobs=8"]
RUN ["gcovr", \
 "--sort-percentage", \
 "--gcov-executable=llvm-cov gcov", \
 "--html-details=html/", \
 "--root=..", \
 "--exclude=CMakeFiles/", \
 "--exclude=_deps/", \
 "--exclude=(.+/)?auto_tests/", \
 "--exclude=.+_test.cc?$", \
 "--exclude=(.+/)?other/", \
 "--exclude=(.+/)?testing/"]

WORKDIR /work
