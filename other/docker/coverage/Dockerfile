FROM toxchat/c-toxcore:sources AS src
FROM ubuntu:22.04 AS build

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 clang \
 cmake \
 gcc \
 git \
 golang \
 libconfig-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 llvm-dev \
 make \
 ninja-build \
 pkg-config \
 python3-pip \
 python3-pygments \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir gcovr

ENV CC=clang \
    CXX=clang++ \
    PYTHONUNBUFFERED=1
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
 -DNON_HERMETIC_TESTS=ON \
 -DSTRICT_ABI=ON \
 -DAUTOTEST=ON \
 -DPROXY_TEST=ON \
 -DUSE_IPV6=OFF \
 -DTEST_TIMEOUT_SECONDS=30 \
 && cmake --build _build --parallel 8 --target install

WORKDIR /work/_build
RUN /work/proxy_server \
 & ctest -j50 --output-on-failure --rerun-failed --repeat until-pass:6

WORKDIR /work/mallocfail
RUN ["git", "clone", "--depth=1", "https://github.com/ralight/mallocfail", "/work/mallocfail"]
COPY run_mallocfail /usr/local/bin/
COPY syscall_funcs.c src/
RUN gcc -fPIC -shared -O2 -g3 -Wall -Ideps/uthash -Ideps/sha3 deps/*/*.c src/*.c -o mallocfail.so -ldl -lbacktrace \
 && install mallocfail.so /usr/local/lib/mallocfail.so

WORKDIR /work/_build
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

FROM nginx:alpine
COPY --from=build /work/_build/html/coverage_details.html /usr/share/nginx/html/index.html
COPY --from=build /work/_build/html/ /usr/share/nginx/html/
