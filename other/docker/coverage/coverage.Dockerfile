FROM toxchat/c-toxcore:sources AS sources
FROM ubuntu:20.04 AS build

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 ca-certificates \
 curl \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

RUN echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-17 main" >> /etc/apt/sources.list \
 && curl -L https://apt.llvm.org/llvm-snapshot.gpg.key | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc \
 && apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 clang-17 \
 cmake \
 git \
 golang-1.18 \
 libclang-rt-17-dev \
 libconfig-dev \
 libgmock-dev \
 libgtest-dev \
 libopus-dev \
 libsodium-dev \
 libunwind-17-dev \
 libvpx-dev \
 lld-17 \
 llvm-17-dev \
 make \
 ninja-build \
 pkg-config \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
RUN ["curl", "-s", "https://codecov.io/bash", "-o", "/usr/local/bin/codecov"]
RUN ["chmod", "+x", "/usr/local/bin/codecov"]

ENV CC=clang-17 \
    CXX=clang++-17 \
    PYTHONUNBUFFERED=1 \
    PATH=$PATH:/usr/lib/go-1.18/bin

COPY --from=sources /src/ /work/

WORKDIR /work
RUN git clone --depth=1 https://github.com/TokTok/toktok-fuzzer /work/testing/fuzzing/toktok-fuzzer
RUN source .github/scripts/flags-coverage.sh \
 && go version \
 && (cd other/proxy && go get github.com/things-go/go-socks5 && go build proxy_server.go) \
 && cmake -B_build -H. -GNinja \
 -DCMAKE_C_FLAGS="$C_FLAGS" \
 -DCMAKE_CXX_FLAGS="$CXX_FLAGS" \
 -DCMAKE_EXE_LINKER_FLAGS="$LD_FLAGS -fuse-ld=lld" \
 -DCMAKE_UNITY_BUILD=ON \
 -DENABLE_SHARED=OFF \
 -DMIN_LOGGER_LEVEL=TRACE \
 -DMUST_BUILD_TOXAV=ON \
 -DNON_HERMETIC_TESTS=OFF \
 -DSTRICT_ABI=ON \
 -DAUTOTEST=ON \
 -DPROXY_TEST=ON \
 -DBUILD_FUZZ_TESTS=ON \
 -DUSE_IPV6=OFF \
 -DTEST_TIMEOUT_SECONDS=40 \
 && cmake --build _build --parallel 8 --target install

WORKDIR /work/_build
RUN /work/other/proxy/proxy_server \
 & (ctest -j50 --output-on-failure --rerun-failed --repeat until-pass:6 || \
    ctest -j50 --output-on-failure --rerun-failed --repeat until-pass:6)

WORKDIR /work/mallocfail
RUN ["git", "clone", "--depth=1", "https://github.com/TokTok/mallocfail", "/work/mallocfail"]
RUN clang-17 -fuse-ld=lld -fPIC -shared -O2 -g3 -Wall -I/usr/lib/llvm-17/include -L/usr/lib/llvm-17/lib -Ideps/uthash -Ideps/sha3 deps/*/*.c src/*.c -o mallocfail.so -ldl -lunwind \
 && install mallocfail.so /usr/local/lib/mallocfail.so

WORKDIR /work/_build
COPY other/docker/coverage/run_mallocfail /usr/local/bin/
RUN ["run_mallocfail", "--ctest=1", "--jobs=8"]
RUN llvm-profdata-17 merge -sparse $(find . -name "*.profraw") -o toxcore.profdata
RUN llvm-cov-17 show -format=text -instr-profile=toxcore.profdata -sources $(cmake --build . --target help | grep -o '[^:]*_test:' | grep -o '[^:]*' | xargs -n1 find . -type f -name | awk '{print "-object "$1}') > coverage.txt
RUN llvm-cov-17 show -format=html -instr-profile=toxcore.profdata -sources $(cmake --build . --target help | grep -o '[^:]*_test:' | grep -o '[^:]*' | xargs -n1 find . -type f -name | awk '{print "-object "$1}') -output-dir=html

WORKDIR /work
