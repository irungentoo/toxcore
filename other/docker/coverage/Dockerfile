FROM toxchat/c-toxcore:sources AS src
FROM ubuntu:20.04 AS build

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 build-essential \
 cmake \
 git \
 libconfig-dev \
 libgtest-dev \
 libmsgpack-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 llvm-dev \
 ninja-build \
 pkg-config \
 python3-pip \
 python3-pygments \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir gcovr

WORKDIR /work/mallocfail
RUN ["git", "clone", "--depth=1", "https://github.com/ralight/mallocfail", "/work/mallocfail"]
RUN ["make", "install"]

WORKDIR /work
COPY --from=src /src/ /work/
RUN ["cmake", "-B_build", "-H.", "-GNinja", \
 "-DCMAKE_C_FLAGS=-fsanitize=undefined -fno-sanitize-recover=all -fprofile-arcs -ftest-coverage -O2 -fno-omit-frame-pointer -fno-inline -g", \
 "-DENABLE_SHARED=OFF", \
 "-DMIN_LOGGER_LEVEL=TRACE", \
 "-DMUST_BUILD_TOXAV=ON", \
 "-DNON_HERMETIC_TESTS=ON", \
 "-DSTRICT_ABI=ON", \
 "-DAUTOTEST=ON"]
RUN ["cmake", "--build", "_build", "--parallel", "8", "--target", "install"]

WORKDIR /work/_build
RUN ["ctest", "-j50", "--output-on-failure", "--rerun-failed", "--repeat", "until-pass:6"]
COPY run_mallocfail /usr/local/bin/
ENV PYTHONUNBUFFERED=1 \
    UBSAN_OPTIONS=color=always,print_stacktrace=1
RUN run_mallocfail ./unit_*_test
RUN run_mallocfail ./auto_send_message_test
RUN ["gcovr", \
 "--sort-percentage", \
 "--gcov-executable=gcov", \
 "--html-details=html/", \
 "--html-self-contained", \
 "--root=..", \
 "--exclude=CMakeFiles/", \
 "--exclude=_deps/", \
 "--exclude=(.+/)?auto_tests/", \
 "--exclude=(.+/)?other/", \
 "--exclude=(.+/)?testing/"]

FROM nginx:alpine
COPY --from=build /work/_build/html/coverage_details.html /usr/share/nginx/html/index.html
COPY --from=build /work/_build/html/ /usr/share/nginx/html/
