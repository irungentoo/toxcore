FROM toxchat/c-toxcore:sources AS src
FROM ubuntu:18.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 bison \
 ccache \
 cmake \
 flex \
 git \
 gperf \
 libncurses-dev \
 ninja-build \
 python \
 python-cryptography \
 python-future \
 python-pip \
 python-pyparsing \
 python-serial \
 python-setuptools \
 wget \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

ENV ESP32_TARBALL=xtensa-esp32-elf-linux64-1.22.0-80-g6c4433a-5.2.0 \
    IDF_PATH="/root/esp/esp-idf" \
    PATH="/root/esp/esp-idf/tools:/root/esp/xtensa-esp32-elf/bin:$PATH"
WORKDIR /root/esp
RUN wget -q https://dl.espressif.com/dl/$ESP32_TARBALL.tar.gz \
 && tar zxf $ESP32_TARBALL.tar.gz \
 && rm -f $ESP32_TARBALL.tar.gz \
 && git clone -b v3.3 --recursive --depth=1 --shallow-submodules https://github.com/espressif/esp-idf

# Build a hello world first, so the OS and libsodium etc. are compiled.
WORKDIR /root/esp/toxcore
COPY other/docker/esp32/CMakeLists.txt /root/esp/toxcore/
COPY other/docker/esp32/hello/ /root/esp/toxcore/main/
RUN idf.py build

# Then copy over the actual toxcore sources and build those.
COPY --from=src /src/third_party/cmp/ /root/esp/toxcore/main/third_party/cmp/
COPY --from=src /src/toxencryptsave/defines.h /root/esp/toxcore/main/toxencryptsave/
COPY --from=src /src/toxcore/ /root/esp/toxcore/main/toxcore/
COPY other/docker/esp32/toxcore/CMakeLists.txt /root/esp/toxcore/main/
COPY other/docker/esp32/toxcore/toxcore_main.cc /root/esp/toxcore/main/other/docker/esp32/main/
RUN idf.py build
RUN ls -lh build/toxcore.bin \
 && shasum build/toxcore.bin
