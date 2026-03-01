FROM mluis/qemu-esp32:latest
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV IDF_TARGET=esp32

WORKDIR /root/toxcore

# Build an initial bootstrap hello world just to compile libsodium and other
# system level dependencies.
COPY other/docker/esp32/sdkconfig \
     other/docker/esp32/CMakeLists.txt \
     /root/toxcore/
COPY other/docker/esp32/bootstrap/ \
     /root/toxcore/main/
RUN . /root/esp/esp-idf/export.sh && idf.py build

# Copy over toxcore sources and build those.
COPY third_party/cmp/ /root/toxcore/main/third_party/cmp/
COPY toxencryptsave/defines.h /root/toxcore/main/toxencryptsave/
COPY toxcore/ /root/toxcore/main/toxcore/
COPY other/docker/esp32/main/CMakeLists.txt \
     /root/toxcore/main/
COPY other/docker/esp32/main/*.cc \
     other/docker/esp32/main/*.h \
     /root/toxcore/main/other/docker/esp32/main/
RUN touch /root/toxcore/main/CMakeLists.txt \
 && . /root/esp/esp-idf/export.sh && idf.py build
RUN ls -lh build/toxcore.bin \
 && sha512sum build/toxcore.bin
RUN /root/flash.sh build/toxcore.bin

COPY other/docker/esp32/qemu-test /root/toxcore/
RUN ["/root/toxcore/qemu-test"]
