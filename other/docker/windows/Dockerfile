FROM debian:bullseye-slim

# Build-time environment variables
ARG VERSION_MSGPACK=4.0.0 \
    VERSION_SODIUM=1.0.19 \
    VERSION_OPUS=1.3.1 \
    VERSION_VPX=1.11.0 \
 \
    SUPPORT_TEST=false \
    SUPPORT_ARCH_i686=true \
    SUPPORT_ARCH_x86_64=true \
    CROSS_COMPILE=true

# Make those available when running the container
ENV SUPPORT_TEST=${SUPPORT_TEST} \
    SUPPORT_ARCH_i686=${SUPPORT_ARCH_i686} \
    SUPPORT_ARCH_x86_64=${SUPPORT_ARCH_x86_64} \
    CROSS_COMPILE=${CROSS_COMPILE}

WORKDIR /work
COPY get_packages.sh .
RUN ./get_packages.sh

COPY build_dependencies.sh .
RUN ./build_dependencies.sh

COPY build_toxcore.sh .

ENV ENABLE_TEST=false \
    ALLOW_TEST_FAILURE=false \
    ENABLE_ARCH_i686=true \
    ENABLE_ARCH_x86_64=true \
    EXTRA_CMAKE_FLAGS="-DTEST_TIMEOUT_SECONDS=90"

ENTRYPOINT ["bash", "./build_toxcore.sh"]
