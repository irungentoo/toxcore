FROM debian:stretch-slim

# Build-time environment variables
ARG VERSION_SODIUM=1.0.18
ARG VERSION_OPUS=v1.2.1
ARG VERSION_VPX=v1.6.1

ARG SUPPORT_TEST=false
ARG SUPPORT_ARCH_i686=true
ARG SUPPORT_ARCH_x86_64=true
ARG CROSS_COMPILE=true

# Make those available when running the container
ENV SUPPORT_TEST=${SUPPORT_TEST}
ENV SUPPORT_ARCH_i686=${SUPPORT_ARCH_i686}
ENV SUPPORT_ARCH_x86_64=${SUPPORT_ARCH_x86_64}
ENV CROSS_COMPILE=${CROSS_COMPILE}

COPY get_packages.sh .
RUN sh ./get_packages.sh

COPY build_dependencies.sh .
RUN sh ./build_dependencies.sh

COPY build_toxcore.sh .

ENV ENABLE_TEST=false
ENV ALLOW_TEST_FAILURE=false
ENV ENABLE_ARCH_i686=true
ENV ENABLE_ARCH_x86_64=true
ENV EXTRA_CMAKE_FLAGS="-DTEST_TIMEOUT_SECONDS=90"

ENTRYPOINT ["sh", "./build_toxcore.sh"]
