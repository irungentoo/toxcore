FROM debian:stretch-slim

# Build-time environment variables
ARG VERSION_SODIUM=1.0.18
ARG VERSION_OPUS=v1.2.1
ARG VERSION_VPX=v1.6.1

ARG SUPPORT_TEST=false
ARG SUPPORT_ARCH_i686=true
ARG SUPPORT_ARCH_x86_64=true

# Make those available when running the container
ENV SUPPORT_TEST=${SUPPORT_TEST}
ENV SUPPORT_ARCH_i686=${SUPPORT_ARCH_i686}
ENV SUPPORT_ARCH_x86_64=${SUPPORT_ARCH_x86_64}

ADD get_packages.sh .
RUN sh ./get_packages.sh

ADD build_dependencies.sh .
RUN sh ./build_dependencies.sh

ADD build_toxcore.sh .

ENV ENABLE_TEST=false
ENV ALLOW_TEST_FAILURE=false
ENV ENABLE_ARCH_i686=true
ENV ENABLE_ARCH_x86_64=true
ENV EXTRA_CMAKE_FLAGS="-DWARNINGS=OFF -DBOOTSTRAP_DAEMON=OFF -DTEST_TIMEOUT_SECONDS=300"

CMD sh ./build_toxcore.sh
