FROM debian:bookworm-slim

# When editing, make sure to update /other/windows_build_script_toxcore.sh and
# INSTALL.md to match.

# Build-time environment variables
ARG VERSION_OPUS=1.4 \
    VERSION_SODIUM=1.0.19 \
    VERSION_VPX=1.14.0 \
    ENABLE_HASH_VERIFICATION=true \
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
COPY check_sha256.sh .
COPY get_packages.sh .
RUN ./get_packages.sh

COPY build_dependencies.sh .
RUN ./build_dependencies.sh

COPY build_toxcore.sh .

ENV ENABLE_TEST=false \
    ALLOW_TEST_FAILURE=false \
    ENABLE_ARCH_i686=true \
    ENABLE_ARCH_x86_64=true \
    EXTRA_CMAKE_FLAGS="-DTEST_TIMEOUT_SECONDS=90 -DUSE_IPV6=OFF"

ENTRYPOINT ["bash", "./build_toxcore.sh"]
