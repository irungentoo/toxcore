FROM ubuntu:22.04

RUN apt-get update && \
 DEBIAN_FRONTEND="noninteractive" apt-get install -y --no-install-recommends \
 libc-dev \
 libopus-dev \
 libsodium-dev \
 libvpx-dev \
 pkg-config \
 tcc \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
COPY auto_tests/ /work/auto_tests/
COPY testing/ /work/testing/
COPY toxav/ /work/toxav/
COPY toxcore/ /work/toxcore/
COPY toxencryptsave/ /work/toxencryptsave/
COPY third_party/ /work/third_party/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN tcc \
 -Dinline=static \
 -o send_message_test \
 -Wall -Werror \
 -bench -g \
 auto_tests/auto_test_support.c \
 auto_tests/send_message_test.c \
 testing/misc_tools.c \
 toxav/*.c \
 toxcore/*.c \
 toxcore/*/*.c \
 toxencryptsave/*.c \
 third_party/cmp/*.c \
 $(pkg-config --cflags --libs libsodium opus vpx) \
 && ./send_message_test | grep 'tox clients connected'

COPY other/make_single_file /work/other/
RUN \
 other/make_single_file -core \
   auto_tests/auto_test_support.c \
   auto_tests/send_message_test.c \
   testing/misc_tools.c | \
 tcc - \
   -o send_message_test \
   -Wall -Werror \
   -bench -g \
   $(pkg-config --cflags --libs libsodium) \
 && ./send_message_test | grep 'tox clients connected'

RUN \
 other/make_single_file \
   auto_tests/auto_test_support.c \
   auto_tests/toxav_basic_test.c \
   testing/misc_tools.c | \
 tcc - \
   -o toxav_basic_test \
   -Wall -Werror \
   -bench -g \
   $(pkg-config --cflags --libs libsodium opus vpx) \
 && ./toxav_basic_test | grep 'Test successful'
