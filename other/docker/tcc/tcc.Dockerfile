FROM toxchat/c-toxcore:sources AS sources
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
COPY --from=sources /src/ /work/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN tcc \
 -Dinline=static \
 -o send_message_test \
 -Wall -Werror \
 -bench -g \
 auto_tests/scenarios/framework/framework.c \
 auto_tests/scenarios/scenario_send_message_test.c \
 testing/misc_tools.c \
 toxav/*.c \
 toxcore/*.c \
 toxcore/*/*.c \
 toxencryptsave/*.c \
 third_party/cmp/*.c \
 $(pkg-config --cflags --libs libsodium opus vpx) \
 && ./send_message_test 2>&1 | grep 'Correctly failed to send too long message'

COPY other/deploy/single-file/make_single_file /work/
RUN \
 ./make_single_file -core \
   auto_tests/scenarios/framework/framework.c \
   auto_tests/scenarios/scenario_send_message_test.c \
   testing/misc_tools.c | \
 tcc - \
   -o send_message_test \
   -Wall -Werror \
   -bench -g \
   $(pkg-config --cflags --libs libsodium) \
 && ./send_message_test 2>&1 | grep 'Correctly failed to send too long message'

RUN \
 ./make_single_file \
   auto_tests/scenarios/framework/framework.c \
   auto_tests/scenarios/scenario_toxav_basic_test.c \
   testing/misc_tools.c | \
 tcc - \
   -o toxav_basic_test \
   -Wall -Werror \
   -bench -g \
   $(pkg-config --cflags --libs libsodium opus vpx) \
 && ./toxav_basic_test 2>&1 | grep 'Cancel Flow finished'
