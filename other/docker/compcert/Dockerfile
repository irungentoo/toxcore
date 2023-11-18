FROM toxchat/compcert:latest

WORKDIR /work
COPY auto_tests/ /work/auto_tests/
COPY testing/ /work/testing/
COPY toxav/ /work/toxav/
COPY toxcore/ /work/toxcore/
COPY toxencryptsave/ /work/toxencryptsave/
COPY third_party/ /work/third_party/

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN ccomp \
 -o send_message_test \
 -Wall -Werror \
 -Wno-c11-extensions \
 -Wno-unknown-pragmas \
 -Wno-unused-variable \
 -fstruct-passing -fno-unprototyped -g \
 auto_tests/auto_test_support.c \
 auto_tests/send_message_test.c \
 testing/misc_tools.c \
 toxav/*.c \
 toxcore/*.c \
 toxcore/*/*.c \
 toxencryptsave/*.c \
 third_party/cmp/*.c \
 -D__COMPCERT__ -DDISABLE_VLA -Dinline= \
 -lpthread $(pkg-config --cflags --libs libsodium opus vpx) \
 && ./send_message_test | grep 'tox clients connected'
