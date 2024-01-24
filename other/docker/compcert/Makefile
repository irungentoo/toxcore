SOURCES := $(wildcard auto_tests/auto_test_support.c \
		   auto_tests/send_message_test.c \
		   testing/misc_tools.c \
		   toxav/*.c \
		   toxcore/*.c \
		   toxcore/*/*.c \
		   toxencryptsave/*.c \
		   third_party/cmp/*.c)

OBJECTS := $(SOURCES:.c=.o)

CC := ccomp
CFLAGS := -Wall -Werror \
		  -Wno-c11-extensions \
		  -Wno-unknown-pragmas \
		  -Wno-unused-variable \
		  -fstruct-passing -fno-unprototyped -g \
		  -D__COMPCERT__ \
		  -DDISABLE_VLA \
		  -DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE \
		  -Dinline= \
		  $(shell pkg-config --cflags libsodium opus vpx)
LDFLAGS := -lpthread $(shell pkg-config --libs libsodium opus vpx)

send_message_test: $(OBJECTS)
	$(CC) -o $@ $+ $(LDFLAGS)
