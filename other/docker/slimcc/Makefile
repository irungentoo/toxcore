SOURCES		:= \
		   auto_tests/scenarios/framework/framework.c \
		   auto_tests/scenarios/scenario_send_message_test.c \
		   testing/misc_tools.c \
		   $(wildcard tox*/*.c tox*/*/*.c) \
		   third_party/cmp/cmp.c
OBJECTS		:= $(SOURCES:.c=.o)

CC		:= /work/slimcc/slimcc
CFLAGS		:= $(shell pkg-config --cflags libsodium opus vpx)
LDFLAGS		:= $(shell pkg-config --libs libsodium opus vpx)

send_message_test: $(OBJECTS)
	$(CC) -o $@ $+ $(LDFLAGS)
