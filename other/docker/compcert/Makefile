CC := ccomp
CFLAGS := -Wall \
	  -Wno-c11-extensions \
	  -Wno-unknown-pragmas \
	  -Wno-unused-variable \
	  -fstruct-passing -fno-unprototyped -g \
	  -Ilibsodium/src/libsodium/include \
	  $(shell pkg-config --cflags opus vpx)
LDFLAGS := -lpthread $(shell pkg-config --libs opus vpx)

libsodium_SOURCES := $(shell find libsodium/src/libsodium -name "*.c")
libsodium_OBJECTS := $(libsodium_SOURCES:.c=.o)

$(libsodium_OBJECTS): CFLAGS += \
	-DDEV_MODE \
	-DCONFIGURED \
	-D_DEFAULT_SOURCE \
	-Ilibsodium/builds/msvc \
	-Ilibsodium/src/libsodium/include/sodium

toxcore_SOURCES := $(wildcard \
	   auto_tests/auto_test_support.c \
	   auto_tests/send_message_test.c \
	   testing/misc_tools.c \
	   toxav/*.c \
	   toxcore/*.c \
	   toxcore/*/*.c \
	   toxencryptsave/*.c \
	   third_party/cmp/*.c)
toxcore_OBJECTS := $(toxcore_SOURCES:.c=.o)
$(toxcore_OBJECTS): CFLAGS += \
	-Werror \
	-D__COMPCERT__ \
	-DDISABLE_VLA \
	-DMIN_LOGGER_LEVEL=LOGGER_LEVEL_TRACE \
	-Dinline= \

send_message_test: $(libsodium_OBJECTS) $(toxcore_OBJECTS)
	$(CC) -o $@ $+ $(LDFLAGS)
