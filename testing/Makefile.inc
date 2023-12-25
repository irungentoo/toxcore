if BUILD_TESTS
TEST_LIB = misc_tools
endif
if BUILD_TESTING
TEST_LIB = misc_tools
endif

noinst_LTLIBRARIES += libmisc_tools.la
libmisc_tools_la_SOURCES = ../testing/misc_tools.c ../testing/misc_tools.h

libmisc_tools_la_CFLAGS =  $(LIBSODIUM_CFLAGS)

libmisc_tools_la_LIBADD =  $(LIBSODIUM_LDFLAGS)

if BUILD_TESTING

noinst_PROGRAMS +=      Messenger_test

Messenger_test_SOURCES = \
                        ../testing/Messenger_test.c

Messenger_test_CFLAGS = $(LIBSODIUM_CFLAGS)

Messenger_test_LDADD =  $(LIBSODIUM_LDFLAGS) \
                        libmisc_tools.la \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)

endif
