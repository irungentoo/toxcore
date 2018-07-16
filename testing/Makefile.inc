if BUILD_TESTS
TEST_LIB = misc_tools
endif
if BUILD_TESTING
TEST_LIB = misc_tools
endif

noinst_LTLIBRARIES += libmisc_tools.la
libmisc_tools_la_SOURCES = ../testing/misc_tools.c ../testing/misc_tools.h

if BUILD_TESTING

noinst_PROGRAMS +=      DHT_test \
                        Messenger_test

DHT_test_SOURCES =      ../testing/DHT_test.c

DHT_test_CFLAGS =       $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

DHT_test_LDADD =        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libmisc_tools.la \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)


Messenger_test_SOURCES = \
                        ../testing/Messenger_test.c

Messenger_test_CFLAGS = $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

Messenger_test_LDADD =  $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libmisc_tools.la \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)

endif
