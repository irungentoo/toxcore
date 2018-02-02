if BUILD_TESTING

noinst_PROGRAMS +=      DHT_test \
                        Messenger_test

DHT_test_SOURCES =      ../testing/DHT_test.c

DHT_test_CFLAGS =       $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

DHT_test_LDADD =        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
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
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)


EXTRA_DIST += 			$(top_srcdir)/testing/misc_tools.c

endif
