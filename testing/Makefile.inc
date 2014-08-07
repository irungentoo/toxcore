if BUILD_NTOX

bin_PROGRAMS += nTox

nTox_SOURCES =          ../testing/nTox.h \
                        ../testing/nTox.c

nTox_CFLAGS =           $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(NCURSES_CFLAGS)

nTox_LDADD =            $(LIBSODIUM_LDFLAGS) \
                        $(NAC_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(NCURSES_LIBS) \
                        $(WINSOCK2_LIBS)
endif


if BUILD_TESTING

noinst_PROGRAMS +=      DHT_test \
                        Messenger_test \
                        dns3_test

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



dns3_test_SOURCES = \
                        ../testing/dns3_test.c

dns3_test_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

dns3_test_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxdns.la \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)

if !WIN32

noinst_PROGRAMS +=      tox_sync

tox_sync_SOURCES =      ../testing/tox_sync.c

tox_sync_CFLAGS =       $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

tox_sync_LDADD =        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)
endif

EXTRA_DIST += 			$(top_srcdir)/testing/misc_tools.c

endif
