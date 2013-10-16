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
                        $(NACL_LIBS) \
                        $(NCURSES_LIBS) \
                        $(WINSOCK2_LIBS)
endif


if BUILD_TESTING

noinst_PROGRAMS +=      DHT_test \
                        Lossless_UDP_testclient \
                        Lossless_UDP_testserver \
                        Messenger_test \
                        crypto_speed_test

DHT_test_SOURCES =      ../testing/DHT_test.c

DHT_test_CFLAGS =       $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

DHT_test_LDADD =        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)


Lossless_UDP_testclient_SOURCES = \
                        ../testing/Lossless_UDP_testclient.c

Lossless_UDP_testclient_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

Lossless_UDP_testclient_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)


Lossless_UDP_testserver_SOURCES = \
                        ../testing/Lossless_UDP_testserver.c

Lossless_UDP_testserver_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

Lossless_UDP_testserver_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
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
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)


crypto_speed_test_SOURCES = \
                        ../testing/crypto_speed_test.c

crypto_speed_test_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS)

crypto_speed_test_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
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
                        $(NACL_LIBS) \
                        $(WINSOCK2_LIBS)
endif

EXTRA_DIST += 			$(top_srcdir)/testing/misc_tools.c

endif
