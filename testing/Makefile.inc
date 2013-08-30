if BUILD_NTOX

bin_PROGRAMS += nTox

nTox_SOURCES =          $(top_srcdir)/testing/nTox.h \
                        $(top_srcdir)/testing/nTox.c

nTox_CFLAGS =           $(LIBSODIUM_CFLAGS) \
                        $(NCURSES_CFLAGS)

nTox_LDADD =            $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NCURSES_LIBS) \
                        $(WINSOCK2_LIBS)
endif


noinst_PROGRAMS +=      DHT_test \
                        Lossless_UDP_testclient \
                        Lossless_UDP_testserver \
                        Messenger_test \
                        crypto_speed_test

DHT_test_SOURCES =      $(top_srcdir)/testing/DHT_test.c

DHT_test_CFLAGS =       $(LIBSODIUM_CFLAGS) 

DHT_test_LDADD =        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)


Lossless_UDP_testclient_SOURCES = \
                        $(top_srcdir)/testing/Lossless_UDP_testclient.c

Lossless_UDP_testclient_CFLAGS = \
                        $(LIBSODIUM_CFLAGS)

Lossless_UDP_testclient_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)


Lossless_UDP_testserver_SOURCES = \
                        $(top_srcdir)/testing/Lossless_UDP_testserver.c

Lossless_UDP_testserver_CFLAGS = \
                        $(LIBSODIUM_CFLAGS)

Lossless_UDP_testserver_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)


Messenger_test_SOURCES = \
                        $(top_srcdir)/testing/Messenger_test.c

Messenger_test_CFLAGS = $(LIBSODIUM_CFLAGS)

Messenger_test_LDADD =  $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)


crypto_speed_test_SOURCES = \
                        $(top_srcdir)/testing/crypto_speed_test.c

crypto_speed_test_CFLAGS = \
                        $(LIBSODIUM_CFLAGS)

crypto_speed_test_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)

