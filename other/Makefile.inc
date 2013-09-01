noinst_PROGRAMS += DHT_bootstrap

DHT_bootstrap_SOURCES = ../other/DHT_bootstrap.c \
                        ../toxcore/DHT.h \
                        ../toxcore/friend_requests.h

DHT_bootstrap_CFLAGS = -I$(top_srcdir)/other \
                        $(LIBSODIUM_CFLAGS)

DHT_bootstrap_LDADD =   $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(WINSOCK2_LIBS)

EXTRA_DIST +=           $(top_srcdir)/other/DHTservers \
                        $(top_srcdir)/other/tox.png
