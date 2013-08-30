lib_LTLIBRARIES = libtoxcore.la

libtoxcore_la_include_HEADERS = \
                        $(top_srcdir)/toxcore/tox.h

libtoxcore_la_includedir = $(includedir)/tox

libtoxcore_la_SOURCES = $(top_srcdir)/toxcore/DHT.h \
                        $(top_srcdir)/toxcore/DHT.c \
                        $(top_srcdir)/toxcore/network.h \
                        $(top_srcdir)/toxcore/network.c \
                        $(top_srcdir)/toxcore/Lossless_UDP.h \
                        $(top_srcdir)/toxcore/Lossless_UDP.c \
                        $(top_srcdir)/toxcore/net_crypto.h \
                        $(top_srcdir)/toxcore/net_crypto.c \
                        $(top_srcdir)/toxcore/friend_requests.h \
                        $(top_srcdir)/toxcore/friend_requests.c \
                        $(top_srcdir)/toxcore/LAN_discovery.h \
                        $(top_srcdir)/toxcore/LAN_discovery.c \
                        $(top_srcdir)/toxcore/Messenger.h \
                        $(top_srcdir)/toxcore/Messenger.c \
                        $(top_srcdir)/toxcore/ping.h \
                        $(top_srcdir)/toxcore/ping.c \
                        $(top_srcdir)/toxcore/tox.h \
                        $(top_srcdir)/toxcore/tox.c \
                        $(top_srcdir)/toxcore/util.h \
                        $(top_srcdir)/toxcore/util.c \
                        $(top_srcdir)/toxcore/misc_tools.h

libtoxcore_la_CFLAGS =  -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS)

libtoxcore_la_LDFLAGS = $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(WINSOCK2_LIBS)

libtoxcore_la_LIBS =    $(LIBSODIUM_LIBS)
