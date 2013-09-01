lib_LTLIBRARIES = libtoxcore.la

libtoxcore_la_include_HEADERS = \
                        ../toxcore/tox.h

libtoxcore_la_includedir = $(includedir)/tox

libtoxcore_la_SOURCES = ../toxcore/DHT.h \
                        ../toxcore/DHT.c \
                        ../toxcore/network.h \
                        ../toxcore/network.c \
                        ../toxcore/Lossless_UDP.h \
                        ../toxcore/Lossless_UDP.c \
                        ../toxcore/net_crypto.h \
                        ../toxcore/net_crypto.c \
                        ../toxcore/friend_requests.h \
                        ../toxcore/friend_requests.c \
                        ../toxcore/LAN_discovery.h \
                        ../toxcore/LAN_discovery.c \
                        ../toxcore/Messenger.h \
                        ../toxcore/Messenger.c \
                        ../toxcore/ping.h \
                        ../toxcore/ping.c \
                        ../toxcore/tox.h \
                        ../toxcore/tox.c \
                        ../toxcore/util.h \
                        ../toxcore/util.c \
                        ../toxcore/misc_tools.h

libtoxcore_la_CFLAGS =  -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS)

libtoxcore_la_LDFLAGS = $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(WINSOCK2_LIBS)

libtoxcore_la_LIBS =    $(LIBSODIUM_LIBS)
