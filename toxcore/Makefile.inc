lib_LTLIBRARIES += libtoxcore.la

libtoxcore_la_include_HEADERS = \
                        ../toxcore/tox.h

libtoxcore_la_includedir = $(includedir)/tox

libtoxcore_la_SOURCES = ../toxcore/DHT.h \
                        ../toxcore/DHT.c \
                        ../toxcore/network.h \
                        ../toxcore/network.c \
                        ../toxcore/crypto_core.h \
                        ../toxcore/crypto_core.c \
                        ../toxcore/ping_array.h \
                        ../toxcore/ping_array.c \
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
                        ../toxcore/group_chats.h \
                        ../toxcore/group_chats.c \
                        ../toxcore/assoc.h \
                        ../toxcore/assoc.c \
                        ../toxcore/onion.h \
                        ../toxcore/onion.c \
                        ../toxcore/logger.h \
                        ../toxcore/logger.c \
                        ../toxcore/onion_announce.h \
                        ../toxcore/onion_announce.c \
                        ../toxcore/onion_client.h \
                        ../toxcore/onion_client.c \
                        ../toxcore/TCP_client.h \
                        ../toxcore/TCP_client.c \
                        ../toxcore/TCP_server.h \
                        ../toxcore/TCP_server.c \
                        ../toxcore/list.c \
                        ../toxcore/list.h \
                        ../toxcore/misc_tools.h

libtoxcore_la_CFLAGS =  -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(PTHREAD_CFLAGS)

libtoxcore_la_LDFLAGS = $(TOXCORE_LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        $(MATH_LDFLAGS) \
                        $(RT_LIBS) \
                        $(WINSOCK2_LIBS)

libtoxcore_la_LIBADD =  $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NAC_LIBS) \
                        $(PTHREAD_LIBS)
