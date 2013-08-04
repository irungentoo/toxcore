EXTRA_DIST=

noinst_LIBRARIES = libtoxcore.a

libtoxcore_a_SOURCES = 	$(top_srcdir)/toxcore/DHT.h \
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
						$(top_srcdir)/toxcore/packets.h \
						$(top_srcdir)/toxcore/ping.h \
						$(top_srcdir)/toxcore/ping.c \
						$(top_srcdir)/toxcore/util.h \
						$(top_srcdir)/toxcore/util.c

libtoxcore_a_CFLAGS = 	-I$(top_srcdir) \
						-I$(top_srcdir)/toxcore \
						$(LIBSODIUM_CFLAGS)

bin_PROGRAMS = nTox	toxic


COMMONCFLAGS =			-I$(top_srcdir) \
						-I$(top_srcdir)/testing \
						$(LIBSODIUM_CFLAGS) \
						$(NCURSES_CFLAGS)

COMMONLDADD =			$(LIBSODIUM_LDFLAGS) \
						$(LIBSODIUM_LIBS) \
						$(NCURSES_LIBS) \
						libtoxcore.a


nTox_SOURCES = 			$(top_srcdir)/testing/misc_tools.h \
						$(top_srcdir)/testing/misc_tools.c

if WIN32
nTox_SOURCES +=			$(top_srcdir)/testing/nTox_win32.h \
						$(top_srcdir)/testing/nTox_win32.c
else
nTox_SOURCES +=			$(top_srcdir)/testing/nTox.h \
						$(top_srcdir)/testing/nTox.c
endif

nTox_CFLAGS = 			$(COMMONCFLAGS)	

nTox_LDADD = 			$(COMMONLDADD)


toxic_SOURCES =			$(top_srcdir)/testing/toxic/main.c \
						$(top_srcdir)/testing/toxic/chat.c \
						$(top_srcdir)/testing/toxic/prompt.c \
						$(top_srcdir)/testing/toxic/friendlist.c \
						$(top_srcdir)/testing/toxic/windows.h

toxic_CFLAGS =			-I$(top_srcdir) \
						-I$(top_srcdir)/testing/toxic \
						$(LIBSODIUM_CFLAGS) \
						$(NCURSES_CFLAGS)

toxic_LDADD =			$(LIBSODIUM_LDFLAGS) \
						$(LIBSODIUM_LIBS) \
						$(NCURSES_LIBS) \
						libtoxcore.a


noinst_bindir =			$(top_builddir)/build

noinst_PROGRAMS = 		DHT_test \
						Lossless_UDP_testclient \
						Lossless_UDP_testserver \
						Messenger_test \
						DHT_bootstrap

DHT_test_SOURCES =		$(top_srcdir)/testing/DHT_test.c \
						$(top_srcdir)/testing/misc_tools.h \
						$(top_srcdir)/testing/misc_tools.c

DHT_test_CFLAGS =		-I$(top_srcdir) \
						-I$(top_srcdir)/testing \
						$(LIBSODIUM_CFLAGS) \
						$(NCURSES_CFLAGS)

DHT_test_LDADD = 		$(LIBSODIUM_LDFLAGS) \
						$(LIBSODIUM_LIBS) \
						$(NCURSES_LIBS) \
						libtoxcore.a


Lossless_UDP_testclient_SOURCES = \
						$(top_srcdir)/testing/Lossless_UDP_testclient.c
Lossless_UDP_testclient_CFLAGS = \
						$(COMMONCFLAGS)
Lossless_UDP_testclient_LDADD = \
						$(COMMONLDADD)


Lossless_UDP_testserver_SOURCES = \
						$(top_srcdir)/testing/Lossless_UDP_testserver.c

Lossless_UDP_testserver_CFLAGS = \
						$(COMMONCFLAGS)

Lossless_UDP_testserver_LDADD = \
						$(COMMONLDADD)


Messenger_test_SOURCES = \
						$(top_srcdir)/testing/Messenger_test.c \
						$(top_srcdir)/testing/misc_tools.h \
						$(top_srcdir)/testing/misc_tools.c

Messenger_test_CFLAGS = $(COMMONCFLAGS)

Messenger_test_LDADD =	$(COMMONLDADD)

DHT_bootstrap_SOURCES =	$(top_srcdir)/other/DHT_bootstrap.c \
						$(top_srcdir)/toxcore/DHT.h \
						$(top_srcdir)/toxcore/friend_requests.h \
						$(top_srcdir)/testing/misc_tools.h \
						$(top_srcdir)/testing/misc_tools.c
DHT_bootstrap_CFLAGS =	$(COMMONCFLAGS)
DHT_bootstrap_LDADD =	$(COMMONLDADD)

if BUILD_DHT_BOOTSTRAP_DAEMON
noinst_PROGRAMS += 		DHT_bootstrap_daemon
EXTRA_DIST +=			$(top_srcdir)/other/bootstrap_serverdaemon/server.cfg
DHT_bootstrap_daemon_SOURCES = \
						$(top_srcdir)/other/bootstrap_serverdaemon/DHT_bootstrap_daemon.c

DHT_bootstrap_daemon_CFLAGS = \
						$(COMMONCFLAGS) \
						$(LIBCONFIG_CFLAGS)

DHT_bootstrap_daemon_LDADD = \
						$(LIBCONFIG_LIBS) \
						$(COMMONLDADD)
endif
