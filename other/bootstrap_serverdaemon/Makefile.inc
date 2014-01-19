if BUILD_DHT_BOOTSTRAP_DAEMON

noinst_PROGRAMS +=      tox-dht-bootstrap-server-daemon

DHT_bootstrap_daemon_SOURCES = \
                        ../other/bootstrap_serverdaemon/tox-dht-bootstrap-server-daemon.c

DHT_bootstrap_daemon_CFLAGS = \
                        -I$(top_srcdir)/other/bootstrap_serverdaemon \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(LIBCONFIG_CFLAGS)

DHT_bootstrap_daemon_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBCONFIG_LIBS) \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS)

endif

EXTRA_DIST += \
    $(top_srcdir)/other/bootstrap_serverdaemon/conf \
    $(top_srcdir)/other/bootstrap_serverdaemon/tox-dht-bootstrap-server-daemon
