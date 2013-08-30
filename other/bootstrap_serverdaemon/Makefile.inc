if BUILD_DHT_BOOTSTRAP_DAEMON

noinst_PROGRAMS +=      DHT_bootstrap_daemon

DHT_bootstrap_daemon_SOURCES = \
                        ../other/bootstrap_serverdaemon/DHT_bootstrap_daemon.c

DHT_bootstrap_daemon_CFLAGS = \
                        -I$(top_srcdir)/other/bootstrap_serverdaemon \
                        $(LIBSODIUM_CFLAGS) \
                        $(LIBCONFIG_CFLAGS)

DHT_bootstrap_daemon_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBCONFIG_LIBS) \
                        $(LIBSODIUM_LIBS)

endif

EXTRA_DIST += \
    $(top_srcdir)/other/bootstrap_serverdaemon/server.cfg \
    $(top_srcdir)/other/bootstrap_serverdaemon/DHT_bootstrap_daemon.sh
