if BUILD_DHT_BOOTSTRAP_DAEMON

bin_PROGRAMS += tox_bootstrap_daemon

tox_bootstrap_daemon_SOURCES = \
                        ../other/bootstrap_daemon/tox_bootstrap_daemon.c

tox_bootstrap_daemon_CFLAGS = \
                        -I$(top_srcdir)/other/bootstrap_daemon \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(LIBCONFIG_CFLAGS)

tox_bootstrap_daemon_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBCONFIG_LIBS) \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS)

endif

EXTRA_DIST += \
    $(top_srcdir)/other/bootstrap_daemon/conf \
    $(top_srcdir)/other/bootstrap_daemon/tox_bootstrap_daemon.sh
    
