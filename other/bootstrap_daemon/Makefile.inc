if BUILD_DHT_BOOTSTRAP_DAEMON

bin_PROGRAMS += tox-bootstrapd

tox_bootstrapd_SOURCES = \
                        ../other/bootstrap_daemon/tox-bootstrapd.c

tox_bootstrapd_CFLAGS = \
                        -I$(top_srcdir)/other/bootstrap_daemon \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(LIBCONFIG_CFLAGS)

tox_bootstrapd_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBCONFIG_LIBS) \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS)

endif

EXTRA_DIST += \
    $(top_srcdir)/other/bootstrap_daemon/tox-bootstrapd.conf \
    $(top_srcdir)/other/bootstrap_daemon/tox-bootstrapd.sh
    
