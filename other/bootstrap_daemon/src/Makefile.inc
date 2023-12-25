if BUILD_DHT_BOOTSTRAP_DAEMON

bin_PROGRAMS += tox-bootstrapd

tox_bootstrapd_SOURCES = \
                        ../other/bootstrap_daemon/src/command_line_arguments.c \
                        ../other/bootstrap_daemon/src/command_line_arguments.h \
                        ../other/bootstrap_daemon/src/config.c \
                        ../other/bootstrap_daemon/src/config.h \
                        ../other/bootstrap_daemon/src/config_defaults.h \
                        ../other/bootstrap_daemon/src/global.h \
                        ../other/bootstrap_daemon/src/log.c \
                        ../other/bootstrap_daemon/src/log.h \
                        ../other/bootstrap_daemon/src/log_backend_stdout.c \
                        ../other/bootstrap_daemon/src/log_backend_stdout.h \
                        ../other/bootstrap_daemon/src/log_backend_syslog.c \
                        ../other/bootstrap_daemon/src/log_backend_syslog.h \
                        ../other/bootstrap_daemon/src/tox-bootstrapd.c \
                        ../other/bootstrap_daemon/src/global.h \
                        ../other/bootstrap_node_packets.c \
                        ../other/bootstrap_node_packets.h


tox_bootstrapd_CFLAGS = \
                        -I$(top_srcdir)/other/bootstrap_daemon \
                        $(LIBSODIUM_CFLAGS) \
                        $(LIBCONFIG_CFLAGS)

tox_bootstrapd_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBCONFIG_LIBS) \
                        $(LIBSODIUM_LIBS)

bashcompdir = $(datarootdir)/bash-completion/completions
dist_bashcomp_DATA = $(top_builddir)/other/bootstrap_daemon/bash-completion/completions/tox-bootstrapd

EXTRA_DIST += \
    $(top_srcdir)/other/bootstrap_daemon/tox-bootstrapd.conf \
    $(top_srcdir)/other/bootstrap_daemon/tox-bootstrapd.service \
    $(top_srcdir)/other/bootstrap_daemon/tox-bootstrapd.sh

endif
