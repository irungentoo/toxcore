bin_PROGRAMS =
noinst_PROGRAMS =
lib_LTLIBRARIES =
noinst_bindir = $(top_builddir)/build
EXTRA_DIST=

if SET_SO_VERSION

include ../so.version

LT_LDFLAGS=-version-info $(CURRENT):$(REVISION):$(AGE)

else

LT_LDFLAGS=-avoid-version

endif

include ../toxcore/Makefile.inc
include ../toxdns/Makefile.inc
include ../toxencryptsave/Makefile.inc
include ../toxav/Makefile.inc
include ../other/Makefile.inc
include ../testing/Makefile.inc
include ../other/bootstrap_daemon/src/Makefile.inc
include ../auto_tests/Makefile.inc
