SUBDIRS = build

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig


pkgconfig_DATA = $(top_builddir)/libtoxcore.pc
BUILT_SOURCES = $(top_builddir)/libtoxcore.pc
CLEANFILES = $(top_builddir)/libtoxcore.pc


EXTRA_DIST = \
	README.md \
	libtoxcore.pc.in \
	tox.spec \
	dist-build/android-arm.sh \
	dist-build/android-armv7.sh \
	dist-build/android-x86.sh \
	dist-build/android-mips.sh \
	dist-build/android-build.sh \
	$(top_srcdir)/docs/updates/Crypto.md \
	$(top_srcdir)/docs/updates/Spam-Prevention.md \
	$(top_srcdir)/docs/updates/Symmetric-NAT-Transversal.md \
	$(top_srcdir)/other/astyle/README.md \
	$(top_srcdir)/other/astyle/astylerc \
	$(top_srcdir)/other/astyle/pre-commit

if BUILD_AV

pkgconfig_DATA += $(top_builddir)/libtoxav.pc
BUILT_SOURCES += $(top_builddir)/libtoxav.pc
CLEANFILES += $(top_builddir)/libtoxav.pc

EXTRA_DIST += libtoxav.pc.in

endif
