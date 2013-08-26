SUBDIRS = build

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = subdir-objects

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_builddir)/libtoxcore.pc

BUILT_SOURCES = $(top_builddir)/libtoxcore.pc
CLEANFILES = $(top_builddir)/libtoxcore.pc


EXTRA_DIST = \
	$(top_srcdir)/libtoxcore.pc.in \
	$(top_srcdir)/docs/install.rst \
	$(top_srcdir)/docs/commands.rst \
	$(top_srcdir)/docs/conf.py.in \
	$(top_srcdir)/docs/index.rst \
	$(top_srcdir)/docs/install.rst \
	$(top_srcdir)/docs/start_guide.de.rst \
	$(top_srcdir)/docs/start_guide.rst \
	$(top_srcdir)/docs/updates/Crypto.md \
	$(top_srcdir)/docs/updates/Spam-Prevention.md \
	$(top_srcdir)/docs/updates/Symmetric-NAT-Transversal.md \
	$(top_srcdir)/tools/README \
	$(top_srcdir)/tools/astylerc \
	$(top_srcdir)/tools/pre-commit

