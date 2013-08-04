SUBDIRS = build

ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(top_srcdir)/libtoxcore.pc

BUILT_SOURCES = $(top_srcdir)/libtoxcore.pc
CLEANFILES = $(top_srcdir)/libtoxcore.pc


EXTRA_DIST = \
	$(top_srcdir)/libtoxcore.pc.in \
	$(top_srcdir)/testing/cmake/Messenger_test.cmake \
	$(top_srcdir)/testing/cmake/DHT_sendfiletest.cmake \
	$(top_srcdir)/testing/cmake/DHT_cryptosendfiletest.cmake \
	$(top_srcdir)/testing/cmake/DHT_test.cmake \
	$(top_srcdir)/testing/cmake/Lossless_UDP_testclient.cmake \
	$(top_srcdir)/testing/cmake/Lossless_UDP_testserver.cmake \
	$(top_srcdir)/testing/cmake/nTox_win32.cmake \
	$(top_srcdir)/testing/cmake/nTox.cmake \
	$(top_srcdir)/testing/toxic/CMakeLists.txt \
	$(top_srcdir)/testing/CMakeLists.txt \
	$(top_srcdir)/cmake/FindLIBCONFIG.cmake \
	$(top_srcdir)/cmake/FindSphinx.cmake \
	$(top_srcdir)/cmake/FindSODIUM.cmake \
	$(top_srcdir)/cmake/FindNaCl.cmake \
	$(top_srcdir)/other/cmake/DHT_bootstrap.cmake \
	$(top_srcdir)/other/bootstrap_serverdaemon/cmake/Modules \
	$(top_srcdir)/other/bootstrap_serverdaemon/cmake/Modules/FindLibConfig.cmake \
	$(top_srcdir)/other/bootstrap_serverdaemon/CMakeLists.txt \
	$(top_srcdir)/other/bootstrap_serverdaemon/cmake/Modules/FindLibConfig.cmake \
	$(top_srcdir)/other/bootstrap_serverdaemon/CMakeLists.txt \
	$(top_srcdir)/other/CMakeLists.txt \
	$(top_srcdir)/toxcore/CMakeLists.txt \
	$(top_srcdir)/docs/CMakeLists.txt \
	$(top_srcdir)/CMakeLists.txt
