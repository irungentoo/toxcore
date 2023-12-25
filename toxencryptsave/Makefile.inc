lib_LTLIBRARIES += libtoxencryptsave.la

libtoxencryptsave_la_include_HEADERS = \
                        ../toxencryptsave/toxencryptsave.h

libtoxencryptsave_la_includedir = $(includedir)/tox

libtoxencryptsave_la_SOURCES = ../toxencryptsave/toxencryptsave.h \
                        ../toxencryptsave/toxencryptsave.c \
                        ../toxencryptsave/defines.h

libtoxencryptsave_la_CFLAGS =   -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS) \
                        $(PTHREAD_CFLAGS)

libtoxencryptsave_la_LDFLAGS =  $(LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(MATH_LDFLAGS) \
                        $(RT_LIBS) \
                        $(WINSOCK2_LIBS)

libtoxencryptsave_la_LIBADD =   $(LIBSODIUM_LIBS) \
                        $(PTHREAD_LIBS) \
                        libtoxcore.la

if SET_SO_VERSION

EXTRA_libtoxencryptsave_la_DEPENDENCIES = ../so.version

endif
