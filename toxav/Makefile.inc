if BUILD_AV

lib_LTLIBRARIES += libtoxav.la
libtoxav_la_include_HEADERS = ../toxav/toxav.h
libtoxav_la_includedir = $(includedir)/tox

libtoxav_la_SOURCES = ../toxav/rtp.h \
                      ../toxav/rtp.c \
                      ../toxav/msi.h \
                      ../toxav/msi.c \
                      ../toxav/codec.h \
                      ../toxav/codec.c \
                      ../toxav/toxav.h \
                      ../toxav/toxav.c


libtoxav_la_CFLAGS = -I../toxcore \
                     -I../toxav \
                     $(LIBSODIUM_CFLAGS) \
                     $(NACL_CFLAGS) \
                     $(AV_CFLAGS) \
                     $(PTHREAD_CFLAGS)

libtoxav_la_LDFLAGS = $(TOXAV_LT_LDFLAGS) \
                      $(LIBSODIUM_LDFLAGS) \
                      $(NACL_LDFLAGS) \
                      $(EXTRA_LT_LDFLAGS) \
                      $(WINSOCK2_LIBS)

libtoxav_la_LIBADD =  libtoxcore.la \
                      $(LIBSODIUM_LIBS) \
                      $(NACL_LIBS) \
                      $(PTHREAD_LIBS) \
                      $(AV_LIBS)

endif