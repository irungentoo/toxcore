lib_LTLIBRARIES += libtoxdns.la

libtoxdns_la_include_HEADERS = \
                        ../toxdns/toxdns.h

libtoxdns_la_includedir = $(includedir)/tox

libtoxdns_la_SOURCES =  ../toxdns/toxdns.h \
                        ../toxdns/toxdns.c

libtoxdns_la_CFLAGS =   -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(PTHREAD_CFLAGS)

libtoxdns_la_LDFLAGS =  $(TOXCORE_LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        $(MATH_LDFLAGS) \
                        $(RT_LIBS) \
                        $(WINSOCK2_LIBS)

libtoxdns_la_LIBADD =   $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NAC_LIBS) \
                        $(PTHREAD_LIBS) \
                        libtoxcore.la
