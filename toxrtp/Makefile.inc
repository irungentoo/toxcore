if BUILD_AV

lib_LTLIBRARIES += libtoxrtp.la

libtoxrtp_la_include_HEADERS = \
                        ../toxrtp/toxrtp.h

libtoxrtp_la_includedir = $(includedir)/tox

libtoxrtp_la_SOURCES = ../toxrtp/toxrtp_error.h \
                       ../toxrtp/toxrtp_error.c \
                       ../toxrtp/toxrtp_error_id.h \
                       ../toxrtp/toxrtp_helper.h \
                       ../toxrtp/toxrtp_helper.c \
                       ../toxrtp/toxrtp.h \
                       ../toxrtp/toxrtp.c \
                       ../toxrtp/toxrtp_message.h \
                       ../toxrtp/toxrtp_message.c \
                       ../toxcore/network.h \
                       ../toxcore/network.c \
                       ../toxcore/util.h \
                       ../toxcore/util.c
 
libtoxrtp_la_CFLAGS =  -I../toxcore \
                       -I../toxrtp \
                       $(NACL_CFLAGS)

libtoxrtp_la_LDFLAGS = $(TOXRTP_LT_LDFLAGS) \
                       $(NACL_LDFLAGS) \
                       $(EXTRA_LT_LDFLAGS)

libtoxrtp_la_LIBS =    $(NACL_LIBS)

endif
