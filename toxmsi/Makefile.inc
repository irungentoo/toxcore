if BUILD_AV

lib_LTLIBRARIES += libtoxmsi.la

libtoxmsi_la_include_HEADERS = \
                        ../toxmsi/msi_impl.h

libtoxmsi_la_includedir = $(includedir)/tox

libtoxmsi_la_SOURCES =  ../toxmsi/msi_impl.h \
                        ../toxmsi/msi_impl.c \
                        ../toxmsi/msi_message.h \
                        ../toxmsi/msi_message.c \
                        ../toxmsi/msi_header.h \
                        ../toxmsi/msi_header.c \
                                          ../toxrtp/tests/test_helper.h \
                                          ../toxrtp/tests/test_helper.c

libtoxmsi_la_CFLAGS =  -I../toxcore \
                        -I../toxmsi \
                        -I../toxrtp \
$(PTHREAD_CFLAGS)

libtoxmsi_la_LDFLAGS = $(TOXMSI_LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
$(PTHREAD_LIBS)

noinst_PROGRAMS += phone

phone_SOURCES = ../toxmsi/phone.c \
                        ../toxmsi/AV_codec.h \
                        ../toxmsi/AV_codec.c

phone_CFLAGS = -I../toxcore \
-I../toxrtp \
$(AVFORMAT_CFLAGS) \
$(AVCODEC_CFLAGS) \
$(AVUTIL_CFLAGS) \
$(AVDEVICE_CFLAGS) \
$(SWSCALE_CFLAGS) \
$(SDL_CFLAGS) \
$(OPENAL_CFLAGS) \
$(PTHREAD_CFLAGS)

phone_LDADD = $(PTHREAD_LIBS) \
libtoxrtp.la \
libtoxmsi.la \
$(AVFORMAT_LIBS) \
$(AVCODEC_LIBS) \
$(AVUTIL_LIBS) \
$(AVDEVICE_LIBS) \
$(SWSCALE_LIBS) \
$(SDL_LIBS) \
$(OPENAL_LIBS) \
-lopus

endif
