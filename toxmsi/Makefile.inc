if BUILD_AV

lib_LTLIBRARIES += libtoxmsi.la

libtoxmsi_la_include_HEADERS = \
                        ../toxmsi/toxmsi.h \
                        ../toxmsi/AV_codec.h

libtoxmsi_la_includedir = $(includedir)/tox


libtoxmsi_la_SOURCES =  ../toxmsi/toxmsi.h \
                        ../toxmsi/toxmsi.c \
                        ../toxmsi/toxmsi_message.h \
                        ../toxmsi/toxmsi_message.c \
                        ../toxmsi/toxmsi_header.h \
                        ../toxmsi/toxmsi_header.c \
                        ../toxmsi/toxmsi_event.h \
                        ../toxmsi/toxmsi_event.c \
                        ../toxrtp/tests/test_helper.h \
                        ../toxrtp/tests/test_helper.c

libtoxmsi_la_CFLAGS =  -I../toxcore \
                       -I../toxmsi \
                       -I../toxrtp \
                       $(NACL_CFLAGS) \
                       $(PTHREAD_CFLAGS)

libtoxmsi_la_LDFLAGS = $(TOXMSI_LT_LDFLAGS) \
                       $(EXTRA_LT_LDFLAGS) \
                       $(NACL_LDFLAGS) \
                       $(PTHREAD_LIBS)

libtoxmsi_la_LIBS    = $(NACL_LIBS)

noinst_PROGRAMS += phone

phone_SOURCES = ../toxmsi/phone.c \
                ../toxmsi/AV_codec.h \
                ../toxmsi/AV_codec.c

phone_CFLAGS =  -I../toxcore \
                -I../toxrtp \
                $(AVFORMAT_CFLAGS) \
                $(AVCODEC_CFLAGS) \
                $(AVUTIL_CFLAGS) \
                $(AVDEVICE_CFLAGS) \
                $(SWSCALE_CFLAGS) \
                $(SDL_CFLAGS) \
                $(OPENAL_CFLAGS) \
                $(NACL_CFLAGS) \
                $(OPUS_CFLAGS) \
                $(PTHREAD_CFLAGS)


phone_LDADD =   $(PTHREAD_LIBS) \
                libtoxrtp.la \
                libtoxmsi.la \
                $(NACL_LDFLAGS) \
                $(AVFORMAT_LIBS) \
                $(AVCODEC_LIBS) \
                $(AVUTIL_LIBS) \
                $(AVDEVICE_LIBS) \
                $(SWSCALE_LIBS) \
                $(SDL_LIBS) \
                $(OPENAL_LIBS) \
                $(NACL_LIBS) \
                $(OPUS_LIBS)

endif
