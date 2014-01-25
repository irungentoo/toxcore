if BUILD_AV

lib_LTLIBRARIES += libtoxrtp.la \
                   libtoxmsi.la \
                   libtoxmedia.la

                   
# ****** RTP ****** #
                   
libtoxrtp_la_include_HEADERS = \
                        ../toxav/toxrtp.h

libtoxrtp_la_includedir = $(includedir)/tox

libtoxrtp_la_SOURCES =  ../toxav/toxrtp.h \
                        ../toxav/toxrtp.c 

libtoxrtp_la_CFLAGS = -I../toxcore \
                       -I../toxav \
                       $(NACL_CFLAGS)

libtoxrtp_la_LDFLAGS = $(TOXRTP_LT_LDFLAGS) \
                       $(NACL_LDFLAGS) \
                       $(EXTRA_LT_LDFLAGS)

libtoxrtp_la_LIBS =    libtoxcore.la \
                       $(NACL_LIBS)
                        
                        
                        
                        
                        
# ****** MSI ****** #

libtoxmsi_la_include_HEADERS = \
                        ../toxav/toxmsi.h

libtoxmsi_la_includedir = $(includedir)/tox

libtoxmsi_la_SOURCES =  ../toxav/toxmsi.h \
                        ../toxav/toxmsi.c 

libtoxmsi_la_CFLAGS = -I../toxcore \
                       -I../toxav \
                       $(NACL_CFLAGS) 

libtoxmsi_la_LDFLAGS = $(TOXMSI_LT_LDFLAGS) \
                       $(EXTRA_LT_LDFLAGS) \
                       $(NACL_LDFLAGS) 

libtoxmsi_la_LIBS =    libtoxcore.la \
                       $(NACL_LIBS)
                        
                        
                        
                        
                        
# ****** MEDIA ****** #

libtoxmedia_la_include_HEADERS = \
                        ../toxav/toxmedia.h

libtoxmedia_la_includedir = $(includedir)/tox

libtoxmedia_la_SOURCES =  ../toxav/toxmedia.h \
                          ../toxav/toxmedia.c 

libtoxmedia_la_CFLAGS =   -I../toxcore \
                          -I../toxav \
                          $(AVFORMAT_CFLAGS) \
                          $(AVCODEC_CFLAGS) \
                          $(AVUTIL_CFLAGS) \
                          $(AVDEVICE_CFLAGS) \
                          $(SWSCALE_CFLAGS) \
                          $(SDL_CFLAGS) \
                          $(OPENAL_CFLAGS) \
                          $(NACL_CFLAGS) \
                          $(OPUS_CFLAGS) 

                          
libtoxmedia_la_LDFLAGS =  $(TOXMSI_LT_LDFLAGS) \
                          $(TOXRTP_LT_LDFLAGS) \
                          $(EXTRA_LT_LDFLAGS) \
                          $(NACL_LDFLAGS) 
                          
                          
libtoxmedia_la_LIBS =     libtoxcore.la \
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
                          
                          
                          
                          
# ***** PHONE ***** #
                          
noinst_PROGRAMS += phone

phone_SOURCES = ../toxav/phone.c 

phone_CFLAGS = -I../toxcore \
               -I../toxav \
                $(AVFORMAT_CFLAGS) \
                $(AVCODEC_CFLAGS) \
                $(AVUTIL_CFLAGS) \
                $(AVDEVICE_CFLAGS) \
                $(SWSCALE_CFLAGS) \
                $(SDL_CFLAGS) \
                $(OPENAL_CFLAGS) \
                $(NACL_CFLAGS) \
                $(OPUS_CFLAGS) 


phone_LDADD =   libtoxrtp.la \
                libtoxmsi.la \
                libtoxmedia.la  \
                libtoxcore.la \
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