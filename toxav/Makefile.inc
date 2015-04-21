if BUILD_AV

lib_LTLIBRARIES += libtoxav.la
libtoxav_la_include_HEADERS = ../toxav/toxav.h
libtoxav_la_includedir = $(includedir)/tox

libtoxav_la_SOURCES = ../toxav/rtp.h \
                      ../toxav/rtp.c \
                      ../toxav/msi.h \
                      ../toxav/msi.c \
                      ../toxav/group.h \
                      ../toxav/group.c \
                      ../toxav/codec.h \
                      ../toxav/codec.c \
                      ../toxav/audio.h \
                      ../toxav/audio.c \
                      ../toxav/video.h \
                      ../toxav/video.c \
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



#noinst_PROGRAMS +=    av_test

#av_test_SOURCES =     ../toxav/av_test.c

#av_test_CFLAGS =      $(LIBSODIUM_CFLAGS) \
                      $(NACL_CFLAGS)

#av_test_LDADD =       $(LIBSODIUM_LDFLAGS) \
                      $(NACL_LDFLAGS) \
                      libtoxav.la \
                      libtoxcore.la \
                      $(LIBSODIUM_LIBS) \
                      $(NACL_OBJECTS) \
                      -lopenal \
                      -lopencv_calib3d -lopencv_contrib -lopencv_core -lopencv_features2d -lopencv_flann -lopencv_gpu -lopencv_highgui -lopencv_imgproc -lopencv_legacy -lopencv_ml -lopencv_objdetect -lopencv_ocl -lopencv_photo -lopencv_stitching -lopencv_superres -lopencv_ts -lopencv_video -lopencv_videostab \
                      -lsndfile \
                      $(NACL_LIBS)


endif