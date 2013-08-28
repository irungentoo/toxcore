if BUILD_AV

noinst_PROGRAMS += 		test_video

test_video_SOURCES =	$(top_srcdir)/toxrtp/tests/AV_codec.h \
						$(top_srcdir)/toxrtp/tests/AV_codec.c \
						$(top_srcdir)/toxrtp/tests/test_helper.h \
						$(top_srcdir)/toxrtp/tests/test_helper.c \
						$(top_srcdir)/toxrtp/tests/test_video.c

test_video_CFLAGS = 	$(PTHREAD_CFLAGS) \
						$(AVFORMAT_CFLAGS) \
						$(AVCODEC_CFLAGS) \
						$(AVUTIL_CFLAGS) \
						$(AVDEVICE_CFLAGS) \
						$(SWSCALE_CFLAGS) \
						$(SDL_CFLAGS) \
						$(OPENAL_CFLAGS)

test_video_LDADD =		libtoxrtp.la \
						$(PTHREAD_LIBS) \
						$(AVFORMAT_LIBS) \
						$(AVCODEC_LIBS) \
						$(AVUTIL_LIBS) \
						$(AVDEVICE_LIBS) \
						$(SWSCALE_LIBS) \
						$(SDL_LIBS) \
						$(OPENAL_LIBS)

endif
