if BUILD_AV

lib_LTLIBRARIES += 		libtoxrtp.la

libtoxrtp_la_include_HEADERS = \
                        ../toxrtp/rtp_impl.h

libtoxrtp_la_includedir = $(includedir)/tox

libtoxrtp_la_SOURCES =	../toxrtp/rtp_allocator.h \
						../toxrtp/rtp_error.h \
						../toxrtp/rtp_error.c \
						../toxrtp/rtp_error_id.h \
						../toxrtp/rtp_helper.h \
						../toxrtp/rtp_helper.c \
						../toxrtp/rtp_impl.h \
						../toxrtp/rtp_impl.c \
						../toxrtp/rtp_message.h \
						../toxrtp/rtp_message.c \
						../toxcore/network.h \
						../toxcore/network.c \
						../toxcore/util.h \
						../toxcore/util.c

libtoxrtp_la_CFLAGS = 	-I.. \
						-I../toxcore \
						-I../toxrtp

libtoxrtp_la_LDFLAGS =	$(TOXRTP_LT_LDFLAGS) \
						$(EXTRA_LT_LDFLAGS)

endif
