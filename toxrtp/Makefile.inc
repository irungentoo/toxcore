if BUILD_AV

lib_LTLIBRARIES += 		libtoxrtp.la

libtoxrtp_la_SOURCES =	$(top_srcdir)/toxrtp/rtp_allocator.h \
						$(top_srcdir)/toxrtp/rtp_error.h \
						$(top_srcdir)/toxrtp/rtp_error.c \
						$(top_srcdir)/toxrtp/rtp_error_id.h \
						$(top_srcdir)/toxrtp/rtp_helper.h \
						$(top_srcdir)/toxrtp/rtp_helper.c \
						$(top_srcdir)/toxrtp/rtp_impl.h \
						$(top_srcdir)/toxrtp/rtp_impl.c \
						$(top_srcdir)/toxrtp/rtp_message.h \
						$(top_srcdir)/toxrtp/rtp_message.c \
						$(top_srcdir)/toxcore/network.h \
						$(top_srcdir)/toxcore/network.c \
						$(top_srcdir)/toxcore/util.h \
						$(top_srcdir)/toxcore/util.c

libtoxrtp_la_CFLAGS = 	-I$(top_srcdir) \
						-I$(top_srcdir)/toxcore \
						-I$(top_srcdir)/toxrtp

libtoxrtp_la_LDFLAGS =	$(TOXRTP_LT_LDFLAGS) \
						$(EXTRA_LT_LDFLAGS)

endif
