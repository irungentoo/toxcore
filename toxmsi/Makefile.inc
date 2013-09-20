if BUILD_AV

lib_LTLIBRARIES += 		libtoxmsi.la

libtoxmsi_la_include_HEADERS = \
                        $(top_srcdir)/toxmsi/msi_impl.h

libtoxmsi_la_includedir = $(includedir)/tox

libtoxmsi_la_SOURCES =  $(top_srcdir)/toxmsi/msi_impl.h \
                        $(top_srcdir)/toxmsi/msi_impl.c \
                        $(top_srcdir)/toxmsi/msi_message.h \
                        $(top_srcdir)/toxmsi/msi_message.c \
                        $(top_srcdir)/toxmsi/msi_header.h \
                        $(top_srcdir)/toxmsi/msi_header.c \
						$(top_srcdir)/toxrtp/tests/test_helper.h \
						$(top_srcdir)/toxrtp/tests/test_helper.c

libtoxmsi_la_CFLAGS =   -I$(top_srcdir) \
						-I$(top_srcdir)/toxcore \
                        -I$(top_srcdir)/toxmsi \
                        -I$(top_srcdir)/toxrtp \
						$(PTHREAD_CFLAGS)

libtoxmsi_la_LDFLAGS =  $(TOXMSI_LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
						$(PTHREAD_LIBS)

noinst_PROGRAMS +=     	phone

phone_SOURCES =         $(top_srcdir)/toxmsi/phone.c

phone_CFLAGS =			-I$(top_srcdir) \
						-I$(top_srcdir)/toxcore \
						-I$(top_srcdir)/toxrtp \
						$(PTHREAD_CFLAGS)

phone_LDADD =			$(PTHREAD_LIBS) \
						libtoxrtp.la \
						libtoxmsi.la

endif
