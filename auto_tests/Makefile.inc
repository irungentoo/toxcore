if BUILD_TESTS

TESTS = messenger_autotest crypto_test network_test rendezvous_test

check_PROGRAMS = messenger_autotest crypto_test network_test rendezvous_test

AUTOTEST_CFLAGS = \
                         $(LIBSODIUM_CFLAGS) \
                         $(NACL_CFLAGS) \
                         $(CHECK_CFLAGS)
 
AUTOTEST_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)

messenger_autotest_SOURCES = ../auto_tests/messenger_test.c

messenger_autotest_CFLAGS = $(AUTOTEST_CFLAGS)

messenger_autotest_LDADD = $(AUTOTEST_LDADD)


crypto_test_SOURCES =   ../auto_tests/crypto_test.c

crypto_test_CFLAGS = $(AUTOTEST_CFLAGS)

crypto_test_LDADD = $(AUTOTEST_LDADD)


network_test_SOURCES = ../auto_tests/network_test.c

network_test_CFLAGS = $(AUTOTEST_CFLAGS)

network_test_LDADD = $(AUTOTEST_LDADD)


rendezvous_test_SOURCES = \
                        ../auto_tests/rendezvous_test.c

rendezvous_test_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(CHECK_CFLAGS)

rendezvous_test_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)

endif

EXTRA_DIST +=           $(top_srcdir)/auto_tests/friends_test.c

