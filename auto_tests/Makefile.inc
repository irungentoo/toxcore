if BUILD_TESTS

TESTS = messenger_autotest crypto_test network_test

check_PROGRAMS = messenger_autotest crypto_test network_test

messenger_autotest_SOURCES = \
                        ../auto_tests/messenger_test.c

messenger_autotest_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(CHECK_CFLAGS)

messenger_autotest_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)


crypto_test_SOURCES =   ../auto_tests/crypto_test.c

crypto_test_CFLAGS =    $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(CHECK_CFLAGS)

crypto_test_LDADD =     $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)

network_test_SOURCES = \
                        ../auto_tests/network_test.c

network_test_CFLAGS = \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(CHECK_CFLAGS)

network_test_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)

endif

EXTRA_DIST +=           $(top_srcdir)/auto_tests/friends_test.c

