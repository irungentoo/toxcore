if BUILD_TESTS

TESTS = encryptsave_test messenger_autotest crypto_test network_test onion_test TCP_test tox_test dht_autotest tox_strncasecmp_test
check_PROGRAMS = encryptsave_test messenger_autotest crypto_test network_test onion_test TCP_test tox_test dht_autotest tox_strncasecmp_test

AUTOTEST_CFLAGS = \
                         $(LIBSODIUM_CFLAGS) \
                         $(NACL_CFLAGS) \
                         $(CHECK_CFLAGS)

AUTOTEST_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        libtoxencryptsave.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)



if BUILD_AV
TESTS += toxav_basic_test toxav_many_test
check_PROGRAMS += toxav_basic_test toxav_many_test
AUTOTEST_LDADD += libtoxav.la
endif

messenger_autotest_SOURCES = ../auto_tests/messenger_test.c

messenger_autotest_CFLAGS = $(AUTOTEST_CFLAGS)

messenger_autotest_LDADD = $(AUTOTEST_LDADD)


crypto_test_SOURCES = ../auto_tests/crypto_test.c

crypto_test_CFLAGS = $(AUTOTEST_CFLAGS)

crypto_test_LDADD = $(AUTOTEST_LDADD)


network_test_SOURCES = ../auto_tests/network_test.c

network_test_CFLAGS = $(AUTOTEST_CFLAGS)

network_test_LDADD = $(AUTOTEST_LDADD)


onion_test_SOURCES = ../auto_tests/onion_test.c

onion_test_CFLAGS = $(AUTOTEST_CFLAGS)

onion_test_LDADD = $(AUTOTEST_LDADD)


TCP_test_SOURCES = ../auto_tests/TCP_test.c

TCP_test_CFLAGS = $(AUTOTEST_CFLAGS)

TCP_test_LDADD = $(AUTOTEST_LDADD)


tox_test_SOURCES = ../auto_tests/tox_test.c

tox_test_CFLAGS = $(AUTOTEST_CFLAGS)

tox_test_LDADD = $(AUTOTEST_LDADD)


dht_autotest_SOURCES = ../auto_tests/dht_test.c

dht_autotest_CFLAGS = $(AUTOTEST_CFLAGS)

dht_autotest_LDADD = $(AUTOTEST_LDADD)


# TODO(iphydf): This test is broken. The code needs to be fixed, as the test
# itself is correct.
#selfname_change_conference_SOURCE = ../auto_tests/selfname_change_conference_test.c
#
#selfname_change_conference_CFLAGS = $(AUTOTEST_CFLAGS)
#
#selfname_change_conference_LDADD = $(AUTOTEST_LDADD)

if BUILD_AV
toxav_basic_test_SOURCES = ../auto_tests/toxav_basic_test.c

toxav_basic_test_CFLAGS = $(AUTOTEST_CFLAGS)

toxav_basic_test_LDADD = $(AUTOTEST_LDADD) $(AV_LIBS)


toxav_many_test_SOURCES = ../auto_tests/toxav_many_test.c

toxav_many_test_CFLAGS = $(AUTOTEST_CFLAGS)

toxav_many_test_LDADD = $(AUTOTEST_LDADD)
endif

endif


encryptsave_test_SOURCES = ../auto_tests/encryptsave_test.c

encryptsave_test_CFLAGS = $(AUTOTEST_CFLAGS)

encryptsave_test_LDADD = $(AUTOTEST_LDADD)


tox_strncasecmp_test_SOURCES = ../auto_tests/tox_strncasecmp_test.c

tox_strncasecmp_test_CFLAGS = $(AUTOTEST_CFLAGS)

tox_strncasecmp_test_LDADD = $(AUTOTEST_LDADD)


EXTRA_DIST += $(top_srcdir)/auto_tests/helpers.h
