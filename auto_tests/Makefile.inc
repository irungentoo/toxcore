if BUILD_TESTS

TESTS = messenger_autotest# crypto_test network_test assoc_test onion_test TCP_test tox_test
check_PROGRAMS = messenger_autotest# crypto_test network_test assoc_test onion_test TCP_test tox_test

AUTOTEST_CFLAGS = \
                         $(LIBSODIUM_CFLAGS) \
                         $(NACL_CFLAGS) \
                         $(CHECK_CFLAGS)
 
AUTOTEST_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libtoxcore.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(CHECK_LIBS)



if BUILD_AV
TESTS += toxav_basic_test #toxav_many_test
check_PROGRAMS += toxav_basic_test #toxav_many_test
AUTOTEST_LDADD += libtoxav.la
endif

messenger_autotest_SOURCES = ../auto_tests/messenger_test.c

messenger_autotest_CFLAGS = $(AUTOTEST_CFLAGS)

messenger_autotest_LDADD = $(AUTOTEST_LDADD)






if BUILD_AV
toxav_basic_test_SOURCES = ../auto_tests/toxav_basic_test.c

toxav_basic_test_CFLAGS = $(AUTOTEST_CFLAGS)

toxav_basic_test_LDADD = $(AUTOTEST_LDADD)


#toxav_many_test_SOURCES = ../auto_tests/toxav_many_test.c

#toxav_many_test_CFLAGS = $(AUTOTEST_CFLAGS)

#toxav_many_test_LDADD = $(AUTOTEST_LDADD)
endif

endif

EXTRA_DIST +=           $(top_srcdir)/auto_tests/friends_test.c

