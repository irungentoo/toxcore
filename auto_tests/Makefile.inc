if BUILD_TESTS

TESTS = bootstrap_test conference_double_invite_test conference_peer_nick_test conference_simple_test conference_test \
        conference_two_test crypto_test dht_test encryptsave_test file_saving_test file_transfer_test friend_connection_test \
        friend_request_test invalid_tcp_proxy_test invalid_udp_proxy_test lan_discovery_test lossless_packet_test \
        lossy_packet_test messenger_test network_test onion_test overflow_recvq_test overflow_sendq_test save_friend_test \
        save_load_test send_message_test set_name_test set_status_message_test skeleton_test tcp_relay_test TCP_test \
        tox_many_tcp_test tox_many_test tox_one_test tox_strncasecmp_test typing_test version_test

check_PROGRAMS = bootstrap_test conference_double_invite_test conference_peer_nick_test conference_simple_test \
                 conference_test conference_two_test crypto_test dht_test encryptsave_test file_saving_test file_transfer_test \
                 friend_connection_test friend_request_test invalid_tcp_proxy_test invalid_udp_proxy_test lan_discovery_test \
                 lossless_packet_test lossy_packet_test messenger_test network_test onion_test overflow_recvq_test \
                 overflow_sendq_test save_friend_test save_load_test send_message_test set_name_test set_status_message_test \
                 skeleton_test tcp_relay_test TCP_test tox_many_tcp_test tox_many_test tox_one_test tox_strncasecmp_test \
                 typing_test version_test

AUTOTEST_CFLAGS = \
                         $(LIBSODIUM_CFLAGS) \
                         $(NACL_CFLAGS)

AUTOTEST_LDADD = \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        libmisc_tools.la \
                        libtoxcore.la \
                        libtoxencryptsave.la \
                        $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS)



if BUILD_AV
TESTS += toxav_basic_test toxav_many_test
check_PROGRAMS += toxav_basic_test toxav_many_test
AUTOTEST_LDADD += libtoxav.la
endif

bootstrap_test_SOURCES = ../auto_tests/bootstrap_test.c
bootstrap_test_CFLAGS = $(AUTO_TEST_CFLAGS)
bootstrap_test_LDADD = $(AUTOTEST_LDADD)

conference_double_invite_test_SOURCES = ../auto_tests/bootstrap_test.c
conference_double_invite_test_CFLAGS = $(AUTO_TEST_CFLAGS)
conference_double_invite_test_LDADD = $(AUTOTEST_LDADD)

conference_peer_nick_test_SOURCES = ../auto_tests/bootstrap_test.c
conference_peer_nick_test_CFLAGS = $(AUTO_TEST_CFLAGS)
conference_peer_nick_test_LDADD = $(AUTOTEST_LDADD)

conference_simple_test_SOURCES = ../auto_tests/bootstrap_test.c
conference_simple_test_CFLAGS = $(AUTO_TEST_CFLAGS)
conference_simple_test_LDADD = $(AUTOTEST_LDADD)

conference_test_SOURCES = ../auto_tests/bootstrap_test.c
conference_test_CFLAGS = $(AUTO_TEST_CFLAGS)
conference_test_LDADD = $(AUTOTEST_LDADD)

conference_two_test_SOURCES = ../auto_tests/bootstrap_test.c
conference_two_test_CFLAGS = $(AUTO_TEST_CFLAGS)
conference_two_test_LDADD = $(AUTOTEST_LDADD)

crypto_test_SOURCES = ../auto_tests/bootstrap_test.c
crypto_test_CFLAGS = $(AUTO_TEST_CFLAGS)
crypto_test_LDADD = $(AUTOTEST_LDADD)

dht_test_SOURCES = ../auto_tests/bootstrap_test.c
dht_test_CFLAGS = $(AUTO_TEST_CFLAGS)
dht_test_LDADD = $(AUTOTEST_LDADD)

encryptsave_test_SOURCES = ../auto_tests/bootstrap_test.c
encryptsave_test_CFLAGS = $(AUTO_TEST_CFLAGS)
encryptsave_test_LDADD = $(AUTOTEST_LDADD)

file_saving_test_SOURCES = ../auto_tests/bootstrap_test.c
file_saving_test_CFLAGS = $(AUTO_TEST_CFLAGS)
file_saving_test_LDADD = $(AUTOTEST_LDADD)

file_transfer_test_SOURCES = ../auto_tests/bootstrap_test.c
file_transfer_test_CFLAGS = $(AUTO_TEST_CFLAGS)
file_transfer_test_LDADD = $(AUTOTEST_LDADD)

friend_connection_test_SOURCES = ../auto_tests/bootstrap_test.c
friend_connection_test_CFLAGS = $(AUTO_TEST_CFLAGS)
friend_connection_test_LDADD = $(AUTOTEST_LDADD)

friend_request_test_SOURCES = ../auto_tests/bootstrap_test.c
friend_request_test_CFLAGS = $(AUTO_TEST_CFLAGS)
friend_request_test_LDADD = $(AUTOTEST_LDADD)

invalid_tcp_proxy_test_SOURCES = ../auto_tests/bootstrap_test.c
invalid_tcp_proxy_test_CFLAGS = $(AUTO_TEST_CFLAGS)
invalid_tcp_proxy_test_LDADD = $(AUTOTEST_LDADD)

invalid_udp_proxy_test_SOURCES = ../auto_tests/bootstrap_test.c
invalid_udp_proxy_test_CFLAGS = $(AUTO_TEST_CFLAGS)
invalid_udp_proxy_test_LDADD = $(AUTOTEST_LDADD)

lan_discovery_test_SOURCES = ../auto_tests/bootstrap_test.c
lan_discovery_test_CFLAGS = $(AUTO_TEST_CFLAGS)
lan_discovery_test_LDADD = $(AUTOTEST_LDADD)

lossless_packet_test_SOURCES = ../auto_tests/bootstrap_test.c
lossless_packet_test_CFLAGS = $(AUTO_TEST_CFLAGS)
lossless_packet_test_LDADD = $(AUTOTEST_LDADD)

lossy_packet_test_SOURCES = ../auto_tests/bootstrap_test.c
lossy_packet_test_CFLAGS = $(AUTO_TEST_CFLAGS)
lossy_packet_test_LDADD = $(AUTOTEST_LDADD)

messenger_test_SOURCES = ../auto_tests/bootstrap_test.c
messenger_test_CFLAGS = $(AUTO_TEST_CFLAGS)
messenger_test_LDADD = $(AUTOTEST_LDADD)

network_test_SOURCES = ../auto_tests/bootstrap_test.c
network_test_CFLAGS = $(AUTO_TEST_CFLAGS)
network_test_LDADD = $(AUTOTEST_LDADD)

onion_test_SOURCES = ../auto_tests/bootstrap_test.c
onion_test_CFLAGS = $(AUTO_TEST_CFLAGS)
onion_test_LDADD = $(AUTOTEST_LDADD)

overflow_recvq_test_SOURCES = ../auto_tests/bootstrap_test.c
overflow_recvq_test_CFLAGS = $(AUTO_TEST_CFLAGS)
overflow_recvq_test_LDADD = $(AUTOTEST_LDADD)

overflow_sendq_test_SOURCES = ../auto_tests/bootstrap_test.c
overflow_sendq_test_CFLAGS = $(AUTO_TEST_CFLAGS)
overflow_sendq_test_LDADD = $(AUTOTEST_LDADD)

save_friend_test_SOURCES = ../auto_tests/bootstrap_test.c
save_friend_test_CFLAGS = $(AUTO_TEST_CFLAGS)
save_friend_test_LDADD = $(AUTOTEST_LDADD)

save_load_test_SOURCES = ../auto_tests/bootstrap_test.c
save_load_test_CFLAGS = $(AUTO_TEST_CFLAGS)
save_load_test_LDADD = $(AUTOTEST_LDADD)

send_message_test_SOURCES = ../auto_tests/bootstrap_test.c
send_message_test_CFLAGS = $(AUTO_TEST_CFLAGS)
send_message_test_LDADD = $(AUTOTEST_LDADD)

set_name_test_SOURCES = ../auto_tests/bootstrap_test.c
set_name_test_CFLAGS = $(AUTO_TEST_CFLAGS)
set_name_test_LDADD = $(AUTOTEST_LDADD)

set_status_message_test_SOURCES = ../auto_tests/bootstrap_test.c
set_status_message_test_CFLAGS = $(AUTO_TEST_CFLAGS)
set_status_message_test_LDADD = $(AUTOTEST_LDADD)

skeleton_test_SOURCES = ../auto_tests/bootstrap_test.c
skeleton_test_CFLAGS = $(AUTO_TEST_CFLAGS)
skeleton_test_LDADD = $(AUTOTEST_LDADD)

tcp_relay_test_SOURCES = ../auto_tests/bootstrap_test.c
tcp_relay_test_CFLAGS = $(AUTO_TEST_CFLAGS)
tcp_relay_test_LDADD = $(AUTOTEST_LDADD)

TCP_test_SOURCES = ../auto_tests/bootstrap_test.c
TCP_test_CFLAGS = $(AUTO_TEST_CFLAGS)
TCP_test_LDADD = $(AUTOTEST_LDADD)

tox_many_tcp_test_SOURCES = ../auto_tests/bootstrap_test.c
tox_many_tcp_test_CFLAGS = $(AUTO_TEST_CFLAGS)
tox_many_tcp_test_LDADD = $(AUTOTEST_LDADD)

tox_many_test_SOURCES = ../auto_tests/bootstrap_test.c
tox_many_test_CFLAGS = $(AUTO_TEST_CFLAGS)
tox_many_test_LDADD = $(AUTOTEST_LDADD)

tox_one_test_SOURCES = ../auto_tests/bootstrap_test.c
tox_one_test_CFLAGS = $(AUTO_TEST_CFLAGS)
tox_one_test_LDADD = $(AUTOTEST_LDADD)

tox_strncasecmp_test_SOURCES = ../auto_tests/bootstrap_test.c
tox_strncasecmp_test_CFLAGS = $(AUTO_TEST_CFLAGS)
tox_strncasecmp_test_LDADD = $(AUTOTEST_LDADD)

typing_test_SOURCES = ../auto_tests/bootstrap_test.c
typing_test_CFLAGS = $(AUTO_TEST_CFLAGS)
typing_test_LDADD = $(AUTOTEST_LDADD)

version_test_SOURCES = ../auto_tests/bootstrap_test.c
version_test_CFLAGS = $(AUTO_TEST_CFLAGS)
version_test_LDADD = $(AUTOTEST_LDADD)

if BUILD_AV

toxav_basic_test_SOURCES = ../auto_tests/toxav_basic_test.c
toxav_basic_test_CFLAGS = $(AUTOTEST_CFLAGS)
toxav_basic_test_LDADD = $(AUTOTEST_LDADD) $(AV_LIBS)

toxav_many_test_SOURCES = ../auto_tests/toxav_many_test.c
toxav_many_test_CFLAGS = $(AUTOTEST_CFLAGS)
toxav_many_test_LDADD = $(AUTOTEST_LDADD)

endif

endif


EXTRA_DIST += $(top_srcdir)/auto_tests/check_compat.h
