if BUILD_TESTS

noinst_LTLIBRARIES += libauto_test_support.la
libauto_test_support_la_SOURCES = ../auto_tests/auto_test_support.c ../auto_tests/auto_test_support.h
libauto_test_support_la_LIBADD = libmisc_tools.la libtoxcore.la

TESTS = \
    announce_test \
	conference_double_invite_test \
	conference_invite_merge_test \
	conference_peer_nick_test \
	conference_simple_test \
	conference_test \
	conference_two_test \
	crypto_test \
	encryptsave_test \
	file_saving_test \
	file_streaming_test \
	file_transfer_test \
	forwarding_test \
	friend_connection_test \
	friend_request_test \
	group_state_test \
	invalid_tcp_proxy_test \
	invalid_udp_proxy_test \
	lan_discovery_test \
	lossless_packet_test \
	lossy_packet_test \
	network_test \
	onion_test \
	overflow_recvq_test \
	overflow_sendq_test \
	reconnect_test \
	save_compatibility_test \
	save_friend_test \
	send_message_test \
	set_name_test \
	set_status_message_test \
	TCP_test \
	tox_dispatch_test \
	tox_events_test \
	tox_many_tcp_test \
	tox_many_test \
	tox_strncasecmp_test \
	typing_test \
	version_test

AUTOTEST_CFLAGS = \
	$(LIBSODIUM_CFLAGS)

AUTOTEST_LDADD = \
	$(LIBSODIUM_LDFLAGS) \
	libmisc_tools.la \
	libauto_test_support.la \
	libtoxcore.la \
	libtoxencryptsave.la \
	$(LIBSODIUM_LIBS)


if BUILD_AV
TESTS += conference_av_test toxav_basic_test toxav_many_test
AUTOTEST_LDADD += libtoxav.la
endif

check_PROGRAMS = $(TESTS)

announce_test_SOURCES = ../auto_tests/announce_test.c
announce_test_CFLAGS = $(AUTOTEST_CFLAGS)
announce_test_LDADD = $(AUTOTEST_LDADD)

conference_double_invite_test_SOURCES = ../auto_tests/conference_double_invite_test.c
conference_double_invite_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_double_invite_test_LDADD = $(AUTOTEST_LDADD)

conference_invite_merge_test_SOURCES = ../auto_tests/conference_invite_merge_test.c
conference_invite_merge_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_invite_merge_test_LDADD = $(AUTOTEST_LDADD)

conference_peer_nick_test_SOURCES = ../auto_tests/conference_peer_nick_test.c
conference_peer_nick_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_peer_nick_test_LDADD = $(AUTOTEST_LDADD)

conference_simple_test_SOURCES = ../auto_tests/conference_simple_test.c
conference_simple_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_simple_test_LDADD = $(AUTOTEST_LDADD)

conference_test_SOURCES = ../auto_tests/conference_test.c
conference_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_test_LDADD = $(AUTOTEST_LDADD)

conference_two_test_SOURCES = ../auto_tests/conference_two_test.c
conference_two_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_two_test_LDADD = $(AUTOTEST_LDADD)

crypto_test_SOURCES = ../auto_tests/crypto_test.c
crypto_test_CFLAGS = $(AUTOTEST_CFLAGS)
crypto_test_LDADD = $(AUTOTEST_LDADD)

encryptsave_test_SOURCES = ../auto_tests/encryptsave_test.c
encryptsave_test_CFLAGS = $(AUTOTEST_CFLAGS)
encryptsave_test_LDADD = $(AUTOTEST_LDADD)

file_saving_test_SOURCES = ../auto_tests/file_saving_test.c
file_saving_test_CFLAGS = $(AUTOTEST_CFLAGS)
file_saving_test_LDADD = $(AUTOTEST_LDADD)

file_streaming_test_SOURCES = ../auto_tests/file_streaming_test.c
file_streaming_test_CFLAGS = $(AUTOTEST_CFLAGS)
file_streaming_test_LDADD = $(AUTOTEST_LDADD)

file_transfer_test_SOURCES = ../auto_tests/file_transfer_test.c
file_transfer_test_CFLAGS = $(AUTOTEST_CFLAGS)
file_transfer_test_LDADD = $(AUTOTEST_LDADD)

forwarding_test_SOURCES = ../auto_tests/forwarding_test.c
forwarding_test_CFLAGS = $(AUTOTEST_CFLAGS)
forwarding_test_LDADD = $(AUTOTEST_LDADD)

friend_connection_test_SOURCES = ../auto_tests/friend_connection_test.c
friend_connection_test_CFLAGS = $(AUTOTEST_CFLAGS)
friend_connection_test_LDADD = $(AUTOTEST_LDADD)

friend_request_test_SOURCES = ../auto_tests/friend_request_test.c
friend_request_test_CFLAGS = $(AUTOTEST_CFLAGS)
friend_request_test_LDADD = $(AUTOTEST_LDADD)

group_state_test_SOURCES = ../auto_tests/group_state_test.c
group_state_test_CFLAGS = $(AUTOTEST_CFLAGS)
group_state_test_LDADD = $(AUTOTEST_LDADD)

invalid_tcp_proxy_test_SOURCES = ../auto_tests/invalid_tcp_proxy_test.c
invalid_tcp_proxy_test_CFLAGS = $(AUTOTEST_CFLAGS)
invalid_tcp_proxy_test_LDADD = $(AUTOTEST_LDADD)

invalid_udp_proxy_test_SOURCES = ../auto_tests/invalid_udp_proxy_test.c
invalid_udp_proxy_test_CFLAGS = $(AUTOTEST_CFLAGS)
invalid_udp_proxy_test_LDADD = $(AUTOTEST_LDADD)

lan_discovery_test_SOURCES = ../auto_tests/lan_discovery_test.c
lan_discovery_test_CFLAGS = $(AUTOTEST_CFLAGS)
lan_discovery_test_LDADD = $(AUTOTEST_LDADD)

lossless_packet_test_SOURCES = ../auto_tests/lossless_packet_test.c
lossless_packet_test_CFLAGS = $(AUTOTEST_CFLAGS)
lossless_packet_test_LDADD = $(AUTOTEST_LDADD)

lossy_packet_test_SOURCES = ../auto_tests/lossy_packet_test.c
lossy_packet_test_CFLAGS = $(AUTOTEST_CFLAGS)
lossy_packet_test_LDADD = $(AUTOTEST_LDADD)

network_test_SOURCES = ../auto_tests/network_test.c
network_test_CFLAGS = $(AUTOTEST_CFLAGS)
network_test_LDADD = $(AUTOTEST_LDADD)

onion_test_SOURCES = ../auto_tests/onion_test.c
onion_test_CFLAGS = $(AUTOTEST_CFLAGS)
onion_test_LDADD = $(AUTOTEST_LDADD)

overflow_recvq_test_SOURCES = ../auto_tests/overflow_recvq_test.c
overflow_recvq_test_CFLAGS = $(AUTOTEST_CFLAGS)
overflow_recvq_test_LDADD = $(AUTOTEST_LDADD)

overflow_sendq_test_SOURCES = ../auto_tests/overflow_sendq_test.c
overflow_sendq_test_CFLAGS = $(AUTOTEST_CFLAGS)
overflow_sendq_test_LDADD = $(AUTOTEST_LDADD)

reconnect_test_SOURCES = ../auto_tests/reconnect_test.c
reconnect_test_CFLAGS = $(AUTO_TEST_CFLAGS)
reconnect_test_LDADD = $(AUTOTEST_LDADD)

save_compatibility_test_SOURCES = ../auto_tests/save_compatibility_test.c
save_compatibility_test_CFLAGS = $(AUTOTEST_CFLAGS)
save_compatibility_test_LDADD = $(AUTOTEST_LDADD)

save_friend_test_SOURCES = ../auto_tests/save_friend_test.c
save_friend_test_CFLAGS = $(AUTOTEST_CFLAGS)
save_friend_test_LDADD = $(AUTOTEST_LDADD)

send_message_test_SOURCES = ../auto_tests/send_message_test.c
send_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
send_message_test_LDADD = $(AUTOTEST_LDADD)

set_name_test_SOURCES = ../auto_tests/set_name_test.c
set_name_test_CFLAGS = $(AUTOTEST_CFLAGS)
set_name_test_LDADD = $(AUTOTEST_LDADD)

set_status_message_test_SOURCES = ../auto_tests/set_status_message_test.c
set_status_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
set_status_message_test_LDADD = $(AUTOTEST_LDADD)

TCP_test_SOURCES = ../auto_tests/TCP_test.c
TCP_test_CFLAGS = $(AUTOTEST_CFLAGS)
TCP_test_LDADD = $(AUTOTEST_LDADD)

tox_dispatch_test_SOURCES = ../auto_tests/tox_dispatch_test.c
tox_dispatch_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_dispatch_test_LDADD = $(AUTOTEST_LDADD)

tox_events_test_SOURCES = ../auto_tests/tox_events_test.c
tox_events_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_events_test_LDADD = $(AUTOTEST_LDADD)

tox_many_tcp_test_SOURCES = ../auto_tests/tox_many_tcp_test.c
tox_many_tcp_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_many_tcp_test_LDADD = $(AUTOTEST_LDADD)

tox_many_test_SOURCES = ../auto_tests/tox_many_test.c
tox_many_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_many_test_LDADD = $(AUTOTEST_LDADD)

tox_strncasecmp_test_SOURCES = ../auto_tests/tox_strncasecmp_test.c
tox_strncasecmp_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_strncasecmp_test_LDADD = $(AUTOTEST_LDADD)

typing_test_SOURCES = ../auto_tests/typing_test.c
typing_test_CFLAGS = $(AUTOTEST_CFLAGS)
typing_test_LDADD = $(AUTOTEST_LDADD)

version_test_SOURCES = ../auto_tests/version_test.c
version_test_CFLAGS = $(AUTOTEST_CFLAGS)
version_test_LDADD = $(AUTOTEST_LDADD)

if BUILD_AV

conference_av_test_SOURCES = ../auto_tests/conference_av_test.c
conference_av_test_CFLAGS = $(AUTOTEST_CFLAGS)
conference_av_test_LDADD = $(AUTOTEST_LDADD)

toxav_basic_test_SOURCES = ../auto_tests/toxav_basic_test.c
toxav_basic_test_CFLAGS = $(AUTOTEST_CFLAGS)
toxav_basic_test_LDADD = $(AUTOTEST_LDADD) $(AV_LIBS)

toxav_many_test_SOURCES = ../auto_tests/toxav_many_test.c
toxav_many_test_CFLAGS = $(AUTOTEST_CFLAGS)
toxav_many_test_LDADD = $(AUTOTEST_LDADD)

endif

endif


EXTRA_DIST += \
	$(top_srcdir)/auto_tests/data/save.tox.big \
	$(top_srcdir)/auto_tests/data/save.tox.little \
	$(top_srcdir)/auto_tests/check_compat.h \
	$(top_srcdir)/auto_tests/auto_test_support.h
