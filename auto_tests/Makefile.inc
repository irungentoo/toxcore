if BUILD_TESTS

LOG_COMPILER = $(top_srcdir)/tools/test-wrapper.sh
AM_LOG_FLAGS = --timeout 60 --retries 3

noinst_LTLIBRARIES += libauto_test_support.la
libauto_test_support_la_SOURCES = ../auto_tests/auto_test_support.c ../auto_tests/auto_test_support.h
libauto_test_support_la_LIBADD = libmisc_tools.la libtoxcore.la

noinst_LTLIBRARIES += libscenario_framework.la
libscenario_framework_la_SOURCES = ../auto_tests/scenarios/framework/framework.c ../auto_tests/scenarios/framework/framework.h
libscenario_framework_la_LIBADD = libmisc_tools.la libtoxcore.la

TESTS = \
    announce_test \
	crypto_test \
	encryptsave_test \
	file_saving_test \
	forwarding_test \
	invalid_tcp_proxy_test \
	invalid_udp_proxy_test \
	network_test \
	onion_test \
	save_compatibility_test \
	scenario_avatar_test \
	scenario_bootstrap_test \
	scenario_conference_double_invite_test \
	scenario_conference_invite_merge_test \
	scenario_conference_offline_test \
	scenario_conference_peer_nick_test \
	scenario_conference_query_test \
	scenario_conference_simple_test \
	scenario_conference_test \
	scenario_conference_two_test \
	scenario_dht_nodes_response_api_test \
	scenario_events_test \
	scenario_file_cancel_test \
	scenario_file_seek_test \
	scenario_file_transfer_test \
	scenario_friend_connection_test \
	scenario_friend_delete_test \
	scenario_friend_query_test \
	scenario_friend_read_receipt_test \
	scenario_friend_request_spam_test \
	scenario_friend_request_test \
	scenario_group_by_id_test \
	scenario_group_general_test \
	scenario_group_invite_test \
	scenario_group_message_test \
	scenario_group_moderation_test \
	scenario_group_save_test \
	scenario_group_state_test \
	scenario_group_sync_test \
	scenario_group_tcp_test \
	scenario_group_topic_test \
	scenario_lossless_packet_test \
	scenario_lossy_packet_test \
	scenario_message_test \
	scenario_netprof_test \
	scenario_nospam_test \
	scenario_overflow_recvq_test \
	scenario_overflow_sendq_test \
	scenario_reconnect_test \
	scenario_save_friend_test \
	scenario_save_load_test \
	scenario_self_query_test \
	scenario_send_message_test \
	scenario_set_name_test \
	scenario_set_status_message_test \
	scenario_tox_many_test \
	scenario_tox_many_tcp_test \
	scenario_typing_test \
	scenario_user_status_test \
	tcp_relay_test \
	TCP_test \
	tox_dispatch_test \
	tox_new_test \
	tox_strncasecmp_test \
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
TESTS += scenario_conference_av_test scenario_toxav_basic_test scenario_toxav_many_test
AUTOTEST_LDADD += libtoxav.la
endif

check_PROGRAMS = $(TESTS)

announce_test_SOURCES = ../auto_tests/announce_test.c
announce_test_CFLAGS = $(AUTOTEST_CFLAGS)
announce_test_LDADD = $(AUTOTEST_LDADD)

crypto_test_SOURCES = ../auto_tests/crypto_test.c
crypto_test_CFLAGS = $(AUTOTEST_CFLAGS)
crypto_test_LDADD = $(AUTOTEST_LDADD)

encryptsave_test_SOURCES = ../auto_tests/encryptsave_test.c
encryptsave_test_CFLAGS = $(AUTOTEST_CFLAGS)
encryptsave_test_LDADD = $(AUTOTEST_LDADD)

file_saving_test_SOURCES = ../auto_tests/file_saving_test.c
file_saving_test_CFLAGS = $(AUTOTEST_CFLAGS)
file_saving_test_LDADD = $(AUTOTEST_LDADD)

forwarding_test_SOURCES = ../auto_tests/forwarding_test.c
forwarding_test_CFLAGS = $(AUTOTEST_CFLAGS)
forwarding_test_LDADD = $(AUTOTEST_LDADD)

invalid_tcp_proxy_test_SOURCES = ../auto_tests/invalid_tcp_proxy_test.c
invalid_tcp_proxy_test_CFLAGS = $(AUTOTEST_CFLAGS)
invalid_tcp_proxy_test_LDADD = $(AUTOTEST_LDADD)

invalid_udp_proxy_test_SOURCES = ../auto_tests/invalid_udp_proxy_test.c
invalid_udp_proxy_test_CFLAGS = $(AUTOTEST_CFLAGS)
invalid_udp_proxy_test_LDADD = $(AUTOTEST_LDADD)

network_test_SOURCES = ../auto_tests/network_test.c
network_test_CFLAGS = $(AUTOTEST_CFLAGS)
network_test_LDADD = $(AUTOTEST_LDADD)

onion_test_SOURCES = ../auto_tests/onion_test.c
onion_test_CFLAGS = $(AUTOTEST_CFLAGS)
onion_test_LDADD = $(AUTOTEST_LDADD)

save_compatibility_test_SOURCES = ../auto_tests/save_compatibility_test.c
save_compatibility_test_CFLAGS = $(AUTOTEST_CFLAGS)
save_compatibility_test_LDADD = $(AUTOTEST_LDADD)

tcp_relay_test_SOURCES = ../auto_tests/tcp_relay_test.c
tcp_relay_test_CFLAGS = $(AUTOTEST_CFLAGS)
tcp_relay_test_LDADD = $(AUTOTEST_LDADD)

tox_new_test_SOURCES = ../auto_tests/tox_new_test.c
tox_new_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_new_test_LDADD = $(AUTOTEST_LDADD)

scenario_avatar_test_SOURCES = ../auto_tests/scenarios/scenario_avatar_test.c
scenario_avatar_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_avatar_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_simple_test_SOURCES = ../auto_tests/scenarios/scenario_conference_simple_test.c
scenario_conference_simple_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_simple_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_offline_test_SOURCES = ../auto_tests/scenarios/scenario_conference_offline_test.c
scenario_conference_offline_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_offline_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_query_test_SOURCES = ../auto_tests/scenarios/scenario_conference_query_test.c
scenario_conference_query_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_query_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_double_invite_test_SOURCES = ../auto_tests/scenarios/scenario_conference_double_invite_test.c
scenario_conference_double_invite_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_double_invite_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_invite_merge_test_SOURCES = ../auto_tests/scenarios/scenario_conference_invite_merge_test.c
scenario_conference_invite_merge_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_invite_merge_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_peer_nick_test_SOURCES = ../auto_tests/scenarios/scenario_conference_peer_nick_test.c
scenario_conference_peer_nick_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_peer_nick_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_av_test_SOURCES = ../auto_tests/scenarios/scenario_conference_av_test.c
scenario_conference_av_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_av_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_bootstrap_test_SOURCES = ../auto_tests/scenarios/scenario_bootstrap_test.c
scenario_bootstrap_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_bootstrap_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_test_SOURCES = ../auto_tests/scenarios/scenario_conference_test.c
scenario_conference_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_conference_two_test_SOURCES = ../auto_tests/scenarios/scenario_conference_two_test.c
scenario_conference_two_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_conference_two_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_dht_nodes_response_api_test_SOURCES = ../auto_tests/scenarios/scenario_dht_nodes_response_api_test.c
scenario_dht_nodes_response_api_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_dht_nodes_response_api_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_events_test_SOURCES = ../auto_tests/scenarios/scenario_events_test.c
scenario_events_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_events_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_file_cancel_test_SOURCES = ../auto_tests/scenarios/scenario_file_cancel_test.c
scenario_file_cancel_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_file_cancel_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_file_seek_test_SOURCES = ../auto_tests/scenarios/scenario_file_seek_test.c
scenario_file_seek_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_file_seek_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_file_transfer_test_SOURCES = ../auto_tests/scenarios/scenario_file_transfer_test.c
scenario_file_transfer_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_file_transfer_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_connection_test_SOURCES = ../auto_tests/scenarios/scenario_friend_connection_test.c
scenario_friend_connection_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_connection_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_request_test_SOURCES = ../auto_tests/scenarios/scenario_friend_request_test.c
scenario_friend_request_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_request_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_delete_test_SOURCES = ../auto_tests/scenarios/scenario_friend_delete_test.c
scenario_friend_delete_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_delete_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_query_test_SOURCES = ../auto_tests/scenarios/scenario_friend_query_test.c
scenario_friend_query_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_query_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_read_receipt_test_SOURCES = ../auto_tests/scenarios/scenario_friend_read_receipt_test.c
scenario_friend_read_receipt_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_read_receipt_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_friend_request_spam_test_SOURCES = ../auto_tests/scenarios/scenario_friend_request_spam_test.c
scenario_friend_request_spam_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_friend_request_spam_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_by_id_test_SOURCES = ../auto_tests/scenarios/scenario_group_by_id_test.c
scenario_group_by_id_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_by_id_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_general_test_SOURCES = ../auto_tests/scenarios/scenario_group_general_test.c
scenario_group_general_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_general_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_invite_test_SOURCES = ../auto_tests/scenarios/scenario_group_invite_test.c
scenario_group_invite_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_invite_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_message_test_SOURCES = ../auto_tests/scenarios/scenario_group_message_test.c
scenario_group_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_message_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_moderation_test_SOURCES = ../auto_tests/scenarios/scenario_group_moderation_test.c
scenario_group_moderation_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_moderation_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_save_test_SOURCES = ../auto_tests/scenarios/scenario_group_save_test.c
scenario_group_save_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_save_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_state_test_SOURCES = ../auto_tests/scenarios/scenario_group_state_test.c
scenario_group_state_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_state_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_sync_test_SOURCES = ../auto_tests/scenarios/scenario_group_sync_test.c
scenario_group_sync_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_sync_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_tcp_test_SOURCES = ../auto_tests/scenarios/scenario_group_tcp_test.c
scenario_group_tcp_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_tcp_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_group_topic_test_SOURCES = ../auto_tests/scenarios/scenario_group_topic_test.c
scenario_group_topic_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_group_topic_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

# A bit flaky, and autotools doesn't do retries.
# scenario_lan_discovery_test_SOURCES = ../auto_tests/scenarios/scenario_lan_discovery_test.c
# scenario_lan_discovery_test_CFLAGS = $(AUTOTEST_CFLAGS)
# scenario_lan_discovery_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_lossless_packet_test_SOURCES = ../auto_tests/scenarios/scenario_lossless_packet_test.c
scenario_lossless_packet_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_lossless_packet_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_lossy_packet_test_SOURCES = ../auto_tests/scenarios/scenario_lossy_packet_test.c
scenario_lossy_packet_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_lossy_packet_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_message_test_SOURCES = ../auto_tests/scenarios/scenario_message_test.c
scenario_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_message_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_netprof_test_SOURCES = ../auto_tests/scenarios/scenario_netprof_test.c
scenario_netprof_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_netprof_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_nospam_test_SOURCES = ../auto_tests/scenarios/scenario_nospam_test.c
scenario_nospam_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_nospam_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_reconnect_test_SOURCES = ../auto_tests/scenarios/scenario_reconnect_test.c
scenario_reconnect_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_reconnect_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_save_friend_test_SOURCES = ../auto_tests/scenarios/scenario_save_friend_test.c
scenario_save_friend_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_save_friend_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_self_query_test_SOURCES = ../auto_tests/scenarios/scenario_self_query_test.c
scenario_self_query_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_self_query_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_overflow_recvq_test_SOURCES = ../auto_tests/scenarios/scenario_overflow_recvq_test.c
scenario_overflow_recvq_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_overflow_recvq_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_overflow_sendq_test_SOURCES = ../auto_tests/scenarios/scenario_overflow_sendq_test.c
scenario_overflow_sendq_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_overflow_sendq_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_save_load_test_SOURCES = ../auto_tests/scenarios/scenario_save_load_test.c
scenario_save_load_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_save_load_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_send_message_test_SOURCES = ../auto_tests/scenarios/scenario_send_message_test.c
scenario_send_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_send_message_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_set_name_test_SOURCES = ../auto_tests/scenarios/scenario_set_name_test.c
scenario_set_name_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_set_name_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_set_status_message_test_SOURCES = ../auto_tests/scenarios/scenario_set_status_message_test.c
scenario_set_status_message_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_set_status_message_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_tox_many_test_SOURCES = ../auto_tests/scenarios/scenario_tox_many_test.c
scenario_tox_many_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_tox_many_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_tox_many_tcp_test_SOURCES = ../auto_tests/scenarios/scenario_tox_many_tcp_test.c
scenario_tox_many_tcp_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_tox_many_tcp_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_typing_test_SOURCES = ../auto_tests/scenarios/scenario_typing_test.c
scenario_typing_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_typing_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_user_status_test_SOURCES = ../auto_tests/scenarios/scenario_user_status_test.c
scenario_user_status_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_user_status_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

TCP_test_SOURCES = ../auto_tests/TCP_test.c
TCP_test_CFLAGS = $(AUTOTEST_CFLAGS)
TCP_test_LDADD = $(AUTOTEST_LDADD)

tox_dispatch_test_SOURCES = ../auto_tests/tox_dispatch_test.c
tox_dispatch_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_dispatch_test_LDADD = $(AUTOTEST_LDADD)

tox_strncasecmp_test_SOURCES = ../auto_tests/tox_strncasecmp_test.c
tox_strncasecmp_test_CFLAGS = $(AUTOTEST_CFLAGS)
tox_strncasecmp_test_LDADD = $(AUTOTEST_LDADD)

version_test_SOURCES = ../auto_tests/version_test.c
version_test_CFLAGS = $(AUTOTEST_CFLAGS)
version_test_LDADD = $(AUTOTEST_LDADD)

if BUILD_AV

scenario_toxav_basic_test_SOURCES = ../auto_tests/scenarios/scenario_toxav_basic_test.c
scenario_toxav_basic_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_toxav_basic_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

scenario_toxav_many_test_SOURCES = ../auto_tests/scenarios/scenario_toxav_many_test.c
scenario_toxav_many_test_CFLAGS = $(AUTOTEST_CFLAGS)
scenario_toxav_many_test_LDADD = $(AUTOTEST_LDADD) libscenario_framework.la

endif

endif


EXTRA_DIST += \
	$(top_srcdir)/auto_tests/data/save.tox.big \
	$(top_srcdir)/auto_tests/data/save.tox.little \
	$(top_srcdir)/auto_tests/check_compat.h \
	$(top_srcdir)/auto_tests/auto_test_support.h \
	$(top_srcdir)/auto_tests/scenarios/framework/framework.h
