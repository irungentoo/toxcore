/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_STRUCT_H
#define C_TOXCORE_TOXCORE_TOX_STRUCT_H

#include <pthread.h>

#include "mono_time.h"
#include "tox.h"
#include "tox_options.h" // tox_log_cb
#include "tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox {
    struct Logger *_Nonnull log;
    struct Messenger *_Nonnull m;
    Mono_Time *_Nonnull mono_time;
    Tox_System sys;
    pthread_mutex_t *_Nullable mutex;

    tox_log_cb *_Nullable log_callback;
    tox_self_connection_status_cb *_Nullable self_connection_status_callback;
    tox_friend_name_cb *_Nullable friend_name_callback;
    tox_friend_status_message_cb *_Nullable friend_status_message_callback;
    tox_friend_status_cb *_Nullable friend_status_callback;
    tox_friend_connection_status_cb *_Nullable friend_connection_status_callback;
    tox_friend_typing_cb *_Nullable friend_typing_callback;
    tox_friend_read_receipt_cb *_Nullable friend_read_receipt_callback;
    tox_friend_request_cb *_Nullable friend_request_callback;
    tox_friend_message_cb *_Nullable friend_message_callback;
    tox_file_recv_control_cb *_Nullable file_recv_control_callback;
    tox_file_chunk_request_cb *_Nullable file_chunk_request_callback;
    tox_file_recv_cb *_Nullable file_recv_callback;
    tox_file_recv_chunk_cb *_Nullable file_recv_chunk_callback;
    tox_conference_invite_cb *_Nullable conference_invite_callback;
    tox_conference_connected_cb *_Nullable conference_connected_callback;
    tox_conference_message_cb *_Nullable conference_message_callback;
    tox_conference_title_cb *_Nullable conference_title_callback;
    tox_conference_peer_name_cb *_Nullable conference_peer_name_callback;
    tox_conference_peer_list_changed_cb *_Nullable conference_peer_list_changed_callback;
    tox_dht_nodes_response_cb *_Nullable dht_nodes_response_callback;
    tox_friend_lossy_packet_cb *_Nullable friend_lossy_packet_callback_per_pktid[UINT8_MAX + 1];
    tox_friend_lossless_packet_cb *_Nullable friend_lossless_packet_callback_per_pktid[UINT8_MAX + 1];
    tox_group_peer_name_cb *_Nullable group_peer_name_callback;
    tox_group_peer_status_cb *_Nullable group_peer_status_callback;
    tox_group_topic_cb *_Nullable group_topic_callback;
    tox_group_privacy_state_cb *_Nullable group_privacy_state_callback;
    tox_group_topic_lock_cb *_Nullable group_topic_lock_callback;
    tox_group_voice_state_cb *_Nullable group_voice_state_callback;
    tox_group_peer_limit_cb *_Nullable group_peer_limit_callback;
    tox_group_password_cb *_Nullable group_password_callback;
    tox_group_message_cb *_Nullable group_message_callback;
    tox_group_private_message_cb *_Nullable group_private_message_callback;
    tox_group_custom_packet_cb *_Nullable group_custom_packet_callback;
    tox_group_custom_private_packet_cb *_Nullable group_custom_private_packet_callback;
    tox_group_invite_cb *_Nullable group_invite_callback;
    tox_group_peer_join_cb *_Nullable group_peer_join_callback;
    tox_group_peer_exit_cb *_Nullable group_peer_exit_callback;
    tox_group_self_join_cb *_Nullable group_self_join_callback;
    tox_group_join_fail_cb *_Nullable group_join_fail_callback;
    tox_group_moderation_cb *_Nullable group_moderation_callback;

    void *_Nullable toxav_object; // workaround to store a ToxAV object (setter and getter functions are available)
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_STRUCT_H */
