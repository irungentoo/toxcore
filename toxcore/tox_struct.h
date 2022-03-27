/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2022 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_STRUCT_H
#define C_TOXCORE_TOXCORE_TOX_STRUCT_H

#include "Messenger.h"
#include "tox.h"
#include "tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox {
    Messenger *m;
    Mono_Time *mono_time;
    Random rng;
    Network ns;
    pthread_mutex_t *mutex;

    tox_log_cb *log_callback;
    tox_self_connection_status_cb *self_connection_status_callback;
    tox_friend_name_cb *friend_name_callback;
    tox_friend_status_message_cb *friend_status_message_callback;
    tox_friend_status_cb *friend_status_callback;
    tox_friend_connection_status_cb *friend_connection_status_callback;
    tox_friend_typing_cb *friend_typing_callback;
    tox_friend_read_receipt_cb *friend_read_receipt_callback;
    tox_friend_request_cb *friend_request_callback;
    tox_friend_message_cb *friend_message_callback;
    tox_file_recv_control_cb *file_recv_control_callback;
    tox_file_chunk_request_cb *file_chunk_request_callback;
    tox_file_recv_cb *file_recv_callback;
    tox_file_recv_chunk_cb *file_recv_chunk_callback;
    tox_conference_invite_cb *conference_invite_callback;
    tox_conference_connected_cb *conference_connected_callback;
    tox_conference_message_cb *conference_message_callback;
    tox_conference_title_cb *conference_title_callback;
    tox_conference_peer_name_cb *conference_peer_name_callback;
    tox_conference_peer_list_changed_cb *conference_peer_list_changed_callback;
    tox_dht_get_nodes_response_cb *dht_get_nodes_response_callback;
    tox_friend_lossy_packet_cb *friend_lossy_packet_callback_per_pktid[UINT8_MAX + 1];
    tox_friend_lossless_packet_cb *friend_lossless_packet_callback_per_pktid[UINT8_MAX + 1];

    void *toxav_object; // workaround to store a ToxAV object (setter and getter functions are available)
};

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_STRUCT_H
