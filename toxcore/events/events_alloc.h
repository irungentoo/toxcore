/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H
#define C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_event.h"
#include "../tox_events.h"
#include "../tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_Events {
    Tox_Event *events;
    uint32_t events_size;
    uint32_t events_capacity;

    const Memory *mem;
};

typedef struct Tox_Events_State {
    Tox_Err_Events_Iterate error;
    const Memory *mem;
    Tox_Events *events;
} Tox_Events_State;

tox_conference_connected_cb tox_events_handle_conference_connected;
tox_conference_invite_cb tox_events_handle_conference_invite;
tox_conference_message_cb tox_events_handle_conference_message;
tox_conference_peer_list_changed_cb tox_events_handle_conference_peer_list_changed;
tox_conference_peer_name_cb tox_events_handle_conference_peer_name;
tox_conference_title_cb tox_events_handle_conference_title;
tox_dht_get_nodes_response_cb tox_events_handle_dht_get_nodes_response;
tox_file_chunk_request_cb tox_events_handle_file_chunk_request;
tox_file_recv_cb tox_events_handle_file_recv;
tox_file_recv_chunk_cb tox_events_handle_file_recv_chunk;
tox_file_recv_control_cb tox_events_handle_file_recv_control;
tox_friend_connection_status_cb tox_events_handle_friend_connection_status;
tox_friend_lossless_packet_cb tox_events_handle_friend_lossless_packet;
tox_friend_lossy_packet_cb tox_events_handle_friend_lossy_packet;
tox_friend_message_cb tox_events_handle_friend_message;
tox_friend_name_cb tox_events_handle_friend_name;
tox_friend_read_receipt_cb tox_events_handle_friend_read_receipt;
tox_friend_request_cb tox_events_handle_friend_request;
tox_friend_status_cb tox_events_handle_friend_status;
tox_friend_status_message_cb tox_events_handle_friend_status_message;
tox_friend_typing_cb tox_events_handle_friend_typing;
tox_self_connection_status_cb tox_events_handle_self_connection_status;
tox_group_peer_name_cb tox_events_handle_group_peer_name;
tox_group_peer_status_cb tox_events_handle_group_peer_status;
tox_group_topic_cb tox_events_handle_group_topic;
tox_group_privacy_state_cb tox_events_handle_group_privacy_state;
tox_group_voice_state_cb tox_events_handle_group_voice_state;
tox_group_topic_lock_cb tox_events_handle_group_topic_lock;
tox_group_peer_limit_cb tox_events_handle_group_peer_limit;
tox_group_password_cb tox_events_handle_group_password;
tox_group_message_cb tox_events_handle_group_message;
tox_group_private_message_cb tox_events_handle_group_private_message;
tox_group_custom_packet_cb tox_events_handle_group_custom_packet;
tox_group_custom_private_packet_cb tox_events_handle_group_custom_private_packet;
tox_group_invite_cb tox_events_handle_group_invite;
tox_group_peer_join_cb tox_events_handle_group_peer_join;
tox_group_peer_exit_cb tox_events_handle_group_peer_exit;
tox_group_self_join_cb tox_events_handle_group_self_join;
tox_group_join_fail_cb tox_events_handle_group_join_fail;
tox_group_moderation_cb tox_events_handle_group_moderation;

non_null()
Tox_Events_State *tox_events_alloc(void *user_data);

non_null()
bool tox_events_add(Tox_Events *events, const Tox_Event *event);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H */
