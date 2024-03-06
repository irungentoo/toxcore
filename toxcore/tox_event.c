/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_event.h"

#include <assert.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "mem.h"
#include "tox_events.h"

const char *tox_event_type_to_string(Tox_Event_Type type)
{
    switch (type) {
        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return "TOX_EVENT_SELF_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_REQUEST:
            return "TOX_EVENT_FRIEND_REQUEST";

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return "TOX_EVENT_FRIEND_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return "TOX_EVENT_FRIEND_LOSSY_PACKET";

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return "TOX_EVENT_FRIEND_LOSSLESS_PACKET";

        case TOX_EVENT_FRIEND_NAME:
            return "TOX_EVENT_FRIEND_NAME";

        case TOX_EVENT_FRIEND_STATUS:
            return "TOX_EVENT_FRIEND_STATUS";

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return "TOX_EVENT_FRIEND_STATUS_MESSAGE";

        case TOX_EVENT_FRIEND_MESSAGE:
            return "TOX_EVENT_FRIEND_MESSAGE";

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return "TOX_EVENT_FRIEND_READ_RECEIPT";

        case TOX_EVENT_FRIEND_TYPING:
            return "TOX_EVENT_FRIEND_TYPING";

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return "TOX_EVENT_FILE_CHUNK_REQUEST";

        case TOX_EVENT_FILE_RECV:
            return "TOX_EVENT_FILE_RECV";

        case TOX_EVENT_FILE_RECV_CHUNK:
            return "TOX_EVENT_FILE_RECV_CHUNK";

        case TOX_EVENT_FILE_RECV_CONTROL:
            return "TOX_EVENT_FILE_RECV_CONTROL";

        case TOX_EVENT_CONFERENCE_INVITE:
            return "TOX_EVENT_CONFERENCE_INVITE";

        case TOX_EVENT_CONFERENCE_CONNECTED:
            return "TOX_EVENT_CONFERENCE_CONNECTED";

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return "TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED";

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return "TOX_EVENT_CONFERENCE_PEER_NAME";

        case TOX_EVENT_CONFERENCE_TITLE:
            return "TOX_EVENT_CONFERENCE_TITLE";

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return "TOX_EVENT_CONFERENCE_MESSAGE";

        case TOX_EVENT_GROUP_PEER_NAME:
            return "TOX_EVENT_GROUP_PEER_NAME";

        case TOX_EVENT_GROUP_PEER_STATUS:
            return "TOX_EVENT_GROUP_PEER_STATUS";

        case TOX_EVENT_GROUP_TOPIC:
            return "TOX_EVENT_GROUP_TOPIC";

        case TOX_EVENT_GROUP_PRIVACY_STATE:
            return "TOX_EVENT_GROUP_PRIVACY_STATE";

        case TOX_EVENT_GROUP_VOICE_STATE:
            return "TOX_EVENT_GROUP_VOICE_STATE";

        case TOX_EVENT_GROUP_TOPIC_LOCK:
            return "TOX_EVENT_GROUP_TOPIC_LOCK";

        case TOX_EVENT_GROUP_PEER_LIMIT:
            return "TOX_EVENT_GROUP_PEER_LIMIT";

        case TOX_EVENT_GROUP_PASSWORD:
            return "TOX_EVENT_GROUP_PASSWORD";

        case TOX_EVENT_GROUP_MESSAGE:
            return "TOX_EVENT_GROUP_MESSAGE";

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return "TOX_EVENT_GROUP_PRIVATE_MESSAGE";

        case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return "TOX_EVENT_GROUP_CUSTOM_PACKET";

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return "TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET";

        case TOX_EVENT_GROUP_INVITE:
            return "TOX_EVENT_GROUP_INVITE";

        case TOX_EVENT_GROUP_PEER_JOIN:
            return "TOX_EVENT_GROUP_PEER_JOIN";

        case TOX_EVENT_GROUP_PEER_EXIT:
            return "TOX_EVENT_GROUP_PEER_EXIT";

        case TOX_EVENT_GROUP_SELF_JOIN:
            return "TOX_EVENT_GROUP_SELF_JOIN";

        case TOX_EVENT_GROUP_JOIN_FAIL:
            return "TOX_EVENT_GROUP_JOIN_FAIL";

        case TOX_EVENT_GROUP_MODERATION:
            return "TOX_EVENT_GROUP_MODERATION";

        case TOX_EVENT_DHT_GET_NODES_RESPONSE:
            return "TOX_EVENT_DHT_GET_NODES_RESPONSE";

        case TOX_EVENT_INVALID:
            return "TOX_EVENT_INVALID";
    }

    return "<invalid Tox_Event_Type>";
}

Tox_Event_Type tox_event_get_type(const Tox_Event *event)
{
    assert(event != nullptr);
    return event->type;
}

bool tox_event_construct(Tox_Event *event, Tox_Event_Type type, const Memory *mem)
{
    event->type = type;
    event->data.value = nullptr;

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            event->data.conference_connected = tox_event_conference_connected_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            event->data.conference_invite = tox_event_conference_invite_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            event->data.conference_message = tox_event_conference_message_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            event->data.conference_peer_list_changed = tox_event_conference_peer_list_changed_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            event->data.conference_peer_name = tox_event_conference_peer_name_new(mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            event->data.conference_title = tox_event_conference_title_new(mem);
            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            event->data.file_chunk_request = tox_event_file_chunk_request_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            event->data.file_recv_chunk = tox_event_file_recv_chunk_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            event->data.file_recv_control = tox_event_file_recv_control_new(mem);
            break;
        }

        case TOX_EVENT_FILE_RECV: {
            event->data.file_recv = tox_event_file_recv_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            event->data.friend_connection_status = tox_event_friend_connection_status_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            event->data.friend_lossless_packet = tox_event_friend_lossless_packet_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            event->data.friend_lossy_packet = tox_event_friend_lossy_packet_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            event->data.friend_message = tox_event_friend_message_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            event->data.friend_name = tox_event_friend_name_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            event->data.friend_read_receipt = tox_event_friend_read_receipt_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            event->data.friend_request = tox_event_friend_request_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            event->data.friend_status = tox_event_friend_status_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            event->data.friend_status_message = tox_event_friend_status_message_new(mem);
            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            event->data.friend_typing = tox_event_friend_typing_new(mem);
            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            event->data.self_connection_status = tox_event_self_connection_status_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            event->data.group_peer_name = tox_event_group_peer_name_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            event->data.group_peer_status = tox_event_group_peer_status_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            event->data.group_topic = tox_event_group_topic_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            event->data.group_privacy_state = tox_event_group_privacy_state_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            event->data.group_voice_state = tox_event_group_voice_state_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            event->data.group_topic_lock = tox_event_group_topic_lock_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            event->data.group_peer_limit = tox_event_group_peer_limit_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            event->data.group_password = tox_event_group_password_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            event->data.group_message = tox_event_group_message_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            event->data.group_private_message = tox_event_group_private_message_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            event->data.group_custom_packet = tox_event_group_custom_packet_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            event->data.group_custom_private_packet = tox_event_group_custom_private_packet_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_INVITE: {
            event->data.group_invite = tox_event_group_invite_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            event->data.group_peer_join = tox_event_group_peer_join_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            event->data.group_peer_exit = tox_event_group_peer_exit_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            event->data.group_self_join = tox_event_group_self_join_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            event->data.group_join_fail = tox_event_group_join_fail_new(mem);
            break;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            event->data.group_moderation = tox_event_group_moderation_new(mem);
            break;
        }

        case TOX_EVENT_DHT_GET_NODES_RESPONSE: {
            event->data.dht_get_nodes_response = tox_event_dht_get_nodes_response_new(mem);
            break;
        }

        case TOX_EVENT_INVALID: {
            return false;
        }
    }

    return event->data.value != nullptr;
}

void tox_event_destruct(Tox_Event *event, const Memory *mem)
{
    if (event == nullptr) {
        return;
    }

    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            tox_event_conference_connected_free(event->data.conference_connected, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            tox_event_conference_invite_free(event->data.conference_invite, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            tox_event_conference_message_free(event->data.conference_message, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            tox_event_conference_peer_list_changed_free(event->data.conference_peer_list_changed, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            tox_event_conference_peer_name_free(event->data.conference_peer_name, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            tox_event_conference_title_free(event->data.conference_title, mem);
            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            tox_event_file_chunk_request_free(event->data.file_chunk_request, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            tox_event_file_recv_chunk_free(event->data.file_recv_chunk, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            tox_event_file_recv_control_free(event->data.file_recv_control, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV: {
            tox_event_file_recv_free(event->data.file_recv, mem);
            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            tox_event_friend_connection_status_free(event->data.friend_connection_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            tox_event_friend_lossless_packet_free(event->data.friend_lossless_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            tox_event_friend_lossy_packet_free(event->data.friend_lossy_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            tox_event_friend_message_free(event->data.friend_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            tox_event_friend_name_free(event->data.friend_name, mem);
            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            tox_event_friend_read_receipt_free(event->data.friend_read_receipt, mem);
            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            tox_event_friend_request_free(event->data.friend_request, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            tox_event_friend_status_free(event->data.friend_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            tox_event_friend_status_message_free(event->data.friend_status_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            tox_event_friend_typing_free(event->data.friend_typing, mem);
            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            tox_event_self_connection_status_free(event->data.self_connection_status, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            tox_event_group_peer_name_free(event->data.group_peer_name, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            tox_event_group_peer_status_free(event->data.group_peer_status, mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            tox_event_group_topic_free(event->data.group_topic, mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            tox_event_group_privacy_state_free(event->data.group_privacy_state, mem);
            break;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            tox_event_group_voice_state_free(event->data.group_voice_state, mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            tox_event_group_topic_lock_free(event->data.group_topic_lock, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            tox_event_group_peer_limit_free(event->data.group_peer_limit, mem);
            break;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            tox_event_group_password_free(event->data.group_password, mem);
            break;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            tox_event_group_message_free(event->data.group_message, mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            tox_event_group_private_message_free(event->data.group_private_message, mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            tox_event_group_custom_packet_free(event->data.group_custom_packet, mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            tox_event_group_custom_private_packet_free(event->data.group_custom_private_packet, mem);
            break;
        }

        case TOX_EVENT_GROUP_INVITE: {
            tox_event_group_invite_free(event->data.group_invite, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            tox_event_group_peer_join_free(event->data.group_peer_join, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            tox_event_group_peer_exit_free(event->data.group_peer_exit, mem);
            break;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            tox_event_group_self_join_free(event->data.group_self_join, mem);
            break;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            tox_event_group_join_fail_free(event->data.group_join_fail, mem);
            break;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            tox_event_group_moderation_free(event->data.group_moderation, mem);
            break;
        }

        case TOX_EVENT_DHT_GET_NODES_RESPONSE: {
            tox_event_dht_get_nodes_response_free(event->data.dht_get_nodes_response, mem);
            break;
        }

        case TOX_EVENT_INVALID: {
            break;
        }
    }

    event->data.value = nullptr;
}

non_null()
static bool tox_event_type_pack(Tox_Event_Type type, Bin_Pack *bp)
{
    return bin_pack_u32(bp, (uint32_t)type);
}

non_null()
static bool tox_event_data_pack(Tox_Event_Type type, const Tox_Event_Data *data, Bin_Pack *bp)
{
    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_event_conference_connected_pack(data->conference_connected, bp);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_event_conference_invite_pack(data->conference_invite, bp);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_event_conference_message_pack(data->conference_message, bp);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_event_conference_peer_list_changed_pack(data->conference_peer_list_changed, bp);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_event_conference_peer_name_pack(data->conference_peer_name, bp);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_event_conference_title_pack(data->conference_title, bp);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_event_file_chunk_request_pack(data->file_chunk_request, bp);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_event_file_recv_chunk_pack(data->file_recv_chunk, bp);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_event_file_recv_control_pack(data->file_recv_control, bp);

        case TOX_EVENT_FILE_RECV:
            return tox_event_file_recv_pack(data->file_recv, bp);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_event_friend_connection_status_pack(data->friend_connection_status, bp);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_event_friend_lossless_packet_pack(data->friend_lossless_packet, bp);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_event_friend_lossy_packet_pack(data->friend_lossy_packet, bp);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_event_friend_message_pack(data->friend_message, bp);

        case TOX_EVENT_FRIEND_NAME:
            return tox_event_friend_name_pack(data->friend_name, bp);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_event_friend_read_receipt_pack(data->friend_read_receipt, bp);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_event_friend_request_pack(data->friend_request, bp);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_event_friend_status_pack(data->friend_status, bp);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_event_friend_status_message_pack(data->friend_status_message, bp);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_event_friend_typing_pack(data->friend_typing, bp);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_event_self_connection_status_pack(data->self_connection_status, bp);

        case TOX_EVENT_GROUP_PEER_NAME:
            return tox_event_group_peer_name_pack(data->group_peer_name, bp);

        case TOX_EVENT_GROUP_PEER_STATUS:
            return tox_event_group_peer_status_pack(data->group_peer_status, bp);

        case TOX_EVENT_GROUP_TOPIC:
            return tox_event_group_topic_pack(data->group_topic, bp);

        case TOX_EVENT_GROUP_PRIVACY_STATE:
            return tox_event_group_privacy_state_pack(data->group_privacy_state, bp);

        case TOX_EVENT_GROUP_VOICE_STATE:
            return tox_event_group_voice_state_pack(data->group_voice_state, bp);

        case TOX_EVENT_GROUP_TOPIC_LOCK:
            return tox_event_group_topic_lock_pack(data->group_topic_lock, bp);

        case TOX_EVENT_GROUP_PEER_LIMIT:
            return tox_event_group_peer_limit_pack(data->group_peer_limit, bp);

        case TOX_EVENT_GROUP_PASSWORD:
            return tox_event_group_password_pack(data->group_password, bp);

        case TOX_EVENT_GROUP_MESSAGE:
            return tox_event_group_message_pack(data->group_message, bp);

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return tox_event_group_private_message_pack(data->group_private_message, bp);

        case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return tox_event_group_custom_packet_pack(data->group_custom_packet, bp);

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return tox_event_group_custom_private_packet_pack(data->group_custom_private_packet, bp);

        case TOX_EVENT_GROUP_INVITE:
            return tox_event_group_invite_pack(data->group_invite, bp);

        case TOX_EVENT_GROUP_PEER_JOIN:
            return tox_event_group_peer_join_pack(data->group_peer_join, bp);

        case TOX_EVENT_GROUP_PEER_EXIT:
            return tox_event_group_peer_exit_pack(data->group_peer_exit, bp);

        case TOX_EVENT_GROUP_SELF_JOIN:
            return tox_event_group_self_join_pack(data->group_self_join, bp);

        case TOX_EVENT_GROUP_JOIN_FAIL:
            return tox_event_group_join_fail_pack(data->group_join_fail, bp);

        case TOX_EVENT_GROUP_MODERATION:
            return tox_event_group_moderation_pack(data->group_moderation, bp);

        case TOX_EVENT_DHT_GET_NODES_RESPONSE:
            return tox_event_dht_get_nodes_response_pack(data->dht_get_nodes_response, bp);

        case TOX_EVENT_INVALID:
            return false;
    }

    return false;
}

bool tox_event_pack(const Tox_Event *event, Bin_Pack *bp)
{
    assert(event->type != TOX_EVENT_INVALID);

    return bin_pack_array(bp, 2)
           && tox_event_type_pack(event->type, bp)
           && tox_event_data_pack(event->type, &event->data, bp);
}

non_null()
static bool tox_event_type_from_int(uint32_t value, Tox_Event_Type *out_enum)
{
    switch (value) {
        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            *out_enum = TOX_EVENT_SELF_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            *out_enum = TOX_EVENT_FRIEND_REQUEST;
            return true;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            *out_enum = TOX_EVENT_FRIEND_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            *out_enum = TOX_EVENT_FRIEND_LOSSY_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            *out_enum = TOX_EVENT_FRIEND_LOSSLESS_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_NAME: {
            *out_enum = TOX_EVENT_FRIEND_NAME;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            *out_enum = TOX_EVENT_FRIEND_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            *out_enum = TOX_EVENT_FRIEND_STATUS_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            *out_enum = TOX_EVENT_FRIEND_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            *out_enum = TOX_EVENT_FRIEND_READ_RECEIPT;
            return true;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            *out_enum = TOX_EVENT_FRIEND_TYPING;
            return true;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            *out_enum = TOX_EVENT_FILE_CHUNK_REQUEST;
            return true;
        }

        case TOX_EVENT_FILE_RECV: {
            *out_enum = TOX_EVENT_FILE_RECV;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            *out_enum = TOX_EVENT_FILE_RECV_CHUNK;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            *out_enum = TOX_EVENT_FILE_RECV_CONTROL;
            return true;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            *out_enum = TOX_EVENT_CONFERENCE_INVITE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_CONNECTED: {
            *out_enum = TOX_EVENT_CONFERENCE_CONNECTED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            *out_enum = TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            *out_enum = TOX_EVENT_CONFERENCE_PEER_NAME;
            return true;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            *out_enum = TOX_EVENT_CONFERENCE_TITLE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            *out_enum = TOX_EVENT_CONFERENCE_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            *out_enum = TOX_EVENT_GROUP_PEER_NAME;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            *out_enum = TOX_EVENT_GROUP_PEER_STATUS;
            return true;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            *out_enum = TOX_EVENT_GROUP_TOPIC;
            return true;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            *out_enum = TOX_EVENT_GROUP_PRIVACY_STATE;
            return true;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            *out_enum = TOX_EVENT_GROUP_VOICE_STATE;
            return true;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            *out_enum = TOX_EVENT_GROUP_TOPIC_LOCK;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            *out_enum = TOX_EVENT_GROUP_PEER_LIMIT;
            return true;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            *out_enum = TOX_EVENT_GROUP_PASSWORD;
            return true;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            *out_enum = TOX_EVENT_GROUP_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            *out_enum = TOX_EVENT_GROUP_PRIVATE_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            *out_enum = TOX_EVENT_GROUP_CUSTOM_PACKET;
            return true;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            *out_enum = TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET;
            return true;
        }

        case TOX_EVENT_GROUP_INVITE: {
            *out_enum = TOX_EVENT_GROUP_INVITE;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            *out_enum = TOX_EVENT_GROUP_PEER_JOIN;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            *out_enum = TOX_EVENT_GROUP_PEER_EXIT;
            return true;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            *out_enum = TOX_EVENT_GROUP_SELF_JOIN;
            return true;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            *out_enum = TOX_EVENT_GROUP_JOIN_FAIL;
            return true;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            *out_enum = TOX_EVENT_GROUP_MODERATION;
            return true;
        }

        case TOX_EVENT_DHT_GET_NODES_RESPONSE: {
            *out_enum = TOX_EVENT_DHT_GET_NODES_RESPONSE;
            return true;
        }

        case TOX_EVENT_INVALID: {
            *out_enum = TOX_EVENT_INVALID;
            return true;
        }

        default: {
            *out_enum = TOX_EVENT_INVALID;
            return false;
        }
    }
}

non_null()
static bool tox_event_type_unpack(Tox_Event_Type *val, Bin_Unpack *bu)
{
    uint32_t u32;
    return bin_unpack_u32(bu, &u32)
           && tox_event_type_from_int(u32, val);
}

non_null()
static bool tox_event_data_unpack(Tox_Event_Type type, Tox_Event_Data *data, Bin_Unpack *bu, const Memory *mem)
{
    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_event_conference_connected_unpack(&data->conference_connected, bu, mem);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_event_conference_invite_unpack(&data->conference_invite, bu, mem);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_event_conference_message_unpack(&data->conference_message, bu, mem);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_event_conference_peer_list_changed_unpack(&data->conference_peer_list_changed, bu, mem);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_event_conference_peer_name_unpack(&data->conference_peer_name, bu, mem);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_event_conference_title_unpack(&data->conference_title, bu, mem);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_event_file_chunk_request_unpack(&data->file_chunk_request, bu, mem);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_event_file_recv_chunk_unpack(&data->file_recv_chunk, bu, mem);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_event_file_recv_control_unpack(&data->file_recv_control, bu, mem);

        case TOX_EVENT_FILE_RECV:
            return tox_event_file_recv_unpack(&data->file_recv, bu, mem);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_event_friend_connection_status_unpack(&data->friend_connection_status, bu, mem);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_event_friend_lossless_packet_unpack(&data->friend_lossless_packet, bu, mem);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_event_friend_lossy_packet_unpack(&data->friend_lossy_packet, bu, mem);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_event_friend_message_unpack(&data->friend_message, bu, mem);

        case TOX_EVENT_FRIEND_NAME:
            return tox_event_friend_name_unpack(&data->friend_name, bu, mem);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_event_friend_read_receipt_unpack(&data->friend_read_receipt, bu, mem);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_event_friend_request_unpack(&data->friend_request, bu, mem);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_event_friend_status_message_unpack(&data->friend_status_message, bu, mem);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_event_friend_status_unpack(&data->friend_status, bu, mem);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_event_friend_typing_unpack(&data->friend_typing, bu, mem);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_event_self_connection_status_unpack(&data->self_connection_status, bu, mem);

        case TOX_EVENT_GROUP_PEER_NAME:
            return tox_event_group_peer_name_unpack(&data->group_peer_name, bu, mem);

        case TOX_EVENT_GROUP_PEER_STATUS:
            return tox_event_group_peer_status_unpack(&data->group_peer_status, bu, mem);

        case TOX_EVENT_GROUP_TOPIC:
            return tox_event_group_topic_unpack(&data->group_topic, bu, mem);

        case TOX_EVENT_GROUP_PRIVACY_STATE:
            return tox_event_group_privacy_state_unpack(&data->group_privacy_state, bu, mem);

        case TOX_EVENT_GROUP_VOICE_STATE:
            return tox_event_group_voice_state_unpack(&data->group_voice_state, bu, mem);

        case TOX_EVENT_GROUP_TOPIC_LOCK:
            return tox_event_group_topic_lock_unpack(&data->group_topic_lock, bu, mem);

        case TOX_EVENT_GROUP_PEER_LIMIT:
            return tox_event_group_peer_limit_unpack(&data->group_peer_limit, bu, mem);

        case TOX_EVENT_GROUP_PASSWORD:
            return tox_event_group_password_unpack(&data->group_password, bu, mem);

        case TOX_EVENT_GROUP_MESSAGE:
            return tox_event_group_message_unpack(&data->group_message, bu, mem);

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return tox_event_group_private_message_unpack(&data->group_private_message, bu, mem);

        case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return tox_event_group_custom_packet_unpack(&data->group_custom_packet, bu, mem);

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return tox_event_group_custom_private_packet_unpack(&data->group_custom_private_packet, bu, mem);

        case TOX_EVENT_GROUP_INVITE:
            return tox_event_group_invite_unpack(&data->group_invite, bu, mem);

        case TOX_EVENT_GROUP_PEER_JOIN:
            return tox_event_group_peer_join_unpack(&data->group_peer_join, bu, mem);

        case TOX_EVENT_GROUP_PEER_EXIT:
            return tox_event_group_peer_exit_unpack(&data->group_peer_exit, bu, mem);

        case TOX_EVENT_GROUP_SELF_JOIN:
            return tox_event_group_self_join_unpack(&data->group_self_join, bu, mem);

        case TOX_EVENT_GROUP_JOIN_FAIL:
            return tox_event_group_join_fail_unpack(&data->group_join_fail, bu, mem);

        case TOX_EVENT_GROUP_MODERATION:
            return tox_event_group_moderation_unpack(&data->group_moderation, bu, mem);

        case TOX_EVENT_DHT_GET_NODES_RESPONSE:
            return tox_event_dht_get_nodes_response_unpack(&data->dht_get_nodes_response, bu, mem);

        case TOX_EVENT_INVALID:
            return false;
    }

    return false;
}

bool tox_event_unpack_into(Tox_Event *event, Bin_Unpack *bu, const Memory *mem)
{
    return bin_unpack_array_fixed(bu, 2, nullptr)  //
           && tox_event_type_unpack(&event->type, bu)  //
           && tox_event_data_unpack(event->type, &event->data, bu, mem);
}
