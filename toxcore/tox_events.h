/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

/**
 * WARNING: This is an experimental API and is subject to change.
 *
 * At this point, it probably won't change very much anymore, but we may have
 * small breaking changes before a stable release.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_H

#include <stdbool.h>
#include <stdint.h>

#include "tox.h"
#include "tox_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Iterate_Options Tox_Iterate_Options;

typedef struct Tox_Event_Conference_Connected Tox_Event_Conference_Connected;
uint32_t tox_event_conference_connected_get_conference_number(
    const Tox_Event_Conference_Connected *_Nonnull conference_connected);

typedef struct Tox_Event_Conference_Invite Tox_Event_Conference_Invite;
const uint8_t *_Nullable tox_event_conference_invite_get_cookie(
    const Tox_Event_Conference_Invite *_Nonnull conference_invite);
uint32_t tox_event_conference_invite_get_cookie_length(
    const Tox_Event_Conference_Invite *_Nonnull conference_invite);
Tox_Conference_Type tox_event_conference_invite_get_type(
    const Tox_Event_Conference_Invite *_Nonnull conference_invite);
uint32_t tox_event_conference_invite_get_friend_number(
    const Tox_Event_Conference_Invite *_Nonnull conference_invite);

typedef struct Tox_Event_Conference_Message Tox_Event_Conference_Message;
const uint8_t *_Nullable tox_event_conference_message_get_message(
    const Tox_Event_Conference_Message *_Nonnull conference_message);
uint32_t tox_event_conference_message_get_message_length(
    const Tox_Event_Conference_Message *_Nonnull conference_message);
Tox_Message_Type tox_event_conference_message_get_type(
    const Tox_Event_Conference_Message *_Nonnull conference_message);
uint32_t tox_event_conference_message_get_conference_number(
    const Tox_Event_Conference_Message *_Nonnull conference_message);
uint32_t tox_event_conference_message_get_peer_number(
    const Tox_Event_Conference_Message *_Nonnull conference_message);

typedef struct Tox_Event_Conference_Peer_List_Changed Tox_Event_Conference_Peer_List_Changed;
uint32_t tox_event_conference_peer_list_changed_get_conference_number(
    const Tox_Event_Conference_Peer_List_Changed *_Nonnull conference_peer_list_changed);

typedef struct Tox_Event_Conference_Peer_Name Tox_Event_Conference_Peer_Name;
const uint8_t *_Nullable tox_event_conference_peer_name_get_name(
    const Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name);
uint32_t tox_event_conference_peer_name_get_name_length(
    const Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name);
uint32_t tox_event_conference_peer_name_get_conference_number(
    const Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name);
uint32_t tox_event_conference_peer_name_get_peer_number(
    const Tox_Event_Conference_Peer_Name *_Nonnull conference_peer_name);

typedef struct Tox_Event_Conference_Title Tox_Event_Conference_Title;
const uint8_t *_Nullable tox_event_conference_title_get_title(
    const Tox_Event_Conference_Title *_Nonnull conference_title);
uint32_t tox_event_conference_title_get_title_length(
    const Tox_Event_Conference_Title *_Nonnull conference_title);
uint32_t tox_event_conference_title_get_conference_number(
    const Tox_Event_Conference_Title *_Nonnull conference_title);
uint32_t tox_event_conference_title_get_peer_number(
    const Tox_Event_Conference_Title *_Nonnull conference_title);

typedef struct Tox_Event_File_Chunk_Request Tox_Event_File_Chunk_Request;
uint16_t tox_event_file_chunk_request_get_length(
    const Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request);
uint32_t tox_event_file_chunk_request_get_file_number(
    const Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request);
uint32_t tox_event_file_chunk_request_get_friend_number(
    const Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request);
uint64_t tox_event_file_chunk_request_get_position(
    const Tox_Event_File_Chunk_Request *_Nonnull file_chunk_request);

typedef struct Tox_Event_File_Recv Tox_Event_File_Recv;
const uint8_t *_Nullable tox_event_file_recv_get_filename(
    const Tox_Event_File_Recv *_Nonnull file_recv);
uint32_t tox_event_file_recv_get_filename_length(
    const Tox_Event_File_Recv *_Nonnull file_recv);
uint32_t tox_event_file_recv_get_file_number(
    const Tox_Event_File_Recv *_Nonnull file_recv);
uint64_t tox_event_file_recv_get_file_size(
    const Tox_Event_File_Recv *_Nonnull file_recv);
uint32_t tox_event_file_recv_get_friend_number(
    const Tox_Event_File_Recv *_Nonnull file_recv);
uint32_t tox_event_file_recv_get_kind(
    const Tox_Event_File_Recv *_Nonnull file_recv);

typedef struct Tox_Event_File_Recv_Chunk Tox_Event_File_Recv_Chunk;
const uint8_t *_Nullable tox_event_file_recv_chunk_get_data(
    const Tox_Event_File_Recv_Chunk *_Nonnull file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_data_length(
    const Tox_Event_File_Recv_Chunk *_Nonnull file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_file_number(
    const Tox_Event_File_Recv_Chunk *_Nonnull file_recv_chunk);
uint32_t tox_event_file_recv_chunk_get_friend_number(
    const Tox_Event_File_Recv_Chunk *_Nonnull file_recv_chunk);
uint64_t tox_event_file_recv_chunk_get_position(
    const Tox_Event_File_Recv_Chunk *_Nonnull file_recv_chunk);

typedef struct Tox_Event_File_Recv_Control Tox_Event_File_Recv_Control;
Tox_File_Control tox_event_file_recv_control_get_control(
    const Tox_Event_File_Recv_Control *_Nonnull file_recv_control);
uint32_t tox_event_file_recv_control_get_file_number(
    const Tox_Event_File_Recv_Control *_Nonnull file_recv_control);
uint32_t tox_event_file_recv_control_get_friend_number(
    const Tox_Event_File_Recv_Control *_Nonnull file_recv_control);

typedef struct Tox_Event_Friend_Connection_Status Tox_Event_Friend_Connection_Status;
Tox_Connection tox_event_friend_connection_status_get_connection_status(
    const Tox_Event_Friend_Connection_Status *_Nonnull friend_connection_status);
uint32_t tox_event_friend_connection_status_get_friend_number(
    const Tox_Event_Friend_Connection_Status *_Nonnull friend_connection_status);

typedef struct Tox_Event_Friend_Lossless_Packet Tox_Event_Friend_Lossless_Packet;
const uint8_t *_Nullable tox_event_friend_lossless_packet_get_data(
    const Tox_Event_Friend_Lossless_Packet *_Nonnull friend_lossless_packet);
uint32_t tox_event_friend_lossless_packet_get_data_length(
    const Tox_Event_Friend_Lossless_Packet *_Nonnull friend_lossless_packet);
uint32_t tox_event_friend_lossless_packet_get_friend_number(
    const Tox_Event_Friend_Lossless_Packet *_Nonnull friend_lossless_packet);

typedef struct Tox_Event_Friend_Lossy_Packet Tox_Event_Friend_Lossy_Packet;
const uint8_t *_Nullable tox_event_friend_lossy_packet_get_data(
    const Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet);
uint32_t tox_event_friend_lossy_packet_get_data_length(
    const Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet);
uint32_t tox_event_friend_lossy_packet_get_friend_number(
    const Tox_Event_Friend_Lossy_Packet *_Nonnull friend_lossy_packet);

typedef struct Tox_Event_Friend_Message Tox_Event_Friend_Message;
uint32_t tox_event_friend_message_get_friend_number(
    const Tox_Event_Friend_Message *_Nonnull friend_message);
Tox_Message_Type tox_event_friend_message_get_type(
    const Tox_Event_Friend_Message *_Nonnull friend_message);
uint32_t tox_event_friend_message_get_message_length(
    const Tox_Event_Friend_Message *_Nonnull friend_message);
const uint8_t *_Nullable tox_event_friend_message_get_message(
    const Tox_Event_Friend_Message *_Nonnull friend_message);

typedef struct Tox_Event_Friend_Name Tox_Event_Friend_Name;
const uint8_t *_Nullable tox_event_friend_name_get_name(
    const Tox_Event_Friend_Name *_Nonnull friend_name);
uint32_t tox_event_friend_name_get_name_length(
    const Tox_Event_Friend_Name *_Nonnull friend_name);
uint32_t tox_event_friend_name_get_friend_number(
    const Tox_Event_Friend_Name *_Nonnull friend_name);

typedef struct Tox_Event_Friend_Read_Receipt Tox_Event_Friend_Read_Receipt;
uint32_t tox_event_friend_read_receipt_get_friend_number(
    const Tox_Event_Friend_Read_Receipt *_Nonnull friend_read_receipt);
uint32_t tox_event_friend_read_receipt_get_message_id(
    const Tox_Event_Friend_Read_Receipt *_Nonnull friend_read_receipt);

typedef struct Tox_Event_Friend_Request Tox_Event_Friend_Request;
const uint8_t *_Nullable tox_event_friend_request_get_message(
    const Tox_Event_Friend_Request *_Nonnull friend_request);
const uint8_t *_Nonnull tox_event_friend_request_get_public_key(
    const Tox_Event_Friend_Request *_Nonnull friend_request);
uint32_t tox_event_friend_request_get_message_length(
    const Tox_Event_Friend_Request *_Nonnull friend_request);

typedef struct Tox_Event_Friend_Status Tox_Event_Friend_Status;
Tox_User_Status tox_event_friend_status_get_status(
    const Tox_Event_Friend_Status *_Nonnull friend_status);
uint32_t tox_event_friend_status_get_friend_number(
    const Tox_Event_Friend_Status *_Nonnull friend_status);

typedef struct Tox_Event_Friend_Status_Message Tox_Event_Friend_Status_Message;
const uint8_t *_Nullable tox_event_friend_status_message_get_message(
    const Tox_Event_Friend_Status_Message *_Nonnull friend_status_message);
uint32_t tox_event_friend_status_message_get_message_length(
    const Tox_Event_Friend_Status_Message *_Nonnull friend_status_message);
uint32_t tox_event_friend_status_message_get_friend_number(
    const Tox_Event_Friend_Status_Message *_Nonnull friend_status_message);

typedef struct Tox_Event_Friend_Typing Tox_Event_Friend_Typing;
bool tox_event_friend_typing_get_typing(
    const Tox_Event_Friend_Typing *_Nonnull friend_typing);
uint32_t tox_event_friend_typing_get_friend_number(
    const Tox_Event_Friend_Typing *_Nonnull friend_typing);

typedef struct Tox_Event_Self_Connection_Status Tox_Event_Self_Connection_Status;
Tox_Connection tox_event_self_connection_status_get_connection_status(
    const Tox_Event_Self_Connection_Status *_Nonnull self_connection_status);

typedef struct Tox_Event_Group_Peer_Name Tox_Event_Group_Peer_Name;
uint32_t tox_event_group_peer_name_get_group_number(
    const Tox_Event_Group_Peer_Name *_Nonnull group_peer_name);
uint32_t tox_event_group_peer_name_get_peer_id(
    const Tox_Event_Group_Peer_Name *_Nonnull group_peer_name);
const uint8_t *_Nullable tox_event_group_peer_name_get_name(
    const Tox_Event_Group_Peer_Name *_Nonnull group_peer_name);
uint32_t tox_event_group_peer_name_get_name_length(
    const Tox_Event_Group_Peer_Name *_Nonnull group_peer_name);

typedef struct Tox_Event_Group_Peer_Status Tox_Event_Group_Peer_Status;
uint32_t tox_event_group_peer_status_get_group_number(
    const Tox_Event_Group_Peer_Status *_Nonnull group_peer_status);
uint32_t tox_event_group_peer_status_get_peer_id(
    const Tox_Event_Group_Peer_Status *_Nonnull group_peer_status);
Tox_User_Status tox_event_group_peer_status_get_status(
    const Tox_Event_Group_Peer_Status *_Nonnull group_peer_status);

typedef struct Tox_Event_Group_Topic Tox_Event_Group_Topic;
uint32_t tox_event_group_topic_get_group_number(
    const Tox_Event_Group_Topic *_Nonnull group_topic);
uint32_t tox_event_group_topic_get_peer_id(
    const Tox_Event_Group_Topic *_Nonnull group_topic);
const uint8_t *_Nullable tox_event_group_topic_get_topic(
    const Tox_Event_Group_Topic *_Nonnull group_topic);
uint32_t tox_event_group_topic_get_topic_length(
    const Tox_Event_Group_Topic *_Nonnull group_topic);

typedef struct Tox_Event_Group_Privacy_State Tox_Event_Group_Privacy_State;
uint32_t tox_event_group_privacy_state_get_group_number(
    const Tox_Event_Group_Privacy_State *_Nonnull group_privacy_state);
Tox_Group_Privacy_State tox_event_group_privacy_state_get_privacy_state(
    const Tox_Event_Group_Privacy_State *_Nonnull group_privacy_state);

typedef struct Tox_Event_Group_Voice_State Tox_Event_Group_Voice_State;
uint32_t tox_event_group_voice_state_get_group_number(
    const Tox_Event_Group_Voice_State *_Nonnull group_voice_state);
Tox_Group_Voice_State tox_event_group_voice_state_get_voice_state(
    const Tox_Event_Group_Voice_State *_Nonnull group_voice_state);

typedef struct Tox_Event_Group_Topic_Lock Tox_Event_Group_Topic_Lock;
uint32_t tox_event_group_topic_lock_get_group_number(
    const Tox_Event_Group_Topic_Lock *_Nonnull group_topic_lock);
Tox_Group_Topic_Lock tox_event_group_topic_lock_get_topic_lock(
    const Tox_Event_Group_Topic_Lock *_Nonnull group_topic_lock);

typedef struct Tox_Event_Group_Peer_Limit Tox_Event_Group_Peer_Limit;
uint32_t tox_event_group_peer_limit_get_group_number(
    const Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit);
uint32_t tox_event_group_peer_limit_get_peer_limit(
    const Tox_Event_Group_Peer_Limit *_Nonnull group_peer_limit);

typedef struct Tox_Event_Group_Password Tox_Event_Group_Password;
uint32_t tox_event_group_password_get_group_number(
    const Tox_Event_Group_Password *_Nonnull group_password);
const uint8_t *_Nullable tox_event_group_password_get_password(
    const Tox_Event_Group_Password *_Nonnull group_password);
uint32_t tox_event_group_password_get_password_length(
    const Tox_Event_Group_Password *_Nonnull group_password);

typedef struct Tox_Event_Group_Message Tox_Event_Group_Message;
uint32_t tox_event_group_message_get_group_number(
    const Tox_Event_Group_Message *_Nonnull group_message);
uint32_t tox_event_group_message_get_peer_id(
    const Tox_Event_Group_Message *_Nonnull group_message);
Tox_Message_Type tox_event_group_message_get_message_type(
    const Tox_Event_Group_Message *_Nonnull group_message);
const uint8_t *_Nullable tox_event_group_message_get_message(
    const Tox_Event_Group_Message *_Nonnull group_message);
uint32_t tox_event_group_message_get_message_length(
    const Tox_Event_Group_Message *_Nonnull group_message);
uint32_t tox_event_group_message_get_message_id(
    const Tox_Event_Group_Message *_Nonnull group_message);

typedef struct Tox_Event_Group_Private_Message Tox_Event_Group_Private_Message;
uint32_t tox_event_group_private_message_get_group_number(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);
uint32_t tox_event_group_private_message_get_peer_id(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);
Tox_Message_Type tox_event_group_private_message_get_message_type(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);
const uint8_t *_Nullable tox_event_group_private_message_get_message(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);
uint32_t tox_event_group_private_message_get_message_length(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);
uint32_t tox_event_group_private_message_get_message_id(
    const Tox_Event_Group_Private_Message *_Nonnull group_private_message);

typedef struct Tox_Event_Group_Custom_Packet Tox_Event_Group_Custom_Packet;
uint32_t tox_event_group_custom_packet_get_group_number(
    const Tox_Event_Group_Custom_Packet *_Nonnull group_custom_packet);
uint32_t tox_event_group_custom_packet_get_peer_id(
    const Tox_Event_Group_Custom_Packet *_Nonnull group_custom_packet);
const uint8_t *_Nullable tox_event_group_custom_packet_get_data(
    const Tox_Event_Group_Custom_Packet *_Nonnull group_custom_packet);
uint32_t tox_event_group_custom_packet_get_data_length(
    const Tox_Event_Group_Custom_Packet *_Nonnull group_custom_packet);

typedef struct Tox_Event_Group_Custom_Private_Packet Tox_Event_Group_Custom_Private_Packet;
uint32_t tox_event_group_custom_private_packet_get_group_number(
    const Tox_Event_Group_Custom_Private_Packet *_Nonnull group_custom_private_packet);
uint32_t tox_event_group_custom_private_packet_get_peer_id(
    const Tox_Event_Group_Custom_Private_Packet *_Nonnull group_custom_private_packet);
const uint8_t *_Nullable tox_event_group_custom_private_packet_get_data(
    const Tox_Event_Group_Custom_Private_Packet *_Nonnull group_custom_private_packet);
uint32_t tox_event_group_custom_private_packet_get_data_length(
    const Tox_Event_Group_Custom_Private_Packet *_Nonnull group_custom_private_packet);

typedef struct Tox_Event_Group_Invite Tox_Event_Group_Invite;
uint32_t tox_event_group_invite_get_friend_number(
    const Tox_Event_Group_Invite *_Nonnull group_invite);
const uint8_t *_Nullable tox_event_group_invite_get_invite_data(
    const Tox_Event_Group_Invite *_Nonnull group_invite);
uint32_t tox_event_group_invite_get_invite_data_length(
    const Tox_Event_Group_Invite *_Nonnull group_invite);
const uint8_t *_Nullable tox_event_group_invite_get_group_name(
    const Tox_Event_Group_Invite *_Nonnull group_invite);
uint32_t tox_event_group_invite_get_group_name_length(
    const Tox_Event_Group_Invite *_Nonnull group_invite);

typedef struct Tox_Event_Group_Peer_Join Tox_Event_Group_Peer_Join;
uint32_t tox_event_group_peer_join_get_group_number(
    const Tox_Event_Group_Peer_Join *_Nonnull group_peer_join);
uint32_t tox_event_group_peer_join_get_peer_id(
    const Tox_Event_Group_Peer_Join *_Nonnull group_peer_join);

typedef struct Tox_Event_Group_Peer_Exit Tox_Event_Group_Peer_Exit;
uint32_t tox_event_group_peer_exit_get_group_number(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
uint32_t tox_event_group_peer_exit_get_peer_id(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
Tox_Group_Exit_Type tox_event_group_peer_exit_get_exit_type(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
const uint8_t *_Nullable tox_event_group_peer_exit_get_name(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
uint32_t tox_event_group_peer_exit_get_name_length(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
const uint8_t *_Nullable tox_event_group_peer_exit_get_part_message(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);
uint32_t tox_event_group_peer_exit_get_part_message_length(
    const Tox_Event_Group_Peer_Exit *_Nonnull group_peer_exit);

typedef struct Tox_Event_Group_Self_Join Tox_Event_Group_Self_Join;
uint32_t tox_event_group_self_join_get_group_number(
    const Tox_Event_Group_Self_Join *_Nonnull group_self_join);

typedef struct Tox_Event_Group_Join_Fail Tox_Event_Group_Join_Fail;
uint32_t tox_event_group_join_fail_get_group_number(
    const Tox_Event_Group_Join_Fail *_Nonnull group_join_fail);
Tox_Group_Join_Fail tox_event_group_join_fail_get_fail_type(
    const Tox_Event_Group_Join_Fail *_Nonnull group_join_fail);

typedef struct Tox_Event_Group_Moderation Tox_Event_Group_Moderation;
uint32_t tox_event_group_moderation_get_group_number(
    const Tox_Event_Group_Moderation *_Nonnull group_moderation);
uint32_t tox_event_group_moderation_get_source_peer_id(
    const Tox_Event_Group_Moderation *_Nonnull group_moderation);
uint32_t tox_event_group_moderation_get_target_peer_id(
    const Tox_Event_Group_Moderation *_Nonnull group_moderation);
Tox_Group_Mod_Event tox_event_group_moderation_get_mod_type(
    const Tox_Event_Group_Moderation *_Nonnull group_moderation);

typedef struct Tox_Event_Dht_Nodes_Response Tox_Event_Dht_Nodes_Response;
const uint8_t *_Nonnull tox_event_dht_nodes_response_get_public_key(
    const Tox_Event_Dht_Nodes_Response *_Nonnull dht_nodes_response);
const char *_Nullable tox_event_dht_nodes_response_get_ip(
    const Tox_Event_Dht_Nodes_Response *_Nonnull dht_nodes_response);
uint32_t tox_event_dht_nodes_response_get_ip_length(
    const Tox_Event_Dht_Nodes_Response *_Nonnull dht_nodes_response);
uint16_t tox_event_dht_nodes_response_get_port(
    const Tox_Event_Dht_Nodes_Response *_Nonnull dht_nodes_response);

typedef enum Tox_Event_Type {
    TOX_EVENT_SELF_CONNECTION_STATUS        = 0,

    TOX_EVENT_FRIEND_REQUEST                = 1,
    TOX_EVENT_FRIEND_CONNECTION_STATUS      = 2,
    TOX_EVENT_FRIEND_LOSSY_PACKET           = 3,
    TOX_EVENT_FRIEND_LOSSLESS_PACKET        = 4,

    TOX_EVENT_FRIEND_NAME                   = 5,
    TOX_EVENT_FRIEND_STATUS                 = 6,
    TOX_EVENT_FRIEND_STATUS_MESSAGE         = 7,

    TOX_EVENT_FRIEND_MESSAGE                = 8,
    TOX_EVENT_FRIEND_READ_RECEIPT           = 9,
    TOX_EVENT_FRIEND_TYPING                 = 10,

    TOX_EVENT_FILE_CHUNK_REQUEST            = 11,
    TOX_EVENT_FILE_RECV                     = 12,
    TOX_EVENT_FILE_RECV_CHUNK               = 13,
    TOX_EVENT_FILE_RECV_CONTROL             = 14,

    TOX_EVENT_CONFERENCE_INVITE             = 15,
    TOX_EVENT_CONFERENCE_CONNECTED          = 16,
    TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED  = 17,
    TOX_EVENT_CONFERENCE_PEER_NAME          = 18,
    TOX_EVENT_CONFERENCE_TITLE              = 19,

    TOX_EVENT_CONFERENCE_MESSAGE            = 20,

    TOX_EVENT_GROUP_PEER_NAME               = 21,
    TOX_EVENT_GROUP_PEER_STATUS             = 22,
    TOX_EVENT_GROUP_TOPIC                   = 23,
    TOX_EVENT_GROUP_PRIVACY_STATE           = 24,
    TOX_EVENT_GROUP_VOICE_STATE             = 25,
    TOX_EVENT_GROUP_TOPIC_LOCK              = 26,
    TOX_EVENT_GROUP_PEER_LIMIT              = 27,
    TOX_EVENT_GROUP_PASSWORD                = 28,
    TOX_EVENT_GROUP_MESSAGE                 = 29,
    TOX_EVENT_GROUP_PRIVATE_MESSAGE         = 30,
    TOX_EVENT_GROUP_CUSTOM_PACKET           = 31,
    TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET   = 32,
    TOX_EVENT_GROUP_INVITE                  = 33,
    TOX_EVENT_GROUP_PEER_JOIN               = 34,
    TOX_EVENT_GROUP_PEER_EXIT               = 35,
    TOX_EVENT_GROUP_SELF_JOIN               = 36,
    TOX_EVENT_GROUP_JOIN_FAIL               = 37,
    TOX_EVENT_GROUP_MODERATION              = 38,

    TOX_EVENT_DHT_NODES_RESPONSE            = 39,

    TOX_EVENT_INVALID                       = 255,
} Tox_Event_Type;

const char *_Nonnull tox_event_type_to_string(Tox_Event_Type type);

/**
 * A single Tox core event.
 *
 * It could contain any of the above event types. Use `tox_event_get_type` to
 * find out which one it is, then use one of the `get` functions to get the
 * actual event object out. The `get` functions will return NULL in case of type
 * mismatch.
 */
typedef struct Tox_Event Tox_Event;

Tox_Event_Type tox_event_get_type(const Tox_Event *_Nonnull event);

const Tox_Event_Conference_Connected *_Nullable tox_event_get_conference_connected(
    const Tox_Event *_Nonnull event);
const Tox_Event_Conference_Invite *_Nullable tox_event_get_conference_invite(
    const Tox_Event *_Nonnull event);
const Tox_Event_Conference_Message *_Nullable tox_event_get_conference_message(
    const Tox_Event *_Nonnull event);
const Tox_Event_Conference_Peer_List_Changed *_Nullable tox_event_get_conference_peer_list_changed(
    const Tox_Event *_Nonnull event);
const Tox_Event_Conference_Peer_Name *_Nullable tox_event_get_conference_peer_name(
    const Tox_Event *_Nonnull event);
const Tox_Event_Conference_Title *_Nullable tox_event_get_conference_title(
    const Tox_Event *_Nonnull event);
const Tox_Event_File_Chunk_Request *_Nullable tox_event_get_file_chunk_request(
    const Tox_Event *_Nonnull event);
const Tox_Event_File_Recv_Chunk *_Nullable tox_event_get_file_recv_chunk(
    const Tox_Event *_Nonnull event);
const Tox_Event_File_Recv_Control *_Nullable tox_event_get_file_recv_control(
    const Tox_Event *_Nonnull event);
const Tox_Event_File_Recv *_Nullable tox_event_get_file_recv(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Connection_Status *_Nullable tox_event_get_friend_connection_status(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Lossless_Packet *_Nullable tox_event_get_friend_lossless_packet(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Lossy_Packet *_Nullable tox_event_get_friend_lossy_packet(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Message *_Nullable tox_event_get_friend_message(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Name *_Nullable tox_event_get_friend_name(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Read_Receipt *_Nullable tox_event_get_friend_read_receipt(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Request *_Nullable tox_event_get_friend_request(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Status_Message *_Nullable tox_event_get_friend_status_message(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Status *_Nullable tox_event_get_friend_status(
    const Tox_Event *_Nonnull event);
const Tox_Event_Friend_Typing *_Nullable tox_event_get_friend_typing(
    const Tox_Event *_Nonnull event);
const Tox_Event_Self_Connection_Status *_Nullable tox_event_get_self_connection_status(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Peer_Name *_Nullable tox_event_get_group_peer_name(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Peer_Status *_Nullable tox_event_get_group_peer_status(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Topic *_Nullable tox_event_get_group_topic(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Privacy_State *_Nullable tox_event_get_group_privacy_state(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Voice_State *_Nullable tox_event_get_group_voice_state(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Topic_Lock *_Nullable tox_event_get_group_topic_lock(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Peer_Limit *_Nullable tox_event_get_group_peer_limit(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Password *_Nullable tox_event_get_group_password(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Message *_Nullable tox_event_get_group_message(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Private_Message *_Nullable tox_event_get_group_private_message(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Custom_Packet *_Nullable tox_event_get_group_custom_packet(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Custom_Private_Packet *_Nullable tox_event_get_group_custom_private_packet(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Invite *_Nullable tox_event_get_group_invite(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Peer_Join *_Nullable tox_event_get_group_peer_join(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Peer_Exit *_Nullable tox_event_get_group_peer_exit(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Self_Join *_Nullable tox_event_get_group_self_join(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Join_Fail *_Nullable tox_event_get_group_join_fail(
    const Tox_Event *_Nonnull event);
const Tox_Event_Group_Moderation *_Nullable tox_event_get_group_moderation(
    const Tox_Event *_Nonnull event);
const Tox_Event_Dht_Nodes_Response *_Nullable tox_event_get_dht_nodes_response(
    const Tox_Event *_Nonnull event);

/**
 * Container object for all Tox core events.
 *
 * This is an immutable object once created.
 */
typedef struct Tox_Events Tox_Events;

uint32_t tox_events_get_size(const Tox_Events *_Nullable events);
const Tox_Event *_Nullable tox_events_get(const Tox_Events *_Nullable events, uint32_t index);

/**
 * Initialise the events recording system.
 *
 * All callbacks will be set to handlers inside the events recording system.
 * After this function returns, no user-defined event handlers will be
 * invoked. If the client sets their own handlers after calling this function,
 * the events associated with that handler will not be recorded.
 */
void tox_events_init(Tox *_Nonnull tox);

typedef enum Tox_Err_Events_Iterate {
    /**
     * The function returned successfully.
     */
    TOX_ERR_EVENTS_ITERATE_OK,

    /**
     * The function failed to allocate enough memory to store the events.
     *
     * Some events may still be stored if the return value is NULL. The events
     * object will always be valid (or NULL) but if this error code is set,
     * the function may have missed some events.
     */
    TOX_ERR_EVENTS_ITERATE_MALLOC,
} Tox_Err_Events_Iterate;

/**
 * Run a single `tox_iterate` iteration and record all the events.
 *
 * If allocation of the top level events object fails, this returns NULL.
 * Otherwise it returns an object with the recorded events in it. If an
 * allocation fails while recording events, some events may be dropped.
 *
 * If `fail_hard` in @p options is `true`, any failure will result in NULL, so
 * all recorded events will be dropped.
 *
 * The result must be freed using `tox_events_free`.
 *
 * @param tox The Tox instance to iterate on.
 * @param options Options for the iteration. If NULL, default options are used.
 * @param error An error code. Will be set to OK on success.
 *
 * @return the recorded events structure.
 */
Tox_Events *_Nullable tox_events_iterate(
    Tox *_Nonnull tox,
    const Tox_Iterate_Options *_Nullable options,
    Tox_Err_Events_Iterate *_Nullable error);

/**
 * Dispatch all events in the events object to the registered callbacks in the
 * Tox instance.
 *
 * @param tox The Tox instance to dispatch to.
 * @param events The events object to dispatch.
 * @param user_data The user data to pass to the callbacks.
 */
void tox_events_dispatch(Tox *_Nonnull tox, Tox_Events *_Nullable events, void *_Nullable user_data);

/**
 * Frees all memory associated with the events structure.
 *
 * All pointers into this object and its sub-objects, including byte buffers,
 * will be invalid once this function returns.
 */
void tox_events_free(Tox_Events *_Nullable events);

uint32_t tox_events_bytes_size(const Tox_Events *_Nullable events);
bool tox_events_get_bytes(const Tox_Events *_Nullable events, uint8_t *_Nonnull bytes);

typedef struct Tox_System Tox_System;

Tox_Events *_Nullable tox_events_load(const Tox_System *_Nonnull sys, const uint8_t *_Nonnull bytes, uint32_t bytes_size);

bool tox_events_equal(const Tox_System *_Nonnull sys, const Tox_Events *_Nullable a, const Tox_Events *_Nullable b);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_EVENTS_H */
