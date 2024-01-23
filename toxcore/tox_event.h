/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENT_H
#define C_TOXCORE_TOXCORE_TOX_EVENT_H

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "mem.h"
#include "tox_events.h"
#include "tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union Tox_Event_Data {
    /**
     * Opaque pointer just to check whether any value is set.
     */
    void *value;

    Tox_Event_Conference_Connected *conference_connected;
    Tox_Event_Conference_Invite *conference_invite;
    Tox_Event_Conference_Message *conference_message;
    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed;
    Tox_Event_Conference_Peer_Name *conference_peer_name;
    Tox_Event_Conference_Title *conference_title;
    Tox_Event_File_Chunk_Request *file_chunk_request;
    Tox_Event_File_Recv *file_recv;
    Tox_Event_File_Recv_Chunk *file_recv_chunk;
    Tox_Event_File_Recv_Control *file_recv_control;
    Tox_Event_Friend_Connection_Status *friend_connection_status;
    Tox_Event_Friend_Lossless_Packet *friend_lossless_packet;
    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet;
    Tox_Event_Friend_Message *friend_message;
    Tox_Event_Friend_Name *friend_name;
    Tox_Event_Friend_Read_Receipt *friend_read_receipt;
    Tox_Event_Friend_Request *friend_request;
    Tox_Event_Friend_Status *friend_status;
    Tox_Event_Friend_Status_Message *friend_status_message;
    Tox_Event_Friend_Typing *friend_typing;
    Tox_Event_Self_Connection_Status *self_connection_status;
    Tox_Event_Group_Peer_Name *group_peer_name;
    Tox_Event_Group_Peer_Status *group_peer_status;
    Tox_Event_Group_Topic *group_topic;
    Tox_Event_Group_Privacy_State *group_privacy_state;
    Tox_Event_Group_Voice_State *group_voice_state;
    Tox_Event_Group_Topic_Lock *group_topic_lock;
    Tox_Event_Group_Peer_Limit *group_peer_limit;
    Tox_Event_Group_Password *group_password;
    Tox_Event_Group_Message *group_message;
    Tox_Event_Group_Private_Message *group_private_message;
    Tox_Event_Group_Custom_Packet *group_custom_packet;
    Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet;
    Tox_Event_Group_Invite *group_invite;
    Tox_Event_Group_Peer_Join *group_peer_join;
    Tox_Event_Group_Peer_Exit *group_peer_exit;
    Tox_Event_Group_Self_Join *group_self_join;
    Tox_Event_Group_Join_Fail *group_join_fail;
    Tox_Event_Group_Moderation *group_moderation;
    Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response;
} Tox_Event_Data;

struct Tox_Event {
    Tox_Event_Type type;
    Tox_Event_Data data;
};

/**
 * Constructor.
 */
non_null() bool tox_event_construct(Tox_Event *event, Tox_Event_Type type, const Memory *mem);

non_null() Tox_Event_Conference_Connected *tox_event_conference_connected_new(const Memory *mem);
non_null() Tox_Event_Conference_Invite *tox_event_conference_invite_new(const Memory *mem);
non_null() Tox_Event_Conference_Message *tox_event_conference_message_new(const Memory *mem);
non_null() Tox_Event_Conference_Peer_List_Changed *tox_event_conference_peer_list_changed_new(const Memory *mem);
non_null() Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_new(const Memory *mem);
non_null() Tox_Event_Conference_Title *tox_event_conference_title_new(const Memory *mem);
non_null() Tox_Event_File_Chunk_Request *tox_event_file_chunk_request_new(const Memory *mem);
non_null() Tox_Event_File_Recv_Chunk *tox_event_file_recv_chunk_new(const Memory *mem);
non_null() Tox_Event_File_Recv_Control *tox_event_file_recv_control_new(const Memory *mem);
non_null() Tox_Event_File_Recv *tox_event_file_recv_new(const Memory *mem);
non_null() Tox_Event_Friend_Connection_Status *tox_event_friend_connection_status_new(const Memory *mem);
non_null() Tox_Event_Friend_Lossless_Packet *tox_event_friend_lossless_packet_new(const Memory *mem);
non_null() Tox_Event_Friend_Lossy_Packet *tox_event_friend_lossy_packet_new(const Memory *mem);
non_null() Tox_Event_Friend_Message *tox_event_friend_message_new(const Memory *mem);
non_null() Tox_Event_Friend_Name *tox_event_friend_name_new(const Memory *mem);
non_null() Tox_Event_Friend_Read_Receipt *tox_event_friend_read_receipt_new(const Memory *mem);
non_null() Tox_Event_Friend_Request *tox_event_friend_request_new(const Memory *mem);
non_null() Tox_Event_Friend_Status_Message *tox_event_friend_status_message_new(const Memory *mem);
non_null() Tox_Event_Friend_Status *tox_event_friend_status_new(const Memory *mem);
non_null() Tox_Event_Friend_Typing *tox_event_friend_typing_new(const Memory *mem);
non_null() Tox_Event_Self_Connection_Status *tox_event_self_connection_status_new(const Memory *mem);
non_null() Tox_Event_Group_Peer_Name *tox_event_group_peer_name_new(const Memory *mem);
non_null() Tox_Event_Group_Peer_Status *tox_event_group_peer_status_new(const Memory *mem);
non_null() Tox_Event_Group_Topic *tox_event_group_topic_new(const Memory *mem);
non_null() Tox_Event_Group_Privacy_State *tox_event_group_privacy_state_new(const Memory *mem);
non_null() Tox_Event_Group_Voice_State *tox_event_group_voice_state_new(const Memory *mem);
non_null() Tox_Event_Group_Topic_Lock *tox_event_group_topic_lock_new(const Memory *mem);
non_null() Tox_Event_Group_Peer_Limit *tox_event_group_peer_limit_new(const Memory *mem);
non_null() Tox_Event_Group_Password *tox_event_group_password_new(const Memory *mem);
non_null() Tox_Event_Group_Message *tox_event_group_message_new(const Memory *mem);
non_null() Tox_Event_Group_Private_Message *tox_event_group_private_message_new(const Memory *mem);
non_null() Tox_Event_Group_Custom_Packet *tox_event_group_custom_packet_new(const Memory *mem);
non_null() Tox_Event_Group_Custom_Private_Packet *tox_event_group_custom_private_packet_new(const Memory *mem);
non_null() Tox_Event_Group_Invite *tox_event_group_invite_new(const Memory *mem);
non_null() Tox_Event_Group_Peer_Join *tox_event_group_peer_join_new(const Memory *mem);
non_null() Tox_Event_Group_Peer_Exit *tox_event_group_peer_exit_new(const Memory *mem);
non_null() Tox_Event_Group_Self_Join *tox_event_group_self_join_new(const Memory *mem);
non_null() Tox_Event_Group_Join_Fail *tox_event_group_join_fail_new(const Memory *mem);
non_null() Tox_Event_Group_Moderation *tox_event_group_moderation_new(const Memory *mem);
non_null() Tox_Event_Dht_Get_Nodes_Response *tox_event_dht_get_nodes_response_new(const Memory *mem);

/**
 * Destructor.
 */
non_null(2) nullable(1) void tox_event_destruct(Tox_Event *event, const Memory *mem);

non_null(2) nullable(1) void tox_event_conference_connected_free(Tox_Event_Conference_Connected *conference_connected, const Memory *mem);
non_null(2) nullable(1) void tox_event_conference_invite_free(Tox_Event_Conference_Invite *conference_invite, const Memory *mem);
non_null(2) nullable(1) void tox_event_conference_message_free(Tox_Event_Conference_Message *conference_message, const Memory *mem);
non_null(2) nullable(1) void tox_event_conference_peer_list_changed_free(Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed, const Memory *mem);
non_null(2) nullable(1) void tox_event_conference_peer_name_free(Tox_Event_Conference_Peer_Name *conference_peer_name, const Memory *mem);
non_null(2) nullable(1) void tox_event_conference_title_free(Tox_Event_Conference_Title *conference_title, const Memory *mem);
non_null(2) nullable(1) void tox_event_file_chunk_request_free(Tox_Event_File_Chunk_Request *file_chunk_request, const Memory *mem);
non_null(2) nullable(1) void tox_event_file_recv_chunk_free(Tox_Event_File_Recv_Chunk *file_recv_chunk, const Memory *mem);
non_null(2) nullable(1) void tox_event_file_recv_control_free(Tox_Event_File_Recv_Control *file_recv_control, const Memory *mem);
non_null(2) nullable(1) void tox_event_file_recv_free(Tox_Event_File_Recv *file_recv, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_connection_status_free(Tox_Event_Friend_Connection_Status *friend_connection_status, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_lossless_packet_free(Tox_Event_Friend_Lossless_Packet *friend_lossless_packet, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_lossy_packet_free(Tox_Event_Friend_Lossy_Packet *friend_lossy_packet, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_message_free(Tox_Event_Friend_Message *friend_message, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_name_free(Tox_Event_Friend_Name *friend_name, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_read_receipt_free(Tox_Event_Friend_Read_Receipt *friend_read_receipt, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_request_free(Tox_Event_Friend_Request *friend_request, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_status_message_free(Tox_Event_Friend_Status_Message *friend_status_message, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_status_free(Tox_Event_Friend_Status *friend_status, const Memory *mem);
non_null(2) nullable(1) void tox_event_friend_typing_free(Tox_Event_Friend_Typing *friend_typing, const Memory *mem);
non_null(2) nullable(1) void tox_event_self_connection_status_free(Tox_Event_Self_Connection_Status *self_connection_status, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_peer_name_free(Tox_Event_Group_Peer_Name *group_peer_name, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_peer_status_free(Tox_Event_Group_Peer_Status *group_peer_status, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_topic_free(Tox_Event_Group_Topic *group_topic, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_privacy_state_free(Tox_Event_Group_Privacy_State *group_privacy_state, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_voice_state_free(Tox_Event_Group_Voice_State *group_voice_state, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_topic_lock_free(Tox_Event_Group_Topic_Lock *group_topic_lock, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_peer_limit_free(Tox_Event_Group_Peer_Limit *group_peer_limit, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_password_free(Tox_Event_Group_Password *group_password, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_message_free(Tox_Event_Group_Message *group_message, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_private_message_free(Tox_Event_Group_Private_Message *group_private_message, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_custom_packet_free(Tox_Event_Group_Custom_Packet *group_custom_packet, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_custom_private_packet_free(Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_invite_free(Tox_Event_Group_Invite *group_invite, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_peer_join_free(Tox_Event_Group_Peer_Join *group_peer_join, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_peer_exit_free(Tox_Event_Group_Peer_Exit *group_peer_exit, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_self_join_free(Tox_Event_Group_Self_Join *group_self_join, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_join_fail_free(Tox_Event_Group_Join_Fail *group_join_fail, const Memory *mem);
non_null(2) nullable(1) void tox_event_group_moderation_free(Tox_Event_Group_Moderation *group_moderation, const Memory *mem);
non_null(2) nullable(1) void tox_event_dht_get_nodes_response_free(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response, const Memory *mem);

/**
 * Pack into msgpack.
 */
non_null() bool tox_event_pack(const Tox_Event *event, Bin_Pack *bp);

non_null() bool tox_event_conference_connected_pack(const Tox_Event_Conference_Connected *event, Bin_Pack *bp);
non_null() bool tox_event_conference_invite_pack(const Tox_Event_Conference_Invite *event, Bin_Pack *bp);
non_null() bool tox_event_conference_message_pack(const Tox_Event_Conference_Message *event, Bin_Pack *bp);
non_null() bool tox_event_conference_peer_list_changed_pack(const Tox_Event_Conference_Peer_List_Changed *event, Bin_Pack *bp);
non_null() bool tox_event_conference_peer_name_pack(const Tox_Event_Conference_Peer_Name *event, Bin_Pack *bp);
non_null() bool tox_event_conference_title_pack(const Tox_Event_Conference_Title *event, Bin_Pack *bp);
non_null() bool tox_event_file_chunk_request_pack(const Tox_Event_File_Chunk_Request *event, Bin_Pack *bp);
non_null() bool tox_event_file_recv_chunk_pack(const Tox_Event_File_Recv_Chunk *event, Bin_Pack *bp);
non_null() bool tox_event_file_recv_control_pack(const Tox_Event_File_Recv_Control *event, Bin_Pack *bp);
non_null() bool tox_event_file_recv_pack(const Tox_Event_File_Recv *event, Bin_Pack *bp);
non_null() bool tox_event_friend_connection_status_pack(const Tox_Event_Friend_Connection_Status *event, Bin_Pack *bp);
non_null() bool tox_event_friend_lossless_packet_pack(const Tox_Event_Friend_Lossless_Packet *event, Bin_Pack *bp);
non_null() bool tox_event_friend_lossy_packet_pack(const Tox_Event_Friend_Lossy_Packet *event, Bin_Pack *bp);
non_null() bool tox_event_friend_message_pack(const Tox_Event_Friend_Message *event, Bin_Pack *bp);
non_null() bool tox_event_friend_name_pack(const Tox_Event_Friend_Name *event, Bin_Pack *bp);
non_null() bool tox_event_friend_read_receipt_pack(const Tox_Event_Friend_Read_Receipt *event, Bin_Pack *bp);
non_null() bool tox_event_friend_request_pack(const Tox_Event_Friend_Request *event, Bin_Pack *bp);
non_null() bool tox_event_friend_status_message_pack(const Tox_Event_Friend_Status_Message *event, Bin_Pack *bp);
non_null() bool tox_event_friend_status_pack(const Tox_Event_Friend_Status *event, Bin_Pack *bp);
non_null() bool tox_event_friend_typing_pack(const Tox_Event_Friend_Typing *event, Bin_Pack *bp);
non_null() bool tox_event_self_connection_status_pack(const Tox_Event_Self_Connection_Status *event, Bin_Pack *bp);
non_null() bool tox_event_group_peer_name_pack(const Tox_Event_Group_Peer_Name *event, Bin_Pack *bp);
non_null() bool tox_event_group_peer_status_pack(const Tox_Event_Group_Peer_Status *event, Bin_Pack *bp);
non_null() bool tox_event_group_topic_pack(const Tox_Event_Group_Topic *event, Bin_Pack *bp);
non_null() bool tox_event_group_privacy_state_pack(const Tox_Event_Group_Privacy_State *event, Bin_Pack *bp);
non_null() bool tox_event_group_voice_state_pack(const Tox_Event_Group_Voice_State *event, Bin_Pack *bp);
non_null() bool tox_event_group_topic_lock_pack(const Tox_Event_Group_Topic_Lock *event, Bin_Pack *bp);
non_null() bool tox_event_group_peer_limit_pack(const Tox_Event_Group_Peer_Limit *event, Bin_Pack *bp);
non_null() bool tox_event_group_password_pack(const Tox_Event_Group_Password *event, Bin_Pack *bp);
non_null() bool tox_event_group_message_pack(const Tox_Event_Group_Message *event, Bin_Pack *bp);
non_null() bool tox_event_group_private_message_pack(const Tox_Event_Group_Private_Message *event, Bin_Pack *bp);
non_null() bool tox_event_group_custom_packet_pack(const Tox_Event_Group_Custom_Packet *event, Bin_Pack *bp);
non_null() bool tox_event_group_custom_private_packet_pack(const Tox_Event_Group_Custom_Private_Packet *event, Bin_Pack *bp);
non_null() bool tox_event_group_invite_pack(const Tox_Event_Group_Invite *event, Bin_Pack *bp);
non_null() bool tox_event_group_peer_join_pack(const Tox_Event_Group_Peer_Join *event, Bin_Pack *bp);
non_null() bool tox_event_group_peer_exit_pack(const Tox_Event_Group_Peer_Exit *event, Bin_Pack *bp);
non_null() bool tox_event_group_self_join_pack(const Tox_Event_Group_Self_Join *event, Bin_Pack *bp);
non_null() bool tox_event_group_join_fail_pack(const Tox_Event_Group_Join_Fail *event, Bin_Pack *bp);
non_null() bool tox_event_group_moderation_pack(const Tox_Event_Group_Moderation *event, Bin_Pack *bp);
non_null() bool tox_event_dht_get_nodes_response_pack(const Tox_Event_Dht_Get_Nodes_Response *event, Bin_Pack *bp);

/**
 * Unpack from msgpack.
 */
non_null() bool tox_event_unpack_into(Tox_Event *event, Bin_Unpack *bu, const Memory *mem);

non_null() bool tox_event_conference_connected_unpack(Tox_Event_Conference_Connected **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_conference_invite_unpack(Tox_Event_Conference_Invite **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_conference_message_unpack(Tox_Event_Conference_Message **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_conference_peer_list_changed_unpack(Tox_Event_Conference_Peer_List_Changed **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_conference_peer_name_unpack(Tox_Event_Conference_Peer_Name **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_conference_title_unpack(Tox_Event_Conference_Title **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_file_chunk_request_unpack(Tox_Event_File_Chunk_Request **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_file_recv_chunk_unpack(Tox_Event_File_Recv_Chunk **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_file_recv_control_unpack(Tox_Event_File_Recv_Control **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_file_recv_unpack(Tox_Event_File_Recv **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_connection_status_unpack(Tox_Event_Friend_Connection_Status **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_lossless_packet_unpack(Tox_Event_Friend_Lossless_Packet **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_lossy_packet_unpack(Tox_Event_Friend_Lossy_Packet **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_message_unpack(Tox_Event_Friend_Message **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_name_unpack(Tox_Event_Friend_Name **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_read_receipt_unpack(Tox_Event_Friend_Read_Receipt **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_request_unpack(Tox_Event_Friend_Request **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_status_message_unpack(Tox_Event_Friend_Status_Message **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_status_unpack(Tox_Event_Friend_Status **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_friend_typing_unpack(Tox_Event_Friend_Typing **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_self_connection_status_unpack(Tox_Event_Self_Connection_Status **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_peer_name_unpack(Tox_Event_Group_Peer_Name **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_peer_status_unpack(Tox_Event_Group_Peer_Status **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_topic_unpack(Tox_Event_Group_Topic **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_privacy_state_unpack(Tox_Event_Group_Privacy_State **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_voice_state_unpack(Tox_Event_Group_Voice_State **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_topic_lock_unpack(Tox_Event_Group_Topic_Lock **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_peer_limit_unpack(Tox_Event_Group_Peer_Limit **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_password_unpack(Tox_Event_Group_Password **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_message_unpack(Tox_Event_Group_Message **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_private_message_unpack(Tox_Event_Group_Private_Message **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_custom_packet_unpack(Tox_Event_Group_Custom_Packet **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_custom_private_packet_unpack(Tox_Event_Group_Custom_Private_Packet **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_invite_unpack(Tox_Event_Group_Invite **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_peer_join_unpack(Tox_Event_Group_Peer_Join **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_peer_exit_unpack(Tox_Event_Group_Peer_Exit **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_self_join_unpack(Tox_Event_Group_Self_Join **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_join_fail_unpack(Tox_Event_Group_Join_Fail **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_group_moderation_unpack(Tox_Event_Group_Moderation **event, Bin_Unpack *bu, const Memory *mem);
non_null() bool tox_event_dht_get_nodes_response_unpack(Tox_Event_Dht_Get_Nodes_Response **event, Bin_Unpack *bu, const Memory *mem);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_EVENT_H */
