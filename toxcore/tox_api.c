/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "tox.h"

#include <stdlib.h>

#include "ccompat.h"
#include "tox_private.h"

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

uint32_t tox_version_major(void)
{
    return TOX_VERSION_MAJOR;
}
uint32_t tox_version_minor(void)
{
    return TOX_VERSION_MINOR;
}
uint32_t tox_version_patch(void)
{
    return TOX_VERSION_PATCH;
}
uint32_t tox_public_key_size(void)
{
    return TOX_PUBLIC_KEY_SIZE;
}
uint32_t tox_secret_key_size(void)
{
    return TOX_SECRET_KEY_SIZE;
}
uint32_t tox_conference_uid_size(void)
{
    return TOX_CONFERENCE_UID_SIZE;
}
uint32_t tox_conference_id_size(void)
{
    return TOX_CONFERENCE_ID_SIZE;
}
uint32_t tox_nospam_size(void)
{
    return TOX_NOSPAM_SIZE;
}
uint32_t tox_address_size(void)
{
    return TOX_ADDRESS_SIZE;
}
uint32_t tox_max_name_length(void)
{
    return TOX_MAX_NAME_LENGTH;
}
uint32_t tox_max_status_message_length(void)
{
    return TOX_MAX_STATUS_MESSAGE_LENGTH;
}
uint32_t tox_max_friend_request_length(void)
{
    return TOX_MAX_FRIEND_REQUEST_LENGTH;
}
uint32_t tox_max_message_length(void)
{
    return TOX_MAX_MESSAGE_LENGTH;
}
uint32_t tox_max_custom_packet_size(void)
{
    return TOX_MAX_CUSTOM_PACKET_SIZE;
}
uint32_t tox_hash_length(void)
{
    return TOX_HASH_LENGTH;
}
uint32_t tox_file_id_length(void)
{
    return TOX_FILE_ID_LENGTH;
}
uint32_t tox_max_filename_length(void)
{
    return TOX_MAX_FILENAME_LENGTH;
}
uint32_t tox_max_hostname_length(void)
{
    return TOX_MAX_HOSTNAME_LENGTH;
}
uint32_t tox_group_max_topic_length(void)
{
    return TOX_GROUP_MAX_TOPIC_LENGTH;
}
uint32_t tox_group_max_part_length(void)
{
    return TOX_GROUP_MAX_PART_LENGTH;
}
uint32_t tox_group_max_message_length(void)
{
    return TOX_GROUP_MAX_MESSAGE_LENGTH;
}
uint32_t tox_group_max_custom_lossy_packet_length(void)
{
    return TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH;
}
uint32_t tox_group_max_custom_lossless_packet_length(void)
{
    return TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH;
}
uint32_t tox_group_max_group_name_length(void)
{
    return TOX_GROUP_MAX_GROUP_NAME_LENGTH;
}
uint32_t tox_group_max_password_size(void)
{
    return TOX_GROUP_MAX_PASSWORD_SIZE;
}
uint32_t tox_group_chat_id_size(void)
{
    return TOX_GROUP_CHAT_ID_SIZE;
}
uint32_t tox_group_peer_public_key_size(void)
{
    return TOX_GROUP_PEER_PUBLIC_KEY_SIZE;
}
uint32_t tox_group_peer_ip_string_max_length(void)
{
    return TOX_GROUP_PEER_IP_STRING_MAX_LENGTH;
}
uint32_t tox_dht_node_ip_string_size(void)
{
    return TOX_DHT_NODE_IP_STRING_SIZE;
}
uint32_t tox_dht_node_public_key_size(void)
{
    return TOX_DHT_NODE_PUBLIC_KEY_SIZE;
}

bool tox_options_get_ipv6_enabled(const Tox_Options *options)
{
    return options->ipv6_enabled;
}
void tox_options_set_ipv6_enabled(Tox_Options *options, bool ipv6_enabled)
{
    options->ipv6_enabled = ipv6_enabled;
}
bool tox_options_get_udp_enabled(const Tox_Options *options)
{
    return options->udp_enabled;
}
void tox_options_set_udp_enabled(Tox_Options *options, bool udp_enabled)
{
    options->udp_enabled = udp_enabled;
}
Tox_Proxy_Type tox_options_get_proxy_type(const Tox_Options *options)
{
    return options->proxy_type;
}
void tox_options_set_proxy_type(Tox_Options *options, Tox_Proxy_Type proxy_type)
{
    options->proxy_type = proxy_type;
}
const char *tox_options_get_proxy_host(const Tox_Options *options)
{
    return options->proxy_host;
}
void tox_options_set_proxy_host(Tox_Options *options, const char *proxy_host)
{
    options->proxy_host = proxy_host;
}
uint16_t tox_options_get_proxy_port(const Tox_Options *options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(Tox_Options *options, uint16_t proxy_port)
{
    options->proxy_port = proxy_port;
}
uint16_t tox_options_get_start_port(const Tox_Options *options)
{
    return options->start_port;
}
void tox_options_set_start_port(Tox_Options *options, uint16_t start_port)
{
    options->start_port = start_port;
}
uint16_t tox_options_get_end_port(const Tox_Options *options)
{
    return options->end_port;
}
void tox_options_set_end_port(Tox_Options *options, uint16_t end_port)
{
    options->end_port = end_port;
}
uint16_t tox_options_get_tcp_port(const Tox_Options *options)
{
    return options->tcp_port;
}
void tox_options_set_tcp_port(Tox_Options *options, uint16_t tcp_port)
{
    options->tcp_port = tcp_port;
}
bool tox_options_get_hole_punching_enabled(const Tox_Options *options)
{
    return options->hole_punching_enabled;
}
void tox_options_set_hole_punching_enabled(Tox_Options *options, bool hole_punching_enabled)
{
    options->hole_punching_enabled = hole_punching_enabled;
}
Tox_Savedata_Type tox_options_get_savedata_type(const Tox_Options *options)
{
    return options->savedata_type;
}
void tox_options_set_savedata_type(Tox_Options *options, Tox_Savedata_Type savedata_type)
{
    options->savedata_type = savedata_type;
}
size_t tox_options_get_savedata_length(const Tox_Options *options)
{
    return options->savedata_length;
}
void tox_options_set_savedata_length(Tox_Options *options, size_t savedata_length)
{
    options->savedata_length = savedata_length;
}
tox_log_cb *tox_options_get_log_callback(const Tox_Options *options)
{
    return options->log_callback;
}
void tox_options_set_log_callback(Tox_Options *options, tox_log_cb *log_callback)
{
    options->log_callback = log_callback;
}
void *tox_options_get_log_user_data(const Tox_Options *options)
{
    return options->log_user_data;
}
void tox_options_set_log_user_data(Tox_Options *options, void *log_user_data)
{
    options->log_user_data = log_user_data;
}
bool tox_options_get_local_discovery_enabled(const Tox_Options *options)
{
    return options->local_discovery_enabled;
}
void tox_options_set_local_discovery_enabled(Tox_Options *options, bool local_discovery_enabled)
{
    options->local_discovery_enabled = local_discovery_enabled;
}
bool tox_options_get_dht_announcements_enabled(const Tox_Options *options)
{
    return options->dht_announcements_enabled;
}
void tox_options_set_dht_announcements_enabled(Tox_Options *options, bool dht_announcements_enabled)
{
    options->dht_announcements_enabled = dht_announcements_enabled;
}
bool tox_options_get_experimental_thread_safety(const Tox_Options *options)
{
    return options->experimental_thread_safety;
}
void tox_options_set_experimental_thread_safety(
    Tox_Options *options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
const Tox_System *tox_options_get_operating_system(const Tox_Options *options)
{
    return options->operating_system;
}
void tox_options_set_operating_system(Tox_Options *options, const Tox_System *operating_system)
{
    options->operating_system = operating_system;
}
bool tox_options_get_experimental_groups_persistence(const Tox_Options *options)
{
    return options->experimental_groups_persistence;
}
void tox_options_set_experimental_groups_persistence(
    Tox_Options *options, bool experimental_groups_persistence)
{
    options->experimental_groups_persistence = experimental_groups_persistence;
}

const uint8_t *tox_options_get_savedata_data(const Tox_Options *options)
{
    return options->savedata_data;
}

void tox_options_set_savedata_data(Tox_Options *options, const uint8_t *savedata_data, size_t length)
{
    options->savedata_data = savedata_data;
    options->savedata_length = length;
}

void tox_options_default(Tox_Options *options)
{
    if (options != nullptr) {
        const Tox_Options default_options = {false};
        *options = default_options;
        tox_options_set_ipv6_enabled(options, true);
        tox_options_set_udp_enabled(options, true);
        tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);
        tox_options_set_hole_punching_enabled(options, true);
        tox_options_set_local_discovery_enabled(options, true);
        tox_options_set_dht_announcements_enabled(options, true);
        tox_options_set_experimental_thread_safety(options, false);
        tox_options_set_experimental_groups_persistence(options, false);
    }
}

Tox_Options *tox_options_new(Tox_Err_Options_New *error)
{
    Tox_Options *options = (Tox_Options *)calloc(1, sizeof(Tox_Options));

    if (options != nullptr) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return nullptr;
}

void tox_options_free(Tox_Options *options)
{
    free(options);
}

const char *tox_user_status_to_string(Tox_User_Status value)
{
    switch (value) {
        case TOX_USER_STATUS_NONE:
            return "TOX_USER_STATUS_NONE";

        case TOX_USER_STATUS_AWAY:
            return "TOX_USER_STATUS_AWAY";

        case TOX_USER_STATUS_BUSY:
            return "TOX_USER_STATUS_BUSY";
    }

    return "<invalid Tox_User_Status>";
}
const char *tox_message_type_to_string(Tox_Message_Type value)
{
    switch (value) {
        case TOX_MESSAGE_TYPE_NORMAL:
            return "TOX_MESSAGE_TYPE_NORMAL";

        case TOX_MESSAGE_TYPE_ACTION:
            return "TOX_MESSAGE_TYPE_ACTION";
    }

    return "<invalid Tox_Message_Type>";
}
const char *tox_proxy_type_to_string(Tox_Proxy_Type value)
{
    switch (value) {
        case TOX_PROXY_TYPE_NONE:
            return "TOX_PROXY_TYPE_NONE";

        case TOX_PROXY_TYPE_HTTP:
            return "TOX_PROXY_TYPE_HTTP";

        case TOX_PROXY_TYPE_SOCKS5:
            return "TOX_PROXY_TYPE_SOCKS5";
    }

    return "<invalid Tox_Proxy_Type>";
}
const char *tox_savedata_type_to_string(Tox_Savedata_Type value)
{
    switch (value) {
        case TOX_SAVEDATA_TYPE_NONE:
            return "TOX_SAVEDATA_TYPE_NONE";

        case TOX_SAVEDATA_TYPE_TOX_SAVE:
            return "TOX_SAVEDATA_TYPE_TOX_SAVE";

        case TOX_SAVEDATA_TYPE_SECRET_KEY:
            return "TOX_SAVEDATA_TYPE_SECRET_KEY";
    }

    return "<invalid Tox_Savedata_Type>";
}
const char *tox_log_level_to_string(Tox_Log_Level value)
{
    switch (value) {
        case TOX_LOG_LEVEL_TRACE:
            return "TOX_LOG_LEVEL_TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "TOX_LOG_LEVEL_DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "TOX_LOG_LEVEL_INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "TOX_LOG_LEVEL_WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "TOX_LOG_LEVEL_ERROR";
    }

    return "<invalid Tox_Log_Level>";
}
const char *tox_err_options_new_to_string(Tox_Err_Options_New value)
{
    switch (value) {
        case TOX_ERR_OPTIONS_NEW_OK:
            return "TOX_ERR_OPTIONS_NEW_OK";

        case TOX_ERR_OPTIONS_NEW_MALLOC:
            return "TOX_ERR_OPTIONS_NEW_MALLOC";
    }

    return "<invalid Tox_Err_Options_New>";
}
const char *tox_err_new_to_string(Tox_Err_New value)
{
    switch (value) {
        case TOX_ERR_NEW_OK:
            return "TOX_ERR_NEW_OK";

        case TOX_ERR_NEW_NULL:
            return "TOX_ERR_NEW_NULL";

        case TOX_ERR_NEW_MALLOC:
            return "TOX_ERR_NEW_MALLOC";

        case TOX_ERR_NEW_PORT_ALLOC:
            return "TOX_ERR_NEW_PORT_ALLOC";

        case TOX_ERR_NEW_PROXY_BAD_TYPE:
            return "TOX_ERR_NEW_PROXY_BAD_TYPE";

        case TOX_ERR_NEW_PROXY_BAD_HOST:
            return "TOX_ERR_NEW_PROXY_BAD_HOST";

        case TOX_ERR_NEW_PROXY_BAD_PORT:
            return "TOX_ERR_NEW_PROXY_BAD_PORT";

        case TOX_ERR_NEW_PROXY_NOT_FOUND:
            return "TOX_ERR_NEW_PROXY_NOT_FOUND";

        case TOX_ERR_NEW_LOAD_ENCRYPTED:
            return "TOX_ERR_NEW_LOAD_ENCRYPTED";

        case TOX_ERR_NEW_LOAD_BAD_FORMAT:
            return "TOX_ERR_NEW_LOAD_BAD_FORMAT";
    }

    return "<invalid Tox_Err_New>";
}
const char *tox_err_bootstrap_to_string(Tox_Err_Bootstrap value)
{
    switch (value) {
        case TOX_ERR_BOOTSTRAP_OK:
            return "TOX_ERR_BOOTSTRAP_OK";

        case TOX_ERR_BOOTSTRAP_NULL:
            return "TOX_ERR_BOOTSTRAP_NULL";

        case TOX_ERR_BOOTSTRAP_BAD_HOST:
            return "TOX_ERR_BOOTSTRAP_BAD_HOST";

        case TOX_ERR_BOOTSTRAP_BAD_PORT:
            return "TOX_ERR_BOOTSTRAP_BAD_PORT";
    }

    return "<invalid Tox_Err_Bootstrap>";
}
const char *tox_connection_to_string(Tox_Connection value)
{
    switch (value) {
        case TOX_CONNECTION_NONE:
            return "TOX_CONNECTION_NONE";

        case TOX_CONNECTION_TCP:
            return "TOX_CONNECTION_TCP";

        case TOX_CONNECTION_UDP:
            return "TOX_CONNECTION_UDP";
    }

    return "<invalid Tox_Connection>";
}
const char *tox_err_set_info_to_string(Tox_Err_Set_Info value)
{
    switch (value) {
        case TOX_ERR_SET_INFO_OK:
            return "TOX_ERR_SET_INFO_OK";

        case TOX_ERR_SET_INFO_NULL:
            return "TOX_ERR_SET_INFO_NULL";

        case TOX_ERR_SET_INFO_TOO_LONG:
            return "TOX_ERR_SET_INFO_TOO_LONG";
    }

    return "<invalid Tox_Err_Set_Info>";
}
const char *tox_err_friend_add_to_string(Tox_Err_Friend_Add value)
{
    switch (value) {
        case TOX_ERR_FRIEND_ADD_OK:
            return "TOX_ERR_FRIEND_ADD_OK";

        case TOX_ERR_FRIEND_ADD_NULL:
            return "TOX_ERR_FRIEND_ADD_NULL";

        case TOX_ERR_FRIEND_ADD_TOO_LONG:
            return "TOX_ERR_FRIEND_ADD_TOO_LONG";

        case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
            return "TOX_ERR_FRIEND_ADD_NO_MESSAGE";

        case TOX_ERR_FRIEND_ADD_OWN_KEY:
            return "TOX_ERR_FRIEND_ADD_OWN_KEY";

        case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
            return "TOX_ERR_FRIEND_ADD_ALREADY_SENT";

        case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
            return "TOX_ERR_FRIEND_ADD_BAD_CHECKSUM";

        case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
            return "TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM";

        case TOX_ERR_FRIEND_ADD_MALLOC:
            return "TOX_ERR_FRIEND_ADD_MALLOC";
    }

    return "<invalid Tox_Err_Friend_Add>";
}
const char *tox_err_friend_delete_to_string(Tox_Err_Friend_Delete value)
{
    switch (value) {
        case TOX_ERR_FRIEND_DELETE_OK:
            return "TOX_ERR_FRIEND_DELETE_OK";

        case TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND";
    }

    return "<invalid Tox_Err_Friend_Delete>";
}
const char *tox_err_friend_by_public_key_to_string(Tox_Err_Friend_By_Public_Key value)
{
    switch (value) {
        case TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK:
            return "TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK";

        case TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL:
            return "TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL";

        case TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND:
            return "TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND";
    }

    return "<invalid Tox_Err_Friend_By_Public_Key>";
}
const char *tox_err_friend_get_public_key_to_string(Tox_Err_Friend_Get_Public_Key value)
{
    switch (value) {
        case TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK:
            return "TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK";

        case TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND";
    }

    return "<invalid Tox_Err_Friend_Get_Public_Key>";
}
const char *tox_err_friend_get_last_online_to_string(Tox_Err_Friend_Get_Last_Online value)
{
    switch (value) {
        case TOX_ERR_FRIEND_GET_LAST_ONLINE_OK:
            return "TOX_ERR_FRIEND_GET_LAST_ONLINE_OK";

        case TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND";
    }

    return "<invalid Tox_Err_Friend_Get_Last_Online>";
}
const char *tox_err_friend_query_to_string(Tox_Err_Friend_Query value)
{
    switch (value) {
        case TOX_ERR_FRIEND_QUERY_OK:
            return "TOX_ERR_FRIEND_QUERY_OK";

        case TOX_ERR_FRIEND_QUERY_NULL:
            return "TOX_ERR_FRIEND_QUERY_NULL";

        case TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND";
    }

    return "<invalid Tox_Err_Friend_Query>";
}
const char *tox_err_set_typing_to_string(Tox_Err_Set_Typing value)
{
    switch (value) {
        case TOX_ERR_SET_TYPING_OK:
            return "TOX_ERR_SET_TYPING_OK";

        case TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND:
            return "TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND";
    }

    return "<invalid Tox_Err_Set_Typing>";
}
const char *tox_err_friend_send_message_to_string(Tox_Err_Friend_Send_Message value)
{
    switch (value) {
        case TOX_ERR_FRIEND_SEND_MESSAGE_OK:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_OK";

        case TOX_ERR_FRIEND_SEND_MESSAGE_NULL:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_NULL";

        case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND";

        case TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ";

        case TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG";

        case TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY:
            return "TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY";
    }

    return "<invalid Tox_Err_Friend_Send_Message>";
}
const char *tox_file_control_to_string(Tox_File_Control value)
{
    switch (value) {
        case TOX_FILE_CONTROL_RESUME:
            return "TOX_FILE_CONTROL_RESUME";

        case TOX_FILE_CONTROL_PAUSE:
            return "TOX_FILE_CONTROL_PAUSE";

        case TOX_FILE_CONTROL_CANCEL:
            return "TOX_FILE_CONTROL_CANCEL";
    }

    return "<invalid Tox_File_Control>";
}
const char *tox_err_file_control_to_string(Tox_Err_File_Control value)
{
    switch (value) {
        case TOX_ERR_FILE_CONTROL_OK:
            return "TOX_ERR_FILE_CONTROL_OK";

        case TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND:
            return "TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND";

        case TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FILE_CONTROL_NOT_FOUND:
            return "TOX_ERR_FILE_CONTROL_NOT_FOUND";

        case TOX_ERR_FILE_CONTROL_NOT_PAUSED:
            return "TOX_ERR_FILE_CONTROL_NOT_PAUSED";

        case TOX_ERR_FILE_CONTROL_DENIED:
            return "TOX_ERR_FILE_CONTROL_DENIED";

        case TOX_ERR_FILE_CONTROL_ALREADY_PAUSED:
            return "TOX_ERR_FILE_CONTROL_ALREADY_PAUSED";

        case TOX_ERR_FILE_CONTROL_SENDQ:
            return "TOX_ERR_FILE_CONTROL_SENDQ";
    }

    return "<invalid Tox_Err_File_Control>";
}
const char *tox_err_file_seek_to_string(Tox_Err_File_Seek value)
{
    switch (value) {
        case TOX_ERR_FILE_SEEK_OK:
            return "TOX_ERR_FILE_SEEK_OK";

        case TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND:
            return "TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND";

        case TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FILE_SEEK_NOT_FOUND:
            return "TOX_ERR_FILE_SEEK_NOT_FOUND";

        case TOX_ERR_FILE_SEEK_DENIED:
            return "TOX_ERR_FILE_SEEK_DENIED";

        case TOX_ERR_FILE_SEEK_INVALID_POSITION:
            return "TOX_ERR_FILE_SEEK_INVALID_POSITION";

        case TOX_ERR_FILE_SEEK_SENDQ:
            return "TOX_ERR_FILE_SEEK_SENDQ";
    }

    return "<invalid Tox_Err_File_Seek>";
}
const char *tox_err_file_get_to_string(Tox_Err_File_Get value)
{
    switch (value) {
        case TOX_ERR_FILE_GET_OK:
            return "TOX_ERR_FILE_GET_OK";

        case TOX_ERR_FILE_GET_NULL:
            return "TOX_ERR_FILE_GET_NULL";

        case TOX_ERR_FILE_GET_FRIEND_NOT_FOUND:
            return "TOX_ERR_FILE_GET_FRIEND_NOT_FOUND";

        case TOX_ERR_FILE_GET_NOT_FOUND:
            return "TOX_ERR_FILE_GET_NOT_FOUND";
    }

    return "<invalid Tox_Err_File_Get>";
}
const char *tox_err_file_send_to_string(Tox_Err_File_Send value)
{
    switch (value) {
        case TOX_ERR_FILE_SEND_OK:
            return "TOX_ERR_FILE_SEND_OK";

        case TOX_ERR_FILE_SEND_NULL:
            return "TOX_ERR_FILE_SEND_NULL";

        case TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND:
            return "TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND";

        case TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FILE_SEND_NAME_TOO_LONG:
            return "TOX_ERR_FILE_SEND_NAME_TOO_LONG";

        case TOX_ERR_FILE_SEND_TOO_MANY:
            return "TOX_ERR_FILE_SEND_TOO_MANY";
    }

    return "<invalid Tox_Err_File_Send>";
}
const char *tox_err_file_send_chunk_to_string(Tox_Err_File_Send_Chunk value)
{
    switch (value) {
        case TOX_ERR_FILE_SEND_CHUNK_OK:
            return "TOX_ERR_FILE_SEND_CHUNK_OK";

        case TOX_ERR_FILE_SEND_CHUNK_NULL:
            return "TOX_ERR_FILE_SEND_CHUNK_NULL";

        case TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND:
            return "TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND";

        case TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND:
            return "TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND";

        case TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING:
            return "TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING";

        case TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH:
            return "TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH";

        case TOX_ERR_FILE_SEND_CHUNK_SENDQ:
            return "TOX_ERR_FILE_SEND_CHUNK_SENDQ";

        case TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION:
            return "TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION";
    }

    return "<invalid Tox_Err_File_Send_Chunk>";
}
const char *tox_conference_type_to_string(Tox_Conference_Type value)
{
    switch (value) {
        case TOX_CONFERENCE_TYPE_TEXT:
            return "TOX_CONFERENCE_TYPE_TEXT";

        case TOX_CONFERENCE_TYPE_AV:
            return "TOX_CONFERENCE_TYPE_AV";
    }

    return "<invalid Tox_Conference_Type>";
}
const char *tox_err_conference_new_to_string(Tox_Err_Conference_New value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_NEW_OK:
            return "TOX_ERR_CONFERENCE_NEW_OK";

        case TOX_ERR_CONFERENCE_NEW_INIT:
            return "TOX_ERR_CONFERENCE_NEW_INIT";
    }

    return "<invalid Tox_Err_Conference_New>";
}
const char *tox_err_conference_delete_to_string(Tox_Err_Conference_Delete value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_DELETE_OK:
            return "TOX_ERR_CONFERENCE_DELETE_OK";

        case TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND";
    }

    return "<invalid Tox_Err_Conference_Delete>";
}
const char *tox_err_conference_peer_query_to_string(Tox_Err_Conference_Peer_Query value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_PEER_QUERY_OK:
            return "TOX_ERR_CONFERENCE_PEER_QUERY_OK";

        case TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND";

        case TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND";

        case TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION:
            return "TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION";
    }

    return "<invalid Tox_Err_Conference_Peer_Query>";
}
const char *tox_err_conference_set_max_offline_to_string(Tox_Err_Conference_Set_Max_Offline value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK:
            return "TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK";

        case TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_CONFERENCE_NOT_FOUND";
    }

    return "<invalid Tox_Err_Conference_Set_Max_Offline>";
}
const char *tox_err_conference_invite_to_string(Tox_Err_Conference_Invite value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_INVITE_OK:
            return "TOX_ERR_CONFERENCE_INVITE_OK";

        case TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND";

        case TOX_ERR_CONFERENCE_INVITE_FAIL_SEND:
            return "TOX_ERR_CONFERENCE_INVITE_FAIL_SEND";

        case TOX_ERR_CONFERENCE_INVITE_NO_CONNECTION:
            return "TOX_ERR_CONFERENCE_INVITE_NO_CONNECTION";
    }

    return "<invalid Tox_Err_Conference_Invite>";
}
const char *tox_err_conference_join_to_string(Tox_Err_Conference_Join value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_JOIN_OK:
            return "TOX_ERR_CONFERENCE_JOIN_OK";

        case TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH:
            return "TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH";

        case TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE:
            return "TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE";

        case TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND";

        case TOX_ERR_CONFERENCE_JOIN_DUPLICATE:
            return "TOX_ERR_CONFERENCE_JOIN_DUPLICATE";

        case TOX_ERR_CONFERENCE_JOIN_INIT_FAIL:
            return "TOX_ERR_CONFERENCE_JOIN_INIT_FAIL";

        case TOX_ERR_CONFERENCE_JOIN_FAIL_SEND:
            return "TOX_ERR_CONFERENCE_JOIN_FAIL_SEND";
    }

    return "<invalid Tox_Err_Conference_Join>";
}
const char *tox_err_conference_send_message_to_string(Tox_Err_Conference_Send_Message value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_SEND_MESSAGE_OK:
            return "TOX_ERR_CONFERENCE_SEND_MESSAGE_OK";

        case TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND";

        case TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG:
            return "TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG";

        case TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION:
            return "TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION";

        case TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND:
            return "TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND";
    }

    return "<invalid Tox_Err_Conference_Send_Message>";
}
const char *tox_err_conference_title_to_string(Tox_Err_Conference_Title value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_TITLE_OK:
            return "TOX_ERR_CONFERENCE_TITLE_OK";

        case TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND";

        case TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH:
            return "TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH";

        case TOX_ERR_CONFERENCE_TITLE_FAIL_SEND:
            return "TOX_ERR_CONFERENCE_TITLE_FAIL_SEND";
    }

    return "<invalid Tox_Err_Conference_Title>";
}
const char *tox_err_conference_get_type_to_string(Tox_Err_Conference_Get_Type value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_GET_TYPE_OK:
            return "TOX_ERR_CONFERENCE_GET_TYPE_OK";

        case TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND";
    }

    return "<invalid Tox_Err_Conference_Get_Type>";
}
const char *tox_err_conference_by_id_to_string(Tox_Err_Conference_By_Id value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_BY_ID_OK:
            return "TOX_ERR_CONFERENCE_BY_ID_OK";

        case TOX_ERR_CONFERENCE_BY_ID_NULL:
            return "TOX_ERR_CONFERENCE_BY_ID_NULL";

        case TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND";
    }

    return "<invalid Tox_Err_Conference_By_Id>";
}
const char *tox_err_conference_by_uid_to_string(Tox_Err_Conference_By_Uid value)
{
    switch (value) {
        case TOX_ERR_CONFERENCE_BY_UID_OK:
            return "TOX_ERR_CONFERENCE_BY_UID_OK";

        case TOX_ERR_CONFERENCE_BY_UID_NULL:
            return "TOX_ERR_CONFERENCE_BY_UID_NULL";

        case TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND:
            return "TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND";
    }

    return "<invalid Tox_Err_Conference_By_Uid>";
}
const char *tox_err_friend_custom_packet_to_string(Tox_Err_Friend_Custom_Packet value)
{
    switch (value) {
        case TOX_ERR_FRIEND_CUSTOM_PACKET_OK:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_OK";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_NULL:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_NULL";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG";

        case TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ:
            return "TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ";
    }

    return "<invalid Tox_Err_Friend_Custom_Packet>";
}
const char *tox_err_get_port_to_string(Tox_Err_Get_Port value)
{
    switch (value) {
        case TOX_ERR_GET_PORT_OK:
            return "TOX_ERR_GET_PORT_OK";

        case TOX_ERR_GET_PORT_NOT_BOUND:
            return "TOX_ERR_GET_PORT_NOT_BOUND";
    }

    return "<invalid Tox_Err_Get_Port>";
}
const char *tox_group_privacy_state_to_string(Tox_Group_Privacy_State value)
{
    switch (value) {
        case TOX_GROUP_PRIVACY_STATE_PUBLIC:
            return "TOX_GROUP_PRIVACY_STATE_PUBLIC";

        case TOX_GROUP_PRIVACY_STATE_PRIVATE:
            return "TOX_GROUP_PRIVACY_STATE_PRIVATE";
    }

    return "<invalid Tox_Group_Privacy_State>";
}
const char *tox_group_topic_lock_to_string(Tox_Group_Topic_Lock value)
{
    switch (value) {
        case TOX_GROUP_TOPIC_LOCK_ENABLED:
            return "TOX_GROUP_TOPIC_LOCK_ENABLED";

        case TOX_GROUP_TOPIC_LOCK_DISABLED:
            return "TOX_GROUP_TOPIC_LOCK_DISABLED";
    }

    return "<invalid Tox_Group_Topic_Lock>";
}
const char *tox_group_voice_state_to_string(Tox_Group_Voice_State value)
{
    switch (value) {
        case TOX_GROUP_VOICE_STATE_ALL:
            return "TOX_GROUP_VOICE_STATE_ALL";

        case TOX_GROUP_VOICE_STATE_MODERATOR:
            return "TOX_GROUP_VOICE_STATE_MODERATOR";

        case TOX_GROUP_VOICE_STATE_FOUNDER:
            return "TOX_GROUP_VOICE_STATE_FOUNDER";
    }

    return "<invalid Tox_Group_Voice_State>";
}
const char *tox_group_role_to_string(Tox_Group_Role value)
{
    switch (value) {
        case TOX_GROUP_ROLE_FOUNDER:
            return "TOX_GROUP_ROLE_FOUNDER";

        case TOX_GROUP_ROLE_MODERATOR:
            return "TOX_GROUP_ROLE_MODERATOR";

        case TOX_GROUP_ROLE_USER:
            return "TOX_GROUP_ROLE_USER";

        case TOX_GROUP_ROLE_OBSERVER:
            return "TOX_GROUP_ROLE_OBSERVER";
    }

    return "<invalid Tox_Group_Role>";
}
const char *tox_err_group_new_to_string(Tox_Err_Group_New value)
{
    switch (value) {
        case TOX_ERR_GROUP_NEW_OK:
            return "TOX_ERR_GROUP_NEW_OK";

        case TOX_ERR_GROUP_NEW_TOO_LONG:
            return "TOX_ERR_GROUP_NEW_TOO_LONG";

        case TOX_ERR_GROUP_NEW_EMPTY:
            return "TOX_ERR_GROUP_NEW_EMPTY";

        case TOX_ERR_GROUP_NEW_INIT:
            return "TOX_ERR_GROUP_NEW_INIT";

        case TOX_ERR_GROUP_NEW_STATE:
            return "TOX_ERR_GROUP_NEW_STATE";

        case TOX_ERR_GROUP_NEW_ANNOUNCE:
            return "TOX_ERR_GROUP_NEW_ANNOUNCE";
    }

    return "<invalid Tox_Err_Group_New>";
}
const char *tox_err_group_join_to_string(Tox_Err_Group_Join value)
{
    switch (value) {
        case TOX_ERR_GROUP_JOIN_OK:
            return "TOX_ERR_GROUP_JOIN_OK";

        case TOX_ERR_GROUP_JOIN_INIT:
            return "TOX_ERR_GROUP_JOIN_INIT";

        case TOX_ERR_GROUP_JOIN_BAD_CHAT_ID:
            return "TOX_ERR_GROUP_JOIN_BAD_CHAT_ID";

        case TOX_ERR_GROUP_JOIN_EMPTY:
            return "TOX_ERR_GROUP_JOIN_EMPTY";

        case TOX_ERR_GROUP_JOIN_TOO_LONG:
            return "TOX_ERR_GROUP_JOIN_TOO_LONG";

        case TOX_ERR_GROUP_JOIN_PASSWORD:
            return "TOX_ERR_GROUP_JOIN_PASSWORD";

        case TOX_ERR_GROUP_JOIN_CORE:
            return "TOX_ERR_GROUP_JOIN_CORE";
    }

    return "<invalid Tox_Err_Group_Join>";
}
const char *tox_err_group_is_connected_to_string(Tox_Err_Group_Is_Connected value)
{
    switch (value) {
        case TOX_ERR_GROUP_IS_CONNECTED_OK:
            return "TOX_ERR_GROUP_IS_CONNECTED_OK";

        case TOX_ERR_GROUP_IS_CONNECTED_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_IS_CONNECTED_GROUP_NOT_FOUND";
    }

    return "<invalid Tox_Err_Group_Is_Connected>";
}
const char *tox_err_group_disconnect_to_string(Tox_Err_Group_Disconnect value)
{
    switch (value) {
        case TOX_ERR_GROUP_DISCONNECT_OK:
            return "TOX_ERR_GROUP_DISCONNECT_OK";

        case TOX_ERR_GROUP_DISCONNECT_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_DISCONNECT_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_DISCONNECT_ALREADY_DISCONNECTED:
            return "TOX_ERR_GROUP_DISCONNECT_ALREADY_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Disconnect>";
}
const char *tox_err_group_reconnect_to_string(Tox_Err_Group_Reconnect value)
{
    switch (value) {
        case TOX_ERR_GROUP_RECONNECT_OK:
            return "TOX_ERR_GROUP_RECONNECT_OK";

        case TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_RECONNECT_CORE:
            return "TOX_ERR_GROUP_RECONNECT_CORE";
    }

    return "<invalid Tox_Err_Group_Reconnect>";
}
const char *tox_err_group_leave_to_string(Tox_Err_Group_Leave value)
{
    switch (value) {
        case TOX_ERR_GROUP_LEAVE_OK:
            return "TOX_ERR_GROUP_LEAVE_OK";

        case TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_LEAVE_TOO_LONG:
            return "TOX_ERR_GROUP_LEAVE_TOO_LONG";

        case TOX_ERR_GROUP_LEAVE_FAIL_SEND:
            return "TOX_ERR_GROUP_LEAVE_FAIL_SEND";
    }

    return "<invalid Tox_Err_Group_Leave>";
}
const char *tox_err_group_self_query_to_string(Tox_Err_Group_Self_Query value)
{
    switch (value) {
        case TOX_ERR_GROUP_SELF_QUERY_OK:
            return "TOX_ERR_GROUP_SELF_QUERY_OK";

        case TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND";
    }

    return "<invalid Tox_Err_Group_Self_Query>";
}
const char *tox_err_group_self_name_set_to_string(Tox_Err_Group_Self_Name_Set value)
{
    switch (value) {
        case TOX_ERR_GROUP_SELF_NAME_SET_OK:
            return "TOX_ERR_GROUP_SELF_NAME_SET_OK";

        case TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG:
            return "TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG";

        case TOX_ERR_GROUP_SELF_NAME_SET_INVALID:
            return "TOX_ERR_GROUP_SELF_NAME_SET_INVALID";

        case TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND:
            return "TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND";
    }

    return "<invalid Tox_Err_Group_Self_Name_Set>";
}
const char *tox_err_group_self_status_set_to_string(Tox_Err_Group_Self_Status_Set value)
{
    switch (value) {
        case TOX_ERR_GROUP_SELF_STATUS_SET_OK:
            return "TOX_ERR_GROUP_SELF_STATUS_SET_OK";

        case TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND:
            return "TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND";
    }

    return "<invalid Tox_Err_Group_Self_Status_Set>";
}
const char *tox_err_group_peer_query_to_string(Tox_Err_Group_Peer_Query value)
{
    switch (value) {
        case TOX_ERR_GROUP_PEER_QUERY_OK:
            return "TOX_ERR_GROUP_PEER_QUERY_OK";

        case TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND";
    }

    return "<invalid Tox_Err_Group_Peer_Query>";
}
const char *tox_err_group_state_queries_to_string(Tox_Err_Group_State_Queries value)
{
    switch (value) {
        case TOX_ERR_GROUP_STATE_QUERIES_OK:
            return "TOX_ERR_GROUP_STATE_QUERIES_OK";

        case TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND";
    }

    return "<invalid Tox_Err_Group_State_Queries>";
}
const char *tox_err_group_topic_set_to_string(Tox_Err_Group_Topic_Set value)
{
    switch (value) {
        case TOX_ERR_GROUP_TOPIC_SET_OK:
            return "TOX_ERR_GROUP_TOPIC_SET_OK";

        case TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_TOPIC_SET_TOO_LONG:
            return "TOX_ERR_GROUP_TOPIC_SET_TOO_LONG";

        case TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS:
            return "TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS";

        case TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE:
            return "TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE";

        case TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND:
            return "TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND";

        case TOX_ERR_GROUP_TOPIC_SET_DISCONNECTED:
            return "TOX_ERR_GROUP_TOPIC_SET_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Topic_Set>";
}
const char *tox_err_group_send_message_to_string(Tox_Err_Group_Send_Message value)
{
    switch (value) {
        case TOX_ERR_GROUP_SEND_MESSAGE_OK:
            return "TOX_ERR_GROUP_SEND_MESSAGE_OK";

        case TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG:
            return "TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG";

        case TOX_ERR_GROUP_SEND_MESSAGE_EMPTY:
            return "TOX_ERR_GROUP_SEND_MESSAGE_EMPTY";

        case TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE:
            return "TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE";

        case TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS:
            return "TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS";

        case TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND:
            return "TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND";

        case TOX_ERR_GROUP_SEND_MESSAGE_DISCONNECTED:
            return "TOX_ERR_GROUP_SEND_MESSAGE_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Send_Message>";
}
const char *tox_err_group_send_private_message_to_string(Tox_Err_Group_Send_Private_Message value)
{
    switch (value) {
        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_DISCONNECTED:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_DISCONNECTED";

        case TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_BAD_TYPE:
            return "TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_BAD_TYPE";
    }

    return "<invalid Tox_Err_Group_Send_Private_Message>";
}
const char *tox_err_group_send_custom_packet_to_string(Tox_Err_Group_Send_Custom_Packet value)
{
    switch (value) {
        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_DISCONNECTED:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_DISCONNECTED";

        case TOX_ERR_GROUP_SEND_CUSTOM_PACKET_FAIL_SEND:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PACKET_FAIL_SEND";
    }

    return "<invalid Tox_Err_Group_Send_Custom_Packet>";
}
const char *tox_err_group_send_custom_private_packet_to_string(Tox_Err_Group_Send_Custom_Private_Packet value)
{
    switch (value) {
        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_TOO_LONG:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_TOO_LONG";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_EMPTY:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_EMPTY";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PEER_NOT_FOUND";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PERMISSIONS:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PERMISSIONS";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_FAIL_SEND:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_FAIL_SEND";

        case TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_DISCONNECTED:
            return "TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Send_Custom_Private_Packet>";
}
const char *tox_err_group_invite_friend_to_string(Tox_Err_Group_Invite_Friend value)
{
    switch (value) {
        case TOX_ERR_GROUP_INVITE_FRIEND_OK:
            return "TOX_ERR_GROUP_INVITE_FRIEND_OK";

        case TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND:
            return "TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND";

        case TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL:
            return "TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL";

        case TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND:
            return "TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND";

        case TOX_ERR_GROUP_INVITE_FRIEND_DISCONNECTED:
            return "TOX_ERR_GROUP_INVITE_FRIEND_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Invite_Friend>";
}
const char *tox_err_group_invite_accept_to_string(Tox_Err_Group_Invite_Accept value)
{
    switch (value) {
        case TOX_ERR_GROUP_INVITE_ACCEPT_OK:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_OK";

        case TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE";

        case TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED";

        case TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG";

        case TOX_ERR_GROUP_INVITE_ACCEPT_EMPTY:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_EMPTY";

        case TOX_ERR_GROUP_INVITE_ACCEPT_PASSWORD:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_PASSWORD";

        case TOX_ERR_GROUP_INVITE_ACCEPT_CORE:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_CORE";

        case TOX_ERR_GROUP_INVITE_ACCEPT_FAIL_SEND:
            return "TOX_ERR_GROUP_INVITE_ACCEPT_FAIL_SEND";
    }

    return "<invalid Tox_Err_Group_Invite_Accept>";
}
const char *tox_group_exit_type_to_string(Tox_Group_Exit_Type value)
{
    switch (value) {
        case TOX_GROUP_EXIT_TYPE_QUIT:
            return "TOX_GROUP_EXIT_TYPE_QUIT";

        case TOX_GROUP_EXIT_TYPE_TIMEOUT:
            return "TOX_GROUP_EXIT_TYPE_TIMEOUT";

        case TOX_GROUP_EXIT_TYPE_DISCONNECTED:
            return "TOX_GROUP_EXIT_TYPE_DISCONNECTED";

        case TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED:
            return "TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED";

        case TOX_GROUP_EXIT_TYPE_KICK:
            return "TOX_GROUP_EXIT_TYPE_KICK";

        case TOX_GROUP_EXIT_TYPE_SYNC_ERROR:
            return "TOX_GROUP_EXIT_TYPE_SYNC_ERROR";
    }

    return "<invalid Tox_Group_Exit_Type>";
}
const char *tox_group_join_fail_to_string(Tox_Group_Join_Fail value)
{
    switch (value) {
        case TOX_GROUP_JOIN_FAIL_PEER_LIMIT:
            return "TOX_GROUP_JOIN_FAIL_PEER_LIMIT";

        case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD:
            return "TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD";

        case TOX_GROUP_JOIN_FAIL_UNKNOWN:
            return "TOX_GROUP_JOIN_FAIL_UNKNOWN";
    }

    return "<invalid Tox_Group_Join_Fail>";
}
const char *tox_err_group_founder_set_password_to_string(Tox_Err_Group_Founder_Set_Password value)
{
    switch (value) {
        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_MALLOC:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_MALLOC";

        case TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_DISCONNECTED:
            return "TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Founder_Set_Password>";
}
const char *tox_err_group_founder_set_topic_lock_to_string(Tox_Err_Group_Founder_Set_Topic_Lock value)
{
    switch (value) {
        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_INVALID:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_INVALID";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_PERMISSIONS:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_PERMISSIONS";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_FAIL_SET:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_FAIL_SET";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_FAIL_SEND:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_FAIL_SEND";

        case TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_DISCONNECTED:
            return "TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Founder_Set_Topic_Lock>";
}
const char *tox_err_group_founder_set_voice_state_to_string(Tox_Err_Group_Founder_Set_Voice_State value)
{
    switch (value) {
        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_OK";

        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_PERMISSIONS:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_PERMISSIONS";

        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_FAIL_SET:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_FAIL_SET";

        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_FAIL_SEND:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_FAIL_SEND";

        case TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_DISCONNECTED:
            return "TOX_ERR_GROUP_FOUNDER_SET_VOICE_STATE_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Founder_Set_Voice_State>";
}
const char *tox_err_group_founder_set_privacy_state_to_string(Tox_Err_Group_Founder_Set_Privacy_State value)
{
    switch (value) {
        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK";

        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS";

        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET";

        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND";

        case TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_DISCONNECTED:
            return "TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Founder_Set_Privacy_State>";
}
const char *tox_err_group_founder_set_peer_limit_to_string(Tox_Err_Group_Founder_Set_Peer_Limit value)
{
    switch (value) {
        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK";

        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS";

        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET";

        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND";

        case TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_DISCONNECTED:
            return "TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_DISCONNECTED";
    }

    return "<invalid Tox_Err_Group_Founder_Set_Peer_Limit>";
}
const char *tox_err_group_set_ignore_to_string(Tox_Err_Group_Set_Ignore value)
{
    switch (value) {
        case TOX_ERR_GROUP_SET_IGNORE_OK:
            return "TOX_ERR_GROUP_SET_IGNORE_OK";

        case TOX_ERR_GROUP_SET_IGNORE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_SET_IGNORE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_SET_IGNORE_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_SET_IGNORE_PEER_NOT_FOUND";

        case TOX_ERR_GROUP_SET_IGNORE_SELF:
            return "TOX_ERR_GROUP_SET_IGNORE_SELF";
    }

    return "<invalid Tox_Err_Group_Set_Ignore>";
}
const char *tox_err_group_mod_set_role_to_string(Tox_Err_Group_Mod_Set_Role value)
{
    switch (value) {
        case TOX_ERR_GROUP_MOD_SET_ROLE_OK:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_OK";

        case TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND";

        case TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS";

        case TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT";

        case TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION";

        case TOX_ERR_GROUP_MOD_SET_ROLE_SELF:
            return "TOX_ERR_GROUP_MOD_SET_ROLE_SELF";
    }

    return "<invalid Tox_Err_Group_Mod_Set_Role>";
}
const char *tox_err_group_mod_kick_peer_to_string(Tox_Err_Group_Mod_Kick_Peer value)
{
    switch (value) {
        case TOX_ERR_GROUP_MOD_KICK_PEER_OK:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_OK";

        case TOX_ERR_GROUP_MOD_KICK_PEER_GROUP_NOT_FOUND:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_GROUP_NOT_FOUND";

        case TOX_ERR_GROUP_MOD_KICK_PEER_PEER_NOT_FOUND:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_PEER_NOT_FOUND";

        case TOX_ERR_GROUP_MOD_KICK_PEER_PERMISSIONS:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_PERMISSIONS";

        case TOX_ERR_GROUP_MOD_KICK_PEER_FAIL_ACTION:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_FAIL_ACTION";

        case TOX_ERR_GROUP_MOD_KICK_PEER_FAIL_SEND:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_FAIL_SEND";

        case TOX_ERR_GROUP_MOD_KICK_PEER_SELF:
            return "TOX_ERR_GROUP_MOD_KICK_PEER_SELF";
    }

    return "<invalid Tox_Err_Group_Mod_Kick_Peer>";
}
const char *tox_group_mod_event_to_string(Tox_Group_Mod_Event value)
{
    switch (value) {
        case TOX_GROUP_MOD_EVENT_KICK:
            return "TOX_GROUP_MOD_EVENT_KICK";

        case TOX_GROUP_MOD_EVENT_OBSERVER:
            return "TOX_GROUP_MOD_EVENT_OBSERVER";

        case TOX_GROUP_MOD_EVENT_USER:
            return "TOX_GROUP_MOD_EVENT_USER";

        case TOX_GROUP_MOD_EVENT_MODERATOR:
            return "TOX_GROUP_MOD_EVENT_MODERATOR";
    }

    return "<invalid Tox_Group_Mod_Event>";
}
