/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "tox.h"

#include <stdlib.h>
#include <string.h>

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
uint32_t tox_dht_node_ip_string_size(void)
{
    return TOX_DHT_NODE_IP_STRING_SIZE;
}
uint32_t tox_dht_node_public_key_size(void)
{
    return TOX_DHT_NODE_PUBLIC_KEY_SIZE;
}

//!TOKSTYLE-

#define ACCESSORS(type, ns, name) \
type tox_options_get_##ns##name(const struct Tox_Options *options) \
{ \
    return options->ns##name; \
} \
void tox_options_set_##ns##name(struct Tox_Options *options, type name) \
{ \
    options->ns##name = name; \
}

ACCESSORS(bool,, ipv6_enabled)
ACCESSORS(bool,, udp_enabled)
ACCESSORS(Tox_Proxy_Type, proxy_, type)
ACCESSORS(const char *, proxy_, host)
ACCESSORS(uint16_t, proxy_, port)
ACCESSORS(uint16_t,, start_port)
ACCESSORS(uint16_t,, end_port)
ACCESSORS(uint16_t,, tcp_port)
ACCESSORS(bool,, hole_punching_enabled)
ACCESSORS(Tox_Savedata_Type, savedata_, type)
ACCESSORS(size_t, savedata_, length)
ACCESSORS(tox_log_cb *, log_, callback)
ACCESSORS(void *, log_, user_data)
ACCESSORS(bool,, local_discovery_enabled)
ACCESSORS(bool,, dht_announcements_enabled)
ACCESSORS(bool,, experimental_thread_safety)
ACCESSORS(const Tox_System *,, operating_system)

//!TOKSTYLE+

const uint8_t *tox_options_get_savedata_data(const struct Tox_Options *options)
{
    return options->savedata_data;
}

void tox_options_set_savedata_data(struct Tox_Options *options, const uint8_t *data, size_t length)
{
    options->savedata_data = data;
    options->savedata_length = length;
}

void tox_options_default(struct Tox_Options *options)
{
    if (options != nullptr) {
        const struct Tox_Options default_options = {0};
        *options = default_options;
        tox_options_set_ipv6_enabled(options, true);
        tox_options_set_udp_enabled(options, true);
        tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);
        tox_options_set_hole_punching_enabled(options, true);
        tox_options_set_local_discovery_enabled(options, true);
        tox_options_set_dht_announcements_enabled(options, true);
        tox_options_set_experimental_thread_safety(options, false);
    }
}

struct Tox_Options *tox_options_new(Tox_Err_Options_New *error)
{
    struct Tox_Options *options = (struct Tox_Options *)calloc(1, sizeof(struct Tox_Options));

    if (options != nullptr) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return nullptr;
}

void tox_options_free(struct Tox_Options *options)
{
    free(options);
}
