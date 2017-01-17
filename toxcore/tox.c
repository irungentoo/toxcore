/* tox.c
 *
 * The Tox public API.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "Messenger.h"
#include "group_chats.h"
#include "group_moderation.h"
#include "logger.h"

#include "../toxencryptsave/defines.h"

#define TOX_DEFINED
typedef struct Messenger Tox;

#include "tox.h"

#define SET_ERROR_PARAMETER(param, x) {if(param) {*param = x;}}

#if TOX_HASH_LENGTH != crypto_hash_sha256_BYTES
#error TOX_HASH_LENGTH is assumed to be equal to crypto_hash_sha256_BYTES
#endif

#if FILE_ID_LENGTH != crypto_box_KEYBYTES
#error FILE_ID_LENGTH is assumed to be equal to crypto_box_KEYBYTES
#endif

#if TOX_FILE_ID_LENGTH != crypto_box_KEYBYTES
#error TOX_FILE_ID_LENGTH is assumed to be equal to crypto_box_KEYBYTES
#endif

#if TOX_FILE_ID_LENGTH != TOX_HASH_LENGTH
#error TOX_FILE_ID_LENGTH is assumed to be equal to TOX_HASH_LENGTH
#endif

#if TOX_PUBLIC_KEY_SIZE != crypto_box_PUBLICKEYBYTES
#error TOX_PUBLIC_KEY_SIZE is assumed to be equal to crypto_box_PUBLICKEYBYTES
#endif

#if TOX_SECRET_KEY_SIZE != crypto_box_SECRETKEYBYTES
#error TOX_SECRET_KEY_SIZE is assumed to be equal to crypto_box_SECRETKEYBYTES
#endif

#if TOX_MAX_NAME_LENGTH != MAX_NAME_LENGTH
#error TOX_MAX_NAME_LENGTH is assumed to be equal to MAX_NAME_LENGTH
#endif

#if TOX_MAX_STATUS_MESSAGE_LENGTH != MAX_STATUSMESSAGE_LENGTH
#error TOX_MAX_STATUS_MESSAGE_LENGTH is assumed to be equal to MAX_STATUSMESSAGE_LENGTH
#endif

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

bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    return (TOX_VERSION_MAJOR == major && /* Force the major version */
            (TOX_VERSION_MINOR > minor || /* Current minor version must be newer than requested -- or -- */
             (TOX_VERSION_MINOR == minor && TOX_VERSION_PATCH >= patch) /* the patch must be the same or newer */
            )
           );
}


void tox_options_default(struct Tox_Options *options)
{
    if (options) {
        memset(options, 0, sizeof(struct Tox_Options));
        options->ipv6_enabled = 1;
        options->udp_enabled = 1;
        options->proxy_type = TOX_PROXY_TYPE_NONE;
    }
}

struct Tox_Options *tox_options_new(TOX_ERR_OPTIONS_NEW *error)
{
    struct Tox_Options *options = calloc(sizeof(struct Tox_Options), 1);

    if (options) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return NULL;
}

void tox_options_free(struct Tox_Options *options)
{
    free(options);
}

Tox *tox_new(const struct Tox_Options *options, TOX_ERR_NEW *error)
{
    if (!logger_get_global())
        logger_set_global(logger_new(LOGGER_OUTPUT_FILE, LOGGER_LEVEL, "toxcore"));

    Messenger_Options m_options = {0};

    _Bool load_savedata_sk = 0, load_savedata_tox = 0;

    if (options == NULL) {
        m_options.ipv6enabled = TOX_ENABLE_IPV6_DEFAULT;
    } else {
        if (options->savedata_type != TOX_SAVEDATA_TYPE_NONE) {
            if (options->savedata_data == NULL || options->savedata_length == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }
        }

        if (options->savedata_type == TOX_SAVEDATA_TYPE_SECRET_KEY) {
            if (options->savedata_length != TOX_SECRET_KEY_SIZE) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }

            load_savedata_sk = 1;
        } else if (options->savedata_type == TOX_SAVEDATA_TYPE_TOX_SAVE) {
            if (options->savedata_length < TOX_ENC_SAVE_MAGIC_LENGTH) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
                return NULL;
            }

            if (sodium_memcmp(options->savedata_data, TOX_ENC_SAVE_MAGIC_NUMBER, TOX_ENC_SAVE_MAGIC_LENGTH) == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_ENCRYPTED);
                return NULL;
            }

            load_savedata_tox = 1;
        }

        m_options.ipv6enabled = options->ipv6_enabled;
        m_options.udp_disabled = !options->udp_enabled;
        m_options.port_range[0] = options->start_port;
        m_options.port_range[1] = options->end_port;
        m_options.tcp_server_port = options->tcp_port;

        switch (options->proxy_type) {
            case TOX_PROXY_TYPE_HTTP:
                m_options.proxy_info.proxy_type = TCP_PROXY_HTTP;
                break;

            case TOX_PROXY_TYPE_SOCKS5:
                m_options.proxy_info.proxy_type = TCP_PROXY_SOCKS5;
                break;

            case TOX_PROXY_TYPE_NONE:
                m_options.proxy_info.proxy_type = TCP_PROXY_NONE;
                break;

            default:
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_TYPE);
                return NULL;
        }

        if (m_options.proxy_info.proxy_type != TCP_PROXY_NONE) {
            if (options->proxy_port == 0) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_PORT);
                return NULL;
            }

            ip_init(&m_options.proxy_info.ip_port.ip, m_options.ipv6enabled);

            if (m_options.ipv6enabled)
                m_options.proxy_info.ip_port.ip.family = AF_UNSPEC;

            if (!addr_resolve_or_parse_ip(options->proxy_host, &m_options.proxy_info.ip_port.ip, NULL)) {
                SET_ERROR_PARAMETER(error, TOX_ERR_NEW_PROXY_BAD_HOST);
                //TODO: TOX_ERR_NEW_PROXY_NOT_FOUND if domain.
                return NULL;
            }

            m_options.proxy_info.ip_port.port = htons(options->proxy_port);
        }
    }

    unsigned int m_error;
    Messenger *m = new_messenger(&m_options, &m_error);

    if (load_savedata_tox && messenger_load(m, options->savedata_data, options->savedata_length) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_LOAD_BAD_FORMAT);
    } else if (load_savedata_sk) {
        load_secret_key(m->net_crypto, options->savedata_data);
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_NEW_OK);
    }

    return m;
}

void tox_kill(Tox *tox)
{
    Messenger *m = tox;
    kill_groupchats(m->group_handler);
    kill_messenger(m);
    logger_kill_global();
}

size_t tox_get_savedata_size(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_size(m);
}

void tox_get_savedata(const Tox *tox, uint8_t *data)
{
    if (data) {
        const Messenger *m = tox;
        messenger_save(m, data);
    }
}

bool tox_bootstrap(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key, TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    struct addrinfo *root, *info;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    info = root;

    unsigned int count = 0;

    do {
        IP_Port ip_port;
        ip_port.port = htons(port);
        ip_port.ip.family = info->ai_family;

        if (info->ai_socktype && info->ai_socktype != SOCK_DGRAM) {
            continue;
        }

        if (info->ai_family == AF_INET) {
            ip_port.ip.ip4.in_addr = ((struct sockaddr_in *)info->ai_addr)->sin_addr;
        } else if (info->ai_family == AF_INET6) {
            ip_port.ip.ip6.in6_addr = ((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;
        } else {
            continue;
        }

        Messenger *m = tox;
        onion_add_bs_path_node(m->onion_c, ip_port, public_key);
        DHT_bootstrap(m->dht, ip_port, public_key);
        ++count;
    } while ((info = info->ai_next));

    freeaddrinfo(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }
}

bool tox_add_tcp_relay(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key,
                       TOX_ERR_BOOTSTRAP *error)
{
    if (!address || !public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_NULL);
        return 0;
    }

    if (port == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_PORT);
        return 0;
    }

    struct addrinfo *root, *info;

    if (getaddrinfo(address, NULL, NULL, &root) != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }

    info = root;

    unsigned int count = 0;

    do {
        IP_Port ip_port;
        ip_port.port = htons(port);
        ip_port.ip.family = info->ai_family;

        if (info->ai_socktype && info->ai_socktype != SOCK_STREAM) {
            continue;
        }

        if (info->ai_family == AF_INET) {
            ip_port.ip.ip4.in_addr = ((struct sockaddr_in *)info->ai_addr)->sin_addr;
        } else if (info->ai_family == AF_INET6) {
            ip_port.ip.ip6.in6_addr = ((struct sockaddr_in6 *)info->ai_addr)->sin6_addr;
        } else {
            continue;
        }

        Messenger *m = tox;
        add_tcp_relay(m->net_crypto, ip_port, public_key);
        ++count;
    } while ((info = info->ai_next));

    freeaddrinfo(root);

    if (count) {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_BOOTSTRAP_BAD_HOST);
        return 0;
    }
}

TOX_CONNECTION tox_self_get_connection_status(const Tox *tox)
{
    const Messenger *m = tox;

    unsigned int ret = onion_connection_status(m->onion_c);

    if (ret == 2) {
        return TOX_CONNECTION_UDP;
    } else if (ret == 1) {
        return TOX_CONNECTION_TCP;
    } else {
        return TOX_CONNECTION_NONE;
    }
}


void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_core_connection(m, function, user_data);
}

uint32_t tox_iteration_interval(const Tox *tox)
{
    const Messenger *m = tox;
    return messenger_run_interval(m);
}

void tox_iterate(Tox *tox)
{
    Messenger *m = tox;
    do_messenger(m);
}

void tox_self_get_address(const Tox *tox, uint8_t *address)
{
    if (address) {
        const Messenger *m = tox;
        getaddress(m, address);
    }
}

void tox_self_set_nospam(Tox *tox, uint32_t nospam)
{
    Messenger *m = tox;
    set_nospam(&(m->fr), nospam);
}

uint32_t tox_self_get_nospam(const Tox *tox)
{
    const Messenger *m = tox;
    return get_nospam(&(m->fr));
}

void tox_self_get_public_key(const Tox *tox, uint8_t *public_key)
{
    const Messenger *m = tox;

    if (public_key)
        memcpy(public_key, m->net_crypto->self_public_key, crypto_box_PUBLICKEYBYTES);
}

void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key)
{
    const Messenger *m = tox;

    if (secret_key)
        memcpy(secret_key, m->net_crypto->self_secret_key, crypto_box_SECRETKEYBYTES);
}

bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!name && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (setname(m, name, length) == 0) {
        //TODO: function to set different per group names?
        //send_name_all_groups(m->group_chat_object);
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
        return 0;
    }
}

size_t tox_self_get_name_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_name_size(m);
}

void tox_self_get_name(const Tox *tox, uint8_t *name)
{
    if (name) {
        const Messenger *m = tox;
        getself_name(m, name);
    }
}

bool tox_self_set_status_message(Tox *tox, const uint8_t *status, size_t length, TOX_ERR_SET_INFO *error)
{
    if (!status && length != 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (m_set_statusmessage(m, status, length) == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_OK);
        return 1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_INFO_TOO_LONG);
        return 0;
    }
}

size_t tox_self_get_status_message_size(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_statusmessage_size(m);
}

void tox_self_get_status_message(const Tox *tox, uint8_t *status)
{
    if (status) {
        const Messenger *m = tox;
        m_copy_self_statusmessage(m, status);
    }
}

void tox_self_set_status(Tox *tox, TOX_USER_STATUS user_status)
{
    Messenger *m = tox;
    m_set_userstatus(m, user_status);
}

TOX_USER_STATUS tox_self_get_status(const Tox *tox)
{
    const Messenger *m = tox;
    return m_get_self_userstatus(m);
}

static void set_friend_error(int32_t ret, TOX_ERR_FRIEND_ADD *error)
{
    switch (ret) {
        case FAERR_TOOLONG:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_TOO_LONG);
            break;

        case FAERR_NOMESSAGE:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE);
            break;

        case FAERR_OWNKEY:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OWN_KEY);
            break;

        case FAERR_ALREADYSENT:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT);
            break;

        case FAERR_BADCHECKSUM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
            break;

        case FAERR_SETNEWNOSPAM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM);
            break;

        case FAERR_NOMEM:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_MALLOC);
            break;

    }
}

uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        TOX_ERR_FRIEND_ADD *error)
{
    if (!address || !message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend(m, address, message, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_ADD *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_NULL);
        return UINT32_MAX;
    }

    Messenger *m = tox;
    int32_t ret = m_addfriend_norequest(m, public_key);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_ADD_OK);
        return ret;
    }

    set_friend_error(ret, error);
    return UINT32_MAX;
}

bool tox_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error)
{
    Messenger *m = tox;
    int ret = m_delfriend(m, friend_number);

    //TODO handle if realloc fails?
    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_DELETE_OK);
    return 1;
}

uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_BY_PUBLIC_KEY *error)
{
    if (!public_key) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL);
        return UINT32_MAX;
    }

    const Messenger *m = tox;
    int32_t ret = getfriend_id(m, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND);
        return UINT32_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK);
    return ret;
}

bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               TOX_ERR_FRIEND_GET_PUBLIC_KEY *error)
{
    if (!public_key) {
        return 0;
    }

    const Messenger *m = tox;

    if (get_real_pk(m, friend_number, public_key) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);
    return 1;
}

bool tox_friend_exists(const Tox *tox, uint32_t friend_number)
{
    const Messenger *m = tox;
    return m_friend_exists(m, friend_number);
}

uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_GET_LAST_ONLINE *error)
{
    const Messenger *m = tox;
    uint64_t timestamp = m_get_last_online(m, friend_number);

    if (timestamp == UINT64_MAX) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND)
        return UINT64_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_GET_LAST_ONLINE_OK);
    return timestamp;
}

size_t tox_self_get_friend_list_size(const Tox *tox)
{
    const Messenger *m = tox;
    return count_friendlist(m);
}

void tox_self_get_friend_list(const Tox *tox, uint32_t *list)
{
    if (list) {
        const Messenger *m = tox;
        //TODO: size parameter?
        copy_friendlist(m, list, tox_self_get_friend_list_size(tox));
    }
}

size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_name_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, TOX_ERR_FRIEND_QUERY *error)
{
    if (!name) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    int ret = getname(m, friend_number, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_namechange(m, function, user_data);
}

size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_statusmessage_size(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return SIZE_MAX;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *message,
                                   TOX_ERR_FRIEND_QUERY *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_NULL);
        return 0;
    }

    const Messenger *m = tox;
    //TODO: size parameter?
    int ret = m_copy_statusmessage(m, friend_number, message, m_get_statusmessage_size(m, friend_number));

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return 1;
}

void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_statusmessage(m, function, user_data);
}

TOX_USER_STATUS tox_friend_get_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_userstatus(m, friend_number);

    if (ret == USERSTATUS_INVALID) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_USER_STATUS_BUSY + 1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_userstatus(m, function, user_data);
}

TOX_CONNECTION tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;

    int ret = m_get_friend_connectionstatus(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return TOX_CONNECTION_NONE;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return ret;
}

void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_connectionstatus(m, function, user_data);
}

bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error)
{
    const Messenger *m = tox;
    int ret = m_get_istyping(m, friend_number);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_QUERY_OK);
    return !!ret;
}

void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_typingchange(m, function, user_data);
}

bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool is_typing, TOX_ERR_SET_TYPING *error)
{
    Messenger *m = tox;

    if (m_set_usertyping(m, friend_number, is_typing) == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_SET_TYPING_OK);
    return 1;
}

static void set_message_error(int ret, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ);
            break;

        case -5:
            /* can't happen */
            break;
    }
}

uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error)
{
    if (!message) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_NULL);
        return 0;
    }

    if (!length) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY);
        return 0;
    }

    Messenger *m = tox;
    uint32_t message_id = 0;
    set_message_error(m_send_message_generic(m, friend_number, type, message, length, &message_id), error);
    return message_id;
}

void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_read_receipt(m, function, user_data);
}

void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_friendrequest(m, function, user_data);
}

void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *function, void *user_data)
{
    Messenger *m = tox;
    m_callback_friendmessage(m, function, user_data);
}

bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length)
{
    if (!hash || (length && !data)) {
        return 0;
    }

    crypto_hash_sha256(hash, data, length);
    return 1;
}

bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                      TOX_ERR_FILE_CONTROL *error)
{
    Messenger *m = tox;
    int ret = file_control(m, friend_number, file_number, control);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_FOUND);
            return 0;

        case -4:
            /* can't happen */
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_ALREADY_PAUSED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_DENIED);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_NOT_PAUSED);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_CONTROL_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                   TOX_ERR_FILE_SEEK *error)
{
    Messenger *m = tox;
    int ret = file_seek(m, friend_number, file_number, position);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_NOT_FOUND);
            return 0;

        case -4:
        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_DENIED);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_INVALID_POSITION);
            return 0;

        case -8:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEEK_SENDQ);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_control(m, function, user_data);
}

bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          TOX_ERR_FILE_GET *error)
{
    if (!file_id) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NULL);
        return 0;
    }

    const Messenger *m = tox;
    int ret = file_get_id(m, friend_number, file_number, file_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_OK);
        return 1;
    } else if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_FRIEND_NOT_FOUND);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_GET_NOT_FOUND);
    }

    return 0;
}

uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, TOX_ERR_FILE_SEND *error)
{
    if (filename_length && !filename) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NULL);
        return UINT32_MAX;
    }

    uint8_t f_id[FILE_ID_LENGTH];

    if (!file_id) {
        /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
        new_symmetric_key(f_id);
        file_id = f_id;
    }

    Messenger *m = tox;
    long int file_num = new_filesender(m, friend_number, kind, file_size, file_id, filename, filename_length);

    if (file_num >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_OK);
        return file_num;
    }

    switch (file_num) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_NAME_TOO_LONG);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_TOO_MANY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, TOX_ERR_FILE_SEND_CHUNK *error)
{
    Messenger *m = tox;
    int ret = file_data(m, friend_number, file_number, position, data, length);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_OK);
        return 1;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH);
            return 0;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_SENDQ);
            return 0;

        case -7:
            SET_ERROR_PARAMETER(error, TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION);
            return 0;
    }

    /* can't happen */
    return 0;
}

void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_reqchunk(m, function, user_data);
}

void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_sendrequest(m, function, user_data);
}

void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *function, void *user_data)
{
    Messenger *m = tox;
    callback_file_data(m, function, user_data);
}

static void set_custom_packet_error(int ret, TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_OK);
            break;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND);
            break;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG);
            break;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
            break;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED);
            break;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ);
            break;
    }
}

bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    if (data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_LOSSY_AV_RESERVED)) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID);
        return 0;
    }

    int ret = send_custom_lossy_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    } else {
        return 0;
    }
}

void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *function, void *user_data)
{
    Messenger *m = tox;
    custom_lossy_packet_registerhandler(m, function, user_data);
}

bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     TOX_ERR_FRIEND_CUSTOM_PACKET *error)
{
    if (!data) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_NULL);
        return 0;
    }

    Messenger *m = tox;

    if (length == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY);
        return 0;
    }

    int ret = send_custom_lossless_packet(m, friend_number, data, length);

    set_custom_packet_error(ret, error);

    if (ret == 0) {
        return 1;
    } else {
        return 0;
    }
}

void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *function, void *user_data)
{
    Messenger *m = tox;
    custom_lossless_packet_registerhandler(m, function, user_data);
}

void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id)
{
    if (dht_id) {
        const Messenger *m = tox;
        memcpy(dht_id , m->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    }
}

uint16_t tox_self_get_udp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    const Messenger *m = tox;
    uint16_t port = htons(m->net->port);

    if (port) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
    }

    return port;
}

uint16_t tox_self_get_tcp_port(const Tox *tox, TOX_ERR_GET_PORT *error)
{
    const Messenger *m = tox;

    if (m->tcp_server) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_OK);
        return m->options.tcp_server_port;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GET_PORT_NOT_BOUND);
        return 0;
    }
}

/**************** GROUPCHAT FUNCTIONS *****************/

void tox_callback_group_invite(Tox *tox, tox_group_invite_cb *function, void *userdata)
{
    Messenger *m = tox;
    m_callback_group_invite(m, function, userdata);
}

void tox_callback_group_message(Tox *tox, tox_group_message_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_message(m, function, userdata);
}

void tox_callback_group_private_message(Tox *tox, tox_group_private_message_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_private_message(m, function, userdata);
}

void tox_callback_group_moderation(Tox *tox, tox_group_moderation_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_moderation(m, function, userdata);
}

void tox_callback_group_peer_name(Tox *tox, tox_group_peer_name_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_nick_change(m, function, userdata);
}

void tox_callback_group_peer_status(Tox *tox, tox_group_peer_status_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_status_change(m, function, userdata);
}

void tox_callback_group_topic(Tox *tox, tox_group_topic_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_topic_change(m, function, userdata);
}

void tox_callback_group_privacy_state(Tox *tox, tox_group_privacy_state_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_privacy_state(m, function, user_data);
}

void tox_callback_group_peer_limit(Tox *tox, tox_group_peer_limit_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_peer_limit(m, function, user_data);
}

void tox_callback_group_password(Tox *tox, tox_group_password_cb *function, void *user_data)
{
    Messenger *m = tox;
    gc_callback_password(m, function, user_data);
}

void tox_callback_group_peer_join(Tox *tox, tox_group_peer_join_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_join(m, function, userdata);
}

void tox_callback_group_peer_exit(Tox *tox, tox_group_peer_exit_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_peer_exit(m, function, userdata);
}

void tox_callback_group_self_join(Tox *tox, tox_group_self_join_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_self_join(m, function, userdata);
}

void tox_callback_group_join_fail(Tox *tox, tox_group_join_fail_cb *function, void *userdata)
{
    Messenger *m = tox;
    gc_callback_rejected(m, function, userdata);
}

uint32_t tox_group_new(Tox *tox, TOX_GROUP_PRIVACY_STATE privacy_state, const uint8_t *group_name, size_t length,
                       TOX_ERR_GROUP_NEW *error)
{
    Messenger *m = tox;
    int ret = gc_group_add(m->group_handler, privacy_state, group_name, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_TOO_LONG);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_EMPTY);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_PRIVACY);
            return UINT32_MAX;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_INIT);
            return UINT32_MAX;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_STATE);
            return UINT32_MAX;

        case -6:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_NEW_ANNOUNCE);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

uint32_t tox_group_join(Tox *tox, const uint8_t *chat_id, const uint8_t *password, size_t length,
                        TOX_ERR_GROUP_JOIN *error)
{
    Messenger *m = tox;
    int ret = gc_group_join(m->group_handler, chat_id, password, length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_INIT);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_BAD_CHAT_ID);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_JOIN_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_reconnect(Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_RECONNECT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND);
        return 0;
    }

    gc_rejoin_group(m->group_handler, chat);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_RECONNECT_OK);
    return 1;
}

bool tox_group_leave(Tox *tox, uint32_t groupnumber, const uint8_t *partmessage, size_t length,
                     TOX_ERR_GROUP_LEAVE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_group_exit(m->group_handler, chat, partmessage, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_FAIL_SEND);
            return 1;   /* the group was still successfully deleted */

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_LEAVE_DELETE_FAIL);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_self_set_name(Tox *tox, uint32_t groupnumber, const uint8_t *name, size_t length,
                             TOX_ERR_GROUP_SELF_NAME_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_nick(m, groupnumber, name, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_INVALID);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_TAKEN);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_self_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_nick_size(chat);
}

bool tox_group_self_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *name, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_nick(chat, name);
    return 1;
}

bool tox_group_self_set_status(Tox *tox, uint32_t groupnumber, TOX_USER_STATUS status,
                               TOX_ERR_GROUP_SELF_STATUS_SET *error)
{
    Messenger *m = tox;
    int ret = gc_set_self_status(m, groupnumber, status);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

TOX_USER_STATUS tox_group_self_get_status(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_status(chat);
}

TOX_GROUP_ROLE tox_group_self_get_role(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_role(chat);
}

uint32_t tox_group_self_get_peer_id(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    return gc_get_self_peer_id(chat);
}

bool tox_group_self_get_public_key(const Tox *tox, uint32_t groupnumber, uint8_t *public_key,
                                   TOX_ERR_GROUP_SELF_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SELF_QUERY_OK);
    gc_get_self_public_key(chat, public_key);
    return 1;
}

size_t tox_group_peer_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                    TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    int ret = gc_get_peer_nick_size(chat, peer_id);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
        return ret;
    }
}

bool tox_group_peer_get_name(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *name,
                             TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_nick(chat, peer_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

TOX_USER_STATUS tox_group_peer_get_status(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
        TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint8_t ret = gc_get_status(chat, peer_id);

    if (ret == (uint8_t) -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return ret;
}

TOX_GROUP_ROLE tox_group_peer_get_role(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                       TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint8_t ret = gc_get_role(chat, peer_id);

    if (ret == (uint8_t) -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return ret;
}

bool tox_group_peer_get_public_key(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *public_key,
                                   TOX_ERR_GROUP_PEER_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_get_peer_public_key(chat, peer_id, public_key);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_PEER_QUERY_OK);
    return 1;
}

bool tox_group_set_topic(Tox *tox, uint32_t groupnumber, const uint8_t *topic, size_t length,
                         TOX_ERR_GROUP_TOPIC_SET *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_set_topic(chat, topic, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_get_topic_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_topic_size(chat);
}

bool tox_group_get_topic(const Tox *tox, uint32_t groupnumber, uint8_t *topic, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_topic(chat, topic);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

size_t tox_group_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_group_name_size(chat);
}

bool tox_group_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *groupname, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    gc_get_group_name(chat, groupname);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return 1;
}

bool tox_group_get_chat_id(const Tox *tox, uint32_t groupnumber, uint8_t *chat_id, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_chat_id(chat, chat_id);
    return 1;
}

uint32_t tox_group_get_number_groups(const Tox *tox)
{
    const Messenger *m = tox;
    return gc_count_groups(m->group_handler);
}

TOX_GROUP_PRIVACY_STATE tox_group_get_privacy_state(const Tox *tox, uint32_t groupnumber,
        TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_privacy_state(chat);
}

uint32_t tox_group_get_peer_limit(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_max_peers(chat);
}

size_t tox_group_get_password_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    return gc_get_password_size(chat);
}

bool tox_group_get_password(const Tox *tox, uint32_t groupnumber, uint8_t *password, TOX_ERR_GROUP_STATE_QUERIES *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_STATE_QUERIES_OK);
    gc_get_password(chat, password);
    return 1;
}

bool tox_group_send_message(Tox *tox, uint32_t groupnumber, TOX_MESSAGE_TYPE type, const uint8_t *message,
                            size_t length, TOX_ERR_GROUP_SEND_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_message(chat, message, length, type);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_private_message(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *message,
                                    size_t length, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_private_message(chat, peer_id, message, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_send_custom_packet(Tox *tox, uint32_t groupnumber, bool lossless, const uint8_t *data,
                                  size_t length, TOX_ERR_GROUP_SEND_CUSTOM_PACKET *error)
{
    const Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_send_custom_packet(chat, lossless, data, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_invite_friend(Tox *tox, uint32_t groupnumber, uint32_t friend_number, TOX_ERR_GROUP_INVITE_FRIEND *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_invite_friend(m->group_handler, chat, friend_number);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

uint32_t tox_group_invite_accept(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *password, size_t password_length, TOX_ERR_GROUP_INVITE_ACCEPT *error)
{
    Messenger *m = tox;
    int ret = gc_accept_invite(m->group_handler, friend_number, invite_data, length, password, password_length);

    if (ret >= 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_OK);
        return ret;
    }

    switch (ret) {
        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE);
            return UINT32_MAX;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED);
            return UINT32_MAX;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG);
            return UINT32_MAX;
    }

    /* can't happen */
    return UINT32_MAX;
}

bool tox_group_founder_set_password(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_founder_set_password(chat, password, length);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_privacy_state(Tox *tox, uint32_t groupnumber, TOX_GROUP_PRIVACY_STATE privacy_state,
        TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE *error)
{
    Messenger *m = tox;
    int ret = gc_founder_set_privacy_state(m, groupnumber, privacy_state);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_INVALID);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_founder_set_peer_limit(Tox *tox, uint32_t groupnumber, uint32_t maxpeers,
                                      TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_founder_set_max_peers(chat, groupnumber, maxpeers);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_toggle_ignore(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool ignore,
                             TOX_ERR_GROUP_TOGGLE_IGNORE *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_toggle_ignore(chat, peer_id, ignore);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_PEER_NOT_FOUND);
        return 0;
    } else {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_TOGGLE_IGNORE_OK);
        return 1;
    }
}

bool tox_group_mod_set_role(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_GROUP_ROLE role,
                            TOX_ERR_GROUP_MOD_SET_ROLE *error)
{
    Messenger *m = tox;
    int ret = gc_set_peer_role(m, groupnumber, peer_id, role);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_peer(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool set_ban,
                               TOX_ERR_GROUP_MOD_REMOVE_PEER *error)
{
    Messenger *m = tox;
    int ret = gc_remove_peer(m, groupnumber, peer_id, set_ban);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_GROUP_NOT_FOUND);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PEER_NOT_FOUND);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_PERMISSIONS);
            return 0;

        case -4:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_ACTION);
            return 0;

        case -5:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

bool tox_group_mod_remove_ban(Tox *tox, uint32_t groupnumber, uint32_t ban_id, TOX_ERR_GROUP_MOD_REMOVE_BAN *error)
{
    Messenger *m = tox;
    GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = gc_remove_ban(chat, ban_id);

    switch (ret) {
        case 0:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_OK);
            return 1;

        case -1:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_PERMISSIONS);
            return 0;

        case -2:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_ACTION);
            return 0;

        case -3:
            SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_SEND);
            return 0;
    }

    /* can't happen */
    return 0;
}

size_t tox_group_ban_get_list_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return sanctions_list_num_banned(chat);
}

bool tox_group_ban_get_list(const Tox *tox, uint32_t groupnumber, uint32_t *list, TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    sanctions_list_get_ban_list(chat, list);
    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

size_t tox_group_ban_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                   TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint16_t ret = sanctions_list_get_ban_nick_length(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}

bool tox_group_ban_get_name(const Tox *tox, uint32_t groupnumber, uint32_t ban_id, uint8_t *name,
                            TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return 0;
    }

    int ret = sanctions_list_get_ban_nick(chat, ban_id, name);

    if (ret == -1) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return 0;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return 1;
}

uint64_t tox_group_ban_get_time_set(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                    TOX_ERR_GROUP_BAN_QUERY *error)
{
    const Messenger *m = tox;
    const GC_Chat *chat = gc_get_group(m->group_handler, groupnumber);

    if (chat == NULL) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND);
        return -1;
    }

    uint64_t ret = sanctions_list_get_ban_time_set(chat, ban_id);

    if (ret == 0) {
        SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_BAD_ID);
        return -1;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_GROUP_BAN_QUERY_OK);
    return ret;
}
