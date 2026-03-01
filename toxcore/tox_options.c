/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "tox_options.h"

#include <stdlib.h> // free, malloc, calloc
#include <string.h> // memcpy, strlen

#include "ccompat.h" // nullptr

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)


bool tox_options_get_ipv6_enabled(const Tox_Options *_Nonnull options)
{
    return options->ipv6_enabled;
}
void tox_options_set_ipv6_enabled(Tox_Options *_Nonnull options, bool ipv6_enabled)
{
    options->ipv6_enabled = ipv6_enabled;
}
bool tox_options_get_udp_enabled(const Tox_Options *_Nonnull options)
{
    return options->udp_enabled;
}
void tox_options_set_udp_enabled(Tox_Options *_Nonnull options, bool udp_enabled)
{
    options->udp_enabled = udp_enabled;
}
Tox_Proxy_Type tox_options_get_proxy_type(const Tox_Options *_Nonnull options)
{
    return options->proxy_type;
}
void tox_options_set_proxy_type(Tox_Options *_Nonnull options, Tox_Proxy_Type proxy_type)
{
    options->proxy_type = proxy_type;
}
const char *_Nullable tox_options_get_proxy_host(const Tox_Options *_Nonnull options)
{
    return options->proxy_host;
}
bool tox_options_set_proxy_host(Tox_Options *_Nonnull options, const char *_Nullable proxy_host)
{
    if (!options->experimental_owned_data) {
        options->proxy_host = proxy_host;
        return true;
    }

    if (options->owned_proxy_host != nullptr) {
        free(options->owned_proxy_host);
        options->owned_proxy_host = nullptr;
    }
    if (proxy_host == nullptr) {
        options->proxy_host = nullptr;
        return true;
    }

    const size_t proxy_host_length = strlen(proxy_host) + 1;
    char *owned_ptr = (char *)malloc(proxy_host_length);
    if (owned_ptr == nullptr) {
        options->proxy_host = proxy_host;
        options->owned_proxy_host = nullptr;
        return false;
    }

    memcpy(owned_ptr, proxy_host, proxy_host_length);
    options->proxy_host = owned_ptr;
    options->owned_proxy_host = owned_ptr;
    return true;
}
uint16_t tox_options_get_proxy_port(const Tox_Options *_Nonnull options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(Tox_Options *_Nonnull options, uint16_t proxy_port)
{
    options->proxy_port = proxy_port;
}
uint16_t tox_options_get_start_port(const Tox_Options *_Nonnull options)
{
    return options->start_port;
}
void tox_options_set_start_port(Tox_Options *_Nonnull options, uint16_t start_port)
{
    options->start_port = start_port;
}
uint16_t tox_options_get_end_port(const Tox_Options *_Nonnull options)
{
    return options->end_port;
}
void tox_options_set_end_port(Tox_Options *_Nonnull options, uint16_t end_port)
{
    options->end_port = end_port;
}
uint16_t tox_options_get_tcp_port(const Tox_Options *_Nonnull options)
{
    return options->tcp_port;
}
void tox_options_set_tcp_port(Tox_Options *_Nonnull options, uint16_t tcp_port)
{
    options->tcp_port = tcp_port;
}
bool tox_options_get_hole_punching_enabled(const Tox_Options *_Nonnull options)
{
    return options->hole_punching_enabled;
}
void tox_options_set_hole_punching_enabled(Tox_Options *_Nonnull options, bool hole_punching_enabled)
{
    options->hole_punching_enabled = hole_punching_enabled;
}
Tox_Savedata_Type tox_options_get_savedata_type(const Tox_Options *_Nonnull options)
{
    return options->savedata_type;
}
void tox_options_set_savedata_type(Tox_Options *_Nonnull options, Tox_Savedata_Type savedata_type)
{
    options->savedata_type = savedata_type;
}
size_t tox_options_get_savedata_length(const Tox_Options *_Nonnull options)
{
    return options->savedata_length;
}
void tox_options_set_savedata_length(Tox_Options *_Nonnull options, size_t savedata_length)
{
    options->savedata_length = savedata_length;
}
tox_log_cb *_Nullable tox_options_get_log_callback(const Tox_Options *_Nonnull options)
{
    return options->log_callback;
}
void tox_options_set_log_callback(Tox_Options *_Nonnull options, tox_log_cb *_Nullable log_callback)
{
    options->log_callback = log_callback;
}
void *_Nullable tox_options_get_log_user_data(const Tox_Options *_Nonnull options)
{
    return options->log_user_data;
}
void tox_options_set_log_user_data(Tox_Options *_Nonnull options, void *_Nullable log_user_data)
{
    options->log_user_data = log_user_data;
}
bool tox_options_get_local_discovery_enabled(const Tox_Options *_Nonnull options)
{
    return options->local_discovery_enabled;
}
void tox_options_set_local_discovery_enabled(Tox_Options *_Nonnull options, bool local_discovery_enabled)
{
    options->local_discovery_enabled = local_discovery_enabled;
}
bool tox_options_get_dht_announcements_enabled(const Tox_Options *_Nonnull options)
{
    return options->dht_announcements_enabled;
}
void tox_options_set_dht_announcements_enabled(Tox_Options *_Nonnull options, bool dht_announcements_enabled)
{
    options->dht_announcements_enabled = dht_announcements_enabled;
}
bool tox_options_get_experimental_thread_safety(const Tox_Options *_Nonnull options)
{
    return options->experimental_thread_safety;
}
void tox_options_set_experimental_thread_safety(
    Tox_Options *_Nonnull options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
bool tox_options_get_experimental_groups_persistence(const Tox_Options *_Nonnull options)
{
    return options->experimental_groups_persistence;
}
void tox_options_set_experimental_groups_persistence(
    Tox_Options *_Nonnull options, bool experimental_groups_persistence)
{
    options->experimental_groups_persistence = experimental_groups_persistence;
}
bool tox_options_get_experimental_disable_dns(const Tox_Options *_Nonnull options)
{
    return options->experimental_disable_dns;
}
void tox_options_set_experimental_disable_dns(Tox_Options *_Nonnull options, bool experimental_disable_dns)
{
    options->experimental_disable_dns = experimental_disable_dns;
}
bool tox_options_get_experimental_owned_data(const Tox_Options *_Nonnull options)
{
    return options->experimental_owned_data;
}
void tox_options_set_experimental_owned_data(
    Tox_Options *_Nonnull options, bool experimental_owned_data)
{
    options->experimental_owned_data = experimental_owned_data;
}

const uint8_t *_Nullable tox_options_get_savedata_data(const Tox_Options *_Nonnull options)
{
    return options->savedata_data;
}

bool tox_options_set_savedata_data(Tox_Options *_Nonnull options, const uint8_t *_Nullable savedata_data, size_t length)
{
    if (!options->experimental_owned_data) {
        options->savedata_data = savedata_data;
        options->savedata_length = length;
        return true;
    }

    if (options->owned_savedata_data != nullptr) {
        free(options->owned_savedata_data);
        options->owned_savedata_data = nullptr;
    }
    if (savedata_data == nullptr) {
        options->savedata_data = nullptr;
        options->savedata_length = 0;
        return true;
    }

    uint8_t *owned_ptr = (uint8_t *)malloc(length);
    if (owned_ptr == nullptr) {
        options->savedata_data = savedata_data;
        options->savedata_length = length;
        options->owned_savedata_data = nullptr;
        return false;
    }

    memcpy(owned_ptr, savedata_data, length);
    options->savedata_data = owned_ptr;
    options->savedata_length = length;
    options->owned_savedata_data = owned_ptr;
    return true;
}

void tox_options_default(Tox_Options *_Nonnull options)
{
    if (options != nullptr) {
        // Free any owned data.
        tox_options_set_proxy_host(options, nullptr);
        tox_options_set_savedata_data(options, nullptr, 0);

        // Set the rest to default values.
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
        tox_options_set_experimental_disable_dns(options, false);
        tox_options_set_experimental_owned_data(options, false);
    }
}

void tox_options_copy(Tox_Options *_Nullable dest, const Tox_Options *_Nullable src)
{
    if (dest != nullptr && src != nullptr) {
        // Clear dest's owned pointers before copying src's members
        dest->owned_proxy_host = nullptr;
        dest->owned_savedata_data = nullptr;

        // Copy all non-owned members
        *dest = *src;

        // Clear these again as they now point to src's memory
        dest->owned_proxy_host = nullptr;
        dest->owned_savedata_data = nullptr;

        // Use setters to correctly re-allocate and copy if experimental_owned_data is true
        tox_options_set_proxy_host(dest, src->proxy_host);
        tox_options_set_savedata_data(dest, src->savedata_data, src->savedata_length);
    }
}

Tox_Options *_Nullable tox_options_new(Tox_Err_Options_New *_Nullable error)
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

void tox_options_free(Tox_Options *_Nullable options)
{
    if (options != nullptr) {
        // Free any owned data.
        tox_options_set_proxy_host(options, nullptr);
        tox_options_set_savedata_data(options, nullptr, 0);
        free(options);
    }
}
