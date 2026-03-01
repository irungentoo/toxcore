/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_OPTIONS_H
#define C_TOXCORE_TOXCORE_TOX_OPTIONS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox_log_level.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox;

/** @{
 * @name Startup options
 */

/**
 * @brief Type of proxy used to connect to TCP relays.
 */
typedef enum Tox_Proxy_Type {
    /**
     * Don't use a proxy.
     */
    TOX_PROXY_TYPE_NONE,

    /**
     * HTTP proxy using CONNECT.
     */
    TOX_PROXY_TYPE_HTTP,

    /**
     * SOCKS proxy for simple socket pipes.
     */
    TOX_PROXY_TYPE_SOCKS5,
} Tox_Proxy_Type;

const char *tox_proxy_type_to_string(Tox_Proxy_Type value);

/**
 * @brief Type of savedata to create the Tox instance from.
 */
typedef enum Tox_Savedata_Type {
    /**
     * No savedata.
     */
    TOX_SAVEDATA_TYPE_NONE,

    /**
     * Savedata is one that was obtained from tox_get_savedata.
     */
    TOX_SAVEDATA_TYPE_TOX_SAVE,

    /**
     * Savedata is a secret key of length TOX_SECRET_KEY_SIZE.
     */
    TOX_SAVEDATA_TYPE_SECRET_KEY,
} Tox_Savedata_Type;

const char *tox_savedata_type_to_string(Tox_Savedata_Type value);

/**
 * @brief This event is triggered when Tox logs an internal message.
 *
 * This is mostly useful for debugging. This callback can be called from any
 * function, not just tox_iterate. This means the user data lifetime must at
 * least extend between registering and unregistering it or tox_kill.
 *
 * Other toxcore modules such as toxav may concurrently call this callback at
 * any time. Thus, user code must make sure it is equipped to handle concurrent
 * execution, e.g. by employing appropriate mutex locking.
 *
 * When using the experimental_thread_safety option, no Tox API functions can
 * be called from within the log callback.
 *
 * @param level The severity of the log message.
 * @param file The source file from which the message originated.
 * @param line The source line from which the message originated.
 * @param func The function from which the message originated.
 * @param message The log message.
 * @param user_data The user data pointer passed to tox_new in options.
 */
typedef void tox_log_cb(struct Tox *tox, Tox_Log_Level level, const char *file,
                        uint32_t line, const char *func, const char *message,
                        void *user_data);

/**
 * @brief This struct contains all the startup options for Tox.
 *
 * You must tox_options_new to allocate an object of this type.
 *
 * WARNING: Although this struct happens to be visible in the API, it is
 * effectively private. Do not allocate this yourself or access members
 * directly, as it *will* break binary compatibility frequently.
 *
 * @deprecated The memory layout of this struct (size, alignment, and field
 *   order) is not part of the ABI. To remain compatible, prefer to use
 *   tox_options_new to allocate the object and accessor functions to set the
 *   members. The struct will become opaque (i.e. the definition will become
 *   private) in v0.3.0.
 */
typedef struct Tox_Options Tox_Options;

#ifndef TOX_HIDE_DEPRECATED
struct Tox_Options {
    /**
     * The type of socket to create.
     *
     * If this is set to false, an IPv4 socket is created, which subsequently
     * only allows IPv4 communication.
     * If it is set to true, an IPv6 socket is created, allowing both IPv4 and
     * IPv6 communication.
     */
    bool ipv6_enabled;

    /**
     * Enable the use of UDP communication when available.
     *
     * Setting this to false will force Tox to use TCP only. Communications will
     * need to be relayed through a TCP relay node, potentially slowing them
     * down.
     *
     * If a proxy is enabled, UDP will be disabled if either the Tox library or
     * the proxy don't support proxying UDP messages.
     */
    bool udp_enabled;

    /**
     * Enable local network peer discovery.
     *
     * Disabling this will cause Tox to not look for peers on the local network.
     */
    bool local_discovery_enabled;

    /**
     * Enable storing DHT announcements and forwarding corresponding requests.
     *
     * Disabling this will cause Tox to ignore the relevant packets.
     */
    bool dht_announcements_enabled;

    /**
     * Pass communications through a proxy.
     */
    Tox_Proxy_Type proxy_type;

    /**
     * The IP address or DNS name of the proxy to be used.
     *
     * If used, this must be non-NULL and be a valid DNS name. The name must not
     * exceed TOX_MAX_HOSTNAME_LENGTH characters, and be in a NUL-terminated C
     * string format (TOX_MAX_HOSTNAME_LENGTH includes the NUL byte).
     *
     * This member is ignored (it can be NULL) if proxy_type is
     * TOX_PROXY_TYPE_NONE.
     *
     * The data pointed at by this member is owned by the user, so must
     * outlive the options object (unless experimental_owned_data is set).
     */
    const char *proxy_host;

    /**
     * The port to use to connect to the proxy server.
     *
     * Ports must be in the range (1, 65535). The value is ignored if
     * proxy_type is TOX_PROXY_TYPE_NONE.
     */
    uint16_t proxy_port;

    /**
     * The start port of the inclusive port range to attempt to use.
     *
     * If both start_port and end_port are 0, the default port range will be
     * used: `[33445, 33545]`.
     *
     * If either start_port or end_port is 0 while the other is non-zero, the
     * non-zero port will be the only port in the range.
     *
     * Having start_port > end_port will yield the same behavior as if
     * start_port and end_port were swapped.
     */
    uint16_t start_port;

    /**
     * The end port of the inclusive port range to attempt to use.
     */
    uint16_t end_port;

    /**
     * The port to use for the TCP server (relay). If 0, the TCP server is
     * disabled.
     *
     * Enabling it is not required for Tox to function properly.
     *
     * When enabled, your Tox instance can act as a TCP relay for other Tox
     * instance. This leads to increased traffic, thus when writing a client
     * it is recommended to enable TCP server only if the user has an option
     * to disable it.
     */
    uint16_t tcp_port;

    /**
     * Enables or disables UDP hole-punching. (Default: enabled).
     */
    bool hole_punching_enabled;

    /**
     * The type of savedata to load from.
     */
    Tox_Savedata_Type savedata_type;

    /**
     * The savedata (either a Tox save or a secret key) to load from.
     *
     * The data pointed at by this member is owned by the user, so must
     * outlive the options object (unless experimental_owned_data is set).
     */
    const uint8_t *savedata_data;

    /**
     * The length of the savedata.
     */
    size_t savedata_length;

    /**
     * Logging callback for the new Tox instance.
     */
    tox_log_cb *log_callback;

    /**
     * User data pointer passed to the logging callback.
     */
    void *log_user_data;

    /*
     * These options are experimental, so avoid writing code that depends on
     * them. Options marked "experimental" may change their behaviour or go away
     * entirely in the future, or may be renamed to something non-experimental
     * if they become part of the supported API.
     */

    /**
     * Make public API functions thread-safe using a per-instance lock.
     *
     * Default: false.
     */
    bool experimental_thread_safety;

    /**
     * Enable saving DHT-based group chats to Tox save data (via
     * `tox_get_savedata`). This format will change in the future, so don't rely
     * on it.
     *
     * As an alternative, clients can save the group chat ID in client-owned
     * savedata. Then, when the client starts, it can use `tox_group_join`
     * with the saved chat ID to recreate the group chat.
     *
     * Default: false.
     */
    bool experimental_groups_persistence;

    /**
     * @brief Disable DNS hostname resolution.
     *
     * Hostnames or IP addresses are passed to the bootstrap/add_tcp_relay
     * function and proxy host options. If disabled (this flag is true), only
     * IP addresses are allowed.
     *
     * If this is set to true, the library will not attempt to resolve
     * hostnames. This is useful for clients that want to resolve hostnames
     * themselves and pass the resolved IP addresses to the library (e.g. in
     * case it wants to use Tor).
     * Passing hostnames will result in a TOX_ERR_BOOTSTRAP_BAD_HOST error if
     * this is set to true.
     *
     * Default: false. May become true in the future (0.3.0).
     */
    bool experimental_disable_dns;

    /**
     * @brief Whether the savedata data is owned by the Tox_Options object.
     *
     * If true, the setters for savedata and proxy_host try to copy the string.
     * If that fails, the value is not copied and the member is set to the
     * user-provided pointer. In that case, the user must not free the string
     * until the Tox_Options object is freed. Client code can check whether
     * allocation succeeded by checking the returned bool. If
     * experimental_owned_data is false, it will always return true. If set to
     * true, the return value will be false on allocation failure.
     *
     * If set to true, this must be set before any other member that allocates
     * memory is set.
     */
    bool experimental_owned_data;

    /**
     * @brief Owned pointer to the savedata data.
     * @private
     */
    uint8_t *owned_savedata_data;

    /**
     * @brief Owned pointer to the proxy host.
     * @private
     */
    char *owned_proxy_host;
};
#endif /* TOX_HIDE_DEPRECATED */

bool tox_options_get_ipv6_enabled(const Tox_Options *options);

void tox_options_set_ipv6_enabled(Tox_Options *options, bool ipv6_enabled);

bool tox_options_get_udp_enabled(const Tox_Options *options);

void tox_options_set_udp_enabled(Tox_Options *options, bool udp_enabled);

bool tox_options_get_local_discovery_enabled(const Tox_Options *options);

void tox_options_set_local_discovery_enabled(Tox_Options *options, bool local_discovery_enabled);

bool tox_options_get_dht_announcements_enabled(const Tox_Options *options);

void tox_options_set_dht_announcements_enabled(
    Tox_Options *options, bool dht_announcements_enabled);

Tox_Proxy_Type tox_options_get_proxy_type(const Tox_Options *options);

void tox_options_set_proxy_type(Tox_Options *options, Tox_Proxy_Type proxy_type);

const char *tox_options_get_proxy_host(const Tox_Options *options);

bool tox_options_set_proxy_host(Tox_Options *options, const char *proxy_host);

uint16_t tox_options_get_proxy_port(const Tox_Options *options);

void tox_options_set_proxy_port(Tox_Options *options, uint16_t proxy_port);

uint16_t tox_options_get_start_port(const Tox_Options *options);

void tox_options_set_start_port(Tox_Options *options, uint16_t start_port);

uint16_t tox_options_get_end_port(const Tox_Options *options);

void tox_options_set_end_port(Tox_Options *options, uint16_t end_port);

uint16_t tox_options_get_tcp_port(const Tox_Options *options);

void tox_options_set_tcp_port(Tox_Options *options, uint16_t tcp_port);

bool tox_options_get_hole_punching_enabled(const Tox_Options *options);

void tox_options_set_hole_punching_enabled(Tox_Options *options, bool hole_punching_enabled);

Tox_Savedata_Type tox_options_get_savedata_type(const Tox_Options *options);

void tox_options_set_savedata_type(Tox_Options *options, Tox_Savedata_Type savedata_type);

const uint8_t *tox_options_get_savedata_data(const Tox_Options *options);

bool tox_options_set_savedata_data(
    Tox_Options *options, const uint8_t savedata_data[], size_t length);

size_t tox_options_get_savedata_length(const Tox_Options *options);

void tox_options_set_savedata_length(Tox_Options *options, size_t savedata_length);

tox_log_cb *tox_options_get_log_callback(const Tox_Options *options);

void tox_options_set_log_callback(Tox_Options *options, tox_log_cb *log_callback);

void *tox_options_get_log_user_data(const Tox_Options *options);

void tox_options_set_log_user_data(Tox_Options *options, void *log_user_data);

bool tox_options_get_experimental_owned_data(const Tox_Options *options);

void tox_options_set_experimental_owned_data(Tox_Options *options, bool experimental_owned_data);

bool tox_options_get_experimental_thread_safety(const Tox_Options *options);

void tox_options_set_experimental_thread_safety(
    Tox_Options *options, bool experimental_thread_safety);

bool tox_options_get_experimental_groups_persistence(const Tox_Options *options);

void tox_options_set_experimental_groups_persistence(
    Tox_Options *options, bool experimental_groups_persistence);

bool tox_options_get_experimental_disable_dns(const Tox_Options *options);

void tox_options_set_experimental_disable_dns(Tox_Options *options, bool experimental_disable_dns);

/**
 * @brief Initialises a Tox_Options object with the default options.
 *
 * The result of this function is independent of the original options. All
 * values will be overwritten, no values will be read (so it is permissible
 * to pass an uninitialised object).
 *
 * If options is NULL, this function has no effect.
 *
 * @param options An options object to be filled with default options.
 */
void tox_options_default(Tox_Options *options);

/**
 * @brief Copy all options from one object to another.
 *
 * The result of this function is independent of the original options.
 *
 * If either options object is NULL, this function has no effect.
 *
 * @param dest The options object to be written to.
 * @param src The options object to be read from.
 */
void tox_options_copy(Tox_Options *dest, const Tox_Options *src);

typedef enum Tox_Err_Options_New {
    /**
     * The function returned successfully.
     */
    TOX_ERR_OPTIONS_NEW_OK,

    /**
     * The function failed to allocate enough memory for the options struct.
     */
    TOX_ERR_OPTIONS_NEW_MALLOC,
} Tox_Err_Options_New;

const char *tox_err_options_new_to_string(Tox_Err_Options_New value);

/**
 * @brief Allocates a new Tox_Options object and initialises it with the default
 *   options.
 *
 * This function can be used to preserve long term ABI compatibility by
 * giving the responsibility of allocation and deallocation to the Tox library.
 *
 * Objects returned from this function must be freed using the tox_options_free
 * function.
 *
 * @return A new Tox_Options object with default options or NULL on failure.
 */
Tox_Options *tox_options_new(Tox_Err_Options_New *error);

/**
 * @brief Releases all resources associated with an options objects.
 *
 * Passing a pointer that was not returned by tox_options_new results in
 * undefined behaviour.
 */
void tox_options_free(Tox_Options *options);

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_OPTIONS_H */
