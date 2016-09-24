/* tox.h
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

#ifndef TOX_H
#define TOX_H

#ifndef DHT_GROUPCHATS
#define DHT_GROUPCHATS

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/*******************************************************************************
 * `tox.h` SHOULD *NOT* BE EDITED MANUALLY – any changes should be made to   *
 * `tox.in.h`, located in `other/apidsl/`. For instructions on how to        *
 * generate `tox.h` from `tox.in.h` please refer to `other/apidsl/README.md` *
 ******************************************************************************/



/** \page core Public core API for Tox clients.
 *
 * Every function that can fail takes a function-specific error code pointer
 * that can be used to diagnose problems with the Tox state or the function
 * arguments. The error code pointer can be NULL, which does not influence the
 * function's behaviour, but can be done if the reason for failure is irrelevant
 * to the client.
 *
 * The exception to this rule are simple allocation functions whose only failure
 * mode is allocation failure. They return NULL in that case, and do not set an
 * error code.
 *
 * Every error code type has an OK value to which functions will set their error
 * code value on success. Clients can keep their error code uninitialised before
 * passing it to a function. The library guarantees that after returning, the
 * value pointed to by the error code pointer has been initialised.
 *
 * Functions with pointer parameters often have a NULL error code, meaning they
 * could not perform any operation, because one of the required parameters was
 * NULL. Some functions operate correctly or are defined as effectless on NULL.
 *
 * Some functions additionally return a value outside their
 * return type domain, or a bool containing true on success and false on
 * failure.
 *
 * All functions that take a Tox instance pointer will cause undefined behaviour
 * when passed a NULL Tox pointer.
 *
 * All integer values are expected in host byte order.
 *
 * Functions with parameters with enum types cause unspecified behaviour if the
 * enumeration value is outside the valid range of the type. If possible, the
 * function will try to use a sane default, but there will be no error code,
 * and one possible action for the function to take is to have no effect.
 */
/** \subsection events Events and callbacks
 *
 * Events are handled by callbacks. One callback can be registered per event.
 * All events have a callback function type named `tox_{event}_cb` and a
 * function to register it named `tox_callback_{event}`. Passing a NULL
 * callback will result in no callback being registered for that event. Only
 * one callback per event can be registered, so if a client needs multiple
 * event listeners, it needs to implement the dispatch functionality itself.
 */
/** \subsection threading Threading implications
 *
 * It is possible to run multiple concurrent threads with a Tox instance for
 * each thread. It is also possible to run all Tox instances in the same thread.
 * A common way to run Tox (multiple or single instance) is to have one thread
 * running a simple tox_iterate loop, sleeping for tox_iteration_interval
 * milliseconds on each iteration.
 *
 * If you want to access a single Tox instance from multiple threads, access
 * to the instance must be synchronised. While multiple threads can concurrently
 * access multiple different Tox instances, no more than one API function can
 * operate on a single instance at any given time.
 *
 * Functions that write to variable length byte arrays will always have a size
 * function associated with them. The result of this size function is only valid
 * until another mutating function (one that takes a pointer to non-const Tox)
 * is called. Thus, clients must ensure that no other thread calls a mutating
 * function between the call to the size function and the call to the retrieval
 * function.
 *
 * E.g. to get the current nickname, one would write
 *
 * \code
 * size_t length = tox_self_get_name_size(tox);
 * uint8_t *name = malloc(length);
 * if (!name) abort();
 * tox_self_get_name(tox, name);
 * \endcode
 *
 * If any other thread calls tox_self_set_name while this thread is allocating
 * memory, the length may have become invalid, and the call to
 * tox_self_get_name may cause undefined behaviour.
 */
/**
 * The Tox instance type. All the state associated with a connection is held
 * within the instance. Multiple instances can exist and operate concurrently.
 * The maximum number of Tox instances that can exist on a single network
 * device is limited. Note that this is not just a per-process limit, since the
 * limiting factor is the number of usable ports on a device.
 */
#ifndef TOX_DEFINED
#define TOX_DEFINED
typedef struct Tox Tox;
#endif /* TOX_DEFINED */


/*******************************************************************************
 *
 * :: API version
 *
 ******************************************************************************/



/**
 * The major version number. Incremented when the API or ABI changes in an
 * incompatible way.
 */
#define TOX_VERSION_MAJOR               0u

/**
 * The minor version number. Incremented when functionality is added without
 * breaking the API or ABI. Set to 0 when the major version number is
 * incremented.
 */
#define TOX_VERSION_MINOR               0u

/**
 * The patch or revision number. Incremented when bugfixes are applied without
 * changing any functionality or API or ABI.
 */
#define TOX_VERSION_PATCH               0u

/**
 * A macro to check at preprocessing time whether the client code is compatible
 * with the installed version of Tox.
 */
#define TOX_VERSION_IS_API_COMPATIBLE(MAJOR, MINOR, PATCH)      \
  (TOX_VERSION_MAJOR == MAJOR &&                                \
   (TOX_VERSION_MINOR > MINOR ||                                \
    (TOX_VERSION_MINOR == MINOR &&                              \
     TOX_VERSION_PATCH >= PATCH)))

/**
 * A macro to make compilation fail if the client code is not compatible with
 * the installed version of Tox.
 */
#define TOX_VERSION_REQUIRE(MAJOR, MINOR, PATCH)                \
  typedef char tox_required_version[TOX_IS_COMPATIBLE(MAJOR, MINOR, PATCH) ? 1 : -1]

/**
 * Return the major version number of the library. Can be used to display the
 * Tox library version or to check whether the client is compatible with the
 * dynamically linked version of Tox.
 */
uint32_t tox_version_major(void);

/**
 * Return the minor version number of the library.
 */
uint32_t tox_version_minor(void);

/**
 * Return the patch number of the library.
 */
uint32_t tox_version_patch(void);

/**
 * Return whether the compiled library version is compatible with the passed
 * version numbers.
 */
bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

/**
 * A convenience macro to call tox_version_is_compatible with the currently
 * compiling API version.
 */
#define TOX_VERSION_IS_ABI_COMPATIBLE()                         \
  tox_version_is_compatible(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH)


/*******************************************************************************
 *
 * :: Numeric constants
 *
 ******************************************************************************/



/**
 * The size of a Tox Public Key in bytes.
 */
#define TOX_PUBLIC_KEY_SIZE            32

uint32_t tox_public_key_size(void);

/**
 * The size of a Tox Secret Key in bytes.
 */
#define TOX_SECRET_KEY_SIZE            32

uint32_t tox_secret_key_size(void);

/**
 * The size of a Tox address in bytes. Tox addresses are in the format
 * [Public Key (TOX_PUBLIC_KEY_SIZE bytes)][nospam (4 bytes)][checksum (2 bytes)].
 *
 * The checksum is computed over the Public Key and the nospam value. The first
 * byte is an XOR of all the even bytes (0, 2, 4, ...), the second byte is an
 * XOR of all the odd bytes (1, 3, 5, ...) of the Public Key and nospam.
 */
#define TOX_ADDRESS_SIZE               (TOX_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

uint32_t tox_address_size(void);

/**
 * Maximum length of a nickname in bytes.
 */
#define TOX_MAX_NAME_LENGTH            128

uint32_t tox_max_name_length(void);

/**
 * Maximum length of a status message in bytes.
 */
#define TOX_MAX_STATUS_MESSAGE_LENGTH  1007

uint32_t tox_max_status_message_length(void);

/**
 * Maximum length of a friend request message in bytes.
 */
#define TOX_MAX_FRIEND_REQUEST_LENGTH  1016

uint32_t tox_max_friend_request_length(void);

/**
 * Maximum length of a single message after which it should be split.
 */
#define TOX_MAX_MESSAGE_LENGTH         1372

uint32_t tox_max_message_length(void);

/**
 * Maximum size of custom packets. TODO: should be LENGTH?
 */
#define TOX_MAX_CUSTOM_PACKET_SIZE     1373

uint32_t tox_max_custom_packet_size(void);

/**
 * The number of bytes in a hash generated by tox_hash.
 */
#define TOX_HASH_LENGTH                32

uint32_t tox_hash_length(void);

/**
 * The number of bytes in a file id.
 */
#define TOX_FILE_ID_LENGTH             32

uint32_t tox_file_id_length(void);

/**
 * Maximum file name length for file transfers.
 */
#define TOX_MAX_FILENAME_LENGTH        255

uint32_t tox_max_filename_length(void);


/*******************************************************************************
 *
 * :: Global enumerations
 *
 ******************************************************************************/



/**
 * Represents the possible statuses a client can have.
 */
typedef enum TOX_USER_STATUS {

    /**
     * User is online and available.
     */
    TOX_USER_STATUS_NONE,

    /**
     * User is away. Clients can set this e.g. after a user defined
     * inactivity time.
     */
    TOX_USER_STATUS_AWAY,

    /**
     * User is busy. Signals to other clients that this client does not
     * currently wish to communicate.
     */
    TOX_USER_STATUS_BUSY,

} TOX_USER_STATUS;


/**
 * Represents message types for tox_friend_send_message and group chat
 * messages.
 */
typedef enum TOX_MESSAGE_TYPE {

    /**
     * Normal text message. Similar to PRIVMSG on IRC.
     */
    TOX_MESSAGE_TYPE_NORMAL,

    /**
     * A message describing an user action. This is similar to /me (CTCP ACTION)
     * on IRC.
     */
    TOX_MESSAGE_TYPE_ACTION,

} TOX_MESSAGE_TYPE;



/*******************************************************************************
 *
 * :: Startup options
 *
 ******************************************************************************/



/**
 * Type of proxy used to connect to TCP relays.
 */
typedef enum TOX_PROXY_TYPE {

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

} TOX_PROXY_TYPE;


/**
 * Type of savedata to create the Tox instance from.
 */
typedef enum TOX_SAVEDATA_TYPE {

    /**
     * No savedata.
     */
    TOX_SAVEDATA_TYPE_NONE,

    /**
     * Savedata is one that was obtained from tox_get_savedata
     */
    TOX_SAVEDATA_TYPE_TOX_SAVE,

    /**
     * Savedata is a secret key of length TOX_SECRET_KEY_SIZE
     */
    TOX_SAVEDATA_TYPE_SECRET_KEY,

} TOX_SAVEDATA_TYPE;


/**
 * This struct contains all the startup options for Tox. You can either allocate
 * this object yourself, and pass it to tox_options_default, or call
 * tox_options_new to get a new default options object.
 */
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
     * need to be relayed through a TCP relay node, potentially slowing them down.
     * Disabling UDP support is necessary when using anonymous proxies or Tor.
     */
    bool udp_enabled;


    /**
     * Pass communications through a proxy.
     */
    TOX_PROXY_TYPE proxy_type;


    /**
     * The IP address or DNS name of the proxy to be used.
     *
     * If used, this must be non-NULL and be a valid DNS name. The name must not
     * exceed 255 characters, and be in a NUL-terminated C string format
     * (255 chars + 1 NUL byte).
     *
     * This member is ignored (it can be NULL) if proxy_type is TOX_PROXY_TYPE_NONE.
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
     * used: [33445, 33545].
     *
     * If either start_port or end_port is 0 while the other is non-zero, the
     * non-zero port will be the only port in the range.
     *
     * Having start_port > end_port will yield the same behavior as if start_port
     * and end_port were swapped.
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
     * The type of savedata to load from.
     */
    TOX_SAVEDATA_TYPE savedata_type;


    /**
     * The savedata.
     */
    const uint8_t *savedata_data;


    /**
     * The length of the savedata.
     */
    size_t savedata_length;

};


/**
 * Initialises a Tox_Options object with the default options.
 *
 * The result of this function is independent of the original options. All
 * values will be overwritten, no values will be read (so it is permissible
 * to pass an uninitialised object).
 *
 * If options is NULL, this function has no effect.
 *
 * @param options An options object to be filled with default options.
 */
void tox_options_default(struct Tox_Options *options);

typedef enum TOX_ERR_OPTIONS_NEW {

    /**
     * The function returned successfully.
     */
    TOX_ERR_OPTIONS_NEW_OK,

    /**
     * The function failed to allocate enough memory for the options struct.
     */
    TOX_ERR_OPTIONS_NEW_MALLOC,

} TOX_ERR_OPTIONS_NEW;


/**
 * Allocates a new Tox_Options object and initialises it with the default
 * options. This function can be used to preserve long term ABI compatibility by
 * giving the responsibility of allocation and deallocation to the Tox library.
 *
 * Objects returned from this function must be freed using the tox_options_free
 * function.
 *
 * @return A new Tox_Options object with default options or NULL on failure.
 */
struct Tox_Options *tox_options_new(TOX_ERR_OPTIONS_NEW *error);

/**
 * Releases all resources associated with an options objects.
 *
 * Passing a pointer that was not returned by tox_options_new results in
 * undefined behaviour.
 */
void tox_options_free(struct Tox_Options *options);


/*******************************************************************************
 *
 * :: Creation and destruction
 *
 ******************************************************************************/



typedef enum TOX_ERR_NEW {

    /**
     * The function returned successfully.
     */
    TOX_ERR_NEW_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_NEW_NULL,

    /**
     * The function was unable to allocate enough memory to store the internal
     * structures for the Tox object.
     */
    TOX_ERR_NEW_MALLOC,

    /**
     * The function was unable to bind to a port. This may mean that all ports
     * have already been bound, e.g. by other Tox instances, or it may mean
     * a permission error. You may be able to gather more information from errno.
     */
    TOX_ERR_NEW_PORT_ALLOC,

    /**
     * proxy_type was invalid.
     */
    TOX_ERR_NEW_PROXY_BAD_TYPE,

    /**
     * proxy_type was valid but the proxy_host passed had an invalid format
     * or was NULL.
     */
    TOX_ERR_NEW_PROXY_BAD_HOST,

    /**
     * proxy_type was valid, but the proxy_port was invalid.
     */
    TOX_ERR_NEW_PROXY_BAD_PORT,

    /**
     * The proxy address passed could not be resolved.
     */
    TOX_ERR_NEW_PROXY_NOT_FOUND,

    /**
     * The byte array to be loaded contained an encrypted save.
     */
    TOX_ERR_NEW_LOAD_ENCRYPTED,

    /**
     * The data format was invalid. This can happen when loading data that was
     * saved by an older version of Tox, or when the data has been corrupted.
     * When loading from badly formatted data, some data may have been loaded,
     * and the rest is discarded. Passing an invalid length parameter also
     * causes this error.
     */
    TOX_ERR_NEW_LOAD_BAD_FORMAT,

} TOX_ERR_NEW;


/**
 * @brief Creates and initialises a new Tox instance with the options passed.
 *
 * This function will bring the instance into a valid state. Running the event
 * loop with a new instance will operate correctly.
 *
 * If loading failed or succeeded only partially, the new or partially loaded
 * instance is returned and an error code is set.
 *
 * @param options An options object as described above. If this parameter is
 *   NULL, the default options are used.
 *
 * @see tox_iterate for the event loop.
 *
 * @return A new Tox instance pointer on success or NULL on failure.
 */
Tox *tox_new(const struct Tox_Options *options, TOX_ERR_NEW *error);

/**
 * Releases all resources associated with the Tox instance and disconnects from
 * the network.
 *
 * After calling this function, the Tox pointer becomes invalid. No other
 * functions can be called, and the pointer value can no longer be read.
 */
void tox_kill(Tox *tox);

/**
 * Calculates the number of bytes required to store the tox instance with
 * tox_get_savedata. This function cannot fail. The result is always greater than 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_get_savedata_size(const Tox *tox);

/**
 * Store all information associated with the tox instance to a byte array.
 *
 * @param data A memory region large enough to store the tox instance data.
 *   Call tox_get_savedata_size to find the number of bytes required. If this parameter
 *   is NULL, this function has no effect.
 */
void tox_get_savedata(const Tox *tox, uint8_t *savedata);


/*******************************************************************************
 *
 * :: Connection lifecycle and event loop
 *
 ******************************************************************************/



typedef enum TOX_ERR_BOOTSTRAP {

    /**
     * The function returned successfully.
     */
    TOX_ERR_BOOTSTRAP_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_BOOTSTRAP_NULL,

    /**
     * The address could not be resolved to an IP address, or the IP address
     * passed was invalid.
     */
    TOX_ERR_BOOTSTRAP_BAD_HOST,

    /**
     * The port passed was invalid. The valid port range is (1, 65535).
     */
    TOX_ERR_BOOTSTRAP_BAD_PORT,

} TOX_ERR_BOOTSTRAP;


/**
 * Sends a "get nodes" request to the given bootstrap node with IP, port, and
 * public key to setup connections.
 *
 * This function will attempt to connect to the node using UDP. You must use
 * this function even if Tox_Options.udp_enabled was set to false.
 *
 * @param address The hostname or IP address (IPv4 or IPv6) of the node.
 * @param port The port on the host on which the bootstrap Tox instance is
 *   listening.
 * @param public_key The long term public key of the bootstrap node
 *   (TOX_PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool tox_bootstrap(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key, TOX_ERR_BOOTSTRAP *error);

/**
 * Adds additional host:port pair as TCP relay.
 *
 * This function can be used to initiate TCP connections to different ports on
 * the same bootstrap node, or to add TCP relays without using them as
 * bootstrap nodes.
 *
 * @param address The hostname or IP address (IPv4 or IPv6) of the TCP relay.
 * @param port The port on the host on which the TCP relay is listening.
 * @param public_key The long term public key of the TCP relay
 *   (TOX_PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool tox_add_tcp_relay(Tox *tox, const char *address, uint16_t port, const uint8_t *public_key,
                       TOX_ERR_BOOTSTRAP *error);

/**
 * Protocols that can be used to connect to the network or friends.
 */
typedef enum TOX_CONNECTION {

    /**
     * There is no connection. This instance, or the friend the state change is
     * about, is now offline.
     */
    TOX_CONNECTION_NONE,

    /**
     * A TCP connection has been established. For the own instance, this means it
     * is connected through a TCP relay, only. For a friend, this means that the
     * connection to that particular friend goes through a TCP relay.
     */
    TOX_CONNECTION_TCP,

    /**
     * A UDP connection has been established. For the own instance, this means it
     * is able to send UDP packets to DHT nodes, but may still be connected to
     * a TCP relay. For a friend, this means that the connection to that
     * particular friend was built using direct UDP packets.
     */
    TOX_CONNECTION_UDP,

} TOX_CONNECTION;


/**
 * Return whether we are connected to the DHT. The return value is equal to the
 * last value received through the `self_connection_status` callback.
 */
TOX_CONNECTION tox_self_get_connection_status(const Tox *tox);

/**
 * @param connection_status Whether we are connected to the DHT.
 */
typedef void tox_self_connection_status_cb(Tox *tox, TOX_CONNECTION connection_status, void *user_data);


/**
 * Set the callback for the `self_connection_status` event. Pass NULL to unset.
 *
 * This event is triggered whenever there is a change in the DHT connection
 * state. When disconnected, a client may choose to call tox_bootstrap again, to
 * reconnect to the DHT. Note that this state may frequently change for short
 * amounts of time. Clients should therefore not immediately bootstrap on
 * receiving a disconnect.
 *
 * TODO: how long should a client wait before bootstrapping again?
 */
void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback, void *user_data);

/**
 * Return the time in milliseconds before tox_iterate() should be called again
 * for optimal performance.
 */
uint32_t tox_iteration_interval(const Tox *tox);

/**
 * The main loop that needs to be run in intervals of tox_iteration_interval()
 * milliseconds.
 */
void tox_iterate(Tox *tox);


/*******************************************************************************
 *
 * :: Internal client information (Tox address/id)
 *
 ******************************************************************************/



/**
 * Writes the Tox friend address of the client to a byte array. The address is
 * not in human-readable format. If a client wants to display the address,
 * formatting is required.
 *
 * @param address A memory region of at least TOX_ADDRESS_SIZE bytes. If this
 *   parameter is NULL, this function has no effect.
 * @see TOX_ADDRESS_SIZE for the address format.
 */
void tox_self_get_address(const Tox *tox, uint8_t *address);

/**
 * Set the 4-byte nospam part of the address.
 *
 * @param nospam Any 32 bit unsigned integer.
 */
void tox_self_set_nospam(Tox *tox, uint32_t nospam);

/**
 * Get the 4-byte nospam part of the address.
 */
uint32_t tox_self_get_nospam(const Tox *tox);

/**
 * Copy the Tox Public Key (long term) from the Tox object.
 *
 * @param public_key A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_self_get_public_key(const Tox *tox, uint8_t *public_key);

/**
 * Copy the Tox Secret Key from the Tox object.
 *
 * @param secret_key A memory region of at least TOX_SECRET_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_self_get_secret_key(const Tox *tox, uint8_t *secret_key);


/*******************************************************************************
 *
 * :: User-visible client information (nickname/status)
 *
 ******************************************************************************/



/**
 * Common error codes for all functions that set a piece of user-visible
 * client information.
 */
typedef enum TOX_ERR_SET_INFO {

    /**
     * The function returned successfully.
     */
    TOX_ERR_SET_INFO_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_SET_INFO_NULL,

    /**
     * Information length exceeded maximum permissible size.
     */
    TOX_ERR_SET_INFO_TOO_LONG,

} TOX_ERR_SET_INFO;


/**
 * Set the nickname for the Tox client.
 *
 * Nickname length cannot exceed TOX_MAX_NAME_LENGTH. If length is 0, the name
 * parameter is ignored (it can be NULL), and the nickname is set back to empty.
 *
 * @param name A byte array containing the new nickname.
 * @param length The size of the name byte array.
 *
 * @return true on success.
 */
bool tox_self_set_name(Tox *tox, const uint8_t *name, size_t length, TOX_ERR_SET_INFO *error);

/**
 * Return the length of the current nickname as passed to tox_self_set_name.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_self_get_name_size(const Tox *tox);

/**
 * Write the nickname set by tox_self_set_name to a byte array.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function has no effect.
 *
 * Call tox_self_get_name_size to find out how much memory to allocate for
 * the result.
 *
 * @param name A valid memory location large enough to hold the nickname.
 *   If this parameter is NULL, the function has no effect.
 */
void tox_self_get_name(const Tox *tox, uint8_t *name);

/**
 * Set the client's status message.
 *
 * Status message length cannot exceed TOX_MAX_STATUS_MESSAGE_LENGTH. If
 * length is 0, the status parameter is ignored (it can be NULL), and the
 * user status is set back to empty.
 */
bool tox_self_set_status_message(Tox *tox, const uint8_t *status_message, size_t length, TOX_ERR_SET_INFO *error);

/**
 * Return the length of the current status message as passed to tox_self_set_status_message.
 *
 * If no status message was set before calling this function, the status
 * is empty, and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_self_get_status_message_size(const Tox *tox);

/**
 * Write the status message set by tox_self_set_status_message to a byte array.
 *
 * If no status message was set before calling this function, the status is
 * empty, and this function has no effect.
 *
 * Call tox_self_get_status_message_size to find out how much memory to allocate for
 * the result.
 *
 * @param status A valid memory location large enough to hold the status message.
 *   If this parameter is NULL, the function has no effect.
 */
void tox_self_get_status_message(const Tox *tox, uint8_t *status_message);

/**
 * Set the client's user status.
 *
 * @param user_status One of the user statuses listed in the enumeration above.
 */
void tox_self_set_status(Tox *tox, TOX_USER_STATUS status);

/**
 * Returns the client's user status.
 */
TOX_USER_STATUS tox_self_get_status(const Tox *tox);


/*******************************************************************************
 *
 * :: Friend list management
 *
 ******************************************************************************/



typedef enum TOX_ERR_FRIEND_ADD {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_ADD_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_ADD_NULL,

    /**
     * The length of the friend request message exceeded
     * TOX_MAX_FRIEND_REQUEST_LENGTH.
     */
    TOX_ERR_FRIEND_ADD_TOO_LONG,

    /**
     * The friend request message was empty. This, and the TOO_LONG code will
     * never be returned from tox_friend_add_norequest.
     */
    TOX_ERR_FRIEND_ADD_NO_MESSAGE,

    /**
     * The friend address belongs to the sending client.
     */
    TOX_ERR_FRIEND_ADD_OWN_KEY,

    /**
     * A friend request has already been sent, or the address belongs to a friend
     * that is already on the friend list.
     */
    TOX_ERR_FRIEND_ADD_ALREADY_SENT,

    /**
     * The friend address checksum failed.
     */
    TOX_ERR_FRIEND_ADD_BAD_CHECKSUM,

    /**
     * The friend was already there, but the nospam value was different.
     */
    TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM,

    /**
     * A memory allocation failed when trying to increase the friend list size.
     */
    TOX_ERR_FRIEND_ADD_MALLOC,

} TOX_ERR_FRIEND_ADD;


/**
 * Add a friend to the friend list and send a friend request.
 *
 * A friend request message must be at least 1 byte long and at most
 * TOX_MAX_FRIEND_REQUEST_LENGTH.
 *
 * Friend numbers are unique identifiers used in all functions that operate on
 * friends. Once added, a friend number is stable for the lifetime of the Tox
 * object. After saving the state and reloading it, the friend numbers may not
 * be the same as before. Deleting a friend creates a gap in the friend number
 * set, which is filled by the next adding of a friend. Any pattern in friend
 * numbers should not be relied on.
 *
 * If more than INT32_MAX friends are added, this function causes undefined
 * behaviour.
 *
 * @param address The address of the friend (returned by tox_self_get_address of
 *   the friend you wish to add) it must be TOX_ADDRESS_SIZE bytes.
 * @param message The message that will be sent along with the friend request.
 * @param length The length of the data byte array.
 *
 * @return the friend number on success, UINT32_MAX on failure.
 */
uint32_t tox_friend_add(Tox *tox, const uint8_t *address, const uint8_t *message, size_t length,
                        TOX_ERR_FRIEND_ADD *error);

/**
 * Add a friend without sending a friend request.
 *
 * This function is used to add a friend in response to a friend request. If the
 * client receives a friend request, it can be reasonably sure that the other
 * client added this client as a friend, eliminating the need for a friend
 * request.
 *
 * This function is also useful in a situation where both instances are
 * controlled by the same entity, so that this entity can perform the mutual
 * friend adding. In this case, there is no need for a friend request, either.
 *
 * @param public_key A byte array of length TOX_PUBLIC_KEY_SIZE containing the
 *   Public Key (not the Address) of the friend to add.
 *
 * @return the friend number on success, UINT32_MAX on failure.
 * @see tox_friend_add for a more detailed description of friend numbers.
 */
uint32_t tox_friend_add_norequest(Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_ADD *error);

typedef enum TOX_ERR_FRIEND_DELETE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_DELETE_OK,

    /**
     * There was no friend with the given friend number. No friends were deleted.
     */
    TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND,

} TOX_ERR_FRIEND_DELETE;


/**
 * Remove a friend from the friend list.
 *
 * This does not notify the friend of their deletion. After calling this
 * function, this client will appear offline to the friend and no communication
 * can occur between the two.
 *
 * @param friend_number Friend number for the friend to be deleted.
 *
 * @return true on success.
 */
bool tox_friend_delete(Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_DELETE *error);


/*******************************************************************************
 *
 * :: Friend list queries
 *
 ******************************************************************************/



typedef enum TOX_ERR_FRIEND_BY_PUBLIC_KEY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL,

    /**
     * No friend with the given Public Key exists on the friend list.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND,

} TOX_ERR_FRIEND_BY_PUBLIC_KEY;


/**
 * Return the friend number associated with that Public Key.
 *
 * @return the friend number on success, UINT32_MAX on failure.
 * @param public_key A byte array containing the Public Key.
 */
uint32_t tox_friend_by_public_key(const Tox *tox, const uint8_t *public_key, TOX_ERR_FRIEND_BY_PUBLIC_KEY *error);

/**
 * Checks if a friend with the given friend number exists and returns true if
 * it does.
 */
bool tox_friend_exists(const Tox *tox, uint32_t friend_number);

/**
 * Return the number of friends on the friend list.
 *
 * This function can be used to determine how much memory to allocate for
 * tox_self_get_friend_list.
 */
size_t tox_self_get_friend_list_size(const Tox *tox);

/**
 * Copy a list of valid friend numbers into an array.
 *
 * Call tox_self_get_friend_list_size to determine the number of elements to allocate.
 *
 * @param list A memory region with enough space to hold the friend list. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_self_get_friend_list(const Tox *tox, uint32_t *friend_list);

typedef enum TOX_ERR_FRIEND_GET_PUBLIC_KEY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK,

    /**
     * No friend with the given number exists on the friend list.
     */
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND,

} TOX_ERR_FRIEND_GET_PUBLIC_KEY;


/**
 * Copies the Public Key associated with a given friend number to a byte array.
 *
 * @param friend_number The friend number you want the Public Key of.
 * @param public_key A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_friend_get_public_key(const Tox *tox, uint32_t friend_number, uint8_t *public_key,
                               TOX_ERR_FRIEND_GET_PUBLIC_KEY *error);

typedef enum TOX_ERR_FRIEND_GET_LAST_ONLINE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_GET_LAST_ONLINE_OK,

    /**
     * No friend with the given number exists on the friend list.
     */
    TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND,

} TOX_ERR_FRIEND_GET_LAST_ONLINE;


/**
 * Return a unix-time timestamp of the last time the friend associated with a given
 * friend number was seen online. This function will return UINT64_MAX on error.
 *
 * @param friend_number The friend number you want to query.
 */
uint64_t tox_friend_get_last_online(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_GET_LAST_ONLINE *error);


/*******************************************************************************
 *
 * :: Friend-specific state queries (can also be received through callbacks)
 *
 ******************************************************************************/



/**
 * Common error codes for friend state query functions.
 */
typedef enum TOX_ERR_FRIEND_QUERY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_QUERY_OK,

    /**
     * The pointer parameter for storing the query result (name, message) was
     * NULL. Unlike the `_self_` variants of these functions, which have no effect
     * when a parameter is NULL, these functions return an error in that case.
     */
    TOX_ERR_FRIEND_QUERY_NULL,

    /**
     * The friend_number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND,

} TOX_ERR_FRIEND_QUERY;


/**
 * Return the length of the friend's name. If the friend number is invalid, the
 * return value is unspecified.
 *
 * The return value is equal to the `length` argument received by the last
 * `friend_name` callback.
 */
size_t tox_friend_get_name_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error);

/**
 * Write the name of the friend designated by the given friend number to a byte
 * array.
 *
 * Call tox_friend_get_name_size to determine the allocation size for the `name`
 * parameter.
 *
 * The data written to `name` is equal to the data received by the last
 * `friend_name` callback.
 *
 * @param name A valid memory region large enough to store the friend's name.
 *
 * @return true on success.
 */
bool tox_friend_get_name(const Tox *tox, uint32_t friend_number, uint8_t *name, TOX_ERR_FRIEND_QUERY *error);

/**
 * @param friend_number The friend number of the friend whose name changed.
 * @param name A byte array containing the same data as
 *   tox_friend_get_name would write to its `name` parameter.
 * @param length A value equal to the return value of
 *   tox_friend_get_name_size.
 */
typedef void tox_friend_name_cb(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length, void *user_data);


/**
 * Set the callback for the `friend_name` event. Pass NULL to unset.
 *
 * This event is triggered when a friend changes their name.
 */
void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *callback, void *user_data);

/**
 * Return the length of the friend's status message. If the friend number is
 * invalid, the return value is SIZE_MAX.
 */
size_t tox_friend_get_status_message_size(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error);

/**
 * Write the status message of the friend designated by the given friend number to a byte
 * array.
 *
 * Call tox_friend_get_status_message_size to determine the allocation size for the `status_name`
 * parameter.
 *
 * The data written to `status_message` is equal to the data received by the last
 * `friend_status_message` callback.
 *
 * @param status_message A valid memory region large enough to store the friend's status message.
 */
bool tox_friend_get_status_message(const Tox *tox, uint32_t friend_number, uint8_t *status_message,
                                   TOX_ERR_FRIEND_QUERY *error);

/**
 * @param friend_number The friend number of the friend whose status message
 *   changed.
 * @param message A byte array containing the same data as
 *   tox_friend_get_status_message would write to its `status_message` parameter.
 * @param length A value equal to the return value of
 *   tox_friend_get_status_message_size.
 */
typedef void tox_friend_status_message_cb(Tox *tox, uint32_t friend_number, const uint8_t *message, size_t length,
        void *user_data);


/**
 * Set the callback for the `friend_status_message` event. Pass NULL to unset.
 *
 * This event is triggered when a friend changes their status message.
 */
void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *callback, void *user_data);

/**
 * Return the friend's user status (away/busy/...). If the friend number is
 * invalid, the return value is unspecified.
 *
 * The status returned is equal to the last status received through the
 * `friend_status` callback.
 */
TOX_USER_STATUS tox_friend_get_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error);

/**
 * @param friend_number The friend number of the friend whose user status
 *   changed.
 * @param status The new user status.
 */
typedef void tox_friend_status_cb(Tox *tox, uint32_t friend_number, TOX_USER_STATUS status, void *user_data);


/**
 * Set the callback for the `friend_status` event. Pass NULL to unset.
 *
 * This event is triggered when a friend changes their user status.
 */
void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback, void *user_data);

/**
 * Check whether a friend is currently connected to this client.
 *
 * The result of this function is equal to the last value received by the
 * `friend_connection_status` callback.
 *
 * @param friend_number The friend number for which to query the connection
 *   status.
 *
 * @return the friend's connection status as it was received through the
 *   `friend_connection_status` event.
 */
TOX_CONNECTION tox_friend_get_connection_status(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error);

/**
 * @param friend_number The friend number of the friend whose connection status
 *   changed.
 * @param connection_status The result of calling
 *   tox_friend_get_connection_status on the passed friend_number.
 */
typedef void tox_friend_connection_status_cb(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data);


/**
 * Set the callback for the `friend_connection_status` event. Pass NULL to unset.
 *
 * This event is triggered when a friend goes offline after having been online,
 * or when a friend goes online.
 *
 * This callback is not called when adding friends. It is assumed that when
 * adding friends, their connection status is initially offline.
 */
void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback, void *user_data);

/**
 * Check whether a friend is currently typing a message.
 *
 * @param friend_number The friend number for which to query the typing status.
 *
 * @return true if the friend is typing.
 * @return false if the friend is not typing, or the friend number was
 *   invalid. Inspect the error code to determine which case it is.
 */
bool tox_friend_get_typing(const Tox *tox, uint32_t friend_number, TOX_ERR_FRIEND_QUERY *error);

/**
 * @param friend_number The friend number of the friend who started or stopped
 *   typing.
 * @param is_typing The result of calling tox_friend_get_typing on the passed
 *   friend_number.
 */
typedef void tox_friend_typing_cb(Tox *tox, uint32_t friend_number, bool is_typing, void *user_data);


/**
 * Set the callback for the `friend_typing` event. Pass NULL to unset.
 *
 * This event is triggered when a friend starts or stops typing.
 */
void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Sending private messages
 *
 ******************************************************************************/



typedef enum TOX_ERR_SET_TYPING {

    /**
     * The function returned successfully.
     */
    TOX_ERR_SET_TYPING_OK,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND,

} TOX_ERR_SET_TYPING;


/**
 * Set the client's typing status for a friend.
 *
 * The client is responsible for turning it on or off.
 *
 * @param friend_number The friend to which the client is typing a message.
 * @param typing The typing status. True means the client is typing.
 *
 * @return true on success.
 */
bool tox_self_set_typing(Tox *tox, uint32_t friend_number, bool typing, TOX_ERR_SET_TYPING *error);

typedef enum TOX_ERR_FRIEND_SEND_MESSAGE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_NULL,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED,

    /**
     * An allocation error occurred while increasing the send queue size.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ,

    /**
     * Message length exceeded TOX_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG,

    /**
     * Attempted to send a zero-length message.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY,

} TOX_ERR_FRIEND_SEND_MESSAGE;


/**
 * Send a text chat message to an online friend.
 *
 * This function creates a chat message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_MAX_MESSAGE_LENGTH. Larger messages
 * must be split by the client and sent as separate messages. Other clients can
 * then reassemble the fragments. Messages may not be empty.
 *
 * The return value of this function is the message ID. If a read receipt is
 * received, the triggered `friend_read_receipt` event will be passed this message ID.
 *
 * Message IDs are unique per friend. The first message ID is 0. Message IDs are
 * incremented by 1 each time a message is sent. If UINT32_MAX messages were
 * sent, the next message ID is 0.
 *
 * @param type Message type (normal, action, ...).
 * @param friend_number The friend number of the friend to send the message to.
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 */
uint32_t tox_friend_send_message(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                 size_t length, TOX_ERR_FRIEND_SEND_MESSAGE *error);

/**
 * @param friend_number The friend number of the friend who received the message.
 * @param message_id The message ID as returned from tox_friend_send_message
 *   corresponding to the message sent.
 */
typedef void tox_friend_read_receipt_cb(Tox *tox, uint32_t friend_number, uint32_t message_id, void *user_data);


/**
 * Set the callback for the `friend_read_receipt` event. Pass NULL to unset.
 *
 * This event is triggered when the friend receives the message sent with
 * tox_friend_send_message with the corresponding message ID.
 */
void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Receiving private messages and friend requests
 *
 ******************************************************************************/



/**
 * @param public_key The Public Key of the user who sent the friend request.
 * @param time_delta A delta in seconds between when the message was composed
 *   and when it is being transmitted. For messages that are sent immediately,
 *   it will be 0. If a message was written and couldn't be sent immediately
 *   (due to a connection failure, for example), the time_delta is an
 *   approximation of when it was composed.
 * @param message The message they sent along with the request.
 * @param length The size of the message byte array.
 */
typedef void tox_friend_request_cb(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                                   void *user_data);


/**
 * Set the callback for the `friend_request` event. Pass NULL to unset.
 *
 * This event is triggered when a friend request is received.
 */
void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *callback, void *user_data);

/**
 * @param friend_number The friend number of the friend who sent the message.
 * @param time_delta Time between composition and sending.
 * @param message The message data they sent.
 * @param length The size of the message byte array.
 *
 * @see friend_request for more information on time_delta.
 */
typedef void tox_friend_message_cb(Tox *tox, uint32_t friend_number, TOX_MESSAGE_TYPE type, const uint8_t *message,
                                   size_t length, void *user_data);


/**
 * Set the callback for the `friend_message` event. Pass NULL to unset.
 *
 * This event is triggered when a message from a friend is received.
 */
void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: File transmission: common between sending and receiving
 *
 ******************************************************************************/



/**
 * Generates a cryptographic hash of the given data.
 *
 * This function may be used by clients for any purpose, but is provided
 * primarily for validating cached avatars. This use is highly recommended to
 * avoid unnecessary avatar updates.
 *
 * If hash is NULL or data is NULL while length is not 0 the function returns false,
 * otherwise it returns true.
 *
 * This function is a wrapper to internal message-digest functions.
 *
 * @param hash A valid memory location the hash data. It must be at least
 *   TOX_HASH_LENGTH bytes in size.
 * @param data Data to be hashed or NULL.
 * @param length Size of the data array or 0.
 *
 * @return true if hash was not NULL.
 */
bool tox_hash(uint8_t *hash, const uint8_t *data, size_t length);

enum TOX_FILE_KIND {

    /**
     * Arbitrary file data. Clients can choose to handle it based on the file name
     * or magic or any other way they choose.
     */
    TOX_FILE_KIND_DATA,

    /**
     * Avatar file_id. This consists of tox_hash(image).
     * Avatar data. This consists of the image data.
     *
     * Avatars can be sent at any time the client wishes. Generally, a client will
     * send the avatar to a friend when that friend comes online, and to all
     * friends when the avatar changed. A client can save some traffic by
     * remembering which friend received the updated avatar already and only send
     * it if the friend has an out of date avatar.
     *
     * Clients who receive avatar send requests can reject it (by sending
     * TOX_FILE_CONTROL_CANCEL before any other controls), or accept it (by
     * sending TOX_FILE_CONTROL_RESUME). The file_id of length TOX_HASH_LENGTH bytes
     * (same length as TOX_FILE_ID_LENGTH) will contain the hash. A client can compare
     * this hash with a saved hash and send TOX_FILE_CONTROL_CANCEL to terminate the avatar
     * transfer if it matches.
     *
     * When file_size is set to 0 in the transfer request it means that the client
     * has no avatar.
     */
    TOX_FILE_KIND_AVATAR,

};


typedef enum TOX_FILE_CONTROL {

    /**
     * Sent by the receiving side to accept a file send request. Also sent after a
     * TOX_FILE_CONTROL_PAUSE command to continue sending or receiving.
     */
    TOX_FILE_CONTROL_RESUME,

    /**
     * Sent by clients to pause the file transfer. The initial state of a file
     * transfer is always paused on the receiving side and running on the sending
     * side. If both the sending and receiving side pause the transfer, then both
     * need to send TOX_FILE_CONTROL_RESUME for the transfer to resume.
     */
    TOX_FILE_CONTROL_PAUSE,

    /**
     * Sent by the receiving side to reject a file send request before any other
     * commands are sent. Also sent by either side to terminate a file transfer.
     */
    TOX_FILE_CONTROL_CANCEL,

} TOX_FILE_CONTROL;


typedef enum TOX_ERR_FILE_CONTROL {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_CONTROL_OK,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given friend.
     */
    TOX_ERR_FILE_CONTROL_NOT_FOUND,

    /**
     * A RESUME control was sent, but the file transfer is running normally.
     */
    TOX_ERR_FILE_CONTROL_NOT_PAUSED,

    /**
     * A RESUME control was sent, but the file transfer was paused by the other
     * party. Only the party that paused the transfer can resume it.
     */
    TOX_ERR_FILE_CONTROL_DENIED,

    /**
     * A PAUSE control was sent, but the file transfer was already paused.
     */
    TOX_ERR_FILE_CONTROL_ALREADY_PAUSED,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_CONTROL_SENDQ,

} TOX_ERR_FILE_CONTROL;


/**
 * Sends a file control command to a friend for a given file transfer.
 *
 * @param friend_number The friend number of the friend the file is being
 *   transferred to or received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param control The control command to send.
 *
 * @return true on success.
 */
bool tox_file_control(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                      TOX_ERR_FILE_CONTROL *error);

/**
 * When receiving TOX_FILE_CONTROL_CANCEL, the client should release the
 * resources associated with the file number and consider the transfer failed.
 *
 * @param friend_number The friend number of the friend who is sending the file.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param control The file control command received.
 */
typedef void tox_file_recv_control_cb(Tox *tox, uint32_t friend_number, uint32_t file_number, TOX_FILE_CONTROL control,
                                      void *user_data);


/**
 * Set the callback for the `file_recv_control` event. Pass NULL to unset.
 *
 * This event is triggered when a file control command is received from a
 * friend.
 */
void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback, void *user_data);

typedef enum TOX_ERR_FILE_SEEK {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEEK_OK,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given friend.
     */
    TOX_ERR_FILE_SEEK_NOT_FOUND,

    /**
     * File was not in a state where it could be seeked.
     */
    TOX_ERR_FILE_SEEK_DENIED,

    /**
     * Seek position was invalid
     */
    TOX_ERR_FILE_SEEK_INVALID_POSITION,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_SEEK_SENDQ,

} TOX_ERR_FILE_SEEK;


/**
 * Sends a file seek control command to a friend for a given file transfer.
 *
 * This function can only be called to resume a file transfer right before
 * TOX_FILE_CONTROL_RESUME is sent.
 *
 * @param friend_number The friend number of the friend the file is being
 *   received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param position The position that the file should be seeked to.
 */
bool tox_file_seek(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, TOX_ERR_FILE_SEEK *error);

typedef enum TOX_ERR_FILE_GET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_GET_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FILE_GET_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_GET_FRIEND_NOT_FOUND,

    /**
     * No file transfer with the given file number was found for the given friend.
     */
    TOX_ERR_FILE_GET_NOT_FOUND,

} TOX_ERR_FILE_GET;


/**
 * Copy the file id associated to the file transfer to a byte array.
 *
 * @param friend_number The friend number of the friend the file is being
 *   transferred to or received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param file_id A memory region of at least TOX_FILE_ID_LENGTH bytes. If
 *   this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_file_get_file_id(const Tox *tox, uint32_t friend_number, uint32_t file_number, uint8_t *file_id,
                          TOX_ERR_FILE_GET *error);


/*******************************************************************************
 *
 * :: File transmission: sending
 *
 ******************************************************************************/



typedef enum TOX_ERR_FILE_SEND {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEND_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FILE_SEND_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED,

    /**
     * Filename length exceeded TOX_MAX_FILENAME_LENGTH bytes.
     */
    TOX_ERR_FILE_SEND_NAME_TOO_LONG,

    /**
     * Too many ongoing transfers. The maximum number of concurrent file transfers
     * is 256 per friend per direction (sending and receiving).
     */
    TOX_ERR_FILE_SEND_TOO_MANY,

} TOX_ERR_FILE_SEND;


/**
 * Send a file transmission request.
 *
 * Maximum filename length is TOX_MAX_FILENAME_LENGTH bytes. The filename
 * should generally just be a file name, not a path with directory names.
 *
 * If a non-UINT64_MAX file size is provided, it can be used by both sides to
 * determine the sending progress. File size can be set to UINT64_MAX for streaming
 * data of unknown size.
 *
 * File transmission occurs in chunks, which are requested through the
 * `file_chunk_request` event.
 *
 * When a friend goes offline, all file transfers associated with the friend are
 * purged from core.
 *
 * If the file contents change during a transfer, the behaviour is unspecified
 * in general. What will actually happen depends on the mode in which the file
 * was modified and how the client determines the file size.
 *
 * - If the file size was increased
 *   - and sending mode was streaming (file_size = UINT64_MAX), the behaviour
 *     will be as expected.
 *   - and sending mode was file (file_size != UINT64_MAX), the
 *     file_chunk_request callback will receive length = 0 when Core thinks
 *     the file transfer has finished. If the client remembers the file size as
 *     it was when sending the request, it will terminate the transfer normally.
 *     If the client re-reads the size, it will think the friend cancelled the
 *     transfer.
 * - If the file size was decreased
 *   - and sending mode was streaming, the behaviour is as expected.
 *   - and sending mode was file, the callback will return 0 at the new
 *     (earlier) end-of-file, signalling to the friend that the transfer was
 *     cancelled.
 * - If the file contents were modified
 *   - at a position before the current read, the two files (local and remote)
 *     will differ after the transfer terminates.
 *   - at a position after the current read, the file transfer will succeed as
 *     expected.
 *   - In either case, both sides will regard the transfer as complete and
 *     successful.
 *
 * @param friend_number The friend number of the friend the file send request
 *   should be sent to.
 * @param kind The meaning of the file to be sent.
 * @param file_size Size in bytes of the file the client wants to send, UINT64_MAX if
 *   unknown or streaming.
 * @param file_id A file identifier of length TOX_FILE_ID_LENGTH that can be used to
 *   uniquely identify file transfers across core restarts. If NULL, a random one will
 *   be generated by core. It can then be obtained by using tox_file_get_file_id().
 * @param filename Name of the file. Does not need to be the actual name. This
 *   name will be sent along with the file send request.
 * @param filename_length Size in bytes of the filename.
 *
 * @return A file number used as an identifier in subsequent callbacks. This
 *   number is per friend. File numbers are reused after a transfer terminates.
 *   On failure, this function returns UINT32_MAX. Any pattern in file numbers
 *   should not be relied on.
 */
uint32_t tox_file_send(Tox *tox, uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t *file_id,
                       const uint8_t *filename, size_t filename_length, TOX_ERR_FILE_SEND *error);

typedef enum TOX_ERR_FILE_SEND_CHUNK {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEND_CHUNK_OK,

    /**
     * The length parameter was non-zero, but data was NULL.
     */
    TOX_ERR_FILE_SEND_CHUNK_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND,

    /**
     * File transfer was found but isn't in a transferring state: (paused, done,
     * broken, etc...) (happens only when not called from the request chunk callback).
     */
    TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING,

    /**
     * Attempted to send more or less data than requested. The requested data size is
     * adjusted according to maximum transmission unit and the expected end of
     * the file. Trying to send less or more than requested will return this error.
     */
    TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_SEND_CHUNK_SENDQ,

    /**
     * Position parameter was wrong.
     */
    TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION,

} TOX_ERR_FILE_SEND_CHUNK;


/**
 * Send a chunk of file data to a friend.
 *
 * This function is called in response to the `file_chunk_request` callback. The
 * length parameter should be equal to the one received though the callback.
 * If it is zero, the transfer is assumed complete. For files with known size,
 * Core will know that the transfer is complete after the last byte has been
 * received, so it is not necessary (though not harmful) to send a zero-length
 * chunk to terminate. For streams, core will know that the transfer is finished
 * if a chunk with length less than the length requested in the callback is sent.
 *
 * @param friend_number The friend number of the receiving friend for this file.
 * @param file_number The file transfer identifier returned by tox_file_send.
 * @param position The file or stream position from which to continue reading.
 * @return true on success.
 */
bool tox_file_send_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *data,
                         size_t length, TOX_ERR_FILE_SEND_CHUNK *error);

/**
 * If the length parameter is 0, the file transfer is finished, and the client's
 * resources associated with the file number should be released. After a call
 * with zero length, the file number can be reused for future file transfers.
 *
 * If the requested position is not equal to the client's idea of the current
 * file or stream position, it will need to seek. In case of read-once streams,
 * the client should keep the last read chunk so that a seek back can be
 * supported. A seek-back only ever needs to read from the last requested chunk.
 * This happens when a chunk was requested, but the send failed. A seek-back
 * request can occur an arbitrary number of times for any given chunk.
 *
 * In response to receiving this callback, the client should call the function
 * `tox_file_send_chunk` with the requested chunk. If the number of bytes sent
 * through that function is zero, the file transfer is assumed complete. A
 * client must send the full length of data requested with this callback.
 *
 * @param friend_number The friend number of the receiving friend for this file.
 * @param file_number The file transfer identifier returned by tox_file_send.
 * @param position The file or stream position from which to continue reading.
 * @param length The number of bytes requested for the current chunk.
 */
typedef void tox_file_chunk_request_cb(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                       size_t length, void *user_data);


/**
 * Set the callback for the `file_chunk_request` event. Pass NULL to unset.
 *
 * This event is triggered when Core is ready to send more file data.
 */
void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: File transmission: receiving
 *
 ******************************************************************************/



/**
 * The client should acquire resources to be associated with the file transfer.
 * Incoming file transfers start in the PAUSED state. After this callback
 * returns, a transfer can be rejected by sending a TOX_FILE_CONTROL_CANCEL
 * control command before any other control commands. It can be accepted by
 * sending TOX_FILE_CONTROL_RESUME.
 *
 * @param friend_number The friend number of the friend who is sending the file
 *   transfer request.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param kind The meaning of the file to be sent.
 * @param file_size Size in bytes of the file the client wants to send,
 *   UINT64_MAX if unknown or streaming.
 * @param filename Name of the file. Does not need to be the actual name. This
 *   name will be sent along with the file send request.
 * @param filename_length Size in bytes of the filename.
 */
typedef void tox_file_recv_cb(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind, uint64_t file_size,
                              const uint8_t *filename, size_t filename_length, void *user_data);


/**
 * Set the callback for the `file_recv` event. Pass NULL to unset.
 *
 * This event is triggered when a file transfer request is received.
 */
void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *callback, void *user_data);

/**
 * When length is 0, the transfer is finished and the client should release the
 * resources it acquired for the transfer. After a call with length = 0, the
 * file number can be reused for new file transfers.
 *
 * If position is equal to file_size (received in the file_receive callback)
 * when the transfer finishes, the file was received completely. Otherwise, if
 * file_size was UINT64_MAX, streaming ended successfully when length is 0.
 *
 * @param friend_number The friend number of the friend who is sending the file.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param position The file position of the first byte in data.
 * @param data A byte array containing the received chunk.
 * @param length The length of the received chunk.
 */
typedef void tox_file_recv_chunk_cb(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                    const uint8_t *data, size_t length, void *user_data);


/**
 * Set the callback for the `file_recv_chunk` event. Pass NULL to unset.
 *
 * This event is first triggered when a file transfer request is received, and
 * subsequently when a chunk of file data for an accepted request was received.
 */
void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Low-level custom packet sending and receiving
 *
 ******************************************************************************/



typedef enum TOX_ERR_FRIEND_CUSTOM_PACKET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_NULL,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED,

    /**
     * The first byte of data was not in the specified range for the packet type.
     * This range is 200-254 for lossy, and 160-191 for lossless packets.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID,

    /**
     * Attempted to send an empty packet.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY,

    /**
     * Packet data length exceeded TOX_MAX_CUSTOM_PACKET_SIZE.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ,

} TOX_ERR_FRIEND_CUSTOM_PACKET;


/**
 * Send a custom lossy packet to a friend.
 *
 * The first byte of data must be in the range 200-254. Maximum length of a
 * custom packet is TOX_MAX_CUSTOM_PACKET_SIZE.
 *
 * Lossy packets behave like UDP packets, meaning they might never reach the
 * other side or might arrive more than once (if someone is messing with the
 * connection) or might arrive in the wrong order.
 *
 * Unless latency is an issue, it is recommended that you use lossless custom
 * packets instead.
 *
 * @param friend_number The friend number of the friend this lossy packet
 *   should be sent to.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_friend_send_lossy_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                  TOX_ERR_FRIEND_CUSTOM_PACKET *error);

/**
 * Send a custom lossless packet to a friend.
 *
 * The first byte of data must be in the range 160-191. Maximum length of a
 * custom packet is TOX_MAX_CUSTOM_PACKET_SIZE.
 *
 * Lossless packet behaviour is comparable to TCP (reliability, arrive in order)
 * but with packets instead of a stream.
 *
 * @param friend_number The friend number of the friend this lossless packet
 *   should be sent to.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_friend_send_lossless_packet(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                     TOX_ERR_FRIEND_CUSTOM_PACKET *error);

/**
 * @param friend_number The friend number of the friend who sent a lossy packet.
 * @param data A byte array containing the received packet data.
 * @param length The length of the packet data byte array.
 */
typedef void tox_friend_lossy_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                                        void *user_data);


/**
 * Set the callback for the `friend_lossy_packet` event. Pass NULL to unset.
 *
 */
void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *callback, void *user_data);

/**
 * @param friend_number The friend number of the friend who sent the packet.
 * @param data A byte array containing the received packet data.
 * @param length The length of the packet data byte array.
 */
typedef void tox_friend_lossless_packet_cb(Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
        void *user_data);


/**
 * Set the callback for the `friend_lossless_packet` event. Pass NULL to unset.
 *
 */
void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Low-level network information
 *
 ******************************************************************************/



/**
 * Writes the temporary DHT public key of this instance to a byte array.
 *
 * This can be used in combination with an externally accessible IP address and
 * the bound port (from tox_self_get_udp_port) to run a temporary bootstrap node.
 *
 * Be aware that every time a new instance is created, the DHT public key
 * changes, meaning this cannot be used to run a permanent bootstrap node.
 *
 * @param dht_id A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If this
 *   parameter is NULL, this function has no effect.
 */
void tox_self_get_dht_id(const Tox *tox, uint8_t *dht_id);

typedef enum TOX_ERR_GET_PORT {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GET_PORT_OK,

    /**
     * The instance was not bound to any port.
     */
    TOX_ERR_GET_PORT_NOT_BOUND,

} TOX_ERR_GET_PORT;


/**
 * Return the UDP port this Tox instance is bound to.
 */
uint16_t tox_self_get_udp_port(const Tox *tox, TOX_ERR_GET_PORT *error);

/**
 * Return the TCP port this Tox instance is bound to. This is only relevant if
 * the instance is acting as a TCP relay.
 */
uint16_t tox_self_get_tcp_port(const Tox *tox, TOX_ERR_GET_PORT *error);


/*******************************************************************************
 *
 * :: Group chats
 *
 ******************************************************************************/




/*******************************************************************************
 *
 * :: Group chat numeric constants
 *
 ******************************************************************************/



/**
 * Maximum length of a group topic.
 */
#define TOX_GROUP_MAX_TOPIC_LENGTH     512

uint32_t tox_group_max_topic_length(void);

/**
 * Maximum length of a peer part message.
 */
#define TOX_GROUP_MAX_PART_LENGTH      128

uint32_t tox_group_max_part_length(void);

/**
 * Maximum length of a group name.
 */
#define TOX_GROUP_MAX_GROUP_NAME_LENGTH 48

uint32_t tox_group_max_group_name_length(void);

/**
 * Maximum length of a group password.
 */
#define TOX_GROUP_MAX_PASSWORD_SIZE    32

uint32_t tox_group_max_password_size(void);

/**
 * Number of bytes in a group Chat ID.
 */
#define TOX_GROUP_CHAT_ID_SIZE         32

uint32_t tox_group_chat_id_size(void);

/**
 * Size of a peer public key.
 */
#define TOX_GROUP_PEER_PUBLIC_KEY_SIZE 32

uint32_t tox_group_peer_public_key_size(void);


/*******************************************************************************
 *
 * :: Group chat state enumerators
 *
 ******************************************************************************/



typedef enum TOX_GROUP_PRIVACY_STATE {

    /**
     * The group is considered to be public. Anyone may join the group using the Chat ID.
     *
     * If the group is in this state, even if the Chat ID is never explicitly shared
     * with someone outside of the group, information including the Chat ID, IP addresses,
     * and peer ID's (but not Tox ID's) is visible to anyone with access to a node
     * storing a DHT entry for the given group.
     */
    TOX_GROUP_PRIVACY_STATE_PUBLIC,

    /**
     * The group is considered to be private. The only way to join the group is by having
     * someone in your contact list send you an invite.
     *
     * If the group is in this state, no group information (mentioned above) is present in the DHT;
     * the DHT is not used for any purpose at all. If a public group is set to private,
     * all DHT information related to the group will expire shortly.
     */
    TOX_GROUP_PRIVACY_STATE_PRIVATE,

} TOX_GROUP_PRIVACY_STATE;


/**
 * Represents group roles.
 *
 * Roles are are hierarchical in that each role has a set of privileges plus all the privileges
 * of the roles below it.
 */
typedef enum TOX_GROUP_ROLE {

    /**
     * May kick and ban all other peers as well as set their role to anything (except founder).
     * Founders may also set the group password, toggle the privacy state, and set the peer limit.
     */
    TOX_GROUP_ROLE_FOUNDER,

    /**
     * May kick, ban and set the user and observer roles for peers below this role.
     * May also set the group topic.
     */
    TOX_GROUP_ROLE_MODERATOR,

    /**
     * May communicate with other peers normally.
     */
    TOX_GROUP_ROLE_USER,

    /**
     * May observe the group and ignore peers; may not communicate with other peers or with the group.
     */
    TOX_GROUP_ROLE_OBSERVER,

} TOX_GROUP_ROLE;



/*******************************************************************************
 *
 * :: Group chat instance management
 *
 ******************************************************************************/



typedef enum TOX_ERR_GROUP_NEW {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_NEW_OK,

    /**
     * The group name exceeded TOX_GROUP_MAX_GROUP_NAME_LENGTH.
     */
    TOX_ERR_GROUP_NEW_TOO_LONG,

    /**
     * group_name is NULL or length is zero.
     */
    TOX_ERR_GROUP_NEW_EMPTY,

    /**
     * TOX_GROUP_PRIVACY_STATE is an invalid type.
     */
    TOX_ERR_GROUP_NEW_PRIVACY,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_NEW_INIT,

    /**
     * The group state failed to initialize. This usually indicates that something went wrong
     * related to cryptographic signing.
     */
    TOX_ERR_GROUP_NEW_STATE,

    /**
     * The group failed to announce to the DHT. This indicates a network related error.
     */
    TOX_ERR_GROUP_NEW_ANNOUNCE,

} TOX_ERR_GROUP_NEW;


/**
 * Creates a new group chat.
 *
 * This function creates a new group chat object and adds it to the chats array.
 *
 * The client should initiate its peer list with self info after calling this function, as
 * the peer_join callback will not be triggered.
 *
 * @param privacy_state The privacy state of the group. If this is set to TOX_GROUP_PRIVACY_STATE_PUBLIC,
 *   the group will attempt to announce itself to the DHT and anyone with the Chat ID may join.
 *   Otherwise a friend invite will be required to join the group.
 * @param group_name The name of the group. The name must be non-NULL.
 * @param length The length of the group name. This must be greater than zero and no larger than
 *   TOX_GROUP_MAX_GROUP_NAME_LENGTH.
 *
 * @return groupnumber on success, UINT32_MAX on failure.
 */
uint32_t tox_group_new(Tox *tox, TOX_GROUP_PRIVACY_STATE privacy_state, const uint8_t *group_name, size_t length,
                       TOX_ERR_GROUP_NEW *error);

typedef enum TOX_ERR_GROUP_JOIN {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_JOIN_OK,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_JOIN_INIT,

    /**
     * The chat_id pointer is set to NULL or a group with chat_id already exists. This usually
     * happens if the client attempts to create multiple sessions for the same group.
     */
    TOX_ERR_GROUP_JOIN_BAD_CHAT_ID,

    /**
     * Password length exceeded TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_JOIN_TOO_LONG,

} TOX_ERR_GROUP_JOIN;


/**
 * Joins a group chat with specified Chat ID.
 *
 * This function creates a new group chat object, adds it to the chats array, and sends
 * a DHT announcement to find peers in the group associated with chat_id. Once a peer has been
 * found a join attempt will be initiated.
 *
 * @param chat_id The Chat ID of the group you wish to join. This must be TOX_GROUP_CHAT_ID_SIZE bytes.
 * @param password The password required to join the group. Set to NULL if no password is required.
 * @param length The length of the password. If length is equal to zero,
 *   the password parameter is ignored. length must be no larger than TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return groupnumber on success, UINT32_MAX on failure.
 */
uint32_t tox_group_join(Tox *tox, const uint8_t *chat_id, const uint8_t *password, size_t length,
                        TOX_ERR_GROUP_JOIN *error);

typedef enum TOX_ERR_GROUP_RECONNECT {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_RECONNECT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND,

} TOX_ERR_GROUP_RECONNECT;


/**
 * Reconnects to a group.
 *
 * This function disconnects from all peers in the group, then attempts to reconnect with the group.
 * The caller's state is not changed (i.e. name, status, role, chat public key etc.)
 *
 * @param groupnumber The group number of the group we wish to reconnect to.
 *
 * @return true on success.
 */
bool tox_group_reconnect(Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_RECONNECT *error);

typedef enum TOX_ERR_GROUP_LEAVE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_LEAVE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_PART_LENGTH.
     */
    TOX_ERR_GROUP_LEAVE_TOO_LONG,

    /**
     * The parting packet failed to send.
     */
    TOX_ERR_GROUP_LEAVE_FAIL_SEND,

    /**
     * The group chat instance failed to be deleted. This may occur due to memory related errors.
     */
    TOX_ERR_GROUP_LEAVE_DELETE_FAIL,

} TOX_ERR_GROUP_LEAVE;


/**
 * Leaves a group.
 *
 * This function sends a parting packet containing a custom (non-obligatory) message to all
 * peers in a group, and deletes the group from the chat array. All group state information is permanently
 * lost, including keys and role credentials.
 *
 * @param groupnumber The group number of the group we wish to leave.
 * @param message The parting message to be sent to all the peers. Set to NULL if we do not wish to
 *   send a parting message.
 * @param length The length of the parting message. Set to 0 if we do not wish to send a parting message.
 *
 * @return true if the group chat instance is successfully deleted.
 */
bool tox_group_leave(Tox *tox, uint32_t groupnumber, const uint8_t *message, size_t length, TOX_ERR_GROUP_LEAVE *error);


/*******************************************************************************
 *
 * :: Group user-visible client information (nickname/status/role/public key)
 *
 ******************************************************************************/



/**
 * General error codes for self state get and size functions.
 */
typedef enum TOX_ERR_GROUP_SELF_QUERY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND,

} TOX_ERR_GROUP_SELF_QUERY;


/**
 * Error codes for self name setting.
 */
typedef enum TOX_ERR_GROUP_SELF_NAME_SET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND,

    /**
     * Name length exceeded TOX_MAX_NAME_LENGTH.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG,

    /**
     * The length given to the set function is zero or name is a NULL pointer.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_INVALID,

    /**
     * The name is already taken by another peer in the group.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_TAKEN,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND,

} TOX_ERR_GROUP_SELF_NAME_SET;


/**
 * Set the client's nickname for the group instance designated by the given group number.
 *
 * Nickname length cannot exceed TOX_MAX_NAME_LENGTH. If length is equal to zero or name is a NULL
 * pointer, the function call will fail.
 *
 * @param name A byte array containing the new nickname.
 * @param length The size of the name byte array.
 *
 * @return true on success.
 */
bool tox_group_self_set_name(Tox *tox, uint32_t groupnumber, const uint8_t *name, size_t length,
                             TOX_ERR_GROUP_SELF_NAME_SET *error);

/**
 * Return the length of the client's current nickname for the group instance designated
 * by groupnumber as passed to tox_group_self_set_name.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_group_self_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error);

/**
 * Write the nickname set by tox_group_self_set_name to a byte array.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function has no effect.
 *
 * Call tox_group_self_get_name_size to find out how much memory to allocate for the result.
 *
 * @param name A valid memory location large enough to hold the nickname.
 *   If this parameter is NULL, the function has no effect.
 *
 * @returns true on success.
 */
bool tox_group_self_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *name, TOX_ERR_GROUP_SELF_QUERY *error);

/**
 * Error codes for self status setting.
 */
typedef enum TOX_ERR_GROUP_SELF_STATUS_SET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND,

    /**
     * An invalid type was passed to the set function.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_INVALID,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND,

} TOX_ERR_GROUP_SELF_STATUS_SET;


/**
 * Set the client's status for the group instance. Status must be a TOX_USER_STATUS.
 *
 * @return true on success.
 */
bool tox_group_self_set_status(Tox *tox, uint32_t groupnumber, TOX_USER_STATUS status,
                               TOX_ERR_GROUP_SELF_STATUS_SET *error);

/**
 * returns the client's status for the group instance on success.
 * return value is unspecified on failure.
 */
TOX_USER_STATUS tox_group_self_get_status(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error);

/**
 * returns the client's role for the group instance on success.
 * return value is unspecified on failure.
 */
TOX_GROUP_ROLE tox_group_self_get_role(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error);

/**
 * returns the client's peer id for the group instance on success.
 * return value is unspecified on failure.
 */
uint32_t tox_group_self_get_peer_id(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_SELF_QUERY *error);

/**
 * Write the client's group public key designated by the given group number to a byte array.
 *
 * This key will be parmanently tied to the client's identity for this particular group until
 * the client explicitly leaves the group or gets kicked/banned. This key is the only way for
 * other peers to reliably identify the client across client restarts.
 *
 * `public_key` should have room for at least TOX_GROUP_PEER_PUBLIC_KEY_SIZE bytes.
 *
 * @param public_key A valid memory region large enough to store the public key.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_self_get_public_key(const Tox *tox, uint32_t groupnumber, uint8_t *public_key,
                                   TOX_ERR_GROUP_SELF_QUERY *error);


/*******************************************************************************
 *
 * :: Peer-specific group state queries.
 *
 ******************************************************************************/



/**
 * Error codes for peer info queries.
 */
typedef enum TOX_ERR_GROUP_PEER_QUERY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_PEER_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND,

} TOX_ERR_GROUP_PEER_QUERY;


/**
 * Return the length of the peer's name. If the group number or ID is invalid, the
 * return value is unspecified.
 *
 * The return value is equal to the `length` argument received by the last
 * `group_peer_name` callback.
 */
size_t tox_group_peer_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                    TOX_ERR_GROUP_PEER_QUERY *error);

/**
 * Write the name of the peer designated by the given ID to a byte
 * array.
 *
 * Call tox_group_peer_get_name_size to determine the allocation size for the `name` parameter.
 *
 * The data written to `name` is equal to the data received by the last
 * `group_peer_name` callback.
 *
 * @param groupnumber The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose name we want to retrieve.
 * @param name A valid memory region large enough to store the friend's name.
 *
 * @return true on success.
 */
bool tox_group_peer_get_name(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *name,
                             TOX_ERR_GROUP_PEER_QUERY *error);

/**
 * Return the peer's user status (away/busy/...). If the ID or group number is
 * invalid, the return value is unspecified.
 *
 * The status returned is equal to the last status received through the
 * `group_peer_status` callback.
 */
TOX_USER_STATUS tox_group_peer_get_status(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
        TOX_ERR_GROUP_PEER_QUERY *error);

/**
 * Return the peer's role (user/moderator/founder...). If the ID or group number is
 * invalid, the return value is unspecified.
 *
 * The role returned is equal to the last role received through the
 * `group_moderation` callback.
 */
TOX_GROUP_ROLE tox_group_peer_get_role(const Tox *tox, uint32_t groupnumber, uint32_t peer_id,
                                       TOX_ERR_GROUP_PEER_QUERY *error);

/**
 * Write the group public key with the designated peer_id for the designated group number to public_key.
 *
 * This key will be parmanently tied to a particular peer until they explicitly leave the group or
 * get kicked/banned, and is the only way to reliably identify the same peer across client restarts.
 *
 * `public_key` should have room for at least TOX_GROUP_PEER_PUBLIC_KEY_SIZE bytes.
 *
 * @param public_key A valid memory region large enough to store the public key.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_peer_get_public_key(const Tox *tox, uint32_t groupnumber, uint32_t peer_id, uint8_t *public_key,
                                   TOX_ERR_GROUP_PEER_QUERY *error);

/**
 * @param groupnumber The group number of the group the name change is intended for.
 * @param peer_id The ID of the peer who has changed their name.
 * @param name The name data.
 * @param length The length of the name.
 */
typedef void tox_group_peer_name_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *name,
                                    size_t length, void *user_data);


/**
 * Set the callback for the `group_peer_name` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes their nickname.
 */
void tox_callback_group_peer_name(Tox *tox, tox_group_peer_name_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group the status change is intended for.
 * @param peer_id The ID of the peer who has changed their status.
 * @param status The new status of the peer.
 */
typedef void tox_group_peer_status_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_USER_STATUS status,
                                      void *user_data);


/**
 * Set the callback for the `group_peer_status` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes their status.
 */
void tox_callback_group_peer_status(Tox *tox, tox_group_peer_status_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Group chat state queries and events.
 *
 ******************************************************************************/



/**
 * General error codes for group state get and size functions.
 */
typedef enum TOX_ERR_GROUP_STATE_QUERIES {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_STATE_QUERIES_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_STATE_QUERIES_GROUP_NOT_FOUND,

} TOX_ERR_GROUP_STATE_QUERIES;


/**
 * Error codes for group topic setting.
 */
typedef enum TOX_ERR_GROUP_TOPIC_SET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_TOPIC_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND,

    /**
     * Topic length exceeded TOX_GROUP_MAX_TOPIC_LENGTH.
     */
    TOX_ERR_GROUP_TOPIC_SET_TOO_LONG,

    /**
     * The caller does not have the required permissions to set the topic.
     */
    TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS,

    /**
     * The packet could not be created. This error is usually related to cryptographic signing.
     */
    TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND,

} TOX_ERR_GROUP_TOPIC_SET;


/**
 * Set the group topic and broadcast it to the rest of the group.
 *
 * topic length cannot be longer than TOX_GROUP_MAX_TOPIC_LENGTH. If length is equal to zero or
 * topic is set to NULL, the topic will be unset.
 *
 * @returns true on success.
 */
bool tox_group_set_topic(Tox *tox, uint32_t groupnumber, const uint8_t *topic, size_t length,
                         TOX_ERR_GROUP_TOPIC_SET *error);

/**
 * Return the length of the group topic. If the group number is invalid, the
 * return value is unspecified.
 *
 * The return value is equal to the `length` argument received by the last
 * `group_topic` callback.
 */
size_t tox_group_get_topic_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * Write the topic designated by the given group number to a byte array.
 *
 * Call tox_group_get_topic_size to determine the allocation size for the `topic` parameter.
 *
 * The data written to `topic` is equal to the data received by the last
 * `group_topic` callback.
 *
 * @param topic A valid memory region large enough to store the topic.
 *   If this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_topic(const Tox *tox, uint32_t groupnumber, uint8_t *topic, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * @param groupnumber The group number of the group the topic change is intended for.
 * @param peer_id The ID of the peer who changed the topic.
 * @param topic The topic data.
 * @param length The topic length.
 */
typedef void tox_group_topic_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic, size_t length,
                                void *user_data);


/**
 * Set the callback for the `group_topic` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes the group topic.
 */
void tox_callback_group_topic(Tox *tox, tox_group_topic_cb *callback, void *user_data);

/**
 * Return the length of the group name. If the group number is invalid, the
 * return value is unspecified.
 */
size_t tox_group_get_name_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * Write the name of the group designated by the given group number to a byte array.
 *
 * Call tox_group_get_name_size to determine the allocation size for the `name` parameter.
 *
 * @param name A valid memory region large enough to store the group name.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_name(const Tox *tox, uint32_t groupnumber, uint8_t *name, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * Write the Chat ID designated by the given group number to a byte array.
 *
 * `chat_id` should have room for at least TOX_GROUP_CHAT_ID_SIZE bytes.
 *
 * @param chat_id A valid memory region large enough to store the Chat ID.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_chat_id(const Tox *tox, uint32_t groupnumber, uint8_t *chat_id, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * Return the number of groups in the Tox chats array.
 */
uint32_t tox_group_get_number_groups(const Tox *tox);

/**
 * Return the privacy state of the group designated by the given group number. If group number
 * is invalid, the return value is unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_privacy_state` callback.
 *
 * @see the `Group chat founder controls` section for the respective set function.
 */
TOX_GROUP_PRIVACY_STATE tox_group_get_privacy_state(const Tox *tox, uint32_t groupnumber,
        TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * @param groupnumber The group number of the group the topic change is intended for.
 * @param privacy_state The new privacy state.
 */
typedef void tox_group_privacy_state_cb(Tox *tox, uint32_t groupnumber, TOX_GROUP_PRIVACY_STATE privacy_state,
                                        void *user_data);


/**
 * Set the callback for the `group_privacy_state` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the privacy state.
 */
void tox_callback_group_privacy_state(Tox *tox, tox_group_privacy_state_cb *callback, void *user_data);

/**
 * Return the maximum number of peers allowed for the group designated by the given group number.
 * If the group number is invalid, the return value is unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_peer_limit` callback.
 *
 * @see the `Group chat founder controls` section for the respective set function.
 */
uint32_t tox_group_get_peer_limit(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * @param groupnumber The group number of the group for which the peer limit has changed.
 * @param peer_limit The new peer limit for the group.
 */
typedef void tox_group_peer_limit_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_limit, void *user_data);


/**
 * Set the callback for the `group_peer_limit` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the maximum peer limit.
 */
void tox_callback_group_peer_limit(Tox *tox, tox_group_peer_limit_cb *callback, void *user_data);

/**
 * Return the length of the group password. If the group number is invalid, the
 * return value is unspecified.
 */
size_t tox_group_get_password_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * Write the password for the group designated by the given group number to a byte array.
 *
 * Call tox_group_get_password_size to determine the allocation size for the `password` parameter.
 *
 * The data received is equal to the data received by the last
 * `group_password` callback.
 *
 * @see the `Group chat founder controls` section for the respective set function.
 *
 * @param password A valid memory region large enough to store the group password.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_password(const Tox *tox, uint32_t groupnumber, uint8_t *password,
                            TOX_ERR_GROUP_STATE_QUERIES *error);

/**
 * @param groupnumber The group number of the group for which the password has changed.
 * @param password The new group password.
 * @param length The length of the password.
 */
typedef void tox_group_password_cb(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                   void *user_data);


/**
 * Set the callback for the `group_password` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the group password.
 */
void tox_callback_group_password(Tox *tox, tox_group_password_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Group chat message sending
 *
 ******************************************************************************/



typedef enum TOX_ERR_GROUP_SEND_MESSAGE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG,

    /**
     * The message pointer is null or length is zero.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_EMPTY,

    /**
     * The message type is invalid.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE,

    /**
     * The caller does not have the required permissions to send group messages.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND,

} TOX_ERR_GROUP_SEND_MESSAGE;


/**
 * Send a text chat message to the group.
 *
 * This function creates a group message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_MAX_MESSAGE_LENGTH. Larger messages
 * must be split by the client and sent as separate messages. Other clients can
 * then reassemble the fragments. Messages may not be empty.
 *
 * @param groupnumber The group number of the group the message is intended for.
 * @param type Message type (normal, action, ...).
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 *
 * @return true on success.
 */
bool tox_group_send_message(Tox *tox, uint32_t groupnumber, TOX_MESSAGE_TYPE type, const uint8_t *message,
                            size_t length, TOX_ERR_GROUP_SEND_MESSAGE *error);

typedef enum TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND,

    /**
     * Message length exceeded TOX_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG,

    /**
     * The message pointer is null or length is zero.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY,

    /**
     * The caller does not have the required permissions to send group messages.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND,

} TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE;


/**
 * Send a text chat message to the specified peer in the specified group.
 *
 * This function creates a group private message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_MAX_MESSAGE_LENGTH. Larger messages
 * must be split by the client and sent as separate messages. Other clients can
 * then reassemble the fragments. Messages may not be empty.
 *
 * @param groupnumber The group number of the group the message is intended for.
 * @param peer_id The ID of the peer the message is intended for.
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 *
 * @return true on success.
 */
bool tox_group_send_private_message(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *message,
                                    size_t length, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE *error);

typedef enum TOX_ERR_GROUP_SEND_CUSTOM_PACKET {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG,

    /**
     * The message pointer is null or length is zero.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY,

    /**
     * The caller does not have the required permissions to send group messages.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_PERMISSIONS,

} TOX_ERR_GROUP_SEND_CUSTOM_PACKET;


/**
 * Send a custom packet to the group.
 *
 * If lossless is true the packet will be lossless. Lossless packet behaviour is comparable
 * to TCP (reliability, arrive in order) but with packets instead of a stream.
 *
 * If lossless is false, the packet will be lossy. Lossy packets behave like UDP packets,
 * meaning they might never reach the other side or might arrive more than once (if someone
 * is messing with the connection) or might arrive in the wrong order.
 *
 * Unless latency is an issue or message reliability is not important, it is recommended that you use
 * lossless custom packets.
 *
 * @param groupnumber The group number of the group the message is intended for.
 * @param lossless True if the packet should be lossless.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_group_send_custom_packet(Tox *tox, uint32_t groupnumber, bool lossless, const uint8_t *data, size_t length,
                                  TOX_ERR_GROUP_SEND_CUSTOM_PACKET *error);


/*******************************************************************************
 *
 * :: Group chat message receiving
 *
 ******************************************************************************/



/**
 * @param groupnumber The group number of the group the message is intended for.
 * @param peer_id The ID of the peer who sent the message.
 * @param type The type of message (normal, action, ...).
 * @param message The message data.
 * @param length The length of the message.
 */
typedef void tox_group_message_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data);


/**
 * Set the callback for the `group_message` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a group message.
 */
void tox_callback_group_message(Tox *tox, tox_group_message_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group the private message is intended for.
 * @param peer_id The ID of the peer who sent the private message.
 * @param message The message data.
 * @param length The length of the message.
 */
typedef void tox_group_private_message_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *message,
        size_t length, void *user_data);


/**
 * Set the callback for the `group_private_message` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a private message.
 */
void tox_callback_group_private_message(Tox *tox, tox_group_private_message_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group the custom packet is intended for.
 * @param peer_id The ID of the peer who sent the custom packet.
 * @param data The custom packet data.
 * @param length The length of the data.
 */
typedef void tox_group_custom_packet_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *data,
                                        size_t length, void *user_data);


/**
 * Set the callback for the `group_custom_packet` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a custom packet.
 */
void tox_callback_group_custom_packet(Tox *tox, tox_group_custom_packet_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Group chat inviting and join/part events
 *
 ******************************************************************************/



typedef enum TOX_ERR_GROUP_INVITE_FRIEND {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND,

    /**
     * The friend number passed did not designate a valid friend.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND,

    /**
     * Creation of the invite packet failed. This indicates a network related error.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND,

} TOX_ERR_GROUP_INVITE_FRIEND;


/**
 * Invite a friend to a group.
 *
 * This function creates an invite request packet and pushes it to the send queue.
 *
 * @param groupnumber The group number of the group the message is intended for.
 * @param friend_number The friend number of the friend the invite is intended for.
 *
 * @return true on success.
 */
bool tox_group_invite_friend(Tox *tox, uint32_t groupnumber, uint32_t friend_number,
                             TOX_ERR_GROUP_INVITE_FRIEND *error);

typedef enum TOX_ERR_GROUP_INVITE_ACCEPT {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_OK,

    /**
     * The invite data is not in the expected format.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED,

    /**
     * Password length exceeded TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG,

} TOX_ERR_GROUP_INVITE_ACCEPT;


/**
 * Accept an invite to a group chat that the client previously received from a friend. The invite
 * is only valid while the inviter is present in the group.
 *
 * @param invite_data The invite data received from the `group_invite` event.
 * @param length The length of the invite data.
 * @param password The password required to join the group. Set to NULL if no password is required.
 * @param password_length The length of the password. If password_length is equal to zero, the password
 *    parameter will be ignored. password_length must be no larger than TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return the groupnumber on success, UINT32_MAX on failure.
 */
uint32_t tox_group_invite_accept(Tox *tox, const uint8_t *invite_data, size_t length, const uint8_t *password,
                                 size_t password_length, TOX_ERR_GROUP_INVITE_ACCEPT *error);

/**
 * @param friend_number The friend number of the contact who sent the invite.
 * @param invite_data The invite data.
 * @param length The length of invite_data.
 */
typedef void tox_group_invite_cb(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 void *user_data);


/**
 * Set the callback for the `group_invite` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a group invite from a friend. The client must store
 * invite_data which is used to join the group via tox_group_invite_accept.
 */
void tox_callback_group_invite(Tox *tox, tox_group_invite_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group in which a new peer has joined.
 * @param peer_id The permanent ID of the new peer. This id should not be relied on for
 * client behaviour and should be treated as a random value.
 */
typedef void tox_group_peer_join_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data);


/**
 * Set the callback for the `group_peer_join` event. Pass NULL to unset.
 *
 * This event is triggered when a peer other than self joins the group.
 */
void tox_callback_group_peer_join(Tox *tox, tox_group_peer_join_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group in which a peer has left.
 * @param peer_id The ID of the peer who left the group.
 * @param part_message The parting message data.
 * @param length The length of the parting message.
 */
typedef void tox_group_peer_exit_cb(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *part_message,
                                    size_t length, void *user_data);


/**
 * Set the callback for the `group_peer_exit` event. Pass NULL to unset.
 *
 * This event is triggered when a peer other than self exits the group.
 */
void tox_callback_group_peer_exit(Tox *tox, tox_group_peer_exit_cb *callback, void *user_data);

/**
 * @param groupnumber The group number of the group that the client has joined.
 */
typedef void tox_group_self_join_cb(Tox *tox, uint32_t groupnumber, void *user_data);


/**
 * Set the callback for the `group_self_join` event. Pass NULL to unset.
 *
 * This event is triggered when the client has successfully joined a group. Use this to initialize
 * any group information the client may need.
 */
void tox_callback_group_self_join(Tox *tox, tox_group_self_join_cb *callback, void *user_data);

/**
 * Represents types of failed group join attempts. These are used in the tox_callback_group_rejected
 * callback when a peer fails to join a group.
 */
typedef enum TOX_GROUP_JOIN_FAIL {

    /**
     * You are using the same nickname as someone who is already in the group.
     */
    TOX_GROUP_JOIN_FAIL_NAME_TAKEN,

    /**
     * The group peer limit has been reached.
     */
    TOX_GROUP_JOIN_FAIL_PEER_LIMIT,

    /**
     * You have supplied an invalid password.
     */
    TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD,

    /**
     * The join attempt failed due to an unspecified error. This often occurs when the group is
     * not found in the DHT.
     */
    TOX_GROUP_JOIN_FAIL_UNKNOWN,

} TOX_GROUP_JOIN_FAIL;


/**
 * @param groupnumber The group number of the group for which the join has failed.
 * @param fail_type The type of group rejection.
 */
typedef void tox_group_join_fail_cb(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data);


/**
 * Set the callback for the `group_join_fail` event. Pass NULL to unset.
 *
 * This event is triggered when the client fails to join a group.
 */
void tox_callback_group_join_fail(Tox *tox, tox_group_join_fail_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Group chat founder controls (these only work for the group founder)
 *
 ******************************************************************************/



typedef enum TOX_ERR_GROUP_FOUNDER_SET_PASSWORD {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the password.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_PERMISSIONS,

    /**
     * Password length exceeded TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_TOO_LONG,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_FAIL_SEND,

} TOX_ERR_GROUP_FOUNDER_SET_PASSWORD;


/**
 * Set or unset the group password.
 *
 * This function sets the groups password, creates a new group shared state including the change,
 * and distributes it to the rest of the group.
 *
 * @param groupnumber The group number of the group for which we wish to set the password.
 * @param password The password we want to set. Set password to NULL to unset the password.
 * @param length The length of the password. length must be no longer than TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return true on success.
 */
bool tox_group_founder_set_password(Tox *tox, uint32_t groupnumber, const uint8_t *password, size_t length,
                                    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD *error);

typedef enum TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_GROUP_NOT_FOUND,

    /**
     * TOX_GROUP_PRIVACY_STATE is an invalid type.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_INVALID,

    /**
     * The caller does not have the required permissions to set the privacy state.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_PERMISSIONS,

    /**
     * The privacy state could not be set. This may occur due to an error related to
     * cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_FAIL_SEND,

} TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE;


/**
 * Set the group privacy state.
 *
 * This function sets the group's privacy state, creates a new group shared state
 * including the change, and distributes it to the rest of the group.
 *
 * If an attempt is made to set the privacy state to the same state that the group is already
 * in, the function call will be successful and no action will be taken.
 *
 * @param groupnumber The group number of the group for which we wish to change the privacy state.
 * @param privacy_state The privacy state we wish to set the group to.
 *
 * @return true on success.
 */
bool tox_group_founder_set_privacy_state(Tox *tox, uint32_t groupnumber, TOX_GROUP_PRIVACY_STATE privacy_state,
        TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE *error);

typedef enum TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the peer limit.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_PERMISSIONS,

    /**
     * The peer limit could not be set. This may occur due to an error related to
     * cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_FAIL_SEND,

} TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT;


/**
 * Set the group peer limit.
 *
 * This function sets a limit for the number of peers who may be in the group, creates a new
 * group shared state including the change, and distributes it to the rest of the group.
 *
 * @param groupnumber The group number of the group for which we wish to set the peer limit.
 * @param max_peers The maximum number of peers to allow in the group.
 *
 * @return true on success.
 */
bool tox_group_founder_set_peer_limit(Tox *tox, uint32_t groupnumber, uint32_t max_peers,
                                      TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT *error);


/*******************************************************************************
 *
 * :: Group chat moderation
 *
 ******************************************************************************/



typedef enum TOX_ERR_GROUP_TOGGLE_IGNORE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_TOGGLE_IGNORE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_TOGGLE_IGNORE_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_TOGGLE_IGNORE_PEER_NOT_FOUND,

} TOX_ERR_GROUP_TOGGLE_IGNORE;


/**
 * Ignore or unignore a peer.
 *
 * @param groupnumber The group number of the group the in which you wish to ignore a peer.
 * @param peer_id The ID of the peer who shall be ignored or unignored.
 * @ignore True to ignore the peer, false to unignore the peer.
 *
 * @return true on success.
 */
bool tox_group_toggle_ignore(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool ignore,
                             TOX_ERR_GROUP_TOGGLE_IGNORE *error);

typedef enum TOX_ERR_GROUP_MOD_SET_ROLE {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer. Note: you cannot set your own role.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_PEER_NOT_FOUND,

    /**
     * The caller does not have the required permissions for this action.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_PERMISSIONS,

    /**
     * The role assignment is invalid. This will occur if you try to set a peer's role to
     * the role they already have.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_ASSIGNMENT,

    /**
     * The role was not successfully set. This may occur if something goes wrong with role setting,
     * or if the packet fails to send.
     */
    TOX_ERR_GROUP_MOD_SET_ROLE_FAIL_ACTION,

} TOX_ERR_GROUP_MOD_SET_ROLE;


/**
 * Set a peer's role.
 *
 * This function will first remove the peer's previous role and then assign them a new role.
 * It will also send a packet to the rest of the group, requesting that they perform
 * the role reassignment. Note: peers cannot be set to the founder role.
 *
 * @param groupnumber The group number of the group the in which you wish set the peer's role.
 * @param peer_id The ID of the peer whose role you wish to set.
 * @param role The role you wish to set the peer to.
 *
 * @return true on success.
 */
bool tox_group_mod_set_role(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_GROUP_ROLE role,
                            TOX_ERR_GROUP_MOD_SET_ROLE *error);

typedef enum TOX_ERR_GROUP_MOD_REMOVE_PEER {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_PEER_NOT_FOUND,

    /**
     * The caller does not have the required permissions for this action.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_PERMISSIONS,

    /**
     * The peer could not be removed from the group.
     *
     * If a ban was set, this error indicates that the ban entry could not be created.
     * This is usually due to the peer's IP address already occurring in the ban list. It may also
     * be due to the entry containing invalid peer information, or a failure to cryptographically
     * authenticate the entry.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_ACTION,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_MOD_REMOVE_PEER_FAIL_SEND,

} TOX_ERR_GROUP_MOD_REMOVE_PEER;


/**
 * Kick/ban a peer.
 *
 * This function will remove a peer from the caller's peer list and optionally add their IP address
 * to the ban list. It will also send a packet to all group members requesting them
 * to do the same.
 *
 * @param groupnumber The group number of the group the ban is intended for.
 * @param peer_id The ID of the peer who will be kicked and/or added to the ban list.
 * @param set_ban Set to true if a ban shall be set on the peer's IP address.
 *
 * @return true on success.
 */
bool tox_group_mod_remove_peer(Tox *tox, uint32_t groupnumber, uint32_t peer_id, bool set_ban,
                               TOX_ERR_GROUP_MOD_REMOVE_PEER *error);

typedef enum TOX_ERR_GROUP_MOD_REMOVE_BAN {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_MOD_REMOVE_BAN_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_MOD_REMOVE_BAN_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions for this action.
     */
    TOX_ERR_GROUP_MOD_REMOVE_BAN_PERMISSIONS,

    /**
     * The ban entry could not be removed. This may occur if ban_id does not designate
     * a valid ban entry.
     */
    TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_ACTION,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_MOD_REMOVE_BAN_FAIL_SEND,

} TOX_ERR_GROUP_MOD_REMOVE_BAN;


/**
 * Removes a ban.
 *
 * This function removes a ban entry from the ban list, and sends a packet to the rest of
 * the group requesting that they do the same.
 *
 * @param groupnumber The group number of the group in which the ban is to be removed.
 * @param ban_id The ID of the ban entry that shall be removed.
 *
 * @return true on success
 */
bool tox_group_mod_remove_ban(Tox *tox, uint32_t groupnumber, uint32_t ban_id, TOX_ERR_GROUP_MOD_REMOVE_BAN *error);

/**
 * Represents moderation events. These should be used with the `group_moderation` event.
 */
typedef enum TOX_GROUP_MOD_EVENT {

    /**
     * A peer has been kicked from the group.
     */
    TOX_GROUP_MOD_EVENT_KICK,

    /**
     * A peer has been banned from the group.
     */
    TOX_GROUP_MOD_EVENT_BAN,

    /**
     * A peer as been given the observer role.
     */
    TOX_GROUP_MOD_EVENT_OBSERVER,

    /**
     * A peer has been given the user role.
     */
    TOX_GROUP_MOD_EVENT_USER,

    /**
     * A peer has been given the moderator role.
     */
    TOX_GROUP_MOD_EVENT_MODERATOR,

} TOX_GROUP_MOD_EVENT;


/**
 * @param groupnumber The group number of the group the event is intended for.
 * @param source_peer_number The ID of the peer who initiated the event.
 * @param target_peer_number The ID of the peer who is the target of the event.
 * @param mod_type The type of event.
 */
typedef void tox_group_moderation_cb(Tox *tox, uint32_t groupnumber, uint32_t source_peer_number,
                                     uint32_t target_peer_number, TOX_GROUP_MOD_EVENT mod_type, void *user_data);


/**
 * Set the callback for the `group_moderation` event. Pass NULL to unset.
 *
 * This event is triggered when a moderator or founder executes a moderation event.
 */
void tox_callback_group_moderation(Tox *tox, tox_group_moderation_cb *callback, void *user_data);


/*******************************************************************************
 *
 * :: Group chat ban list queries
 *
 ******************************************************************************/



/**
 * Error codes for group ban list queries.
 */
typedef enum TOX_ERR_GROUP_BAN_QUERY {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_BAN_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_BAN_QUERY_GROUP_NOT_FOUND,

    /**
     * The ban_id does not designate a valid ban list entry.
     */
    TOX_ERR_GROUP_BAN_QUERY_BAD_ID,

} TOX_ERR_GROUP_BAN_QUERY;


/**
 * Return the number of entries in the ban list for the group designated by
 * the given group number. If the group number is invalid, the return value is unspecified.
 */
size_t tox_group_ban_get_list_size(const Tox *tox, uint32_t groupnumber, TOX_ERR_GROUP_BAN_QUERY *error);

/**
 * Copy a list of valid ban list ID's into an array.
 *
 * Call tox_group_ban_get_list_size to determine the number of elements to allocate.
 *
 * @param list A memory region with enough space to hold the ban list. If
 *   this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_group_ban_get_list(const Tox *tox, uint32_t groupnumber, uint32_t *list, TOX_ERR_GROUP_BAN_QUERY *error);

/**
 * Return the length of the name for the ban list entry designated by ban_id, in the
 * group designated by the given group number. If either groupnumber or ban_id is invalid,
 * the return value is unspecified.
 */
size_t tox_group_ban_get_name_size(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                   TOX_ERR_GROUP_BAN_QUERY *error);

/**
 * Write the name of the ban entry designated by ban_id in the group designated by the
 * given group number to a byte array.
 *
 * Call tox_group_ban_get_name_size to find out how much memory to allocate for the result.
 *
 * @return true on success.
 */
bool tox_group_ban_get_name(const Tox *tox, uint32_t groupnumber, uint32_t ban_id, uint8_t *name,
                            TOX_ERR_GROUP_BAN_QUERY *error);

/**
 * Return a time stamp indicating the time the ban was set, for the ban list entry
 * designated by ban_id, in the group designated by the given group number.
 * If either groupnumber or ban_id is invalid, the return value is unspecified.
 */
uint64_t tox_group_ban_get_time_set(const Tox *tox, uint32_t groupnumber, uint32_t ban_id,
                                    TOX_ERR_GROUP_BAN_QUERY *error);


#ifdef __cplusplus
}
#endif

#endif /* DHT_GROUPCHATS */
#endif /* TOX_H */
