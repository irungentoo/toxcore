%{
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
%}


/*****************************************************************************
 * `tox.h` SHOULD *NOT* BE EDITED MANUALLY – any changes should be made to   *
 * `tox.in.h`, located in `other/apidsl/`. For instructions on how to        *
 * generate `tox.h` from `tox.in.h` please refer to `other/apidsl/README.md` *
 *****************************************************************************/


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
 * running a simple ${tox.iterate} loop, sleeping for ${tox.iteration_interval}
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
 * size_t length = ${tox.self.name.size}(tox);
 * uint8_t *name = malloc(length);
 * if (!name) abort();
 * ${tox.self.name.get}(tox, name);
 * \endcode
 *
 * If any other thread calls ${tox.self.name.set} while this thread is allocating
 * memory, the length may have become invalid, and the call to
 * ${tox.self.name.get} may cause undefined behaviour.
 */

// The rest of this file is in class tox.
class tox {

/**
 * The Tox instance type. All the state associated with a connection is held
 * within the instance. Multiple instances can exist and operate concurrently.
 * The maximum number of Tox instances that can exist on a single network
 * device is limited. Note that this is not just a per-process limit, since the
 * limiting factor is the number of usable ports on a device.
 */
struct this;


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

static namespace version {

  /**
   * Return the major version number of the library. Can be used to display the
   * Tox library version or to check whether the client is compatible with the
   * dynamically linked version of Tox.
   */
  uint32_t major();

  /**
   * Return the minor version number of the library.
   */
  uint32_t minor();

  /**
   * Return the patch number of the library.
   */
  uint32_t patch();

  /**
   * Return whether the compiled library version is compatible with the passed
   * version numbers.
   */
  bool is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

}

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
const PUBLIC_KEY_SIZE              = 32;

/**
 * The size of a Tox Secret Key in bytes.
 */
const SECRET_KEY_SIZE              = 32;

/**
 * The size of a Tox address in bytes. Tox addresses are in the format
 * [Public Key ($PUBLIC_KEY_SIZE bytes)][nospam (4 bytes)][checksum (2 bytes)].
 *
 * The checksum is computed over the Public Key and the nospam value. The first
 * byte is an XOR of all the even bytes (0, 2, 4, ...), the second byte is an
 * XOR of all the odd bytes (1, 3, 5, ...) of the Public Key and nospam.
 */
const ADDRESS_SIZE                = PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t);

/**
 * Maximum length of a nickname in bytes.
 */
const MAX_NAME_LENGTH             = 128;

/**
 * Maximum length of a status message in bytes.
 */
const MAX_STATUS_MESSAGE_LENGTH   = 1007;

/**
 * Maximum length of a friend request message in bytes.
 */
const MAX_FRIEND_REQUEST_LENGTH   = 1016;

/**
 * Maximum length of a single message after which it should be split.
 */
const MAX_MESSAGE_LENGTH          = 1372;

/**
 * Maximum size of custom packets. TODO: should be LENGTH?
 */
const MAX_CUSTOM_PACKET_SIZE      = 1373;

/**
 * The number of bytes in a hash generated by $hash.
 */
const HASH_LENGTH                 = 32;

/**
 * The number of bytes in a file id.
 */
const FILE_ID_LENGTH              = 32;

/**
 * Maximum file name length for file transfers.
 */
const MAX_FILENAME_LENGTH         = 255;


/*******************************************************************************
 *
 * :: Global enumerations
 *
 ******************************************************************************/


/**
 * Represents the possible statuses a client can have.
 */
enum class USER_STATUS {
  /**
   * User is online and available.
   */
  NONE,
  /**
   * User is away. Clients can set this e.g. after a user defined
   * inactivity time.
   */
  AWAY,
  /**
   * User is busy. Signals to other clients that this client does not
   * currently wish to communicate.
   */
  BUSY,
}


/**
 * Represents message types for ${tox.friend.send.message} and group chat
 * messages.
 */
enum class MESSAGE_TYPE {
  /**
   * Normal text message. Similar to PRIVMSG on IRC.
   */
  NORMAL,
  /**
   * A message describing an user action. This is similar to /me (CTCP ACTION)
   * on IRC.
   */
  ACTION,
}


/*******************************************************************************
 *
 * :: Startup options
 *
 ******************************************************************************/


/**
 * Type of proxy used to connect to TCP relays.
 */
enum class PROXY_TYPE {
  /**
   * Don't use a proxy.
   */
  NONE,
  /**
   * HTTP proxy using CONNECT.
   */
  HTTP,
  /**
   * SOCKS proxy for simple socket pipes.
   */
  SOCKS5,
}

/**
 * Type of savedata to create the Tox instance from.
 */
enum class SAVEDATA_TYPE {
  /**
   * No savedata.
   */
  NONE,
  /**
   * Savedata is one that was obtained from ${savedata.get}
   */
  TOX_SAVE,
  /**
   * Savedata is a secret key of length ${SECRET_KEY_SIZE}
   */
  SECRET_KEY,
}


static class options {
  /**
   * This struct contains all the startup options for Tox. You can either allocate
   * this object yourself, and pass it to $default, or call
   * $new to get a new default options object.
   */
  struct this {
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

    namespace proxy {
      /**
       * Pass communications through a proxy.
       */
      PROXY_TYPE type;

      /**
       * The IP address or DNS name of the proxy to be used.
       *
       * If used, this must be non-NULL and be a valid DNS name. The name must not
       * exceed 255 characters, and be in a NUL-terminated C string format
       * (255 chars + 1 NUL byte).
       *
       * This member is ignored (it can be NULL) if proxy_type is TOX_PROXY_TYPE_NONE.
       */
      string host;

      /**
       * The port to use to connect to the proxy server.
       *
       * Ports must be in the range (1, 65535). The value is ignored if
       * proxy_type is TOX_PROXY_TYPE_NONE.
       */
      uint16_t port;
    }

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

    namespace savedata {
      /**
       * The type of savedata to load from.
       */
      SAVEDATA_TYPE type;

      /**
       * The savedata.
       */
      const uint8_t[length] data;

      /**
       * The length of the savedata.
       */
      size_t length;
    }
  }


  /**
   * Initialises a $this object with the default options.
   *
   * The result of this function is independent of the original options. All
   * values will be overwritten, no values will be read (so it is permissible
   * to pass an uninitialised object).
   *
   * If options is NULL, this function has no effect.
   *
   * @param options An options object to be filled with default options.
   */
  void default();


  /**
   * Allocates a new $this object and initialises it with the default
   * options. This function can be used to preserve long term ABI compatibility by
   * giving the responsibility of allocation and deallocation to the Tox library.
   *
   * Objects returned from this function must be freed using the $free
   * function.
   *
   * @return A new $this object with default options or NULL on failure.
   */
  static this new() {
    /**
     * The function failed to allocate enough memory for the options struct.
     */
    MALLOC,
  }


  /**
   * Releases all resources associated with an options objects.
   *
   * Passing a pointer that was not returned by $new results in
   * undefined behaviour.
   */
  void free();
}


/*******************************************************************************
 *
 * :: Creation and destruction
 *
 ******************************************************************************/


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
 * @see $iterate for the event loop.
 *
 * @return A new Tox instance pointer on success or NULL on failure.
 */
static this new(const options_t *options) {
  NULL,
  /**
   * The function was unable to allocate enough memory to store the internal
   * structures for the Tox object.
   */
  MALLOC,
  /**
   * The function was unable to bind to a port. This may mean that all ports
   * have already been bound, e.g. by other Tox instances, or it may mean
   * a permission error. You may be able to gather more information from errno.
   */
  PORT_ALLOC,

  namespace PROXY {
    /**
     * proxy_type was invalid.
     */
    BAD_TYPE,
    /**
     * proxy_type was valid but the proxy_host passed had an invalid format
     * or was NULL.
     */
    BAD_HOST,
    /**
     * proxy_type was valid, but the proxy_port was invalid.
     */
    BAD_PORT,
    /**
     * The proxy address passed could not be resolved.
     */
    NOT_FOUND,
  }

  namespace LOAD {
    /**
     * The byte array to be loaded contained an encrypted save.
     */
    ENCRYPTED,
    /**
     * The data format was invalid. This can happen when loading data that was
     * saved by an older version of Tox, or when the data has been corrupted.
     * When loading from badly formatted data, some data may have been loaded,
     * and the rest is discarded. Passing an invalid length parameter also
     * causes this error.
     */
    BAD_FORMAT,
  }
}


/**
 * Releases all resources associated with the Tox instance and disconnects from
 * the network.
 *
 * After calling this function, the Tox pointer becomes invalid. No other
 * functions can be called, and the pointer value can no longer be read.
 */
void kill();


uint8_t[size] savedata {
  /**
   * Calculates the number of bytes required to store the tox instance with
   * $get. This function cannot fail. The result is always greater than 0.
   *
   * @see threading for concurrency implications.
   */
  size();

  /**
   * Store all information associated with the tox instance to a byte array.
   *
   * @param data A memory region large enough to store the tox instance data.
   *   Call $size to find the number of bytes required. If this parameter
   *   is NULL, this function has no effect.
   */
  get();
}


/*******************************************************************************
 *
 * :: Connection lifecycle and event loop
 *
 ******************************************************************************/


/**
 * Sends a "get nodes" request to the given bootstrap node with IP, port, and
 * public key to setup connections.
 *
 * This function will attempt to connect to the node using UDP. You must use
 * this function even if ${options.this.udp_enabled} was set to false.
 *
 * @param address The hostname or IP address (IPv4 or IPv6) of the node.
 * @param port The port on the host on which the bootstrap Tox instance is
 *   listening.
 * @param public_key The long term public key of the bootstrap node
 *   ($PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool bootstrap(string address, uint16_t port, const uint8_t[PUBLIC_KEY_SIZE] public_key) {
  NULL,
  /**
   * The address could not be resolved to an IP address, or the IP address
   * passed was invalid.
   */
  BAD_HOST,
  /**
   * The port passed was invalid. The valid port range is (1, 65535).
   */
  BAD_PORT,
}


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
 *   ($PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool add_tcp_relay(string address, uint16_t port, const uint8_t[PUBLIC_KEY_SIZE] public_key)
    with error for bootstrap;


/**
 * Protocols that can be used to connect to the network or friends.
 */
enum class CONNECTION {
  /**
   * There is no connection. This instance, or the friend the state change is
   * about, is now offline.
   */
  NONE,
  /**
   * A TCP connection has been established. For the own instance, this means it
   * is connected through a TCP relay, only. For a friend, this means that the
   * connection to that particular friend goes through a TCP relay.
   */
  TCP,
  /**
   * A UDP connection has been established. For the own instance, this means it
   * is able to send UDP packets to DHT nodes, but may still be connected to
   * a TCP relay. For a friend, this means that the connection to that
   * particular friend was built using direct UDP packets.
   */
  UDP,
}


inline namespace self {

  CONNECTION connection_status {
    /**
     * Return whether we are connected to the DHT. The return value is equal to the
     * last value received through the `${event connection_status}` callback.
     */
    get();
  }


  /**
   * This event is triggered whenever there is a change in the DHT connection
   * state. When disconnected, a client may choose to call $bootstrap again, to
   * reconnect to the DHT. Note that this state may frequently change for short
   * amounts of time. Clients should therefore not immediately bootstrap on
   * receiving a disconnect.
   *
   * TODO: how long should a client wait before bootstrapping again?
   */
  event connection_status {
    /**
     * @param connection_status Whether we are connected to the DHT.
     */
    typedef void(CONNECTION connection_status);
  }

}


/**
 * Return the time in milliseconds before $iterate() should be called again
 * for optimal performance.
 */
const uint32_t iteration_interval();


/**
 * The main loop that needs to be run in intervals of $iteration_interval()
 * milliseconds.
 */
void iterate();


/*******************************************************************************
 *
 * :: Internal client information (Tox address/id)
 *
 ******************************************************************************/


inline namespace self {

  uint8_t[ADDRESS_SIZE] address {
    /**
     * Writes the Tox friend address of the client to a byte array. The address is
     * not in human-readable format. If a client wants to display the address,
     * formatting is required.
     *
     * @param address A memory region of at least $ADDRESS_SIZE bytes. If this
     *   parameter is NULL, this function has no effect.
     * @see $ADDRESS_SIZE for the address format.
     */
    get();
  }


  uint32_t nospam {
    /**
     * Set the 4-byte nospam part of the address.
     *
     * @param nospam Any 32 bit unsigned integer.
     */
    set();

    /**
     * Get the 4-byte nospam part of the address.
     */
    get();
  }


  uint8_t[PUBLIC_KEY_SIZE] public_key {
    /**
     * Copy the Tox Public Key (long term) from the Tox object.
     *
     * @param public_key A memory region of at least $PUBLIC_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     */
    get();
  }


  uint8_t[SECRET_KEY_SIZE] secret_key {
    /**
     * Copy the Tox Secret Key from the Tox object.
     *
     * @param secret_key A memory region of at least $SECRET_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     */
    get();
  }

}


/*******************************************************************************
 *
 * :: User-visible client information (nickname/status)
 *
 ******************************************************************************/


/**
 * Common error codes for all functions that set a piece of user-visible
 * client information.
 */
error for set_info {
  NULL,
  /**
   * Information length exceeded maximum permissible size.
   */
  TOO_LONG,
}


inline namespace self {

  uint8_t[length <= MAX_NAME_LENGTH] name {
    /**
     * Set the nickname for the Tox client.
     *
     * Nickname length cannot exceed $MAX_NAME_LENGTH. If length is 0, the name
     * parameter is ignored (it can be NULL), and the nickname is set back to empty.
     *
     * @param name A byte array containing the new nickname.
     * @param length The size of the name byte array.
     *
     * @return true on success.
     */
    set() with error for set_info;

    /**
     * Return the length of the current nickname as passed to $set.
     *
     * If no nickname was set before calling this function, the name is empty,
     * and this function returns 0.
     *
     * @see threading for concurrency implications.
     */
    size();

    /**
     * Write the nickname set by $set to a byte array.
     *
     * If no nickname was set before calling this function, the name is empty,
     * and this function has no effect.
     *
     * Call $size to find out how much memory to allocate for
     * the result.
     *
     * @param name A valid memory location large enough to hold the nickname.
     *   If this parameter is NULL, the function has no effect.
     */
    get();

  }


  uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] status_message {
    /**
     * Set the client's status message.
     *
     * Status message length cannot exceed $MAX_STATUS_MESSAGE_LENGTH. If
     * length is 0, the status parameter is ignored (it can be NULL), and the
     * user status is set back to empty.
     */
    set() with error for set_info;

    /**
     * Return the length of the current status message as passed to $set.
     *
     * If no status message was set before calling this function, the status
     * is empty, and this function returns 0.
     *
     * @see threading for concurrency implications.
     */
    size();

    /**
     * Write the status message set by $set to a byte array.
     *
     * If no status message was set before calling this function, the status is
     * empty, and this function has no effect.
     *
     * Call $size to find out how much memory to allocate for
     * the result.
     *
     * @param status A valid memory location large enough to hold the status message.
     *   If this parameter is NULL, the function has no effect.
     */
    get();
  }


  USER_STATUS status {
    /**
     * Set the client's user status.
     *
     * @param user_status One of the user statuses listed in the enumeration above.
     */
    set();

    /**
     * Returns the client's user status.
     */
    get();
  }

}


/*******************************************************************************
 *
 * :: Friend list management
 *
 ******************************************************************************/


namespace friend {

  /**
   * Add a friend to the friend list and send a friend request.
   *
   * A friend request message must be at least 1 byte long and at most
   * $MAX_FRIEND_REQUEST_LENGTH.
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
   * @param address The address of the friend (returned by ${self.address.get} of
   *   the friend you wish to add) it must be $ADDRESS_SIZE bytes.
   * @param message The message that will be sent along with the friend request.
   * @param length The length of the data byte array.
   *
   * @return the friend number on success, UINT32_MAX on failure.
   */
  uint32_t add(
      const uint8_t[ADDRESS_SIZE] address,
      const uint8_t[length <= MAX_FRIEND_REQUEST_LENGTH] message
  ) {
    NULL,
    /**
     * The length of the friend request message exceeded
     * $MAX_FRIEND_REQUEST_LENGTH.
     */
    TOO_LONG,
    /**
     * The friend request message was empty. This, and the TOO_LONG code will
     * never be returned from $add_norequest.
     */
    NO_MESSAGE,
    /**
     * The friend address belongs to the sending client.
     */
    OWN_KEY,
    /**
     * A friend request has already been sent, or the address belongs to a friend
     * that is already on the friend list.
     */
    ALREADY_SENT,
    /**
     * The friend address checksum failed.
     */
    BAD_CHECKSUM,
    /**
     * The friend was already there, but the nospam value was different.
     */
    SET_NEW_NOSPAM,
    /**
     * A memory allocation failed when trying to increase the friend list size.
     */
    MALLOC,
  }


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
   * @param public_key A byte array of length $PUBLIC_KEY_SIZE containing the
   *   Public Key (not the Address) of the friend to add.
   *
   * @return the friend number on success, UINT32_MAX on failure.
   * @see $add for a more detailed description of friend numbers.
   */
  uint32_t add_norequest(const uint8_t[PUBLIC_KEY_SIZE] public_key)
      with error for add;


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
  bool delete(uint32_t friend_number) {
    /**
     * There was no friend with the given friend number. No friends were deleted.
     */
    FRIEND_NOT_FOUND,
  }

}


/*******************************************************************************
 *
 * :: Friend list queries
 *
 ******************************************************************************/

namespace friend {

  /**
   * Return the friend number associated with that Public Key.
   *
   * @return the friend number on success, UINT32_MAX on failure.
   * @param public_key A byte array containing the Public Key.
   */
  const uint32_t by_public_key(const uint8_t[PUBLIC_KEY_SIZE] public_key) {
    NULL,
    /**
     * No friend with the given Public Key exists on the friend list.
     */
    NOT_FOUND,
  }


  /**
   * Checks if a friend with the given friend number exists and returns true if
   * it does.
   */
  const bool exists(uint32_t friend_number);


}

inline namespace self {

  uint32_t[size] friend_list {
    /**
     * Return the number of friends on the friend list.
     *
     * This function can be used to determine how much memory to allocate for
     * $get.
     */
    size();


    /**
     * Copy a list of valid friend numbers into an array.
     *
     * Call $size to determine the number of elements to allocate.
     *
     * @param list A memory region with enough space to hold the friend list. If
     *   this parameter is NULL, this function has no effect.
     */
    get();
  }

}



namespace friend {

  uint8_t[PUBLIC_KEY_SIZE] public_key {
    /**
     * Copies the Public Key associated with a given friend number to a byte array.
     *
     * @param friend_number The friend number you want the Public Key of.
     * @param public_key A memory region of at least $PUBLIC_KEY_SIZE bytes. If
     *   this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t friend_number) {
      /**
       * No friend with the given number exists on the friend list.
       */
      FRIEND_NOT_FOUND,
    }
  }

}

namespace friend {

  uint64_t last_online {
    /**
    * Return a unix-time timestamp of the last time the friend associated with a given
    * friend number was seen online. This function will return UINT64_MAX on error.
    *
    * @param friend_number The friend number you want to query.
    */
    get(uint32_t friend_number) {
      /**
       * No friend with the given number exists on the friend list.
       */
      FRIEND_NOT_FOUND,
    }
  }

}

/*******************************************************************************
 *
 * :: Friend-specific state queries (can also be received through callbacks)
 *
 ******************************************************************************/


namespace friend {

  /**
   * Common error codes for friend state query functions.
   */
  error for query {
    /**
     * The pointer parameter for storing the query result (name, message) was
     * NULL. Unlike the `_self_` variants of these functions, which have no effect
     * when a parameter is NULL, these functions return an error in that case.
     */
    NULL,
    /**
     * The friend_number did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
  }


  uint8_t[length <= MAX_NAME_LENGTH] name {
    /**
     * Return the length of the friend's name. If the friend number is invalid, the
     * return value is unspecified.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event name}` callback.
     */
    size(uint32_t friend_number)
        with error for query;

    /**
     * Write the name of the friend designated by the given friend number to a byte
     * array.
     *
     * Call $size to determine the allocation size for the `name`
     * parameter.
     *
     * The data written to `name` is equal to the data received by the last
     * `${event name}` callback.
     *
     * @param name A valid memory region large enough to store the friend's name.
     *
     * @return true on success.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their name.
   */
  event name {
    /**
     * @param friend_number The friend number of the friend whose name changed.
     * @param name A byte array containing the same data as
     *   ${name.get} would write to its `name` parameter.
     * @param length A value equal to the return value of
     *   ${name.size}.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_NAME_LENGTH] name);
  }


  uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] status_message {
    /**
     * Return the length of the friend's status message. If the friend number is
     * invalid, the return value is SIZE_MAX.
     */
    size(uint32_t friend_number)
        with error for query;

    /**
     * Write the name of the friend designated by the given friend number to a byte
     * array.
     *
     * Call $size to determine the allocation size for the `status_name`
     * parameter.
     *
     * The data written to `status_message` is equal to the data received by the last
     * `${event status_message}` callback.
     *
     * @param name A valid memory region large enough to store the friend's name.
     */
    get(uint32_t friend_number)
        with error for query;

  }


  /**
   * This event is triggered when a friend changes their status message.
   */
  event status_message {
    /**
     * @param friend_number The friend number of the friend whose status message
     *   changed.
     * @param message A byte array containing the same data as
     *   ${status_message.get} would write to its `status_message` parameter.
     * @param length A value equal to the return value of
     *   ${status_message.size}.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_STATUS_MESSAGE_LENGTH] message);
  }


  USER_STATUS status {
    /**
     * Return the friend's user status (away/busy/...). If the friend number is
     * invalid, the return value is unspecified.
     *
     * The status returned is equal to the last status received through the
     * `${event status}` callback.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their user status.
   */
  event status {
    /**
     * @param friend_number The friend number of the friend whose user status
     *   changed.
     * @param status The new user status.
     */
    typedef void(uint32_t friend_number, USER_STATUS status);
  }


  CONNECTION connection_status {
    /**
     * Check whether a friend is currently connected to this client.
     *
     * The result of this function is equal to the last value received by the
     * `${event connection_status}` callback.
     *
     * @param friend_number The friend number for which to query the connection
     *   status.
     *
     * @return the friend's connection status as it was received through the
     *   `${event connection_status}` event.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend goes offline after having been online,
   * or when a friend goes online.
   *
   * This callback is not called when adding friends. It is assumed that when
   * adding friends, their connection status is initially offline.
   */
  event connection_status {
    /**
     * @param friend_number The friend number of the friend whose connection status
     *   changed.
     * @param connection_status The result of calling
     *   ${connection_status.get} on the passed friend_number.
     */
    typedef void(uint32_t friend_number, CONNECTION connection_status);
  }


  bool typing {
    /**
     * Check whether a friend is currently typing a message.
     *
     * @param friend_number The friend number for which to query the typing status.
     *
     * @return true if the friend is typing.
     * @return false if the friend is not typing, or the friend number was
     *   invalid. Inspect the error code to determine which case it is.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend starts or stops typing.
   */
  event typing {
    /**
     * @param friend_number The friend number of the friend who started or stopped
     *   typing.
     * @param is_typing The result of calling ${typing.get} on the passed
     *   friend_number.
     */
    typedef void(uint32_t friend_number, bool is_typing);
  }

}


/*******************************************************************************
 *
 * :: Sending private messages
 *
 ******************************************************************************/


inline namespace self {

  bool typing {
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
    set(uint32_t friend_number) {
      /**
       * The friend number did not designate a valid friend.
       */
      FRIEND_NOT_FOUND,
    }
  }

}


namespace friend {

  namespace send {

    /**
     * Send a text chat message to an online friend.
     *
     * This function creates a chat message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * The return value of this function is the message ID. If a read receipt is
     * received, the triggered `${event read_receipt}` event will be passed this message ID.
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
    uint32_t message(uint32_t friend_number, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      NULL,
      /**
       * The friend number did not designate a valid friend.
       */
      FRIEND_NOT_FOUND,
      /**
       * This client is currently not connected to the friend.
       */
      FRIEND_NOT_CONNECTED,
      /**
       * An allocation error occurred while increasing the send queue size.
       */
      SENDQ,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * Attempted to send a zero-length message.
       */
      EMPTY,
    }

  }


  /**
   * This event is triggered when the friend receives the message sent with
   * ${send.message} with the corresponding message ID.
   */
  event read_receipt {
    /**
     * @param friend_number The friend number of the friend who received the message.
     * @param message_id The message ID as returned from ${send.message}
     *   corresponding to the message sent.
     */
    typedef void(uint32_t friend_number, uint32_t message_id);
  }

}


/*******************************************************************************
 *
 * :: Receiving private messages and friend requests
 *
 ******************************************************************************/


namespace friend {

  /**
   * This event is triggered when a friend request is received.
   */
  event request {
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
    typedef void(const uint8_t[PUBLIC_KEY_SIZE] public_key
        //, uint32_t time_delta
        , const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }


  /**
   * This event is triggered when a message from a friend is received.
   */
  event message {
    /**
     * @param friend_number The friend number of the friend who sent the message.
     * @param time_delta Time between composition and sending.
     * @param message The message data they sent.
     * @param length The size of the message byte array.
     *
     * @see ${event request} for more information on time_delta.
     */
    typedef void(uint32_t friend_number
        //, uint32_t time_delta
        , MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

}


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
static bool hash(uint8_t[HASH_LENGTH] hash, const uint8_t[length] data);


namespace file {

  enum KIND {
    /**
     * Arbitrary file data. Clients can choose to handle it based on the file name
     * or magic or any other way they choose.
     */
    DATA,
    /**
     * Avatar file_id. This consists of $hash(image).
     * Avatar data. This consists of the image data.
     *
     * Avatars can be sent at any time the client wishes. Generally, a client will
     * send the avatar to a friend when that friend comes online, and to all
     * friends when the avatar changed. A client can save some traffic by
     * remembering which friend received the updated avatar already and only send
     * it if the friend has an out of date avatar.
     *
     * Clients who receive avatar send requests can reject it (by sending
     * ${CONTROL.CANCEL} before any other controls), or accept it (by
     * sending ${CONTROL.RESUME}). The file_id of length $HASH_LENGTH bytes
     * (same length as $FILE_ID_LENGTH) will contain the hash. A client can compare
     * this hash with a saved hash and send ${CONTROL.CANCEL} to terminate the avatar
     * transfer if it matches.
     *
     * When file_size is set to 0 in the transfer request it means that the client
     * has no avatar.
     */
    AVATAR,
  }


  enum class CONTROL {
    /**
     * Sent by the receiving side to accept a file send request. Also sent after a
     * $PAUSE command to continue sending or receiving.
     */
    RESUME,
    /**
     * Sent by clients to pause the file transfer. The initial state of a file
     * transfer is always paused on the receiving side and running on the sending
     * side. If both the sending and receiving side pause the transfer, then both
     * need to send $RESUME for the transfer to resume.
     */
    PAUSE,
    /**
     * Sent by the receiving side to reject a file send request before any other
     * commands are sent. Also sent by either side to terminate a file transfer.
     */
    CANCEL,
  }


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
  bool control(uint32_t friend_number, uint32_t file_number, CONTROL control) {
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * A RESUME control was sent, but the file transfer is running normally.
     */
    NOT_PAUSED,
    /**
     * A RESUME control was sent, but the file transfer was paused by the other
     * party. Only the party that paused the transfer can resume it.
     */
    DENIED,
    /**
     * A PAUSE control was sent, but the file transfer was already paused.
     */
    ALREADY_PAUSED,
    /**
     * Packet queue is full.
     */
    SENDQ,
  }


  /**
   * This event is triggered when a file control command is received from a
   * friend.
   */
  event recv_control {
    /**
     * When receiving ${CONTROL.CANCEL}, the client should release the
     * resources associated with the file number and consider the transfer failed.
     *
     * @param friend_number The friend number of the friend who is sending the file.
     * @param file_number The friend-specific file number the data received is
     *   associated with.
     * @param control The file control command received.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, CONTROL control);
  }

  /**
   * Sends a file seek control command to a friend for a given file transfer.
   *
   * This function can only be called to resume a file transfer right before
   * ${CONTROL.RESUME} is sent.
   *
   * @param friend_number The friend number of the friend the file is being
   *   received from.
   * @param file_number The friend-specific identifier for the file transfer.
   * @param position The position that the file should be seeked to.
   */
  bool seek(uint32_t friend_number, uint32_t file_number, uint64_t position) {
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * File was not in a state where it could be seeked.
     */
    DENIED,
    /**
     * Seek position was invalid
     */
    INVALID_POSITION,
    /**
     * Packet queue is full.
     */
    SENDQ,
  }


  error for get {
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
  }

  /**
   * Copy the file id associated to the file transfer to a byte array.
   *
   * @param friend_number The friend number of the friend the file is being
   *   transferred to or received from.
   * @param file_number The friend-specific identifier for the file transfer.
   * @param file_id A memory region of at least $FILE_ID_LENGTH bytes. If
   *   this parameter is NULL, this function has no effect.
   *
   * @return true on success.
   */
  const bool get_file_id(uint32_t friend_number, uint32_t file_number, uint8_t[FILE_ID_LENGTH] file_id)
      with error for get;

}


/*******************************************************************************
 *
 * :: File transmission: sending
 *
 ******************************************************************************/


namespace file {

  /**
   * Send a file transmission request.
   *
   * Maximum filename length is $MAX_FILENAME_LENGTH bytes. The filename
   * should generally just be a file name, not a path with directory names.
   *
   * If a non-UINT64_MAX file size is provided, it can be used by both sides to
   * determine the sending progress. File size can be set to UINT64_MAX for streaming
   * data of unknown size.
   *
   * File transmission occurs in chunks, which are requested through the
   * `${event chunk_request}` event.
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
   *     ${event chunk_request} callback will receive length = 0 when Core thinks
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
   * @param file_id A file identifier of length $FILE_ID_LENGTH that can be used to
   *   uniquely identify file transfers across core restarts. If NULL, a random one will
   *   be generated by core. It can then be obtained by using $get_file_id().
   * @param filename Name of the file. Does not need to be the actual name. This
   *   name will be sent along with the file send request.
   * @param filename_length Size in bytes of the filename.
   *
   * @return A file number used as an identifier in subsequent callbacks. This
   *   number is per friend. File numbers are reused after a transfer terminates.
   *   On failure, this function returns UINT32_MAX. Any pattern in file numbers
   *   should not be relied on.
   */
  uint32_t send(uint32_t friend_number, uint32_t kind, uint64_t file_size, const uint8_t[FILE_ID_LENGTH] file_id, const uint8_t[filename_length <= MAX_FILENAME_LENGTH] filename) {
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * Filename length exceeded $MAX_FILENAME_LENGTH bytes.
     */
    NAME_TOO_LONG,
    /**
     * Too many ongoing transfers. The maximum number of concurrent file transfers
     * is 256 per friend per direction (sending and receiving).
     */
    TOO_MANY,
  }


  /**
   * Send a chunk of file data to a friend.
   *
   * This function is called in response to the `${event chunk_request}` callback. The
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
  bool send_chunk(uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t[length] data) {
    /**
     * The length parameter was non-zero, but data was NULL.
     */
    NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * This client is currently not connected to the friend.
     */
    FRIEND_NOT_CONNECTED,
    /**
     * No file transfer with the given file number was found for the given friend.
     */
    NOT_FOUND,
    /**
     * File transfer was found but isn't in a transferring state: (paused, done,
     * broken, etc...) (happens only when not called from the request chunk callback).
     */
    NOT_TRANSFERRING,
    /**
     * Attempted to send more or less data than requested. The requested data size is
     * adjusted according to maximum transmission unit and the expected end of
     * the file. Trying to send less or more than requested will return this error.
     */
    INVALID_LENGTH,
    /**
     * Packet queue is full.
     */
    SENDQ,
    /**
     * Position parameter was wrong.
     */
    WRONG_POSITION,
  }


  /**
   * This event is triggered when Core is ready to send more file data.
   */
  event chunk_request {
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
     * `$send_chunk` with the requested chunk. If the number of bytes sent
     * through that function is zero, the file transfer is assumed complete. A
     * client must send the full length of data requested with this callback.
     *
     * @param friend_number The friend number of the receiving friend for this file.
     * @param file_number The file transfer identifier returned by $send.
     * @param position The file or stream position from which to continue reading.
     * @param length The number of bytes requested for the current chunk.
     */
    typedef void(uint32_t friend_number, uint32_t file_number, uint64_t position, size_t length);
  }

}


/*******************************************************************************
 *
 * :: File transmission: receiving
 *
 ******************************************************************************/


namespace file {

  /**
   * This event is triggered when a file transfer request is received.
   */
  event recv {
    /**
     * The client should acquire resources to be associated with the file transfer.
     * Incoming file transfers start in the PAUSED state. After this callback
     * returns, a transfer can be rejected by sending a ${CONTROL.CANCEL}
     * control command before any other control commands. It can be accepted by
     * sending ${CONTROL.RESUME}.
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
    typedef void(uint32_t friend_number, uint32_t file_number, uint32_t kind,
        uint64_t file_size, const uint8_t[filename_length <= MAX_FILENAME_LENGTH] filename);
  }


  /**
   * This event is first triggered when a file transfer request is received, and
   * subsequently when a chunk of file data for an accepted request was received.
   */
  event recv_chunk {
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
    typedef void(uint32_t friend_number, uint32_t file_number, uint64_t position,
        const uint8_t[length] data);
  }

}


/*******************************************************************************
 *
 * :: Low-level custom packet sending and receiving
 *
 ******************************************************************************/


namespace friend {

  inline namespace send {

    error for custom_packet {
      NULL,
      /**
       * The friend number did not designate a valid friend.
       */
      FRIEND_NOT_FOUND,
      /**
       * This client is currently not connected to the friend.
       */
      FRIEND_NOT_CONNECTED,
      /**
       * The first byte of data was not in the specified range for the packet type.
       * This range is 200-254 for lossy, and 160-191 for lossless packets.
       */
      INVALID,
      /**
       * Attempted to send an empty packet.
       */
      EMPTY,
      /**
       * Packet data length exceeded $MAX_CUSTOM_PACKET_SIZE.
       */
      TOO_LONG,
      /**
       * Packet queue is full.
       */
      SENDQ,
    }

    /**
     * Send a custom lossy packet to a friend.
     *
     * The first byte of data must be in the range 200-254. Maximum length of a
     * custom packet is $MAX_CUSTOM_PACKET_SIZE.
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
    bool lossy_packet(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data)
        with error for custom_packet;


    /**
     * Send a custom lossless packet to a friend.
     *
     * The first byte of data must be in the range 160-191. Maximum length of a
     * custom packet is $MAX_CUSTOM_PACKET_SIZE.
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
    bool lossless_packet(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data)
        with error for custom_packet;

  }


  event lossy_packet {
    /**
     * @param friend_number The friend number of the friend who sent a lossy packet.
     * @param data A byte array containing the received packet data.
     * @param length The length of the packet data byte array.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data);
  }


  event lossless_packet {
    /**
     * @param friend_number The friend number of the friend who sent the packet.
     * @param data A byte array containing the received packet data.
     * @param length The length of the packet data byte array.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data);
  }

}



/*******************************************************************************
 *
 * :: Low-level network information
 *
 ******************************************************************************/


inline namespace self {

  uint8_t[PUBLIC_KEY_SIZE] dht_id {
    /**
     * Writes the temporary DHT public key of this instance to a byte array.
     *
     * This can be used in combination with an externally accessible IP address and
     * the bound port (from ${udp_port.get}) to run a temporary bootstrap node.
     *
     * Be aware that every time a new instance is created, the DHT public key
     * changes, meaning this cannot be used to run a permanent bootstrap node.
     *
     * @param dht_id A memory region of at least $PUBLIC_KEY_SIZE bytes. If this
     *   parameter is NULL, this function has no effect.
     */
    get();
  }


  error for get_port {
    /**
     * The instance was not bound to any port.
     */
    NOT_BOUND,
  }


  uint16_t udp_port {
    /**
     * Return the UDP port this Tox instance is bound to.
     */
    get() with error for get_port;
  }


  uint16_t tcp_port {
    /**
     * Return the TCP port this Tox instance is bound to. This is only relevant if
     * the instance is acting as a TCP relay.
     */
    get() with error for get_port;
  }

}

/*******************************************************************************
 *
 * :: Group chat numeric constants
 *
 ****************************************************************************/

namespace group {
  /**
   * Maximum length of a group topic.
   */
  const MAX_TOPIC_LENGTH          = 512;

  /**
   * Maximum length of a peer part message.
   */
  const MAX_PART_LENGTH           = 128;

  /**
   * Maximum length of a group name.
   */
  const MAX_GROUP_NAME_LENGTH     = 48;

  /**
   * Maximum length of a group password.
   */
  const MAX_PASSWD_SIZE           = 32;

  /**
   * Number of bytes in a group Chat ID.
   */
  const CHAT_ID_SIZE              = 32;
}

/*******************************************************************************
 *
 * :: Group chat state enumerators
 *
 ****************************************************************************/

namespace group {

  enum class PRIVACY_STATE {
    /**
     * The group is considered to be public. Anyone may join the group using the Chat ID.
     *
     * If the group is in this state, even if the Chat ID is never explicitly shared
     * with someone outside of the group, information including the Chat ID, IP addresses,
     * and peer ID's (but not Tox ID's) is visible to anyone with access to a node
     * storing a DHT entry for the given group.
     */
    PUBLIC,

    /**
     * The group is considered to be private. The only way to join the group is by having
     * someone in your contact list send you an invite.
     *
     * If the group is in this state, no group information (mentioned above) is present in the DHT;
     * the DHT is not used for any purpose at all. If a public group is set to private,
     * all DHT information related to the group will expire shortly.
     */
    PRIVATE,
  }

  /**
   * Represents group roles.
   *
   * Roles are are hierarchical in that each role has a set of privileges plus all the privileges
   * of the roles below it.
   */
  enum class ROLE {
    /**
     * May kick and ban all other peers as well as set their role to anything (except founder).
     * Founders may also set the group password, toggle the privacy state, and set the peer limit.
     */
    FOUNDER,

    /**
     * May kick, ban and set the user and observer roles for peers below this role.
     */
    MODERATOR,

    /**
     * May communicate with other peers and change the group topic.
     */
    USER,

    /**
     * May observe the group and ignore peers; may not communicate with other peers or with the group.
     */
    OBSERVER,
  }

}

/*******************************************************************************
 *
 * :: Group chat instance management
 *
 ******************************************************************************/


namespace group {

  /**
   * Creates a new group chat.
   *
   * This function creates a new group chat object adds it to the chats array.
   *
   * @param privacy_state The privacy state of the group. If this is set to TOX_GROUP_PRIVACY_STATE_PUBLIC,
   *   the group will attempt to announce itself to the DHT and anyone with the Chat ID may join.
   *   Otherwise a friend invite will be required to join the group.
   * @param group_name The name of the group. The name must be non-NULL.
   * @param length The length of the group name. This must be greater than zero and no larger than
   *   $MAX_GROUP_NAME_LENGTH.
   *
   * @return true on success.
   */
  bool new(PRIVACY_STATE privacy_state, const uint8_t[length <= MAX_GROUP_NAME_LENGTH] group_name) {
    /**
     * The group name exceeded $MAX_GROUP_NAME_LENGTH.
     */
    TOO_LONG,
    /**
     * group_name is NULL or length is zero.
     */
    EMPTY,
    /**
     * $PRIVACY_STATE is an invalid type.
     */
    PRIVACY,
    /**
     * The group instance failed to initialize.
     */
    INIT,
    /**
     * The group state failed to initialize. This usually indicates that something went wrong
     * related to cryptographic signing.
     */
    STATE,
    /**
     * The group failed to announce to the DHT. This indicates a network related error.
     */
    ANNOUNCE,
  }

  /**
   * Joins a group chat with specified Chat ID.
   *
   * This function creates a new group chat object, adds it to the chats array, and sends
   * a DHT announcement to find peers in the group associated with chat_id. Once a peer has been
   * found a join attempt will be initiated.
   *
   * @param chat_id The Chat ID of the group you wish to join. This must be $CHAT_ID_SIZE bytes.
   * @param password The password required to join the group. Set to NULL if no password is required.
   * @param password_length The length of the password. If length is equal to zero,
   *   the password parameter is ignored. password_length must be no larger than $MAX_PASSWD_SIZE.
   *
   * @return true on success.
   */
  bool join(const uint8_t[CHAT_ID_SIZE] chat_id, const uint8_t[password_length <= MAX_PASSWD_SIZE] password) {
    /**
     * The group instance failed to initialize.
     */
    INIT,
    /**
     * The chat_id pointer is set to NULL.
     */
    BAD_CHAT_ID,
    /**
     * Password length exceeded $MAX_PASSWD_SIZE.
     */
    TOO_LONG,
  }

  /**
   * Reconnects to a group.
   *
   * This function disconnects from all peers in the group, then attempts to reconnect with the group.
   * The caller's state is not changed (i.e. name, status, role, chat public key etc.)
   *
   * @param groupnumber The groupnumber of the group we wish to reconnect to.
   *
   * @return true on success.
   */
  bool reconnect(uint32_t groupnumber) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
  }

  /**
   * Leaves a group.
   *
   * This function sends a parting packet containing a custom (non-obligatory) message to all
   * peers in a group, and deletes the group from the chat array. All group state information is permanently
   * lost, including keys and role credentials.
   *
   * @param groupnumber The groupnumber of the group we wish to leave.
   * @param message The parting message to be sent to all the peers. Set to NULL if we do not wish to
   *   send a parting message.
   * @param length The length of the parting message. Set to 0 if we do not wish to send a parting message.
   *
   * @return true if the group chat instance is successfully deleted.
   */
  bool leave(uint32_t groupnumber, const uint8_t[length <= MAX_PART_LENGTH] message) {
    /**
     * The group number passed did not designate a valid group.
     */
    GROUP_NOT_FOUND,
    /**
     * Message length exceeded $MAX_PART_LENGTH.
     */
    TOO_LONG,
    /**
     * The parting packet failed to send.
     */
    SEND_FAIL,
    /**
     * The group chat instance failed to be deleted. This may occur due to memory related errors.
     */
    DELETE_FAIL,
  }

}

/*******************************************************************************
 *
 * :: Group user-visible client information (nickname/status/role)
 *
 ******************************************************************************/

namespace group {

  inline namespace self {

    /**
     * Error codes for self name getting, setting and size functions.
     */
    error for self_name {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Name length exceeded $MAX_NAME_LENGTH.
       */
      TOO_LONG,
      /**
       * The length given to the set function is zero or name is a NULL pointer.
       */
      INVALID,
      /**
       * The name is already taken by another peer in the group.
       */
      TAKEN,
      /**
       * The packet failed to send.
       */
      SEND_FAIL,
    }

    uint8_t[length <= MAX_NAME_LENGTH] name {

      /**
       * Set the client's nickname for the group instance designated by the given group number.
       *
       * Nickname length cannot exceed $MAX_NAME_LENGTH. If length is equal to zero or name is a NULL
       * pointer, the function call will fail.
       *
       * @param name A byte array containing the new nickname.
       * @param length The size of the name byte array.
       *
       * @return true on success.
       */
      set(uint32_t groupnumber) with error for self_name;

      /**
       * Return the length of the client's current nickname for the group instance designated
       * by groupnumber as passed to $set.
       *
       * If no nickname was set before calling this function, the name is empty,
       * and this function returns 0.
       *
       * @see threading for concurrency implications.
       */
      size(uint32_t groupnumber) with error for self_name;

      /**
       * Write the nickname set by $set to a byte array.
       *
       * If no nickname was set before calling this function, the name is empty,
       * and this function has no effect.
       *
       * Call $size to find out how much memory to allocate for the result.
       *
       * @param name A valid memory location large enough to hold the nickname.
       *   If this parameter is NULL, the function has no effect.
       *
       * @returns true on success.
       */
      get(uint32_t groupnumber) with error for self_name;
    }

    /**
     * Error codes for self status/role getting and setting.
     */
    error for self_info {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * An invalid type was passed to the set function.
       */
      INVALID,
      /**
       * The packet failed to send.
       */
      SEND_FAIL,
    }

    USER_STATUS status {

      /**
       * Set the client's status for the group instance. Status must be a $USER_STATUS.
       *
       * @return true on succcess.
       */
      set(uint32_t groupnumber) with error for self_info;

      /**
       * returns the client's status for the group instance on success.
       * return value is unspecified on failure.
       */
      get(uint32_t groupnumber) with error for self_info;
    }

    ROLE role {

      /**
       * Returns the client's role for the group instance on success.
       * return value is unspecified on failure.
       */
      get(uint32_t groupnumber) with error for self_info;
    }
  }

}

/*******************************************************************************
 *
 * :: Peer-specific group state queries (can also be received through callbacks)
 *
 ******************************************************************************/

namespace group {

  namespace peer {

    /**
     * Error codes for peer info queries.
     */
    error for query {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
    }

    uint8_t[length <= MAX_NAME_LENGTH] name {

      /**
       * Return the length of the peer's name. If the group number or peer number is invalid, the
       * return value is unspecified.
       *
       * The return value is equal to the `length` argument received by the last
       * `${event name}` callback.
       */
      size(uint32_t groupnumber, uint32_t peernumber) with error for query;

      /**
       * Write the name of the peer designated by the given peer number to a byte
       * array.
       *
       * Call $size to determine the allocation size for the `name` parameter.
       *
       * The data written to `name` is equal to the data received by the last
       * `${event name}` callback.
       *
       * @param groupnumber The group number of the group we wish to query.
       * @param peernumber The peer number of the peer whose name we want to retrieve.
       * @param name A valid memory region large enough to store the friend's name.
       *
       * @return true on success.
       */
      get(uint32_t groupnumber, uint32_t  peernumber) with error for query;
    }

    USER_STATUS status {

      /**
       * Return the peer's user status (away/busy/...). If the peer number or group number is
       * invalid, the return value is unspecified.
       *
       * The status returned is equal to the last status received through the
       * `${event status}` callback.
       */
      get(uint32_t groupnumber, uint32_t peernumber) with error for query;
    }

    ROLE role {
      /**
       * Return the peer's role (user/moderator/founder...). If the peer number or group number is
       * invalid, the return value is unspecified.
       *
       * The role returned is equal to the last role received through the
       * `${event moderation}` callback.
       */
      get(uint32_t groupnumber, uint32_t peernumber) with error for query;
    }

    /**
     * This event is triggered when a peer changes their nickname.
     */
    event name {
      /**
       * @param groupnumber The groupnumber of the group the name change is intended for.
       * @param peernumber The peernumber of the peer who has changed their name.
       * @param name The name data.
       * @param length The length of the name.
       */
      typedef void(uint32_t groupnumber, uint32_t peernumber, const uint8_t[length <= MAX_NAME_LENGTH] name);
    }

    /**
     * This event is triggered when a peer changes their status.
     */
    event status {
      /**
       * @param groupnumber The groupnumber of the group the status change is intended for.
       * @param peernumber The peernumber of the peer who has changed their status.
       * @param status The new status of the peer.
       */
      typedef void(uint32_t groupnumber, uint32_t peernumber, USER_STATUS status);
    }
  }

}


/******************************************************************************
 *
 * :: Group chat state queries.
 *
 ******************************************************************************/

namespace group {

  /**
   * Error codes for group topic setting/queries.
   */
  error for topic {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Topic length exceeded $MAX_TOPIC_LENGTH.
       */
      TOO_LONG,
      /**
       * The caller does not have the required permissions to set the topic.
       */
      PERMISSIONS,
      /**
       * The packet failed to send.
       */
      SEND_FAIL,
  }

  uint8_t[length <= MAX_TOPIC_LENGTH] topic {

    /**
     * Set the group topic and broadcast it to the rest of the group.
     *
     * topic length cannot be longer than $MAX_TOPIC_LENGTH. If length is equal to zero or
     * topic is set to NULL, the topic will be unset.
     *
     * @returns true on success.
     */
    set(uint32_t groupnumber) with error for topic;

    /**
     * Return the length of the group topic. If the group number is invalid, the
     * return value is unspecified.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event topic}` callback.
     */
    size(uint32_t groupnumber) with error for topic;

    /**
     * Write the topic designated by the given group number to a byte array.
     *
     * Call $size to determine the allocation size for the `topic` parameter.
     *
     * The data written to `topic` is equal to the data received by the last
     * `${event topic}` callback.
     *
     * @param topic A valid memory region large enough to store the topic.
     *   If this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t groupnumber) with error for topic;
  }

  /**
   * This event is triggered when a peer changes the group topic.
   */
  event topic {
    /**
     * @param groupnumber The groupnumber of the group the topic change is intended for.
     * @param peernumber The peernumber of the peer who changed the topic.
     * @param topic The topic data.
     * @param length The topic length.
     */
    typedef void(uint32_t groupnumber, uint32_t peernumber, const uint8_t[length <= MAX_TOPIC_LENGTH] topic);
  }


  /**
   * Error codes for group name queries.
   */
  error for name {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
  }

  uint8_t[length <= MAX_TOPIC_LENGTH] name {
    /**
     * Return the length of the group name. If the group number is invalid, the
     * return value is unspecified.
     */
    size(uint32_t groupnumber) with error for name;

    /**
     * Write the name of the group designated by the given group number to a byte array.
     *
     * Call $size to determine the allocation size for the `name` parameter.
     *
     * @param name A valid memory region large enough to store the group name.
     *   If this parameter is NULL, this function call has no effect.
     *
     * @return true on success.
     */
    get(uint32_t groupnumber) with error for name;
  }

  /**
   * Error codes for group Chat ID retrieval.
   */
  error for chat_id {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
  }

  uint8_t[length] chat_id {

    /**
     * Write the Chat ID designated by the given group number to a byte array.
     *
     * `chat_id` should have room for at least $CHAT_ID_SIZE bytes.
     *
     * @param chat_id A valid memory region large enough to store the Chat ID.
     *   If this parameter is NULL, this function call has no effect.
     *
     * @return true on success.
     */
    get(uint32_t groupnumber) with error for chat_id;
  }

  /**
   * Error codes for misc. group state queries.
   */
  error for state_info {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
  }

  uint32_t number_peers {

    /**
     * Return the number of peers in the group designated by the given group number. If group number
     * is invalid, the return value is unspecified.
     *
     * All values below the return value of this function are valid peer numbers, and all values
     * equal to or greater than the return value are invalid peer numbers.
     */
    get(uint32_t groupnumber) with error for state_info;
  }

  uint32_t number_groups {
    /**
     * Return the number of groups in the Tox chats array.
     */
     get();
  }

  PRIVACY_STATE privacy_state {

    /**
     * Return the privacy state of the group designated by the given group number. If group number
     * is invalid, the return value is unspecified.
     */
    get(uint32_t groupnumber) with error for state_info;
  }

  uint32_t peer_limit {

    /**
     * Return the maximum number of peers allowed for the group designated by the given group number.
     * If the group number is invalid, the return value is unspecified.
     */
    get(uint32_t groupnumber) with error for state_info;
  }

  /**
   * This callback is triggered when a peer joins or leaves the group, and should be used to
   * retrieve up to date information about the peer list for the client.
   */
  event peerlist_update {
    /**
     * @param groupnumber The groupnumber of the group that must have its peer list updated.
     */
    typedef void(uint32_t groupnumber);
  }

}

/******************************************************************************
 *
 * :: Group chat message sending
 *
 ******************************************************************************/

namespace group {

  namespace send {
    /**
     * Send a text chat message to the entire group.
     *
     * This function creates a group message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * @param groupnumber The groupnumber of the group the message is intended for.
     * @param type Message type (normal, action, ...).
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool message(uint32_t groupnumber, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * The message pointer is null or length is zero.
       */
      EMPTY,
      /**
       * The message type is invalid.
       */
      BAD_TYPE,
      /**
       * The caller does not have the required permissions to send group messages.
       */
      PERMISSIONS,
      /**
       * Packet failed to send.
       */
      SEND_FAIL,
    }

    /**
     * Send a text chat message to the specified peer in the specified group.
     *
     * This function creates a group private message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments. Messages may not be empty.
     *
     * @param groupnumber The groupnumber of the group the message is intended for.
     * @param peernumber The peernumber of the peer the message is intended for.
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool private_message(uint32_t groupnumber, uint32_t peernumber, const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * Message length exceeded $MAX_MESSAGE_LENGTH.
       */
      TOO_LONG,
      /**
       * The message pointer is null or length is zero.
       */
      EMPTY,
      /**
       * The caller does not have the required permissions to send group messages.
       */
      PERMISSIONS,
      /**
       * Packet failed to send.
       */
      SEND_FAIL,
    }
  }
}

/******************************************************************************
 *
 * :: Group chat message receiving
 *
 ******************************************************************************/

namespace group {

  /**
   * This event is triggered when you receive a group message.
   */
  event message {
    /**
     * @param groupnumber The groupnumber of the group the message is intended for.
     * @param peernumber The peernumber of the peer who sent the message.
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t groupnumber, uint32_t peernumber, MESSAGE_TYPE type, const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

  /**
   * This event is triggered when you receive a private message.
   */
  event private_message {
    /**
     * @param groupnumber The groupnumber of the group the private message is intended for.
     * @param peernumber The peernumber of the peer who sent the private message.
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t groupnumber, uint32_t peernumber, const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }

}

/******************************************************************************
 *
 * :: Group chat inviting and join/part events
 *
 ******************************************************************************/

namespace group {

  namespace invite {

    /**
     * Invite a friend to a group.
     *
     * This function creates an invite request packet and pushes it to the send queue.
     *
     * @param groupnumber The groupnumber of the group the message is intended for.
     * @param friendnumber The friendnumber of the friend the invite is intended for.
     *
     * @return true on success.
     */
    bool friend(uint32_t groupnumber, int32_t friendnumber) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The friend number passed did not designate a valid friend.
       */
      NOFRIEND,
      /**
       * Creation of the invite packet failed. This indicates a network related error.
       */
      INVITE_FAIL,
      /**
       * Packet failed to send.
       */
      SEND_FAIL,
    }

    /**
     * Accept an invite to a group chat that the client previously received from a friend. The invite
     * is only valid while the inviter is present in the group.
     *
     * @param invite_data The invite data received from the `${event invite}` event.
     * @param length The length of the invite data.
     * @param password The password required to join the group. Set to NULL if no password is required.
     * @param password_length The length of the password. If length is equal to zero, the password
     *    parameter will be ignored. password_length must be no larger than $MAX_PASSWD_SIZE.
     *
     * @return true on success
     */
    bool accept(const uint8_t[length] invite_data, const uint8_t[password_length <= MAX_PASSWD_SIZE] password) {
      /**
       * The invite data is not in the expected format.
       */
      BAD_INVITE,
      /**
       * The group instance failed to initialize.
       */
      INIT_FAILED,
      /**
       * Password length exceeded $MAX_PASSWD_SIZE.
       */
      TOO_LONG,
    }
  }

  /**
   * This event is triggered when you receive a group invite from a friend. The client must store
   * invite_data which is used to join the group via tox_group_invite_accept.
   */
  event invite {
    /**
     * @param friendnumber The friendnumber of the contact who invited you.
     * @param invite_data The invite data.
     * @param length The length of invite_data.
     */
    typedef void(int32_t friendnumber, const uint8_t[length] invite_data);
  }

  /**
   * This event is triggered when a peer joins the group. Do not use this to update the peer list; use
   * tox_callback_group_peerlist_update instead.
   */
  event peer_join {
    /**
     * @param groupnumber The groupnumber of the group in which a new peer has joined.
     * @param peernumber The peernumber of the new peer.
     */
    typedef void(uint32_t groupnumber, uint32_t peernumber);
  }

  /**
   * This event is triggered when a peer exits the group. Do not use this to update the peer list; use
   * tox_callback_group_peerlist_update instead.
   */
  event peer_exit {
    /**
     * @param groupnumber The groupnumber of the group in which a peer has left.
     * @param peernumber The peernumber of the peer who left the group.
     * @param part_message The parting message data.
     * @param length The length of the parting message.
     */
    typedef void(uint32_t groupnumber, uint32_t peernumber, const uint8_t[length <= MAX_PART_LENGTH] part_message);
  }

  /**
   * This event is triggered when the client has successfully joined a group. Use this to initialize
   * any group information the client may need.
   */
  event self_join {
    /**
     * @param groupnumber The groupnumber of the group that the client has joined.
     */
    typedef void(uint32_t groupnumber);
  }

  /**
   * Represents types of failed group join attempts. These are used in the tox_callback_group_rejected
   * callback when a peer fails to join a group.
   */
  enum class JOIN_FAIL {
    /**
     * You are using the same nickname as someone who is already in the group.
     */
    NAME_TAKEN,

    /**
     * The group peer limit has been reached.
     */
    PEER_LIMIT,

    /**
     * You have supplied an invalid password.
     */
    INVALID_PASSWORD,

    /**
     * The join attempt failed due to an unspecified error. This often occurs when the group is
     * not found in the DHT.
     */
    UNKNOWN,
  }

  /**
   * This event is triggered when the client fails to join a group.
   */
  event join_fail {
    /**
     * @param groupnumber The groupnumber of the group for which the join has failed.
     * @param type The type of group rejection.
     */
    typedef void(uint32_t groupnumber, JOIN_FAIL type);
  }
}


/*******************************************************************************
 *
 * :: Group chat founder controls (these only work for the group founder)
 *
 ******************************************************************************/

namespace group {

  namespace founder {

    /**
     * Set or unset the group password.
     *
     * This function sets the groups password, creates a new group shared state including the change,
     * and distributes it to the rest of the group.
     *
     * @param groupnumber The groupnumber of the group for which we wish to set the password.
     * @param password The password we want to set. Set password to NULL to unset the password.
     * @param length The length of the password. length must be no longer than $MAX_PASSWD_SIZE.
     *
     * @return true on success.
     */
    bool set_password(uint32_t groupnumber, const uint8_t[length <= MAX_PASSWD_SIZE] password) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The caller does not have the required permissions to set the password.
       */
      PERMISSIONS,
      /**
       * Password length exceeded $MAX_PASSWD_SIZE.
       */
      TOO_LONG,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }

    /**
     * Set the group privacy state.
     *
     * This function sets the group's privacy state, creates a new group shared state
     * including the change, and distributes it to the rest of the group.
     *
     * If an attempt is made to set the privacy state to the same state that the group is already
     * in, the function call will be successful and no action will be taken.
     *
     * @param groupnumber The groupnumber of the group for which we wish to change the privacy state.
     * @param privacy_state The privacy state we wish to set the group to.
     *
     * @return true on success.
     */
    bool set_privacy_state(uint32_t groupnumber, PRIVACY_STATE privacy_state) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * $PRIVACY_STATE is an invalid type.
       */
      INVALID,
      /**
       * The caller does not have the required permissions to set the privacy state.
       */
      PERMISSIONS,
      /**
       * The privacy state could not be set. This may occur due to an error related to
       * cryptographic signing of the new shared state.
       */
      FAIL_SET,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }

    /**
     * Set the group peer limit.
     *
     * This function sets a limit for the number of peers who may be in the group, creates a new
     * group shared state including the change, and distributes it to the rest of the group.
     *
     * @param groupnumber The groupnumber of the group for which we wish to set the peer limit.
     * @param max_peers The maximum number of peers to allow in the group.
     *
     * @return true on success.
     */
    bool set_peer_limit(uint32_t groupnumber, uint32_t max_peers) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The caller does not have the required permissions to set the privacy state.
       */
      PERMISSIONS,
      /**
       * The peer limit could not be set. This may occur due to an error related to
       * cryptographic signing of the new shared state.
       */
      FAIL_SET,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }
  }

}

/*******************************************************************************
 *
 * :: Group chat moderation
 *
 ******************************************************************************/

namespace group {

  /**
   * Ignore or unignore a peer.
   *
   * @param groupnumber The groupnumber of the group the in which you wish to ignore a peer.
   * @param peernumber The peernumber of the peer who shall be ignored or unignored.
   * @ignore True to ignore the peer, false to unignore the peer.
   *
   * @return true on success.
   */
  bool toggle_ignore(uint32_t groupnumber, uint32_t peernumber, bool ignore) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
  }

  namespace mod {

    /**
     * Set a peer's role.
     *
     * This function will first remove the peer's previous role and then assign them a new role.
     * It will also send a packet to the rest of the group, requesting that they perform
     * the role reassignment. Note: peers cannot be set to the founder role.
     *
     * @param groupnumber The groupnumber of the group the in which you wish set the peer's role.
     * @param peernumber The peernumber of the peer whose role you wish to set.
     * @param role The role you wish to set the peer to.
     *
     * @return true on success.
     */
    bool set_role(uint32_t groupnumber, uint32_t peernumber, ROLE role) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer. Note: you cannot set your own role.
       */
      PEER_NOT_FOUND,
      /**
       * The caller does not have the required permissions for this action.
       */
      PERMISSIONS,
      /**
       * The role assignment is invalid. This will occur if you try to set a peer's role to
       * the role they already have.
       */
      ASSIGNMENT,
      /**
       * The role was not successfully set. This may occur if something goes wrong with role setting,
       * or if the packet fails to send.
       */
      FAIL_ACTION,
    }

    /**
     * Kick/ban a peer.
     *
     * This function will remove a peer from the caller's peer list and optionally add their IP address
     * to the ban list. It will also send a packet to all group members requesting them
     * to do the same.
     *
     * @param groupnumber The groupnumber of the group the ban is intended for.
     * @param peernumber The peernumber of the peer who will be kicked and/or added to the ban list.
     * @param set_ban Set to true if a ban shall be set on the peer's IP address.
     *
     * @return true on success.
     */
    bool remove_peer(uint32_t groupnumber, uint32_t peernumber, bool set_ban) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * The caller does not have the required permissions for this action.
       */
      PERMISSIONS,
      /**
       * The peer failed to be removed from the group. If a ban was set, this error indicates
       * that the ban entry could not be created. This may either be due to the entry containing
       * invalid peer information, or a failure to cryptographically authenticate the entry.
       */
      FAIL_ACTION,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }

    /**
     * Removes a ban.
     *
     * This function removes a ban entry from the ban list, and sends a packet to the rest of
     * the group requesting that they do the same.
     *
     * @param groupnumber The groupnumber of the group in which the ban is to be removed.
     * @param ban_id The ID of the ban entry that shall be removed.
     *
     * @return true on success
     */
    bool remove_ban(uint32_t groupnumber, uint16_t ban_id) {
      /**
       * The group number passed did not designate a valid group.
       */
      GROUP_NOT_FOUND,
      /**
       * The caller does not have the required permissions for this action.
       */
      PERMISSIONS,
      /**
       * The ban entry could not be removed. This may occur if ban_id does not designate
       * a valid ban entry.
       */
      FAIL_ACTION,
      /**
       * The packet failed to send.
       */
      FAIL_SEND,
    }
  }

  /**
   * Represents moderation events. These should be used with the `${event moderation}` event.
   */
  enum class MOD_EVENT {
    /**
     * A peer has been kicked from the group.
     */
    KICK,

    /**
     * A peer has been banned from the group.
     */
    BAN,

    /**
     * A peer as been given the $OBSERVER role.
     */
    OBSERVER,

    /**
     * A peer has been given the $USER role.
     */
    USER,

    /**
     * A peer has been given the $MODERATOR role.
     */
    MODERATOR,
  }

  /**
   * This event is triggered when a moderator or founder executes a moderation event.
   */
  event moderation {
    /**
     * @param groupnumber The groupnumber of the group the event is intended for.
     * @param source_peernum The peernumber of the peer who initiated the event.
     * @param target_peernum The peernumber of the peer who is the target of the event.
     * @param type The type of event (one of $MOD_EVENT).
     */
    typedef void(uint32_t groupnumber, uint32_t source_peernum, uint32_t target_peernum, MOD_EVENT type);
  }

}


/*******************************************************************************
 *
 * :: Group chat ban list queries
 *
 ******************************************************************************/

namespace group {

  namespace ban {

    /**
     * Error codes for group ban list queries.
     */
    error for query {
        /**
         * The group number passed did not designate a valid group.
         */
        GROUP_NOT_FOUND,
        /**
         * The ban_id does not designate a valid ban list entry.
         */
        BAD_ID,
    }

    uint16_t[size] list {

      /**
       * Return the number of entries in the ban list for the group designated by
       * the given group number. If the group number is invalid, the return value is unspecified.
       */
      size(uint32_t groupnumber) with error for query;

      /**
       * Copy a list of valid ban list ID's into an array.
       *
       * Call $size to determine the number of elements to allocate.
       *
       * @param list A memory region with enough space to hold the ban list. If
       *   this parameter is NULL, this function has no effect.
       *
       * @return true on success.
       */
      get(uint32_t groupnumber) with error for query;
    }

    uint8_t[length <= MAX_NAME_LENGTH] name {

      /**
       * Return the length of the name for the ban list entry designated by ban_id, in the
       * group designated by the given group number. If either groupnumber or ban_id is invalid,
       * the return value is unspecified.
       */
      size(uint32_t groupnumber, uint16_t ban_id) with error for query;

      /**
       * Write the name of the ban entry designated by ban_id in the group designated by the
       * given group number to a byte array.
       *
       * Call $size to find out how much memory to allocate for the result.
       *
       * @return true on success.
       */
      get(uint32_t groupnumber, uint16_t ban_id) with error for query;
    }

    uint64_t time_set {

      /**
       * Return a time stamp indicating the time the ban was set, for the ban list entry
       * designated by ban_id, in the group designated by the given group number.
       * If either groupnumber or ban_id is invalid, the return value is unspecified.
       */
      get(uint32_t groupnumber, uint16_t ban_id) with error for query;
    }
  }
}

} // class tox

%{

#ifdef __cplusplus
}
#endif

#endif /* DHT_GROUPCHATS */
#endif /* TOX_H */
%}
