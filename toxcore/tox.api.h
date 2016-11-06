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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
%}


/*****************************************************************************
 * `tox.h` SHOULD *NOT* BE EDITED MANUALLY – any changes should be made to   *
 * `tox.api.h`, located in `toxcore/`. For instructions on how to            *
 * generate `tox.h` from `tox.api.h` please refer to `docs/apidsl.md`        *
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
 *
 * Integer constants and the memory layout of publicly exposed structs are not
 * part of the ABI.
 */

/** \subsection events Events and callbacks
 *
 * Events are handled by callbacks. One callback can be registered per event.
 * All events have a callback function type named `tox_{event}_cb` and a
 * function to register it named `tox_callback_{event}`. Passing a NULL
 * callback will result in no callback being registered for that event. Only
 * one callback per event can be registered, so if a client needs multiple
 * event listeners, it needs to implement the dispatch functionality itself.
 *
 * The last argument to a callback is the user data pointer. It is passed from
 * ${tox.iterate} to each callback in sequence.
 *
 * The user data pointer is never stored or dereferenced by any library code, so
 * can be any pointer, including NULL. Callbacks must all operate on the same
 * object type. In the apidsl code (tox.in.h), this is denoted with `any`. The
 * `any` in ${tox.iterate} must be the same `any` as in all callbacks. In C,
 * lacking parametric polymorphism, this is a pointer to void.
 *
 * Old style callbacks that are registered together with a user data pointer
 * receive that pointer as argument when they are called. They can each have
 * their own user data pointer of their own type.
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
 *
 * The function variants of these constants return the version number of the
 * library. They can be used to display the Tox library version or to check
 * whether the client is compatible with the dynamically linked version of Tox.
 */
const VERSION_MAJOR                = 0;

/**
 * The minor version number. Incremented when functionality is added without
 * breaking the API or ABI. Set to 0 when the major version number is
 * incremented.
 */
const VERSION_MINOR                = 0;

/**
 * The patch or revision number. Incremented when bugfixes are applied without
 * changing any functionality or API or ABI.
 */
const VERSION_PATCH                = 3;

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
 * The values of these are not part of the ABI. Prefer to use the function
 * versions of them for code that should remain compatible with future versions
 * of toxcore.
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
 * Maximum size of custom packets. TODO(iphydf): should be LENGTH?
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
 * Represents message types for ${tox.friend.send.message} and conference
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
   * Savedata is one that was obtained from ${savedata.get}.
   */
  TOX_SAVE,
  /**
   * Savedata is a secret key of length $SECRET_KEY_SIZE.
   */
  SECRET_KEY,
}


/**
 * Severity level of log messages.
 */
enum class LOG_LEVEL {
  /**
   * Very detailed traces including all network activity.
   */
  TRACE,
  /**
   * Debug messages such as which port we bind to.
   */
  DEBUG,
  /**
   * Informational log messages such as video call status changes.
   */
  INFO,
  /**
   * Warnings about internal inconsistency or logic errors.
   */
  WARNING,
  /**
   * Severe unexpected errors caused by external or internal inconsistency.
   */
  ERROR,
}

/**
 * This event is triggered when the toxcore library logs an internal message.
 * This is mostly useful for debugging. This callback can be called from any
 * function, not just $iterate. This means the user data lifetime must at
 * least extend between registering and unregistering it or $kill.
 *
 * Other toxcore modules such as toxav may concurrently call this callback at
 * any time. Thus, user code must make sure it is equipped to handle concurrent
 * execution, e.g. by employing appropriate mutex locking.
 *
 * @param level The severity of the log message.
 * @param file The source file from which the message originated.
 * @param line The source line from which the message originated.
 * @param func The function from which the message originated.
 * @param message The log message.
 * @param user_data The user data pointer passed to $new in options.
 */
typedef void log_cb(LOG_LEVEL level, string file, uint32_t line, string func, string message, any user_data);


static class options {
  /**
   * This struct contains all the startup options for Tox. You can either
   * allocate this object yourself, and pass it to $default, or call $new to get
   * a new default options object.
   *
   * If you allocate it yourself, be aware that your binary will rely on the
   * memory layout of this struct. In particular, if additional fields are added
   * in future versions of the API, code that allocates it itself will become
   * incompatible.
   *
   * The memory layout of this struct (size, alignment, and field order) is not
   * part of the ABI. To remain compatible, prefer to use $new to allocate the
   * object and accessor functions to set the members.
   */
  struct this [get, set] {
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
       * This member is ignored (it can be NULL) if proxy_type is ${PROXY_TYPE.NONE}.
       *
       * The data pointed at by this member is owned by the user, so must
       * outlive the options object.
       */
      string host;

      /**
       * The port to use to connect to the proxy server.
       *
       * Ports must be in the range (1, 65535). The value is ignored if
       * proxy_type is ${PROXY_TYPE.NONE}.
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
       *
       * The data pointed at by this member is owned by the user, so must
       * outlive the options object.
       */
      const uint8_t[length] data;

      /**
       * The length of the savedata.
       */
      size_t length;
    }

    namespace log {
      /**
       * Logging callback for the new tox instance.
       */
      log_cb *callback;

      /**
       * User data pointer passed to the logging callback.
       */
      any user_data;
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
   * @param savedata A memory region large enough to store the tox instance
   *   data. Call $size to find the number of bytes required. If this parameter
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
   * TODO(iphydf): how long should a client wait before bootstrapping again?
   */
  event connection_status const {
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
void iterate(any user_data);


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
     * @param status_message A valid memory location large enough to hold the
     *   status message. If this parameter is NULL, the function has no effect.
     */
    get();
  }


  USER_STATUS status {
    /**
     * Set the client's user status.
     *
     * @param status One of the user statuses listed in the enumeration above.
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
     * @param friend_list A memory region with enough space to hold the friend
     *   list. If this parameter is NULL, this function has no effect.
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
  event name const {
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
     * Write the status message of the friend designated by the given friend number to a byte
     * array.
     *
     * Call $size to determine the allocation size for the `status_name`
     * parameter.
     *
     * The data written to `status_message` is equal to the data received by the last
     * `${event status_message}` callback.
     *
     * @param status_message A valid memory region large enough to store the friend's status message.
     */
    get(uint32_t friend_number)
        with error for query;
  }


  /**
   * This event is triggered when a friend changes their status message.
   */
  event status_message const {
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
  event status const {
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
  event connection_status const {
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
  event typing const {
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
    uint32_t message(uint32_t friend_number, MESSAGE_TYPE type,
                     const uint8_t[length <= MAX_MESSAGE_LENGTH] message) {
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
  event read_receipt const {
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
  event request const {
    /**
     * @param public_key The Public Key of the user who sent the friend request.
     * @param message The message they sent along with the request.
     * @param length The size of the message byte array.
     */
    typedef void(const uint8_t[PUBLIC_KEY_SIZE] public_key,
                 const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
  }


  /**
   * This event is triggered when a message from a friend is received.
   */
  event message const {
    /**
     * @param friend_number The friend number of the friend who sent the message.
     * @param message The message data they sent.
     * @param length The size of the message byte array.
     */
    typedef void(uint32_t friend_number, MESSAGE_TYPE type,
                 const uint8_t[length <= MAX_MESSAGE_LENGTH] message);
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
 *   $HASH_LENGTH bytes in size.
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
  event recv_control const {
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

  uint8_t[FILE_ID_LENGTH] file_id {
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
    get(uint32_t friend_number, uint32_t file_number)
        with error for get;
  }

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
   *   be generated by core. It can then be obtained by using ${file_id.get}().
   * @param filename Name of the file. Does not need to be the actual name. This
   *   name will be sent along with the file send request.
   * @param filename_length Size in bytes of the filename.
   *
   * @return A file number used as an identifier in subsequent callbacks. This
   *   number is per friend. File numbers are reused after a transfer terminates.
   *   On failure, this function returns UINT32_MAX. Any pattern in file numbers
   *   should not be relied on.
   */
  uint32_t send(uint32_t friend_number, uint32_t kind, uint64_t file_size,
                const uint8_t[FILE_ID_LENGTH] file_id,
                const uint8_t[filename_length <= MAX_FILENAME_LENGTH] filename) {
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
  event chunk_request const {
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
  event recv const {
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
  event recv_chunk const {
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
 * :: Conference management
 *
 ******************************************************************************/

namespace conference {

  /**
   * Conference types for the ${event invite} event.
   */
  enum class TYPE {
    /**
     * Text-only conferences that must be accepted with the $join function.
     */
    TEXT,
    /**
     * Video conference. The function to accept these is in toxav.
     */
    AV,
  }


  /**
   * This event is triggered when the client is invited to join a conference.
   */
  event invite const {
    /**
     * The invitation will remain valid until the inviting friend goes offline
     * or exits the conference.
     *
     * @param friend_number The friend who invited us.
     * @param type The conference type (text only or audio/video).
     * @param cookie A piece of data of variable length required to join the
     *   conference.
     * @param length The length of the cookie.
     */
    typedef void(uint32_t friend_number, TYPE type, const uint8_t[length] cookie);
  }


  /**
   * This event is triggered when the client receives a conference message.
   */
  event message const {
    /**
     * @param conference_number The conference number of the conference the message is intended for.
     * @param peer_number The ID of the peer who sent the message.
     * @param type The type of message (normal, action, ...).
     * @param message The message data.
     * @param length The length of the message.
     */
    typedef void(uint32_t conference_number, uint32_t peer_number, MESSAGE_TYPE type,
                 const uint8_t[length] message);
  }


  /**
   * This event is triggered when a peer changes the conference title.
   *
   * If peer_number == UINT32_MAX, then author is unknown (e.g. initial joining the conference).
   */
  event title const {
    /**
     * @param conference_number The conference number of the conference the title change is intended for.
     * @param peer_number The ID of the peer who changed the title.
     * @param title The title data.
     * @param length The title length.
     */
    typedef void(uint32_t conference_number, uint32_t peer_number, const uint8_t[length] title);
  }

  /**
   * Peer list state change types.
   */
  enum class STATE_CHANGE {
    /**
     * A peer has joined the conference.
     */
    PEER_JOIN,
    /**
     * A peer has exited the conference.
     */
    PEER_EXIT,
    /**
     * A peer has changed their name.
     */
    PEER_NAME_CHANGE,
  }

  /**
   * This event is triggered when the peer list changes (name change, peer join, peer exit).
   */
  event namelist_change const {
    /**
     * @param conference_number The conference number of the conference the title change is intended for.
     * @param peer_number The ID of the peer who changed the title.
     * @param change The type of change (one of $STATE_CHANGE).
     */
    typedef void(uint32_t conference_number, uint32_t peer_number, STATE_CHANGE change);
  }


  /**
   * Creates a new conference.
   *
   * This function creates a new text conference.
   *
   * @return conference number on success, or UINT32_MAX on failure.
   */
  uint32_t new() {
    /**
     * The conference instance failed to initialize.
     */
    INIT,
  }

  /**
   * This function deletes a conference.
   *
   * @param conference_number The conference number of the conference to be deleted.
   *
   * @return true on success.
   */
  bool delete(uint32_t conference_number) {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
  }


  namespace peer {

    /**
     * Error codes for peer info queries.
     */
    error for query {
      /**
       * The conference number passed did not designate a valid conference.
       */
      CONFERENCE_NOT_FOUND,
      /**
       * The peer number passed did not designate a valid peer.
       */
      PEER_NOT_FOUND,
      /**
       * The client is not connected to the conference.
       */
      NO_CONNECTION,
    }

    /**
     * Return the number of peers in the conference. Return value is unspecified on failure.
     */
    const uint32_t count(uint32_t conference_number)
        with error for query;

    uint8_t[size] name {

      /**
       * Return the length of the peer's name. Return value is unspecified on failure.
       */
      size(uint32_t conference_number, uint32_t peer_number)
          with error for query;

      /**
       * Copy the name of peer_number who is in conference_number to name.
       * name must be at least $MAX_NAME_LENGTH long.
       *
       * @return true on success.
       */
      get(uint32_t conference_number, uint32_t peer_number)
          with error for query;
    }

    /**
     * Copy the public key of peer_number who is in conference_number to public_key.
     * public_key must be $PUBLIC_KEY_SIZE long.
     *
     * @return true on success.
     */
    uint8_t[PUBLIC_KEY_SIZE] public_key {
      get(uint32_t conference_number, uint32_t peer_number)
          with error for query;
    }

    /**
     * Return true if passed peer_number corresponds to our own.
     */
    const bool number_is_ours(uint32_t conference_number, uint32_t peer_number)
        with error for query;

  }


  /**
   * Invites a friend to a conference.
   *
   * @param friend_number The friend number of the friend we want to invite.
   * @param conference_number The conference number of the conference we want to invite the friend to.
   *
   * @return true on success.
   */
  bool invite(uint32_t friend_number, uint32_t conference_number) {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
    /**
     * The invite packet failed to send.
     */
    FAIL_SEND,
  }


  /**
   * Joins a conference that the client has been invited to.
   *
   * @param friend_number The friend number of the friend who sent the invite.
   * @param cookie Received via the `${event invite}` event.
   * @param length The size of cookie.
   *
   * @return conference number on success, UINT32_MAX on failure.
   */
  uint32_t join(uint32_t friend_number, const uint8_t[length] cookie) {
    /**
     * The cookie passed has an invalid length.
     */
    INVALID_LENGTH,
    /**
     * The conference is not the expected type. This indicates an invalid cookie.
     */
    WRONG_TYPE,
    /**
     * The friend number passed does not designate a valid friend.
     */
    FRIEND_NOT_FOUND,
    /**
     * Client is already in this conference.
     */
    DUPLICATE,
    /**
     * Conference instance failed to initialize.
     */
    INIT_FAIL,
    /**
     * The join packet failed to send.
     */
    FAIL_SEND,
  }


  namespace send {

    /**
     * Send a text chat message to the conference.
     *
     * This function creates a conference message packet and pushes it into the send
     * queue.
     *
     * The message length may not exceed $MAX_MESSAGE_LENGTH. Larger messages
     * must be split by the client and sent as separate messages. Other clients can
     * then reassemble the fragments.
     *
     * @param conference_number The conference number of the conference the message is intended for.
     * @param type Message type (normal, action, ...).
     * @param message A non-NULL pointer to the first element of a byte array
     *   containing the message text.
     * @param length Length of the message to be sent.
     *
     * @return true on success.
     */
    bool message(uint32_t conference_number, MESSAGE_TYPE type, const uint8_t[length] message) {
      /**
       * The conference number passed did not designate a valid conference.
       */
      CONFERENCE_NOT_FOUND,
      /**
       * The message is too long.
       */
      TOO_LONG,
      /**
       * The client is not connected to the conference.
       */
      NO_CONNECTION,
      /**
       * The message packet failed to send.
       */
      FAIL_SEND,
    }
  }

  error for title {
    /**
     * The conference number passed did not designate a valid conference.
     */
    CONFERENCE_NOT_FOUND,
    /**
     * The title is too long or empty.
     */
    INVALID_LENGTH,
    /**
     * The title packet failed to send.
     */
    FAIL_SEND,
  }

  uint8_t[length <= MAX_NAME_LENGTH] title {

    /**
     * Return the length of the conference title. Return value is unspecified on failure.
     *
     * The return value is equal to the `length` argument received by the last
     * `${event title}` callback.
     */
    size(uint32_t conference_number)
        with error for title;

    /**
     * Write the title designated by the given conference number to a byte array.
     *
     * Call $size to determine the allocation size for the `title` parameter.
     *
     * The data written to `title` is equal to the data received by the last
     * `${event title}` callback.
     *
     * @param title A valid memory region large enough to store the title.
     *   If this parameter is NULL, this function has no effect.
     *
     * @return true on success.
     */
    get(uint32_t conference_number)
        with error for title;

    /**
     * Set the conference title and broadcast it to the rest of the conference.
     *
     * Title length cannot be longer than $MAX_NAME_LENGTH.
     *
     * @return true on success.
     */
    set(uint32_t conference_number)
        with error for title;
  }


  uint32_t[size] chatlist {
    /**
     * Return the number of conferences in the Tox instance.
     * This should be used to determine how much memory to allocate for `$get`.
     */
    size();

    /**
     * Copy a list of valid conference IDs into the array chatlist. Determine how much space
     * to allocate for the array with the `$size` function.
     */
    get();
  }


  /**
   * Returns the type of conference ($TYPE) that conference_number is. Return value is
   * unspecified on failure.
   */
  TYPE type {
    get(uint32_t conference_number) {
      /**
       * The conference number passed did not designate a valid conference.
       */
      CONFERENCE_NOT_FOUND,
    }
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


  event lossy_packet const {
    /**
     * @param friend_number The friend number of the friend who sent a lossy packet.
     * @param data A byte array containing the received packet data.
     * @param length The length of the packet data byte array.
     */
    typedef void(uint32_t friend_number, const uint8_t[length <= MAX_CUSTOM_PACKET_SIZE] data);
  }


  event lossless_packet const {
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

} // class tox

%{
#ifdef __cplusplus
}
#endif

#endif
%}
