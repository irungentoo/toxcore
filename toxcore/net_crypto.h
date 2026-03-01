/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Functions for the core network crypto.
 */
#ifndef C_TOXCORE_TOXCORE_NET_CRYPTO_H
#define C_TOXCORE_TOXCORE_NET_CRYPTO_H

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h" // Node_format
#include "TCP_client.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net.h"
#include "net_profile.h"
#include "network.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef const uint8_t *_Nullable nc_dht_get_shared_key_sent_cb(void *_Nonnull obj, const uint8_t *_Nonnull public_key);
typedef const uint8_t *_Nonnull nc_dht_get_self_public_key_cb(const void *_Nonnull obj);
typedef const uint8_t *_Nonnull nc_dht_get_self_secret_key_cb(const void *_Nonnull obj);

typedef struct Net_Crypto_DHT_Funcs {
    nc_dht_get_shared_key_sent_cb *_Nonnull get_shared_key_sent;
    nc_dht_get_self_public_key_cb *_Nonnull get_self_public_key;
    nc_dht_get_self_secret_key_cb *_Nonnull get_self_secret_key;
} Net_Crypto_DHT_Funcs;

/*** Crypto payloads. */

/*** Ranges. */

/** Packets in this range are reserved for net_crypto events_alloc use. */
#define PACKET_ID_RANGE_RESERVED_START 0
#define PACKET_ID_RANGE_RESERVED_END 15
/** Packets in this range are reserved for Messenger use. */
#define PACKET_ID_RANGE_LOSSLESS_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_END 159
/** Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_START 160
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_END 191
#define PACKET_ID_RANGE_LOSSLESS_END 191
/** Packets in this range are reserved for AV use. */
#define PACKET_ID_RANGE_LOSSY_START 192
#define PACKET_ID_RANGE_LOSSY_AV_START 192
#define PACKET_ID_RANGE_LOSSY_AV_END 199
/** Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSY_CUSTOM_START 200
#define PACKET_ID_RANGE_LOSSY_CUSTOM_END 254
#define PACKET_ID_RANGE_LOSSY_END 254

/*** Messages. */

typedef enum Packet_Id {
    PACKET_ID_REQUEST            = 1, // Used to request unreceived packets
    PACKET_ID_KILL               = 2, // Used to kill connection

    PACKET_ID_ONLINE             = 24,
    PACKET_ID_OFFLINE            = 25,
    PACKET_ID_NICKNAME           = 48,
    PACKET_ID_STATUSMESSAGE      = 49,
    PACKET_ID_USERSTATUS         = 50,
    PACKET_ID_TYPING             = 51,
    PACKET_ID_MESSAGE            = 64,
    PACKET_ID_ACTION             = 65, // PACKET_ID_MESSAGE + MESSAGE_ACTION
    PACKET_ID_MSI                = 69, // Used by AV to setup calls and etc
    PACKET_ID_FILE_SENDREQUEST   = 80,
    PACKET_ID_FILE_CONTROL       = 81,
    PACKET_ID_FILE_DATA          = 82,
    PACKET_ID_INVITE_GROUPCHAT   = 95,
    PACKET_ID_INVITE_CONFERENCE  = 96,
    PACKET_ID_ONLINE_PACKET      = 97,
    PACKET_ID_DIRECT_CONFERENCE  = 98,
    PACKET_ID_MESSAGE_CONFERENCE = 99,
    PACKET_ID_REJOIN_CONFERENCE  = 100,
    PACKET_ID_LOSSY_CONFERENCE   = 199,
} Packet_Id;

/** Maximum size of receiving and sending packet buffers. */
#define CRYPTO_PACKET_BUFFER_SIZE 32768 // Must be a power of 2

/** Minimum packet rate per second. */
#define CRYPTO_PACKET_MIN_RATE 4.0

/** Minimum packet queue max length. */
#define CRYPTO_MIN_QUEUE_LENGTH 64

/** Maximum total size of packets that net_crypto sends. */
#define MAX_CRYPTO_PACKET_SIZE 1400

#define CRYPTO_DATA_PACKET_MIN_SIZE (1 + sizeof(uint16_t) + (sizeof(uint32_t) + sizeof(uint32_t)) + CRYPTO_MAC_SIZE)

/** Max size of data in packets */
#define MAX_CRYPTO_DATA_SIZE (MAX_CRYPTO_PACKET_SIZE - CRYPTO_DATA_PACKET_MIN_SIZE)

/** Interval in ms between sending cookie request/handshake packets. */
#define CRYPTO_SEND_PACKET_INTERVAL 1000

/**
 * The maximum number of times we try to send the cookie request and handshake
 * before giving up.
 */
#define MAX_NUM_SENDPACKET_TRIES 8

/** The timeout of no received UDP packets before the direct UDP connection is considered dead. */
#define UDP_DIRECT_TIMEOUT 8

#define MAX_TCP_CONNECTIONS 64
#define MAX_TCP_RELAYS_PEER 4

/** All packets will be padded a number of bytes based on this number. */
#define CRYPTO_MAX_PADDING 8

/**
 * Base current transfer speed on last CONGESTION_QUEUE_ARRAY_SIZE number of points taken
 * at the dT defined in net_crypto.c
 */
#define CONGESTION_QUEUE_ARRAY_SIZE 12
#define CONGESTION_LAST_SENT_ARRAY_SIZE (CONGESTION_QUEUE_ARRAY_SIZE * 2)

/** Default connection ping in ms. */
#define DEFAULT_PING_CONNECTION 1000
#define DEFAULT_TCP_PING_CONNECTION 500

typedef struct Net_Crypto Net_Crypto;

const uint8_t *_Nonnull nc_get_self_public_key(const Net_Crypto *_Nonnull c);
const uint8_t *_Nonnull nc_get_self_secret_key(const Net_Crypto *_Nonnull c);
TCP_Connections *_Nonnull nc_get_tcp_c(const Net_Crypto *_Nonnull c);

typedef struct New_Connection {
    IP_Port source;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The real public key of the peer. */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer. */
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The public key of the peer. */
    uint8_t *_Nonnull cookie;
    uint8_t cookie_length;
} New_Connection;

typedef int connection_status_cb(void *_Nonnull object, int id, bool status, void *_Nullable userdata);
typedef int connection_data_cb(void *_Nonnull object, int id, const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);
typedef int connection_lossy_data_cb(void *_Nonnull object, int id, const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);
typedef void dht_pk_cb(void *_Nonnull object, int32_t number, const uint8_t *_Nonnull dht_public_key, void *_Nullable userdata);
typedef int new_connection_cb(void *_Nonnull object, const New_Connection *_Nonnull n_c);

/** @brief Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *_Nonnull c, new_connection_cb *_Nonnull new_connection_callback, void *_Nonnull object);

/** @brief Accept a crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int accept_crypto_connection(Net_Crypto *_Nonnull c, const New_Connection *_Nonnull n_c);

/** @brief Create a crypto connection.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *_Nonnull c, const uint8_t *_Nonnull real_public_key, const uint8_t *_Nonnull dht_public_key);

/** @brief Set the direct ip of the crypto connection.
 *
 * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_direct_ip_port(Net_Crypto *_Nonnull c, int crypt_connection_id, const IP_Port *_Nonnull ip_port, bool connected);

/** @brief Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_status_handler(const Net_Crypto *_Nonnull c, int crypt_connection_id, connection_status_cb *_Nonnull connection_status_callback, void *_Nonnull object, int id);

/** @brief Set function to be called when connection with crypt_connection_id receives a lossless data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *_Nonnull c, int crypt_connection_id, connection_data_cb *_Nonnull connection_data_callback, void *_Nonnull object, int id);

/** @brief Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(const Net_Crypto *_Nonnull c, int crypt_connection_id, connection_lossy_data_cb *_Nonnull connection_lossy_data_callback, void *_Nonnull object, int id);

/** @brief Set the function for this friend that will be callbacked with object and number if
 * the friend sends us a different dht public key than we have associated to him.
 *
 * If this function is called, the connection should be recreated with the new public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int nc_dht_pk_callback(const Net_Crypto *_Nonnull c, int crypt_connection_id, dht_pk_cb *_Nonnull function, void *_Nonnull object, uint32_t number);

/**
 * @return the number of packet slots left in the sendbuffer.
 * @retval 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(const Net_Crypto *_Nonnull c, int crypt_connection_id);

/**
 * @retval 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * @retval 0 if it wasn't reached.
 */
bool max_speed_reached(const Net_Crypto *_Nonnull c, int crypt_connection_id);

/** @brief Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSLESS.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t write_cryptpacket(const Net_Crypto *_Nonnull c, int crypt_connection_id, const uint8_t *_Nonnull data, uint16_t length, bool congestion_control);

/** @brief Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * Note: The condition `buffer_end - buffer_start < packet_number - buffer_start` is
 * a trick which handles situations `buffer_end >= buffer_start` and
 * `buffer_end < buffer_start` (when buffer_end overflowed) both correctly.
 *
 * It CANNOT be simplified to `packet_number < buffer_start`, as it will fail
 * when `buffer_end < buffer_start`.
 */
int cryptpacket_received(const Net_Crypto *_Nonnull c, int crypt_connection_id, uint32_t packet_number);

/** @brief Sends a lossy cryptopacket.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSY.
 */
int send_lossy_cryptpacket(const Net_Crypto *_Nonnull c, int crypt_connection_id, const uint8_t *_Nonnull data, uint16_t length);

/** @brief Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay_peer(Net_Crypto *_Nonnull c, int crypt_connection_id, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull public_key);

/** @brief Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay(Net_Crypto *_Nonnull c, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull public_key);

/** @brief Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(const Net_Crypto *_Nonnull c);

/** @brief Put IP_Port of a random onion TCP connection in ip_port.
 *
 * return true on success.
 * return false on failure.
 */
bool get_random_tcp_conn_ip_port(const Net_Crypto *_Nonnull c, IP_Port *_Nonnull ip_port);

/** @brief Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto *_Nonnull c, unsigned int tcp_connections_number, const uint8_t *_Nonnull data, uint16_t length);

/**
 * Send a forward request to the TCP relay with IP_Port tcp_forwarder,
 * requesting to forward data via a chain of dht nodes starting with dht_node.
 * A chain_length of 0 means that dht_node is the final destination of data.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_forward_request(const Logger *_Nonnull logger, Net_Crypto *_Nonnull c, const IP_Port *_Nonnull tcp_forwarder, const IP_Port *_Nonnull dht_node,
                             const uint8_t *_Nonnull chain_keys, uint16_t chain_length, const uint8_t *_Nonnull data, uint16_t data_length);

/** @brief Copy a maximum of num random TCP relays we are connected to to tcp_relays.
 *
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(const Net_Crypto *_Nonnull c, Node_format *_Nonnull tcp_relays, uint16_t num);

/**
 * Copy a maximum of `max_num` TCP relays we are connected to starting at the index in the TCP relay array
 * for `tcp_c` designated by `idx`. If idx is greater than the array length a modulo operation is performed.
 *
 * Returns the number of relays successfully copied.
 */
uint32_t copy_connected_tcp_relays_index(const Net_Crypto *_Nonnull c, Node_format *_Nonnull tcp_relays, uint16_t num, uint32_t idx);

/** @brief Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *_Nonnull c, int crypt_connection_id);

/**
 * @retval true if connection is valid, false otherwise
 *
 * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
 * sets online_tcp_relays to the number of connected tcp relays this connection has.
 */
bool crypto_connection_status(
    const Net_Crypto *_Nonnull c, int crypt_connection_id, bool *_Nonnull direct_connected, uint32_t *_Nullable online_tcp_relays);
/** @brief Generate our public and private keys.
 * Only call this function the first time the program starts.
 */
void new_keys(Net_Crypto *_Nonnull c);

/** @brief Save the public and private keys to the keys array.
 * Length must be CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE.
 *
 * TODO(irungentoo): Save only secret key.
 */
void save_keys(const Net_Crypto *_Nonnull c, uint8_t *_Nonnull keys);

/** @brief Load the secret key.
 * Length must be CRYPTO_SECRET_KEY_SIZE.
 */
void load_secret_key(Net_Crypto *_Nonnull c, const uint8_t *_Nonnull sk);

/** @brief Create new instance of Net_Crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto *_Nullable new_net_crypto(const Logger *_Nonnull log, const Memory *_Nonnull mem, const Random *_Nonnull rng, const Network *_Nonnull ns, Mono_Time *_Nonnull mono_time,
                                     Networking_Core *_Nonnull net, void *_Nonnull dht, const Net_Crypto_DHT_Funcs *_Nonnull dht_funcs,
                                     const TCP_Proxy_Info *_Nonnull proxy_info, Net_Profile *_Nonnull tcp_np);

/** return the optimal interval in ms for running do_net_crypto. */
uint32_t crypto_run_interval(const Net_Crypto *_Nonnull c);

/** Main loop. */
void do_net_crypto(Net_Crypto *_Nonnull c, void *_Nullable userdata);
void kill_net_crypto(Net_Crypto *_Nullable c);

/** Unit test support functions. Do not use outside tests. */
void nc_testonly_get_secrets(const Net_Crypto *_Nonnull c, int conn_id, uint8_t *_Nonnull shared_key, uint8_t *_Nonnull sent_nonce, uint8_t *_Nonnull recv_nonce);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_NET_CRYPTO_H */
