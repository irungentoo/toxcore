/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Functions for the core network crypto.
 */
#ifndef C_TOXCORE_TOXCORE_NET_CRYPTO_H
#define C_TOXCORE_TOXCORE_NET_CRYPTO_H

#include "DHT.h"
#include "LAN_discovery.h"
#include "TCP_connection.h"
#include "logger.h"

#include <pthread.h>

/** Crypto payloads. */

/** Ranges. */

/* Packets in this range are reserved for net_crypto internal use. */
#define PACKET_ID_RANGE_RESERVED_START 0
#define PACKET_ID_RANGE_RESERVED_END 15
/* Packets in this range are reserved for Messenger use. */
#define PACKET_ID_RANGE_LOSSLESS_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_START 16
#define PACKET_ID_RANGE_LOSSLESS_NORMAL_END 159
/* Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_START 160
#define PACKET_ID_RANGE_LOSSLESS_CUSTOM_END 191
#define PACKET_ID_RANGE_LOSSLESS_END 191
/* Packets in this range are reserved for AV use. */
#define PACKET_ID_RANGE_LOSSY_START 192
#define PACKET_ID_RANGE_LOSSY_AV_START 192
#define PACKET_ID_RANGE_LOSSY_AV_SIZE 8
#define PACKET_ID_RANGE_LOSSY_AV_END 199
/* Packets in this range can be used for anything. */
#define PACKET_ID_RANGE_LOSSY_CUSTOM_START 200
#define PACKET_ID_RANGE_LOSSY_CUSTOM_END 254
#define PACKET_ID_RANGE_LOSSY_END 254

/** Messages. */

#define PACKET_ID_PADDING 0 // Denotes padding
#define PACKET_ID_REQUEST 1 // Used to request unreceived packets
#define PACKET_ID_KILL    2 // Used to kill connection

#define PACKET_ID_ONLINE 24
#define PACKET_ID_OFFLINE 25
#define PACKET_ID_NICKNAME 48
#define PACKET_ID_STATUSMESSAGE 49
#define PACKET_ID_USERSTATUS 50
#define PACKET_ID_TYPING 51
#define PACKET_ID_MESSAGE 64
#define PACKET_ID_ACTION 65 // PACKET_ID_MESSAGE + MESSAGE_ACTION
#define PACKET_ID_MSI 69    // Used by AV to setup calls and etc
#define PACKET_ID_FILE_SENDREQUEST 80
#define PACKET_ID_FILE_CONTROL 81
#define PACKET_ID_FILE_DATA 82
#define PACKET_ID_INVITE_CONFERENCE 96
#define PACKET_ID_ONLINE_PACKET 97
#define PACKET_ID_DIRECT_CONFERENCE 98
#define PACKET_ID_MESSAGE_CONFERENCE 99
#define PACKET_ID_REJOIN_CONFERENCE 100
#define PACKET_ID_LOSSY_CONFERENCE 199

/* Maximum size of receiving and sending packet buffers. */
#define CRYPTO_PACKET_BUFFER_SIZE 32768 // Must be a power of 2

/* Minimum packet rate per second. */
#define CRYPTO_PACKET_MIN_RATE 4.0

/* Minimum packet queue max length. */
#define CRYPTO_MIN_QUEUE_LENGTH 64

/* Maximum total size of packets that net_crypto sends. */
#define MAX_CRYPTO_PACKET_SIZE (uint16_t)1400

#define CRYPTO_DATA_PACKET_MIN_SIZE (uint16_t)(1 + sizeof(uint16_t) + (sizeof(uint32_t) + sizeof(uint32_t)) + CRYPTO_MAC_SIZE)

/* Max size of data in packets */
#define MAX_CRYPTO_DATA_SIZE (uint16_t)(MAX_CRYPTO_PACKET_SIZE - CRYPTO_DATA_PACKET_MIN_SIZE)

/* Interval in ms between sending cookie request/handshake packets. */
#define CRYPTO_SEND_PACKET_INTERVAL 1000

/* The maximum number of times we try to send the cookie request and handshake
 * before giving up. */
#define MAX_NUM_SENDPACKET_TRIES 8

/* The timeout of no received UDP packets before the direct UDP connection is considered dead. */
#define UDP_DIRECT_TIMEOUT 8

#define MAX_TCP_CONNECTIONS 64
#define MAX_TCP_RELAYS_PEER 4

/* All packets will be padded a number of bytes based on this number. */
#define CRYPTO_MAX_PADDING 8

/* Base current transfer speed on last CONGESTION_QUEUE_ARRAY_SIZE number of points taken
 * at the dT defined in net_crypto.c */
#define CONGESTION_QUEUE_ARRAY_SIZE 12
#define CONGESTION_LAST_SENT_ARRAY_SIZE (CONGESTION_QUEUE_ARRAY_SIZE * 2)

/* Default connection ping in ms. */
#define DEFAULT_PING_CONNECTION 1000
#define DEFAULT_TCP_PING_CONNECTION 500

typedef struct Net_Crypto Net_Crypto;

const uint8_t *nc_get_self_public_key(const Net_Crypto *c);
const uint8_t *nc_get_self_secret_key(const Net_Crypto *c);
TCP_Connections *nc_get_tcp_c(const Net_Crypto *c);
DHT *nc_get_dht(const Net_Crypto *c);

typedef struct New_Connection {
    IP_Port source;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The real public key of the peer. */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer. */
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The public key of the peer. */
    uint8_t *cookie;
    uint8_t cookie_length;
} New_Connection;

typedef int connection_status_cb(void *object, int id, uint8_t status, void *userdata);
typedef int connection_data_cb(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);
typedef int connection_lossy_data_cb(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);
typedef void dht_pk_cb(void *data, int32_t number, const uint8_t *dht_public_key, void *userdata);
typedef int new_connection_cb(void *object, New_Connection *n_c);

/* Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, new_connection_cb *new_connection_callback, void *object);

/* Accept a crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int accept_crypto_connection(Net_Crypto *c, New_Connection *n_c);

/* Create a crypto connection.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *c, const uint8_t *real_public_key, const uint8_t *dht_public_key);

/* Set the direct ip of the crypto connection.
 *
 * Connected is 0 if we are not sure we are connected to that person, 1 if we are sure.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_direct_ip_port(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port, bool connected);

/* Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_status_handler(const Net_Crypto *c, int crypt_connection_id,
                              connection_status_cb *connection_status_callback, void *object, int id);

/* Set function to be called when connection with crypt_connection_id receives a lossless data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *c, int crypt_connection_id,
                            connection_data_cb *connection_data_callback, void *object, int id);


/* Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(Net_Crypto *c, int crypt_connection_id,
                                  connection_lossy_data_cb *connection_lossy_data_callback, void *object, int id);

/* Set the function for this friend that will be callbacked with object and number if
 * the friend sends us a different dht public key than we have associated to him.
 *
 * If this function is called, the connection should be recreated with the new public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int nc_dht_pk_callback(Net_Crypto *c, int crypt_connection_id, dht_pk_cb *function, void *object, uint32_t number);

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(const Net_Crypto *c, int crypt_connection_id);

/* Return 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * Return 0 if it wasn't reached.
 */
bool max_speed_reached(Net_Crypto *c, int crypt_connection_id);

/* Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSLESS.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t write_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                          uint8_t congestion_control);

/* Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int cryptpacket_received(Net_Crypto *c, int crypt_connection_id, uint32_t packet_number);

/* Sends a lossy cryptopacket.
 *
 * return -1 on failure.
 * return 0 on success.
 *
 * The first byte of data must be in the PACKET_ID_RANGE_LOSSY.
 */
int send_lossy_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length);

/* Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay_peer(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port, const uint8_t *public_key);

/* Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay(Net_Crypto *c, IP_Port ip_port, const uint8_t *public_key);

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(Net_Crypto *c);

/* Send an onion packet via the TCP relay corresponding to TCP_conn_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto *c, unsigned int tcp_connections_number, const uint8_t *data, uint16_t length);

/* Copy a maximum of num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(Net_Crypto *c, Node_format *tcp_relays, uint16_t num);

/* Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id);

/* return true if connection is valid, false otherwise
 *
 * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
 * sets online_tcp_relays to the number of connected tcp relays this connection has.
 */
bool crypto_connection_status(const Net_Crypto *c, int crypt_connection_id, bool *direct_connected,
                              unsigned int *online_tcp_relays);

/* Generate our public and private keys.
 *  Only call this function the first time the program starts.
 */
void new_keys(Net_Crypto *c);

/* Save the public and private keys to the keys array.
 *  Length must be CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SECRET_KEY_SIZE.
 */
void save_keys(const Net_Crypto *c, uint8_t *keys);

/* Load the secret key.
 * Length must be CRYPTO_SECRET_KEY_SIZE.
 */
void load_secret_key(Net_Crypto *c, const uint8_t *sk);

/* Create new instance of Net_Crypto.
 *  Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(const Logger *log, Mono_Time *mono_time, DHT *dht, TCP_Proxy_Info *proxy_info);

/* return the optimal interval in ms for running do_net_crypto.
 */
uint32_t crypto_run_interval(const Net_Crypto *c);

/* Main loop. */
void do_net_crypto(Net_Crypto *c, void *userdata);

void kill_net_crypto(Net_Crypto *c);



#endif
