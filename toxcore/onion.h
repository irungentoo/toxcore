/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the onion part of docs/Prevent_Tracking.txt
 */
#ifndef C_TOXCORE_TOXCORE_ONION_H
#define C_TOXCORE_TOXCORE_ONION_H

#include "DHT.h"
#include "logger.h"
#include "mono_time.h"

typedef int onion_recv_1_cb(void *object, const IP_Port *dest, const uint8_t *data, uint16_t length);

typedef struct Onion {
    const Logger *log;
    const Mono_Time *mono_time;
    const Random *rng;
    DHT *dht;
    Networking_Core *net;
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];
    uint64_t timestamp;

    Shared_Keys shared_keys_1;
    Shared_Keys shared_keys_2;
    Shared_Keys shared_keys_3;

    onion_recv_1_cb *recv_1_function;
    void *callback_object;
} Onion;

#define ONION_MAX_PACKET_SIZE 1400

#define ONION_RETURN_1 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE)
#define ONION_RETURN_2 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE + ONION_RETURN_1)
#define ONION_RETURN_3 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE + ONION_RETURN_2)

#define ONION_SEND_BASE (CRYPTO_PUBLIC_KEY_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE)
#define ONION_SEND_3 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE + ONION_RETURN_2)
#define ONION_SEND_2 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE*2 + ONION_RETURN_1)
#define ONION_SEND_1 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE*3)

#define ONION_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1))
#define ONION_RESPONSE_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (1 + ONION_RETURN_3))

#define ONION_PATH_LENGTH 3

typedef struct Onion_Path {
    uint8_t shared_key1[CRYPTO_SHARED_KEY_SIZE];
    uint8_t shared_key2[CRYPTO_SHARED_KEY_SIZE];
    uint8_t shared_key3[CRYPTO_SHARED_KEY_SIZE];

    uint8_t public_key1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t public_key2[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t public_key3[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port1;
    uint8_t     node_public_key1[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port2;
    uint8_t     node_public_key2[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port3;
    uint8_t     node_public_key3[CRYPTO_PUBLIC_KEY_SIZE];

    uint32_t path_num;
} Onion_Path;

/** @brief Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
 *
 * new_path must be an empty memory location of at least Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
non_null()
int create_onion_path(const Random *rng, const DHT *dht, Onion_Path *new_path, const Node_format *nodes);

/** @brief Dump nodes in onion path to nodes of length num_nodes.
 *
 * return -1 on failure.
 * return 0 on success.
 */
non_null()
int onion_path_to_nodes(Node_format *nodes, unsigned int num_nodes, const Onion_Path *path);

/** @brief Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
non_null()
int create_onion_packet(const Random *rng, uint8_t *packet, uint16_t max_packet_length,
                        const Onion_Path *path, const IP_Port *dest,
                        const uint8_t *data, uint16_t length);


/** @brief Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
non_null()
int create_onion_packet_tcp(const Random *rng, uint8_t *packet, uint16_t max_packet_length,
                            const Onion_Path *path, const IP_Port *dest,
                            const uint8_t *data, uint16_t length);

/** @brief Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
non_null()
int send_onion_response(const Networking_Core *net, const IP_Port *dest, const uint8_t *data, uint16_t length,
                        const uint8_t *ret);

/** @brief Function to handle/send received decrypted versions of the packet created by create_onion_packet.
 *
 * return 0 on success.
 * return 1 on failure.
 *
 * Used to handle these packets that are received in a non traditional way (by TCP for example).
 *
 * Source family must be set to something else than TOX_AF_INET6 or TOX_AF_INET so that the callback gets called
 * when the response is received.
 */
non_null()
int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, const IP_Port *source, const uint8_t *nonce);

/** Set the callback to be called when the dest ip_port doesn't have TOX_AF_INET6 or TOX_AF_INET as the family. */
non_null(1) nullable(2, 3)
void set_callback_handle_recv_1(Onion *onion, onion_recv_1_cb *function, void *object);

non_null()
Onion *new_onion(const Logger *log, const Mono_Time *mono_time, const Random *rng, DHT *dht);

nullable(1)
void kill_onion(Onion *onion);


#endif
