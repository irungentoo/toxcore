/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the onion part of docs/Prevent_Tracking.txt
 */
#ifndef C_TOXCORE_TOXCORE_ONION_H
#define C_TOXCORE_TOXCORE_ONION_H

#include <stdint.h>

#include "DHT.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net.h"
#include "network.h"
#include "rng.h"
#include "shared_key_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int onion_recv_1_cb(void *_Nullable object, const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);

typedef struct Onion {
    const Logger *_Nonnull log;
    const Mono_Time *_Nonnull mono_time;
    const Random *_Nonnull rng;
    const Memory *_Nonnull mem;
    DHT *_Nonnull dht;
    Networking_Core *_Nonnull net;
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];
    uint64_t timestamp;

    Shared_Key_Cache *_Nonnull shared_keys_1;
    Shared_Key_Cache *_Nonnull shared_keys_2;
    Shared_Key_Cache *_Nonnull shared_keys_3;

    onion_recv_1_cb *_Nullable recv_1_function;
    void *_Nullable callback_object;
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
int create_onion_path(const Random *_Nonnull rng, const DHT *_Nonnull dht, Onion_Path *_Nonnull new_path, const Node_format *_Nonnull nodes);

/** @brief Dump nodes in onion path to nodes of length num_nodes.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(Node_format *_Nonnull nodes, unsigned int num_nodes, const Onion_Path *_Nonnull path);

/** @brief Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet(const Memory *_Nonnull mem, const Random *_Nonnull rng, uint8_t *_Nonnull packet, uint16_t max_packet_length, const Onion_Path *_Nonnull path,
                        const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);

/** @brief Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(const Memory *_Nonnull mem, const Random *_Nonnull rng, uint8_t *_Nonnull packet, uint16_t max_packet_length, const Onion_Path *_Nonnull path,
                            const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);

/** @brief Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(const Logger *_Nonnull log, const Networking_Core *_Nonnull net, const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length,
                        const uint8_t *_Nonnull ret);

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
int onion_send_1(const Onion *_Nonnull onion, const uint8_t *_Nonnull plain, uint16_t len, const IP_Port *_Nonnull source, const uint8_t *_Nonnull nonce);

/** Set the callback to be called when the dest ip_port doesn't have TOX_AF_INET6 or TOX_AF_INET as the family. */
void set_callback_handle_recv_1(Onion *_Nonnull onion, onion_recv_1_cb *_Nullable function, void *_Nullable object);
Onion *_Nullable new_onion(const Logger *_Nonnull log, const Memory *_Nonnull mem, const Mono_Time *_Nonnull mono_time, const Random *_Nonnull rng, DHT *_Nonnull dht, Networking_Core *_Nonnull net);

void kill_onion(Onion *_Nullable onion);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_ONION_H */
