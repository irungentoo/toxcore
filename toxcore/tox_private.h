/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t tox_mono_time_cb(void *user_data);

struct Tox_System {
    tox_mono_time_cb *mono_time_callback;
    void *mono_time_user_data;
    const struct Random *rng;
    const struct Network *ns;
};

Tox_System tox_default_system(void);

void tox_lock(const Tox *tox);
void tox_unlock(const Tox *tox);

/**
 * Set the callback for the `friend_lossy_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSY_START` to `PACKET_ID_RANGE_LOSSY_END` (both inclusive)
 */
void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid);

/**
 * Set the callback for the `friend_lossless_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSLESS_CUSTOM_START` to `PACKET_ID_RANGE_LOSSLESS_CUSTOM_END` (both inclusive)
 * and
 * `PACKET_ID_MSI`
 */
void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid);

void tox_set_av_object(Tox *tox, void *object);
void *tox_get_av_object(const Tox *tox);


/*******************************************************************************
 *
 * :: DHT network queries.
 *
 ******************************************************************************/

/**
 * The minimum size of an IP string buffer in bytes.
 */
#define TOX_DHT_NODE_IP_STRING_SIZE      96

uint32_t tox_dht_node_ip_string_size(void);

/**
 * The size of a DHT node public key in bytes.
 */
#define TOX_DHT_NODE_PUBLIC_KEY_SIZE     32

uint32_t tox_dht_node_public_key_size(void);

/**
 * @param public_key The node's public key.
 * @param ip The node's IP address, represented as a null terminated string.
 * @param port The node's port.
 */
typedef void tox_dht_get_nodes_response_cb(Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port,
        void *user_data);


/**
 * Set the callback for the `dht_get_nodes_response` event. Pass NULL to unset.
 *
 * This event is triggered when a getnodes response is received from a DHT peer.
 */
void tox_callback_dht_get_nodes_response(Tox *tox, tox_dht_get_nodes_response_cb *callback);


typedef enum Tox_Err_Dht_Get_Nodes {
    /**
     * The function returned successfully.
     */
    TOX_ERR_DHT_GET_NODES_OK,

    /**
     * UDP is disabled in tox options; the DHT can only be queried when UDP is enabled.
     */
    TOX_ERR_DHT_GET_NODES_UDP_DISABLED,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_DHT_GET_NODES_NULL,

    /**
     * The supplied port is invalid.
     */
    TOX_ERR_DHT_GET_NODES_BAD_PORT,

    /**
     * The supplied IP address is invalid.
     */
    TOX_ERR_DHT_GET_NODES_BAD_IP,

    /**
     * The getnodes request failed. This usually means the packet failed to send.
     */
    TOX_ERR_DHT_GET_NODES_FAIL,
} Tox_Err_Dht_Get_Nodes;

/**
 * This function sends a getnodes request to a DHT node for its peers that
 * are "close" to the passed target public key according to the distance metric used
 * by the DHT implementation.
 *
 * @param public_key The public key of the node that we wish to query. This key must be
 *   at least `TOX_DHT_NODE_PUBLIC_KEY_SIZE` bytes in length.
 * @param ip A NULL terminated string representing the IP address of the node we wish to query.
 * @param port The port of the node we wish to query.
 * @param target_public_key The public key for which we want to find close nodes.
 *
 * @return true on success.
 */
bool tox_dht_get_nodes(const Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port,
                       const uint8_t *target_public_key, Tox_Err_Dht_Get_Nodes *error);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_PRIVATE_H
