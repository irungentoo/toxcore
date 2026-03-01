/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2019-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_FORWARDING_H
#define C_TOXCORE_TOXCORE_FORWARDING_H

#include <stdbool.h>
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

#ifdef __cplusplus
extern "C" {
#endif

#define SENDBACK_IPPORT 0
#define SENDBACK_FORWARD 1
#define SENDBACK_TCP 2

#define MAX_SENDBACK_SIZE (0xff - 1)
#define MAX_FORWARD_DATA_SIZE (MAX_UDP_PACKET_SIZE - (1 + 1 + MAX_SENDBACK_SIZE))

#define MAX_FORWARD_CHAIN_LENGTH 4

#define MAX_PACKED_IPPORT_SIZE (1 + SIZE_IP6 + sizeof(uint16_t))

typedef struct Forwarding Forwarding;

/**
 * @brief Send data to forwarder for forwarding via chain of dht nodes.
 * Destination is last key in the chain.
 *
 * @param data Must be of length at most MAX_FORWARD_DATA_SIZE.
 * @param chain_length Number of intermediate nodes in chain.
 *   Must be at least 1 and at most MAX_FORWARD_CHAIN_LENGTH.
 * @param chain_keys Public keys of chain nodes. Must be of length
 *   `chain_length * CRYPTO_PUBLIC_KEY_SIZE`.
 *
 * @return true on success, false otherwise.
 */
bool send_forward_request(const Networking_Core *_Nonnull net, const IP_Port *_Nonnull forwarder, const uint8_t *_Nonnull chain_keys, uint16_t chain_length, const uint8_t *_Nonnull data,
                          uint16_t data_length);

/** Returns size of packet written by create_forward_chain_packet. */
uint16_t forward_chain_packet_size(uint16_t chain_length, uint16_t data_length);

/**
 * @brief Create forward request packet for forwarding data via chain of dht nodes.
 * Destination is last key in the chain.
 *
 * @param data Must be of length at most MAX_FORWARD_DATA_SIZE.
 * @param chain_length Number of intermediate nodes in chain.
 *   Must be at least 1 and at most MAX_FORWARD_CHAIN_LENGTH.
 * @param chain_keys Public keys of chain nodes. Must be of length
 *   `chain_length * CRYPTO_PUBLIC_KEY_SIZE`.
 * @param packet Must be of size at least
 *   `forward_chain_packet_size(chain_length, data_length)` bytes.
 *
 * @return true on success, false otherwise.
 */
bool create_forward_chain_packet(const uint8_t *_Nonnull chain_keys, uint16_t chain_length, const uint8_t *_Nonnull data, uint16_t data_length, uint8_t *_Nonnull packet);

/**
 * @brief Send reply to forwarded packet via forwarder.
 * @param sendback Must be of size at most MAX_SENDBACK_SIZE.
 * @param data Must be of size at most MAX_FORWARD_DATA_SIZE.
 *
 * @return true on success, false otherwise.
 */
bool forward_reply(const Networking_Core *_Nonnull net, const IP_Port *_Nonnull forwarder, const uint8_t *_Nonnull sendback, uint16_t sendback_length, const uint8_t *_Nonnull data,
                   uint16_t length);

/**
 * @brief Set callback to handle a forwarded request.
 * To reply to the packet, callback should use `forward_reply()` to send a reply
 * forwarded via forwarder, passing the provided sendback.
 */
typedef void forwarded_request_cb(void *_Nullable object, const IP_Port *_Nonnull forwarder, const uint8_t *_Nonnull sendback,
                                  uint16_t sendback_length, const uint8_t *_Nonnull data,
                                  uint16_t length, void *_Nullable userdata);
void set_callback_forwarded_request(Forwarding *_Nonnull forwarding, forwarded_request_cb *_Nullable function, void *_Nullable object);
/** @brief Set callback to handle a forwarded response. */
typedef void forwarded_response_cb(void *_Nullable object, const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);
void set_callback_forwarded_response(Forwarding *_Nonnull forwarding, forwarded_response_cb *_Nullable function, void *_Nullable object);
/** @brief Send forwarding packet to dest with given sendback data and data. */
bool send_forwarding(const Forwarding *_Nonnull forwarding, const IP_Port *_Nonnull dest,
                     const uint8_t *_Nullable sendback_data, uint16_t sendback_data_len,
                     const uint8_t *_Nonnull data, uint16_t length);
typedef bool forward_reply_cb(void *_Nullable object, const uint8_t *_Nullable sendback_data, uint16_t sendback_data_len,
                              const uint8_t *_Nonnull data, uint16_t length);

/**
 * @brief Set callback to handle a forward reply with an otherwise unhandled
 * sendback.
 */
void set_callback_forward_reply(Forwarding *_Nonnull forwarding, forward_reply_cb *_Nullable function, void *_Nullable object);
Forwarding *_Nullable new_forwarding(const Logger *_Nonnull log, const Memory *_Nonnull mem, const Random *_Nonnull rng, const Mono_Time *_Nonnull mono_time, DHT *_Nonnull dht,
                                     Networking_Core *_Nonnull net);

void kill_forwarding(Forwarding *_Nullable forwarding);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_FORWARDING_H */
