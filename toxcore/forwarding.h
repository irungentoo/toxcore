/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2019-2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_FORWARDING_H
#define C_TOXCORE_TOXCORE_FORWARDING_H

#include "DHT.h"
#include "network.h"

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

non_null()
DHT *forwarding_get_dht(Forwarding *forwarding);

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
non_null()
bool send_forward_request(Networking_Core *net, const IP_Port *forwarder,
                          const uint8_t *chain_keys, uint16_t chain_length,
                          const uint8_t *data, uint16_t data_length);

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
non_null()
bool create_forward_chain_packet(const uint8_t *chain_keys, uint16_t chain_length,
                                 const uint8_t *data, uint16_t data_length,
                                 uint8_t *packet);

/**
 * @brief Send reply to forwarded packet via forwarder.
 * @param sendback Must be of size at most MAX_SENDBACK_SIZE.
 * @param data Must be of size at most MAX_FORWARD_DATA_SIZE.
 *
 * @return true on success, false otherwise.
 */
non_null()
bool forward_reply(Networking_Core *net, const IP_Port *forwarder,
                   const uint8_t *sendback, uint16_t sendback_length,
                   const uint8_t *data, uint16_t length);


/**
 * @brief Set callback to handle a forwarded request.
 * To reply to the packet, callback should use `forward_reply()` to send a reply
 * forwarded via forwarder, passing the provided sendback.
 */
typedef void forwarded_request_cb(void *object, const IP_Port *forwarder, const uint8_t *sendback,
                                  uint16_t sendback_length, const uint8_t *data,
                                  uint16_t length, void *userdata);
non_null(1) nullable(2, 3)
void set_callback_forwarded_request(Forwarding *forwarding, forwarded_request_cb *function, void *object);

/** @brief Set callback to handle a forwarded response. */
typedef void forwarded_response_cb(void *object, const uint8_t *data, uint16_t length, void *userdata);
non_null(1) nullable(2, 3)
void set_callback_forwarded_response(Forwarding *forwarding, forwarded_response_cb *function, void *object);

/** @brief Send forwarding packet to dest with given sendback data and data. */
non_null(1, 2, 5) nullable(3)
bool send_forwarding(const Forwarding *forwarding, const IP_Port *dest,
                     const uint8_t *sendback_data, uint16_t sendback_data_len,
                     const uint8_t *data, uint16_t length);

typedef bool forward_reply_cb(void *object, const uint8_t *sendback_data, uint16_t sendback_data_len,
                              const uint8_t *data, uint16_t length);

/**
 * @brief Set callback to handle a forward reply with an otherwise unhandled
 * sendback.
 */
non_null(1) nullable(2, 3)
void set_callback_forward_reply(Forwarding *forwarding, forward_reply_cb *function, void *object);

non_null()
Forwarding *new_forwarding(const Logger *log, const Random *rng, const Mono_Time *mono_time, DHT *dht);

nullable(1)
void kill_forwarding(Forwarding *forwarding);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
