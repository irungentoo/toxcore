/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the announce part of docs/Prevent_Tracking.txt
 */
#ifndef C_TOXCORE_TOXCORE_ONION_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ONION_ANNOUNCE_H

#include "logger.h"
#include "onion.h"

#define ONION_ANNOUNCE_MAX_ENTRIES 160
#define ONION_ANNOUNCE_TIMEOUT 300
#define ONION_PING_ID_SIZE CRYPTO_SHA256_SIZE

#define ONION_ANNOUNCE_SENDBACK_DATA_LENGTH (sizeof(uint64_t))

#define ONION_ANNOUNCE_REQUEST_SIZE (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + ONION_PING_ID_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_PUBLIC_KEY_SIZE + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_MAC_SIZE)

#define ONION_ANNOUNCE_RESPONSE_MIN_SIZE (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE + 1 + ONION_PING_ID_SIZE + CRYPTO_MAC_SIZE)
#define ONION_ANNOUNCE_RESPONSE_MAX_SIZE (ONION_ANNOUNCE_RESPONSE_MIN_SIZE + sizeof(Node_format)*MAX_SENT_NODES)

#define ONION_DATA_RESPONSE_MIN_SIZE (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)

#define ONION_DATA_REQUEST_MIN_SIZE (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)
#define MAX_DATA_REQUEST_SIZE (ONION_MAX_DATA_SIZE - ONION_DATA_REQUEST_MIN_SIZE)

typedef struct Onion_Announce Onion_Announce;

/** These two are not public; they are for tests only! */
uint8_t *onion_announce_entry_public_key(Onion_Announce *onion_a, uint32_t entry);
void onion_announce_entry_set_time(Onion_Announce *onion_a, uint32_t entry, uint64_t time);

/** Create an onion announce request packet in packet of max_packet_length (recommended size ONION_ANNOUNCE_REQUEST_SIZE).
 *
 * dest_client_id is the public key of the node the packet will be sent to.
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return packet length on success.
 */
int create_announce_request(uint8_t *packet, uint16_t max_packet_length, const uint8_t *dest_client_id,
                            const uint8_t *public_key, const uint8_t *secret_key, const uint8_t *ping_id, const uint8_t *client_id,
                            const uint8_t *data_public_key, uint64_t sendback_data);

/** Create an onion data request packet in packet of max_packet_length (recommended size ONION_MAX_PACKET_SIZE).
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_data_request(uint8_t *packet, uint16_t max_packet_length, const uint8_t *public_key,
                        const uint8_t *encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length);

/** Create and send an onion announce request packet.
 *
 * path is the path the request will take before it is sent to dest.
 *
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * data_public_key is the public key we want others to encrypt their data packets with.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_announce_request(const Networking_Core *net, const Onion_Path *path, Node_format dest,
                          const uint8_t *public_key, const uint8_t *secret_key,
                          const uint8_t *ping_id, const uint8_t *client_id,
                          const uint8_t *data_public_key,  uint64_t sendback_data);

/** Create and send an onion data request packet.
 *
 * path is the path the request will take before it is sent to dest.
 * (if dest knows the person with the public_key they should
 * send the packet to that person in the form of a response)
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * The maximum length of data is MAX_DATA_REQUEST_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(const Networking_Core *net, const Onion_Path *path, const IP_Port *dest,
                      const uint8_t *public_key,
                      const uint8_t *encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length);


Onion_Announce *new_onion_announce(const Logger *log, Mono_Time *mono_time, DHT *dht);

void kill_onion_announce(Onion_Announce *onion_a);


#endif
