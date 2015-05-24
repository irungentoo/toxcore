/*
* onion_announce.h -- Implementation of the announce part of docs/Prevent_Tracking.txt
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

#ifndef ONION_ANNOUNCE_H
#define ONION_ANNOUNCE_H

#include "onion.h"

#define ONION_ANNOUNCE_MAX_ENTRIES 96
#define ONION_ANNOUNCE_TIMEOUT 300
#define ONION_PING_ID_SIZE crypto_hash_sha256_BYTES

#define ONION_ANNOUNCE_SENDBACK_DATA_LENGTH (sizeof(uint64_t))

#define ONION_ANNOUNCE_REQUEST_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_MACBYTES)

#define ONION_ANNOUNCE_RESPONSE_MIN_SIZE (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES + 1 + ONION_PING_ID_SIZE + crypto_box_MACBYTES)
#define ONION_ANNOUNCE_RESPONSE_MAX_SIZE (ONION_ANNOUNCE_RESPONSE_MIN_SIZE + sizeof(Node_format)*MAX_SENT_NODES)

#define ONION_DATA_RESPONSE_MIN_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)

#if ONION_PING_ID_SIZE != crypto_box_PUBLICKEYBYTES
#error announce response packets assume that ONION_PING_ID_SIZE is equal to crypto_box_PUBLICKEYBYTES
#endif

#define ONION_DATA_REQUEST_MIN_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
#define MAX_DATA_REQUEST_SIZE (ONION_MAX_DATA_SIZE - ONION_DATA_REQUEST_MIN_SIZE)

typedef struct {
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    IP_Port ret_ip_port;
    uint8_t ret[ONION_RETURN_3];
    uint8_t data_public_key[crypto_box_PUBLICKEYBYTES];
    uint64_t time;
} Onion_Announce_Entry;

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    Onion_Announce_Entry entries[ONION_ANNOUNCE_MAX_ENTRIES];
    /* This is crypto_box_KEYBYTES long just so we can use new_symmetric_key() to fill it */
    uint8_t secret_bytes[crypto_box_KEYBYTES];

    Shared_Keys shared_keys_recv;
} Onion_Announce;

/* Create an onion announce request packet in packet of max_packet_length (recommended size ONION_ANNOUNCE_REQUEST_SIZE).
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

/* Create an onion data request packet in packet of max_packet_length (recommended size ONION_MAX_PACKET_SIZE).
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

/* Create and send an onion announce request packet.
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
int send_announce_request(Networking_Core *net, const Onion_Path *path, Node_format dest, const uint8_t *public_key,
                          const uint8_t *secret_key, const uint8_t *ping_id, const uint8_t *client_id, const uint8_t *data_public_key,
                          uint64_t sendback_data);

/* Create and send an onion data request packet.
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
int send_data_request(Networking_Core *net, const Onion_Path *path, IP_Port dest, const uint8_t *public_key,
                      const uint8_t *encrypt_public_key, const uint8_t *nonce, const uint8_t *data, uint16_t length);


Onion_Announce *new_onion_announce(DHT *dht);

void kill_onion_announce(Onion_Announce *onion_a);


#endif
