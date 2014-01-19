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

#define ONION_ANNOUNCE_MAX_ENTRIES 32
#define ONION_ANNOUNCE_TIMEOUT 300
#define ONION_PING_ID_SIZE crypto_hash_sha256_BYTES

#define ONION_ANNOUNCE_SENDBACK_DATA_LENGTH (crypto_secretbox_NONCEBYTES + sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES + sizeof(IP_Port) + crypto_secretbox_MACBYTES)

#define ONION_ANNOUNCE_RESPONSE_MIN_SIZE (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES + 1 + ONION_PING_ID_SIZE + crypto_box_MACBYTES)
#define ONION_ANNOUNCE_RESPONSE_MAX_SIZE (ONION_ANNOUNCE_RESPONSE_MIN_SIZE + sizeof(Node_format)*MAX_SENT_NODES)

#define ONION_DATA_RESPONSE_MIN_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)

#if ONION_PING_ID_SIZE != crypto_box_PUBLICKEYBYTES
#error announce response packets assume that ONION_PING_ID_SIZE is equal to crypto_box_PUBLICKEYBYTES
#endif

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
    /* This is crypto_secretbox_KEYBYTES long just so we can use new_symmetric_key() to fill it */
    uint8_t secret_bytes[crypto_secretbox_KEYBYTES];
} Onion_Announce;

/* Create and send an onion announce request packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the announe
 * request will be sent to 3.
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
int send_announce_request(DHT *dht, Node_format *nodes, uint8_t *public_key, uint8_t *secret_key, uint8_t *ping_id,
                          uint8_t *client_id, uint8_t *data_public_key, uint8_t *sendback_data);

/* Create and send an onion data request packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the data
 * request packet will arrive at 3. (if 3 knows the person with the public_key they should
 * send the packet to that person in the form of a response)
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * encrypt_public_key is the public key used to encrypt the data packet.
 *
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(DHT *dht, Node_format *nodes, uint8_t *public_key, uint8_t *encrypt_public_key, uint8_t *nonce,
                      uint8_t *data, uint16_t length);


Onion_Announce *new_onion_announce(DHT *dht);

void kill_onion_announce(Onion_Announce *onion_a);


#endif
