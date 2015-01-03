/*
* onion.h -- Implementation of the onion part of docs/Prevent_Tracking.txt
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

#ifndef ONION_H
#define ONION_H

#include "DHT.h"

typedef struct {
    DHT     *dht;
    Networking_Core *net;
    uint8_t secret_symmetric_key[crypto_box_KEYBYTES];
    uint64_t timestamp;

    Shared_Keys shared_keys_1;
    Shared_Keys shared_keys_2;
    Shared_Keys shared_keys_3;

    int (*recv_1_function)(void *, IP_Port, const uint8_t *, uint16_t);
    void *callback_object;
} Onion;

#define ONION_MAX_PACKET_SIZE 1400

#define ONION_RETURN_1 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES)
#define ONION_RETURN_2 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES + ONION_RETURN_1)
#define ONION_RETURN_3 (crypto_box_NONCEBYTES + SIZE_IPPORT + crypto_box_MACBYTES + ONION_RETURN_2)

#define ONION_SEND_BASE (crypto_box_PUBLICKEYBYTES + SIZE_IPPORT + crypto_box_MACBYTES)
#define ONION_SEND_3 (crypto_box_NONCEBYTES + ONION_SEND_BASE + ONION_RETURN_2)
#define ONION_SEND_2 (crypto_box_NONCEBYTES + ONION_SEND_BASE*2 + ONION_RETURN_1)
#define ONION_SEND_1 (crypto_box_NONCEBYTES + ONION_SEND_BASE*3)

#define ONION_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1))
#define ONION_RESPONSE_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (1 + ONION_RETURN_3))

typedef struct {
    uint8_t shared_key1[crypto_box_BEFORENMBYTES];
    uint8_t shared_key2[crypto_box_BEFORENMBYTES];
    uint8_t shared_key3[crypto_box_BEFORENMBYTES];

    uint8_t public_key1[crypto_box_PUBLICKEYBYTES];
    uint8_t public_key2[crypto_box_PUBLICKEYBYTES];
    uint8_t public_key3[crypto_box_PUBLICKEYBYTES];

    IP_Port     ip_port1;
    uint8_t     node_public_key1[crypto_box_PUBLICKEYBYTES];

    IP_Port     ip_port2;
    uint8_t     node_public_key2[crypto_box_PUBLICKEYBYTES];

    IP_Port     ip_port3;
    uint8_t     node_public_key3[crypto_box_PUBLICKEYBYTES];

    uint32_t path_num;
} Onion_Path;

/* Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of 3 nodes)
 *
 * new_path must be an empty memory location of atleast Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_onion_path(const DHT *dht, Onion_Path *new_path, const Node_format *nodes);

/* Dump nodes in onion path to nodes of length num_nodes;
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(Node_format *nodes, unsigned int num_nodes, const Onion_Path *path);

/* Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, IP_Port dest,
                        const uint8_t *data, uint16_t length);


/* Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, IP_Port dest,
                            const uint8_t *data, uint16_t length);

/* Create and send a onion packet.
 *
 * Use Onion_Path path to send data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_packet(Networking_Core *net, const Onion_Path *path, IP_Port dest, const uint8_t *data, uint16_t length);

/* Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(Networking_Core *net, IP_Port dest, const uint8_t *data, uint16_t length, const uint8_t *ret);

/* Function to handle/send received decrypted versions of the packet sent with send_onion_packet.
 *
 * return 0 on success.
 * return 1 on failure.
 *
 * Used to handle these packets that are received in a non traditional way (by TCP for example).
 *
 * Source family must be set to something else than AF_INET6 or AF_INET so that the callback gets called
 * when the response is received.
 */
int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, IP_Port source, const uint8_t *nonce);

/* Set the callback to be called when the dest ip_port doesn't have AF_INET6 or AF_INET as the family.
 *
 * Format: function(void *object, IP_Port dest, uint8_t *data, uint16_t length)
 */
void set_callback_handle_recv_1(Onion *onion, int (*function)(void *, IP_Port, const uint8_t *, uint16_t),
                                void *object);

Onion *new_onion(DHT *dht);

void kill_onion(Onion *onion);


#endif
