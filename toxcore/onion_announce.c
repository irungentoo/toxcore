/*
* onion_announce.c -- Implementation of the announce part of docs/Prevent_Tracking.txt
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_announce.h"
#include "LAN_discovery.h"
#include "util.h"

#define PING_ID_SIZE crypto_hash_sha256_BYTES
#define PING_ID_TIMEOUT 10

#define ANNOUNCE_REQUEST_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES + ONION_RETURN_3)

uint8_t ping_id_zero[PING_ID_SIZE];

/* Generate a ping_id and put it in ping_id */
static void generate_ping_id(Onion_Announce *onion_a, uint64_t time, uint8_t *public_key, uint8_t *ret,
                             uint8_t *ping_id)
{
    time /= PING_ID_TIMEOUT;
    uint8_t data[crypto_secretbox_KEYBYTES + sizeof(time) + crypto_box_PUBLICKEYBYTES + ONION_RETURN_3];
    memcpy(data, onion_a->secret_bytes, crypto_secretbox_KEYBYTES);
    memcpy(data + crypto_secretbox_KEYBYTES, &time, sizeof(time));
    memcpy(data + crypto_secretbox_KEYBYTES + sizeof(time), public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(data + crypto_secretbox_KEYBYTES + sizeof(time) + crypto_box_PUBLICKEYBYTES, ret, ONION_RETURN_3);
    crypto_hash_sha256(ping_id, data, sizeof(data));
}

/* add entry to entries list
 *
 * return 0 if failure
 * return 1 if added
 */
static int add_to_entries(Onion_Announce *onion_a, uint8_t *public_key, uint8_t *ret)
{

    return 0;
}

/* check if public key is in entries list
 *
 * return 0 if no
 * return 1 if yes
 */
static int in_entries(Onion_Announce *onion_a, uint8_t *public_key)
{

    return 0;
}

static int handle_announce_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Announce *onion_a = object;

    if (length != ANNOUNCE_REQUEST_SIZE)
        return 1;

    uint8_t plain[PING_ID_SIZE + crypto_box_PUBLICKEYBYTES];
    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion_a->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    uint8_t ping_id1[PING_ID_SIZE];
    generate_ping_id(onion_a, unix_time(), packet + 1 + crypto_box_NONCEBYTES,
                     packet + (ANNOUNCE_REQUEST_SIZE - ONION_RETURN_3), ping_id1);

    uint8_t ping_id2[PING_ID_SIZE];
    generate_ping_id(onion_a, unix_time() + PING_ID_TIMEOUT, packet + 1 + crypto_box_NONCEBYTES,
                     packet + (ANNOUNCE_REQUEST_SIZE - ONION_RETURN_3), ping_id2);

    int stored = 0;

    if (memcmp(ping_id1, plain, PING_ID_SIZE) == 0 || memcmp(ping_id2, plain, PING_ID_SIZE) == 0) {
        stored = add_to_entries(onion_a, packet + 1 + crypto_box_NONCEBYTES,
                                packet + (ANNOUNCE_REQUEST_SIZE - ONION_RETURN_3));
    } else {
        stored = in_entries(onion_a, plain + PING_ID_SIZE);
    }

    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t num_nodes = get_close_nodes(onion_a->dht, plain + PING_ID_SIZE, nodes_list, source.ip.family,
                                         LAN_ip(source.ip) == 0, 1);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    return 0;
}

static int handle_data_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Announce *onion_a = object;

    return 0;
}

Onion_Announce *new_onion_announce(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion_Announce *onion_a = calloc(1, sizeof(Onion_Announce));

    if (onion_a == NULL)
        return NULL;

    onion_a->dht = dht;
    onion_a->net = dht->c->lossless_udp->net;
    new_symmetric_key(onion_a->secret_bytes);

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_announce_request, onion_a);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, &handle_data_request, onion_a);

    return onion_a;
}

void kill_onion_announce(Onion_Announce *onion_a)
{
    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, NULL, NULL);
    free(onion_a);
}
