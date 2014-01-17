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

#define PING_ID_TIMEOUT 20

#define ANNOUNCE_REQUEST_SIZE (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_MACBYTES)
#define ANNOUNCE_REQUEST_SIZE_RECV (ANNOUNCE_REQUEST_SIZE + ONION_RETURN_3)

#define DATA_REQUEST_MIN_SIZE (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)
#define DATA_REQUEST_MIN_SIZE_RECV (DATA_REQUEST_MIN_SIZE + ONION_RETURN_3)

/* Create and send an onion announce request packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the announe
 * request will be sent to 3.
 *
 * public_key and secret_key is the kepair which will be used to encrypt the request.
 * ping_id is the ping id that will be sent in the request.
 * client_id is the client id of the node we are searching for.
 * sendback_data is the data of ONION_ANNOUNCE_SENDBACK_DATA_LENGTH length that we expect to
 * receive back in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_announce_request(DHT *dht, Node_format *nodes, uint8_t *public_key, uint8_t *secret_key, uint8_t *ping_id,
                          uint8_t *client_id, uint8_t *sendback_data)
{
    uint8_t plain[ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
    memcpy(plain, ping_id, ONION_PING_ID_SIZE);
    memcpy(plain + ONION_PING_ID_SIZE, client_id, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES, sendback_data, ONION_ANNOUNCE_SENDBACK_DATA_LENGTH);
    uint8_t packet[ANNOUNCE_REQUEST_SIZE];
    packet[0] = NET_PACKET_ANNOUNCE_REQUEST;
    new_nonce(packet + 1);

    int len = encrypt_data(nodes[3].client_id, secret_key, packet + 1, plain, sizeof(plain),
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES != ANNOUNCE_REQUEST_SIZE)
        return -1;

    memcpy(packet + 1 + crypto_box_NONCEBYTES, public_key, crypto_box_PUBLICKEYBYTES);

    return send_onion_packet(dht, nodes, packet, sizeof(packet));
}

/* Create and send an onion data request packet.
 *
 * nodes is a list of 4 nodes, the packet will route through nodes 0, 1, 2 and the data
 * request packet will arrive at 3. (if 3 knows the person with the public_key they should
 * send the packet to that person in the form of a response)
 *
 * public_key is the real public key of the node which we want to send the data of length length to.
 * nonce is the nonce to encrypt this packet with
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_data_request(DHT *dht, Node_format *nodes, uint8_t *public_key, uint8_t *nonce, uint8_t *data, uint16_t length)
{
    uint8_t packet[DATA_REQUEST_MIN_SIZE + length];
    packet[0] = NET_PACKET_ONION_DATA_REQUEST;
    memcpy(packet + 1, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);

    uint8_t random_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t random_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(random_public_key, random_secret_key);

    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, random_public_key, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data(public_key, random_secret_key, packet + 1 + crypto_box_PUBLICKEYBYTES,
                           data, length, packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES);

    if (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + (uint32_t)len != sizeof(packet))
        return -1;

    return send_onion_packet(dht, nodes, packet, sizeof(packet));
}

/* Generate a ping_id and put it in ping_id */
static void generate_ping_id(Onion_Announce *onion_a, uint64_t time, uint8_t *public_key, IP_Port ret_ip_port,
                             uint8_t *ping_id)
{
    time /= PING_ID_TIMEOUT;
    uint8_t data[crypto_secretbox_KEYBYTES + sizeof(time) + crypto_box_PUBLICKEYBYTES + sizeof(ret_ip_port)];
    memcpy(data, onion_a->secret_bytes, crypto_secretbox_KEYBYTES);
    memcpy(data + crypto_secretbox_KEYBYTES, &time, sizeof(time));
    memcpy(data + crypto_secretbox_KEYBYTES + sizeof(time), public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(data + crypto_secretbox_KEYBYTES + sizeof(time) + crypto_box_PUBLICKEYBYTES, &ret_ip_port, sizeof(ret_ip_port));
    crypto_hash_sha256(ping_id, data, sizeof(data));
}

/* check if public key is in entries list
 *
 * return -1 if no
 * return position in list if yes
 */
static int in_entries(Onion_Announce *onion_a, uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
        if (!is_timeout(onion_a->entries[i].time, ONION_ANNOUNCE_TIMEOUT)
                && memcmp(onion_a->entries[i].public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
            return i;
    }

    return -1;
}

static uint8_t cmp_public_key[crypto_box_PUBLICKEYBYTES];
static int cmp_entry(const void *a, const void *b)
{
    Onion_Announce_Entry entry1, entry2;
    memcpy(&entry1, a, sizeof(Onion_Announce_Entry));
    memcpy(&entry2, b, sizeof(Onion_Announce_Entry));
    int t1 = is_timeout(entry1.time, ONION_ANNOUNCE_TIMEOUT);
    int t2 = is_timeout(entry2.time, ONION_ANNOUNCE_TIMEOUT);

    if (t1 && t2)
        return 0;

    if (t1)
        return -1;

    if (t2)
        return 1;

    int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (close == 1)
        return 1;

    if (close == 2)
        return -1;

    return 0;
}

/* add entry to entries list
 *
 * return 0 if failure
 * return 1 if added
 */
static int add_to_entries(Onion_Announce *onion_a, IP_Port ret_ip_port, uint8_t *public_key, uint8_t *ret)
{

    int pos = in_entries(onion_a, public_key);

    uint32_t i;

    if (pos == -1) {
        for (i = 0; i < ONION_ANNOUNCE_MAX_ENTRIES; ++i) {
            if (is_timeout(onion_a->entries[i].time, ONION_ANNOUNCE_TIMEOUT))
                pos = i;
        }
    }

    if (pos == -1) {
        if (id_closest(onion_a->dht->self_public_key, public_key, onion_a->entries[0].public_key) == 1)
            pos = 0;
    }

    if (pos == -1)
        return 0;

    memcpy(onion_a->entries[pos].public_key, public_key, crypto_box_PUBLICKEYBYTES);
    onion_a->entries[pos].ret_ip_port = ret_ip_port;
    memcpy(onion_a->entries[pos].ret, ret, ONION_RETURN_3);
    onion_a->entries[pos].time = unix_time();

    memcpy(cmp_public_key, onion_a->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    qsort(onion_a->entries, ONION_ANNOUNCE_MAX_ENTRIES, sizeof(Onion_Announce_Entry), cmp_entry);
    return 1;
}

static int handle_announce_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Announce *onion_a = object;

    if (length != ANNOUNCE_REQUEST_SIZE_RECV)
        return 1;

    uint8_t plain[ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion_a->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_MACBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    uint8_t ping_id1[ONION_PING_ID_SIZE];
    generate_ping_id(onion_a, unix_time(), packet + 1 + crypto_box_NONCEBYTES, source, ping_id1);

    uint8_t ping_id2[ONION_PING_ID_SIZE];
    generate_ping_id(onion_a, unix_time() + PING_ID_TIMEOUT, packet + 1 + crypto_box_NONCEBYTES, source, ping_id2);

    int stored = 0;

    if (memcmp(ping_id1, plain, ONION_PING_ID_SIZE) == 0 || memcmp(ping_id2, plain, ONION_PING_ID_SIZE) == 0) {
        stored = add_to_entries(onion_a, source, packet + 1 + crypto_box_NONCEBYTES,
                                packet + (ANNOUNCE_REQUEST_SIZE_RECV - ONION_RETURN_3));
    } else {
        stored = (in_entries(onion_a, plain + ONION_PING_ID_SIZE) != -1);
    }

    /*Respond with a announce response packet*/
    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t num_nodes = get_close_nodes(onion_a->dht, plain + ONION_PING_ID_SIZE, nodes_list, source.ip.family,
                                         LAN_ip(source.ip) == 0, 1);

    uint32_t i;

    for (i = 0; i < num_nodes; ++i)
        to_net_family(&nodes_list[i].ip_port.ip);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t pl[ONION_PING_ID_SIZE + sizeof(nodes_list)] = {0};

    if (!stored) {
        memcpy(pl, ping_id2, ONION_PING_ID_SIZE);
    }

    memcpy(pl + ONION_PING_ID_SIZE, nodes_list, num_nodes * sizeof(Node_format));

    uint8_t data[ONION_ANNOUNCE_RESPONSE_MAX_SIZE];
    len = encrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion_a->dht->self_secret_key, nonce, pl,
                       ONION_PING_ID_SIZE + num_nodes * sizeof(Node_format),
                       data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES);

    if ((uint32_t)len != ONION_PING_ID_SIZE + num_nodes * sizeof(Node_format) + crypto_box_MACBYTES)
        return 1;

    data[0] = NET_PACKET_ANNOUNCE_RESPONSE;
    memcpy(data + 1, plain + ONION_PING_ID_SIZE + crypto_box_PUBLICKEYBYTES, ONION_ANNOUNCE_SENDBACK_DATA_LENGTH);
    memcpy(data + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH, nonce, crypto_box_NONCEBYTES);

    if (send_onion_response(onion_a->net, source, data,
                            1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES + len,
                            packet + (ANNOUNCE_REQUEST_SIZE_RECV - ONION_RETURN_3)) == -1)
        return 1;

    return 0;
}

static int handle_data_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Announce *onion_a = object;

    if (length <= DATA_REQUEST_MIN_SIZE_RECV)
        return 1;

    if (length >= MAX_DATA_SIZE)
        return 1;

    int index = in_entries(onion_a, packet + 1);

    if (index == -1)
        return 1;

    uint8_t data[length - (crypto_box_PUBLICKEYBYTES + ONION_RETURN_3)];
    data[0] = NET_PACKET_ONION_DATA_RESPONSE;
    memcpy(data + 1, packet + 1 + crypto_box_PUBLICKEYBYTES, length - (1 + crypto_box_PUBLICKEYBYTES + ONION_RETURN_3));

    if (send_onion_response(onion_a->net, onion_a->entries[index].ret_ip_port, data, sizeof(data),
                            onion_a->entries[index].ret) == -1)
        return 1;

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
    if (onion_a == NULL)
        return;

    networking_registerhandler(onion_a->net, NET_PACKET_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(onion_a->net, NET_PACKET_ONION_DATA_REQUEST, NULL, NULL);
    free(onion_a);
}
