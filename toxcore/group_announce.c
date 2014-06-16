/*
 * group_announce.h -- Similar to ping.h, but designed for group chat purposes
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "DHT.h"
#include "announce.h"
#include "ping.h"

#include "network.h"
#include "util.h"
#include "ping_array.h"

/* Maximum newly announced online (in terms of group chats) nodes to ping per TIME_TO_PING seconds. */
#define MAX_ANNOUNCED_NODES 30

// CLIENT_ID_SIZE for chat_id in ANNOUNCE_PLAIN_SIZE
#define ANNOUNCE_PLAIN_SIZE (1 + CLIENT_ID_SIZE + sizeof(uint64_t))
#define DHT_ANNOUNCE_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES)
//#define ANNOUNCE_DATA_SIZE (CLIENT_ID_SIZE + CLIENT_ID_SIZE + sizeof(IP_Port))


struct ANNOUNCE {
    DHT *dht;
    Announced_node_format announced_nodes[MAX_ANNOUNCED_NODES];
};

/* Send announce request
 * For members of group chat, who want to announce being online at the current moment
 * Announcing node should send chat_id together with other info
 * We store pinged nodes in PING structure
 */
int send_announce_request(PING *ping, IP_Port ipp, uint8_t *client_id, uint8_t *chat_id)
{
    uint8_t   pk[DHT_ANNOUNCE_SIZE];
    int       rc;
    uint64_t  ping_id;

    if (id_equal(client_id, ping->dht->self_public_key))
        return 1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    // generate key to encrypt ping_id with recipient privkey
    DHT_get_shared_key_sent(ping->dht, shared_key, client_id);
    // Generate random ping_id.
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, client_id);
    memcpy(data + CLIENT_ID_SIZE, &ipp, sizeof(IP_Port));
    ping_id = ping_array_add(&ping->ping_array, data, sizeof(data));

    if (ping_id == 0)
        return 1;

    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    announce_plain[0] = NET_PACKET_ANNOUNCE_REQUEST;
    id_copy(announce_plain + 1, chat_id);     // Our pubkey
    memcpy(announce_plain + 1 + CLIENT_ID_SIZE, &ping_id, sizeof(ping_id));

    pk[0] = NET_PACKET_ANNOUNCE_REQUEST;
    id_copy(pk + 1, ping->dht->self_public_key);     // Our pubkey
    new_nonce(pk + 1 + CLIENT_ID_SIZE); // Generate new nonce

    //rc - length
    rc = encrypt_data_symmetric(shared_key,
                                pk + 1 + CLIENT_ID_SIZE,
                                announce_plain, sizeof(announce_plain),
                                pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES);

    if (rc != ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES)
        return 1;

    return sendpacket(ping->dht->net, ipp, pk, sizeof(pk));    
}

static int handle_announce_request(void * _dht, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = _dht;
    int rc;

    if (length != DHT_ANNOUNCE_SIZE)
        return 1;

    if (id_equal(packet + 1, dht->self_public_key))
        return 1;

    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    // Decrypt ping_id
    DHT_get_shared_key_recv(dht, shared_key, packet + 1);
    rc = decrypt_data_symmetric(shared_key,
                                packet + 1 + CLIENT_ID_SIZE,
                                packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES,
                                announce_plain);

    if (rc != sizeof(announce_plain))
        return 1;

    if (announce_plain[0] != NET_PACKET_ANNOUNCE_REQUEST)
        return 1;

    uint64_t   ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE, sizeof(ping_id));

    //Here, we need to save (client_id, chat_id) in our ANNOUNCE structure

    // Send response. For now I don't see why we should create new type of response
    // And I'm not sure if we need to response:)
    //send_ping_response(dht->ping, source, packet + 1, ping_id, shared_key);

    return 0;
}

int get_announced_nodes_request(DHT * dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, Node_format *sendback_node)
{

    /* Check if packet is going to be sent to ourself. */
    /*if (id_equal(public_key, dht->self_public_key))
        return -1;

    uint8_t plain_message[sizeof(Node_format) * 2] = {0};

    Node_format receiver;
    memcpy(receiver.client_id, public_key, CLIENT_ID_SIZE);
    receiver.ip_port = ip_port;
    memcpy(plain_message, &receiver, sizeof(receiver));

    uint64_t ping_id = 0;

    if (sendback_node != NULL) {
        memcpy(plain_message + sizeof(receiver), sendback_node, sizeof(Node_format));
        ping_id = ping_array_add(&dht->dht_harden_ping_array, plain_message, sizeof(plain_message));
    } else {
        ping_id = ping_array_add(&dht->dht_ping_array, plain_message, sizeof(receiver));
    }

    if (ping_id == 0)
        return -1;

    uint8_t plain[CLIENT_ID_SIZE + sizeof(ping_id)];
    uint8_t encrypt[sizeof(plain) + crypto_box_MACBYTES];
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(encrypt)];

    memcpy(plain, client_id, CLIENT_ID_SIZE);
    memcpy(plain + CLIENT_ID_SIZE, &ping_id, sizeof(ping_id));

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, public_key);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    int len = encrypt_data_symmetric( shared_key,
                                      nonce,
                                      plain,
                                      sizeof(plain),
                                      encrypt );

    if (len != sizeof(encrypt))
        return -1;

    data[0] = NET_PACKET_GET_NODES;
    memcpy(data + 1, dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->net, ip_port, data, sizeof(data));
*/
}

static int handle_get_announced_nodes_request(DHT * dht, IP_Port source, uint8_t *packet, uint32_t length)
{
 /*
 * static int sendnodes_ipv6(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, uint8_t *sendback_data,
 *                         uint16_t length, uint8_t *shared_encryption_key)
 */
}

/* Add nodes to the announced_nodes list.
 * All nodes in this list are pinged every TIME_TO_PING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to store information about members of
 * group chats who are online now and give that info to users who want to join.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_announced_nodes(ANNOUNCE *announce, uint8_t *client_id, uint8_t *chat_id, IP_Port ip_port)
{
    if (!ip_isset(&ip_port.ip))
    return -1;

    if (in_list(announce->dht->close_clientlist, LCLIENT_LIST, client_id, ip_port))
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (!ip_isset(&announce->announced_nodes[i].ip_port.ip)) {
            memcpy(announce->announced_nodes[i].client_id, client_id, CLIENT_ID_SIZE);
            memcpy(announce->announced_nodes[i].chat_id, chat_id, CLIENT_ID_SIZE);
            ipport_copy(&announce->announced_nodes[i].ip_port, &ip_port);
            return 0;
        }

        if (memcmp(announce->announced_nodes[i].client_id, client_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }

        if (memcmp(announce->announced_nodes[i].chat_id, chat_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }
    }

    uint32_t r = rand();

    for (i = 0; i < MAX_TO_PING; ++i) {
        if (id_closest(announce->dht->self_public_key, announce->announced_nodes[(i + r) % MAX_TO_PING].client_id, client_id) == 2) {
            memcpy(announce->announced_nodes[(i + r) % MAX_TO_PING].client_id, client_id, CLIENT_ID_SIZE);
            memcpy(announce->announced_nodes[(i + r) % MAX_TO_PING].chat_id, chat_id, CLIENT_ID_SIZE);
            ipport_copy(&announce->announced_nodes[(i + r) % MAX_TO_PING].ip_port, &ip_port);
            return 0;
        }
    }

    return -1;
}

ANNOUNCE *new_announce(DHT *dht)
{
	ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

    if (ping_array_init(&announce->ping_array, PING_NUM_MAX, PING_TIMEOUT) != 0) {
        free(announce);
        return NULL;
    }

    announce->dht = dht;
    networking_registerhandler(announce->dht->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_announce_request, dht);
    networking_registerhandler(announce->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, &handle_get_announced_nodes_request, dht);

    return announce;
}

void kill_announce(ANNOUNCE *announce)
{
	networking_registerhandler(announce->dht->net, NET_PACKET_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, NULL, NULL);
    ping_array_free_all(&announce->ping_array);

    free(announce);
}