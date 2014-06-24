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
#define SEND_ANNOUNCED_NODES_PLAIN_SIZE (1 + sizeof(Node_format) * MAX_SENT_NODES + sizeof(uint64_t))
#define DHT_SEND_ANNOUNCED_NODES_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + SEND_ANNOUNCED_NODES_PLAIN_SIZE + crypto_box_MACBYTES)

struct ANNOUNCE {
    DHT *dht;
    Announced_node_format announced_nodes[MAX_ANNOUNCED_NODES];
    Ping_Array  ping_array;
    uint64_t    last_to_ping;
};

/* Send announce request
 * For members of group chat, who want to announce being online at the current moment
 */
int send_announce_request(ANNOUNCE *announce, IP_Port ipp, uint8_t *client_id, uint8_t *chat_id)
{
    // Check if packet is going to be sent to ourself
    if (id_equal(client_id, announce->dht->self_public_key))
        return -1;

    // Generate random ping_id.
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, client_id);
    memcpy(data + CLIENT_ID_SIZE, &ipp, sizeof(IP_Port));
    uint64_t ping_id = ping_array_add(&announce->ping_array, data, sizeof(data));

    if (ping_id == 0)
        return -1;

    // Generate announce_plain == NET_PACKET_ANNOUNCE_REQUEST + chat_it + ping_id
    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    announce_plain[0] = NET_PACKET_ANNOUNCE_REQUEST;
    id_copy(announce_plain + 1, chat_id);
    memcpy(announce_plain + 1 + CLIENT_ID_SIZE, &ping_id, sizeof(ping_id));

    // Generate shared_key to encrypt announce_plane
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(announce->dht, shared_key, client_id);

    // Generate new nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    // Generate encrypted data
    uint8_t encrypt[ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES];
    int length = encrypt_data_symmetric(shared_key,
                                        nonce,
                                        announce_plain, sizeof(announce_plain),
                                        encrypt);

    if (length != sizeof(encrypt))
        return -1;

    // Generate DHT packet == NET_PACKET_ANNOUNCE_REQUEST + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t   pk[DHT_ANNOUNCE_SIZE];
    pk[0] = NET_PACKET_ANNOUNCE_REQUEST;
    memcpy(pk + 1, announce->dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, length);

    return sendpacket(announce->dht->net, ipp, pk, sizeof(pk));    
}

static int handle_announce_request(void * _dht, IP_Port ipp, uint8_t *packet, uint32_t length)
{
    DHT *dht = _dht;

    // Check if we got packet of expected size
    if (length != DHT_ANNOUNCE_SIZE)
        return -1;

    // Check if packet is going to be sent to ourself
    if (id_equal(packet + 1, dht->self_public_key))
        return -1;

    // Generate key to decrypt announce_plain
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_recv(dht, shared_key, packet + 1);

    // Decrypt announce_plain
    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    int length = decrypt_data_symmetric(shared_key,
                                        packet + 1 + CLIENT_ID_SIZE,
                                        packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                        ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES,
                                        announce_plain);

    if (length != sizeof(announce_plain))
        return -1;

    // Check if we got correct packet type
    if (announce_plain[0] != NET_PACKET_ANNOUNCE_REQUEST)
        return -1;

    // Get ping_id
    uint64_t  ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE, sizeof(ping_id));

    //Save (client_id, chat_id) in our ANNOUNCE structure
    add_announced_nodes(dht->announce, packet + 1, announce_plain + 1, ipp)

    //Not implemented, don't know if it's needed for now
    //send_announce_response(dht->announce, ipp, packet + 1, ping_id, shared_key);

    return 0;
}

/* Send a getnodes request.
 */
int get_announced_nodes_request(DHT * dht, IP_Port ipp, uint8_t *client_id, uint8_t *chat_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(client_id, dht->self_public_key))
        return -1;

    // Generate random ping_id
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, client_id);
    memcpy(data + CLIENT_ID_SIZE, &ipp, sizeof(IP_Port));
    uint64_t ping_id = ping_array_add(dht->announce->ping_array, data, sizeof(data));

    if (ping_id == 0)
        return -1;

    // Generate announce_plain == NET_PACKET_GET_ANNOUNCED_NODES + chat_id + ping_id
    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    announce_plain[0] = NET_PACKET_GET_ANNOUNCED_NODES;
    id_copy(announce_plain + 1, chat_id);
    memcpy(announce_plain + 1 + CLIENT_ID_SIZE, &ping_id, sizeof(ping_id));

    // Generate shared_key to encrypt announce_plane
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, public_key);

    // Generate new nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    // Generate encrypted data
    uint8_t encrypt[ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES];
    int length = encrypt_data_symmetric(shared_key,
                                        nonce,
                                        announce_plain,
                                        sizeof(announce_plain),
                                        encrypt);

    if (length != sizeof(encrypt))
        return -1;

    // Generate DHT packet == NET_PACKET_GET_ANNOUNCED_NODES + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t pk[DHT_ANNOUNCE_SIZE];
    pk[0] = NET_PACKET_GET_ANNOUNCED_NODES;
    memcpy(pk + 1, dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, length);

    return sendpacket(dht->net, ipp, pk, sizeof(pk));
}

static int handle_get_announced_nodes_request(void *_dht, IP_Port ipp, uint8_t *packet, uint32_t length)
{
    DHT *dht = _dht;

    // Check if we got packet of expected size
    if (length != DHT_ANNOUNCE_SIZE)
        return -1;
    
    // Check if packet is going to be sent to ourself
    if (id_equal(packet + 1, dht->self_public_key))
        return -1;

    // Generate key to decrypt announce_plain
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_recv(dht, shared_key, packet + 1);

    // Decrypt announce_plain
    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    int length = decrypt_data_symmetric(shared_key,
                                        packet + 1 + CLIENT_ID_SIZE,
                                        packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                        ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES,
                                        announce_plain);

    if (length != sizeof(announce_plain))
        return -1;

    // Check if we got correct packet type
    if (announce_plain[0] != NET_PACKET_GET_ANNOUNCED_NODES)
        return -1;

    // Get ping_id
    uint64_t  ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE, sizeof(ping_id));

    //To implement
    //send_announced_nodes(dht, ipp, packet + 1, plain, plain + CLIENT_ID_SIZE, sizeof(uint64_t), shared_key);

    return 0;
}


int send_announced_nodes_response(DHT *dht, IP_Port ipp, uint8_t *client_id, uint8_t *chat_id, uint64_t ping_id,
                                  uint8_t *shared_encryption_key)
{ 
    // Check if packet is going to be sent to ourself.
    if (id_equal(client_id, dht->self_public_key))
        return -1;

    size_t Node_format_size = sizeof(Node_format);
    
    // Get announced nodes from ANNOUNCE list by chat_id
    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t num_nodes = get_announced_nodes(dht->announce, chat_id, nodes_list);
    if (num_nodes == -1)
        return -1;

    // Generate announce_plain == num_nodes + nodes_length + ping_id
    uint8_t announce_plain[SEND_ANNOUNCED_NODES_PLAIN_SIZE];
    announce_plain[0] = num_nodes;
    
    int nodes_length = pack_nodes(announce_plain + 1, Node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);
    if (nodes_length <= 0)
        return -1;
    
    memcpy(announce_plain + 1 + nodes_length, &ping_id, sizeof(ping_id)

    // Generate new nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    // Generate encrypted data
    uint8_t encrypt[sizeof(announce_plain) + crypto_box_MACBYTES];
    int length = encrypt_data_symmetric(shared_encryption_key,
                                        nonce,
                                        plain,
                                        sizeof(announce_plain),
                                        encrypt);

    if (length != sizeof(encrypt))
        return -1;

    // Generate DHT packet == NET_PACKET_SEND_ANNOUNCED_NODES + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t pk[DHT_SEND_ANNOUNCED_NODES_SIZE];
    pk[0] = NET_PACKET_SEND_ANNOUNCED_NODES;
    memcpy(pk + 1, dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, length);

    return sendpacket(dht->net, ipp, pk, sizeof(pk));    
}

int handle_send_announced_nodes_response(void *_dht, IP_Port ipp, uint8_t *packet, uint32_t length)
{
}

/* Add nodes to the announced_nodes list.
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

    uint32_t i;

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
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

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (id_closest(announce->dht->self_public_key, announce->announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].client_id, client_id) == 2) {
            memcpy(announce->announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].client_id, client_id, CLIENT_ID_SIZE);
            memcpy(announce->announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].chat_id, chat_id, CLIENT_ID_SIZE);
            ipport_copy(&announce->announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].ip_port, &ip_port);
            return 0;
        }
    }

    return -1;
}

/* Get nodes from the announced_nodes list given chat_id.
 *
 *  return num_nodes if found.
 *  return -1 if not found.
 */
int get_announced_nodes(ANNOUNCE *announce, uint8_t *chat_id, Node_format *nodes_list)
{
    uint32_t num_nodes = -1;
    for (uint32_t i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (ip_isset(&announce->announced_nodes[i].ip_port.ip)) {
            if (id_equal(chat_id, &announce->announced_nodes[i]).chat_id) {
                num_nodes++;
                memcpy(nodes_list[num_nodes].client_id, &announce->announced_nodes[i], CLIENT_ID_SIZE);
                ipport_copy(nodes_list[num_nodes].ip_port, &announce->announced_nodes[i].ip_port);
            }
        }
    }

    return num_nodes+1;
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