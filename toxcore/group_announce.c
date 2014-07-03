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

#include "group_announce.h"

#include "logger.h"
#include "util.h"

#include "network.h"
#include "DHT.h"
#include "ping.h"
#include "ping_array.h"

#define PING_NUM_MAX 512

// CLIENT_ID_SIZE for chat_id in ANNOUNCE_PLAIN_SIZE
#define ANNOUNCE_PLAIN_SIZE (1 + CLIENT_ID_SIZE + sizeof(uint64_t))
#define DHT_ANNOUNCE_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES)
#define SEND_ANNOUNCED_NODES_PLAIN_SIZE (1 + sizeof(Node_format) * MAX_SENT_NODES + sizeof(uint64_t))
#define DHT_SEND_ANNOUNCED_NODES_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + SEND_ANNOUNCED_NODES_PLAIN_SIZE + crypto_box_MACBYTES)

struct ANNOUNCE {
    DHT *dht;
    Announced_node_format announced_nodes[MAX_ANNOUNCED_NODES]; // The nodes, which you store for others
    Announced_node_format my_announced_nodes[MAX_ANNOUNCED_NODES]; // The nodes you found to join particular chat. Must be cleaned up after use.
    Ping_Array  ping_array;
    uint64_t    last_to_ping;
};

/* Send announce request
 * For members of group chat, who want to announce being online at the current moment
 *
 * return -1 on failure
 * return 0 on success
 */
int send_gc_announce_request(ANNOUNCE *announce, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id)
{
    LOGGER_DEBUG("Inside group announce request");
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
    int encrypt_length = encrypt_data_symmetric(shared_key,
                                        nonce,
                                        announce_plain, sizeof(announce_plain),
                                        encrypt);

    if (encrypt_length != sizeof(encrypt))
        return -1;

    // Generate DHT packet == NET_PACKET_ANNOUNCE_REQUEST + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t   pk[DHT_ANNOUNCE_SIZE];
    pk[0] = NET_PACKET_ANNOUNCE_REQUEST;
    memcpy(pk + 1, announce->dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, encrypt_length);

    if ((uint32_t)sendpacket(announce->dht->net, ipp, pk, sizeof(pk)) != sizeof(pk))
        return -1;

    return 0;    
}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_gc_announce_request(void * _dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    LOGGER_DEBUG("Inside handle group announce request");
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
    int announce_length = decrypt_data_symmetric(shared_key,
                                        packet + 1 + CLIENT_ID_SIZE,
                                        packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                        ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES,
                                        announce_plain);

    if (announce_length != sizeof(announce_plain))
        return -1;

    // Check if we got correct packet type
    if (announce_plain[0] != NET_PACKET_ANNOUNCE_REQUEST)
        return -1;

    // Get ping_id
    uint64_t  ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE, sizeof(ping_id));

    //Save (client_id, chat_id) in our ANNOUNCE structure
    add_announced_nodes(dht->announce, packet + 1, announce_plain + 1, ipp, 0);
    
    LOGGER_INFO("handle_gc_ann_req: %s at %s:%d claims to be part of chat %s", id_toa(packet + 1), ip_ntoa(&ipp.ip), ipp.port, id_toa(announce_plain + 1));
    
    // TODO: repeat the message to the nodes closest to chat id if there is any closer node than we are

    //Not implemented, don't know if it's needed for now
    //send_announce_response(dht->announce, ipp, packet + 1, ping_id, shared_key);

    return 0;
}

/* Send a getnodes request.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int get_gc_announced_nodes_request(DHT * dht, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id)
{
    LOGGER_DEBUG("Inside get announced nodes request");
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(client_id, dht->self_public_key))
        return -1;

    // Generate random ping_id
    uint8_t data[PING_DATA_SIZE];
    id_copy(data, client_id);
    memcpy(data + CLIENT_ID_SIZE, &ipp, sizeof(IP_Port));
    uint64_t ping_id = ping_array_add(&dht->announce->ping_array, data, sizeof(data));

    if (ping_id == 0)
        return -1;

    // Generate announce_plain == NET_PACKET_GET_ANNOUNCED_NODES + chat_id + ping_id
    uint8_t announce_plain[ANNOUNCE_PLAIN_SIZE];
    announce_plain[0] = NET_PACKET_GET_ANNOUNCED_NODES;
    id_copy(announce_plain + 1, chat_id);
    memcpy(announce_plain + 1 + CLIENT_ID_SIZE, &ping_id, sizeof(ping_id));

    // Generate shared_key to encrypt announce_plane
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, client_id);

    // Generate new nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    // Generate encrypted data
    uint8_t encrypt[ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES];
    int encrypt_length = encrypt_data_symmetric(shared_key,
                                        nonce,
                                        announce_plain,
                                        sizeof(announce_plain),
                                        encrypt);

    if (encrypt_length != sizeof(encrypt))
        return -1;

    // Generate DHT packet == NET_PACKET_GET_ANNOUNCED_NODES + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t pk[DHT_ANNOUNCE_SIZE];
    pk[0] = NET_PACKET_GET_ANNOUNCED_NODES;
    memcpy(pk + 1, dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, encrypt_length);

    if ((uint32_t)sendpacket(dht->net, ipp, pk, sizeof(pk)) != sizeof(pk))
        return -1;

    return 0;
}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_get_gc_announced_nodes_request(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    LOGGER_DEBUG("Inside handle get announced nodes request");

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
    int announce_length = decrypt_data_symmetric(shared_key,
                                        packet + 1 + CLIENT_ID_SIZE,
                                        packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                        ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES,
                                        announce_plain);

    if (announce_length != sizeof(announce_plain))
        return -1;

    // Check if we got correct packet type
    if (announce_plain[0] != NET_PACKET_GET_ANNOUNCED_NODES)
        return -1;

    // Get ping_id
    uint64_t  ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE, sizeof(ping_id));

    char originatortxt[CLIENT_ID_SIZE*2+1];
    char chatidtxt[CLIENT_ID_SIZE*2+1];
    strcpy(originatortxt, id_toa(packet + 1));
    strcpy(chatidtxt, id_toa(announce_plain + 1));
    
    LOGGER_DEBUG("handle_gc_ann_req: %s at %s:%d requests members of chat %s", originatortxt, ip_ntoa(&ipp.ip), ipp.port, chatidtxt);

    // Send nodes request
    return send_gc_announced_nodes_response(dht, ipp, packet + 1, announce_plain + 1, ping_id, shared_key);

}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
int send_gc_announced_nodes_response(DHT *dht, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id, uint64_t ping_id,
                                  uint8_t *shared_encryption_key)
{ 
    LOGGER_DEBUG("Inside send announced nodes response");

    // Check if packet is going to be sent to ourself.
    if (id_equal(client_id, dht->self_public_key))
        return -1;

    size_t Node_format_size = sizeof(Node_format);
    
    // Get announced nodes from ANNOUNCE list by chat_id
    Node_format nodes_list[MAX_SENT_NODES]; // WARNING: what if MAX_SENT_NODES < MAX_ANNOUNCED_NODES ?
    uint32_t num_nodes = get_announced_nodes(dht->announce, chat_id, nodes_list, 0);
    //LOGGER_DEBUG("Inside send nodes response, num_nodes: %u", num_nodes);
    if (num_nodes == -1)
        return -1;

    // Generate announce_plain == num_nodes + nodes_length + ping_id
    uint8_t announce_plain[SEND_ANNOUNCED_NODES_PLAIN_SIZE];
    announce_plain[0] = num_nodes;
    memcpy(announce_plain + 1, chat_id, CLIENT_ID_SIZE); 

    int nodes_length = pack_nodes(announce_plain + 1 + CLIENT_ID_SIZE, Node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);
    if (nodes_length <= 0)
        return -1;
    
    memcpy(announce_plain + 1 + CLIENT_ID_SIZE + nodes_length, &ping_id, sizeof(ping_id));

    // Generate new nonce
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    // Generate encrypted data
    uint8_t encrypt[sizeof(announce_plain) + crypto_box_MACBYTES];
    int encrypt_length = encrypt_data_symmetric(shared_encryption_key,
                                        nonce,
                                        announce_plain,
                                        1 + CLIENT_ID_SIZE + nodes_length + sizeof(ping_id),
                                        encrypt);

    if (encrypt_length != 1 + CLIENT_ID_SIZE + nodes_length + sizeof(ping_id) + crypto_box_MACBYTES)
        return -1;

    // Generate DHT packet == NET_PACKET_SEND_ANNOUNCED_NODES + client_id + nonce + announce_plain + crypto_box_MACBYTES
    uint8_t pk[DHT_SEND_ANNOUNCED_NODES_SIZE];
    pk[0] = NET_PACKET_SEND_ANNOUNCED_NODES;
    memcpy(pk + 1, dht->self_public_key, CLIENT_ID_SIZE);
    memcpy(pk + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(pk + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, encrypt_length);

    uint32_t new_pk_length = 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + encrypt_length;
    if ((uint32_t)sendpacket(dht->net, ipp, pk, new_pk_length) != sizeof(new_pk_length))
        return -1;

    return 0;

}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
int handle_send_gc_announced_nodes_response(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    LOGGER_DEBUG("Inside handle send announced nodes response");

    DHT *dht = _dht;
    
    // Check packet size  
    uint32_t cid_size = 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + 1 + CLIENT_ID_SIZE + sizeof(uint64_t) + crypto_box_MACBYTES;  
    if (length <= cid_size) /* too short */
        return -1;

    uint32_t data_size = length - cid_size;
    if (data_size == 0)
        return -1;
    if (data_size > sizeof(Node_format) * MAX_SENT_NODES) /* invalid length */
        return -1;

    // Check if packet is going to be sent to ourself
    if (id_equal(packet + 1, dht->self_public_key))
        return -1;

    // Check if we got correct packet type
    if (packet[0] != NET_PACKET_SEND_ANNOUNCED_NODES)
        return -1;
    
    // Generate key to decrypt announce_plain
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_recv(dht, shared_key, packet + 1);

    uint8_t announce_plain[1 + CLIENT_ID_SIZE + data_size + sizeof(uint64_t)];
    int announce_length = decrypt_data_symmetric(shared_key,
                                        packet + 1 + CLIENT_ID_SIZE,
                                        packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                                        sizeof(announce_plain) + crypto_box_MACBYTES,
                                        announce_plain);
    
    if (announce_length != sizeof(announce_plain))
        return -1;
   
    if (announce_plain[0] > MAX_SENT_NODES || announce_plain[0] <= 0)
        return -1;

    // Get ping_id
    uint64_t ping_id;
    memcpy(&ping_id, announce_plain + 1 + CLIENT_ID_SIZE + data_size, sizeof(ping_id));

    //Check if we send getnodes request previously
    uint8_t data[PING_DATA_SIZE];
    if (ping_array_check(data, sizeof(data), &dht->announce->ping_array, ping_id) != sizeof(data))
        return -1;
   
    //Unpack nodes
    Node_format plain_nodes[MAX_SENT_NODES];
    uint16_t length_nodes = 0;
    uint32_t num_nodes = unpack_nodes(plain_nodes, announce_plain[0], &length_nodes, announce_plain + 1 + CLIENT_ID_SIZE, data_size, 0);
    
    if (length_nodes != data_size)
        return -1;

    if (num_nodes != announce_plain[0])
        return -1;

    char originatortxt[CLIENT_ID_SIZE*2+1];
    char chatidtxt[CLIENT_ID_SIZE*2+1];
    strcpy(originatortxt, id_toa(packet + 1));
    strcpy(chatidtxt, id_toa(announce_plain + 1));
    
    LOGGER_DEBUG("handle_send_gc_ann_nodes_r: %s at %s:%d sent %u announced nodes of chat %s", originatortxt, ip_ntoa(&ipp.ip), ipp.port, num_nodes, chatidtxt);

    uint32_t i;
    for (i = 0; i<num_nodes; i++) {
        add_announced_nodes(dht->announce, plain_nodes[i].client_id, announce_plain + 1, plain_nodes[i].ip_port, 1);
        // Debugging
        char client_id_txt[CLIENT_ID_SIZE*2+1];
        strcpy(client_id_txt, id_toa(plain_nodes[i].client_id));
        LOGGER_DEBUG("\tAnnounced Client_ID: %s\n", client_id_txt);
    }
    
    return 0;
}

/* Add nodes to the announced_nodes list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to store information about members of
 * group chats who are online now and give that info to users who want to join.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */

 /*
 * return -1 on failure.
 * return 0 on success.
 */
int add_announced_nodes(ANNOUNCE *announce, const uint8_t *client_id, uint8_t *chat_id, IP_Port ip_port, int inner)
{
    if (!ip_isset(&ip_port.ip))
        return -1;

    Announced_node_format *announced_nodes;
    if (!inner)
        announced_nodes = announce->announced_nodes;
    else
        announced_nodes = announce->my_announced_nodes;

    uint32_t i;

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (!ip_isset(&announced_nodes[i].ip_port.ip)) {
            memcpy(announced_nodes[i].client_id, client_id, CLIENT_ID_SIZE);
            memcpy(announced_nodes[i].chat_id, chat_id, CLIENT_ID_SIZE);
            ipport_copy(&announced_nodes[i].ip_port, &ip_port);
            return 0;
        }

        if (memcmp(announced_nodes[i].client_id, client_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }

        if (memcmp(announced_nodes[i].chat_id, chat_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }
    }

    uint32_t r = rand();

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (id_closest(announce->dht->self_public_key, announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].client_id, client_id) == 2) {
            memcpy(announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].client_id, client_id, CLIENT_ID_SIZE);
            memcpy(announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].chat_id, chat_id, CLIENT_ID_SIZE);
            ipport_copy(&announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].ip_port, &ip_port);
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
int get_announced_nodes(ANNOUNCE *announce, const uint8_t *chat_id, Node_format *nodes_list, int inner)
{
    uint32_t num_nodes = 0;
    uint32_t i;

    Announced_node_format *announced_nodes;
    if (!inner)
        announced_nodes = announce->announced_nodes;
    else 
        announced_nodes = announce->my_announced_nodes;

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (ip_isset(&announced_nodes[i].ip_port.ip)) {
            if (id_equal(chat_id, announced_nodes[i].chat_id)) {
                memcpy(nodes_list[num_nodes].client_id, announced_nodes[i].client_id, CLIENT_ID_SIZE);
                ipport_copy(&nodes_list[num_nodes].ip_port, &announced_nodes[i].ip_port);
                num_nodes++;
            }
        }
    }

    if (num_nodes==0) 
        return -1;
    else
        return num_nodes;
}

ANNOUNCE *new_announce(DHT *dht)
{
    LOGGER_INIT(LOGGER_OUTPUT_FILE, LOGGER_LEVEL);

	ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

    if (ping_array_init(&announce->ping_array, PING_NUM_MAX, PING_TIMEOUT) != 0) {
        free(announce);
        return NULL;
    }

    announce->dht = dht;
    networking_registerhandler(announce->dht->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_gc_announce_request, dht);
    networking_registerhandler(announce->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, &handle_get_gc_announced_nodes_request, dht);
    networking_registerhandler(announce->dht->net, NET_PACKET_SEND_ANNOUNCED_NODES, &handle_send_gc_announced_nodes_response, dht);
    return announce;
}

void kill_announce(ANNOUNCE *announce)
{
	networking_registerhandler(announce->dht->net, NET_PACKET_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_SEND_ANNOUNCED_NODES, NULL, NULL);    
    ping_array_free_all(&announce->ping_array);

    free(announce);
}
