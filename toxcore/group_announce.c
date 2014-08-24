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

#define MAX_CONCURRENT_REQUESTS     10
#define GC_ANNOUNCE_EXPIRATION      3600 /* sec */
#define MAX_GC_ANNOUNCED_NODES      30
#define TIME_STAMP (sizeof(uint64_t))
#define REQUEST_ID (sizeof(uint64_t))

// Type + Signature + Chat_ID + Client_ID + IP_Port + Timestamp
#define GC_ANNOUNCE_REQUEST_PLAIN_SIZE (1 + SIGNATURE_SIZE + EXT_PUBLIC_KEY + EXT_PUBLIC_KEY + sizeof(IP_Port) + TIME_STAMP)
#define GC_ANNOUNCE_REQUEST_DHT_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_ANNOUNCE_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

// Type + Signature + Chat_ID + Client_ID + IP_Port + RequestID
#define GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE (1 + SIGNATURE_SIZE + EXT_PUBLIC_KEY + EXT_PUBLIC_KEY + sizeof(IP_Port) + REQUEST_ID)
#define GC_ANNOUNCE_GETNODES_REQUEST_DHT_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE + crypto_box_MACBYTES)

// Type + Nodes + RequestID
#define GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE (1 + sizeof(Announced_Node_format) * MAX_SENT_NODES + REQUEST_ID)
#define GC_ANNOUNCE_GETNODES_RESPONSE_DHT_SIZE (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE + crypto_box_MACBYTES)


struct ANNOUNCE {
    DHT *dht;

    // This structure is for announcing requests that we get from
    // online chat members. Timestamp is used for expiration purposes
    struct ANNOUNCED_Node
    {
        uint8_t chat_id[EXT_PUBLIC_KEY];
        Announced_Node_format node;
        uint64_t timestamp;
    }   announcements[MAX_GC_ANNOUNCED_NODES];

    // This structure is for our own requests, when we want to
    // find online chat members
    struct ANNOUNCE_Request                                                            
    {
        uint8_t chat_id[EXT_PUBLIC_KEY];
        Announced_Node_format nodes[MAX_SENT_NODES];
        uint32_t nodes_num;
        uint64_t req_id;
        bool ready;
    }   self_requests[MAX_CONCURRENT_REQUESTS];
    
};


// Handle all decrypt procedures
int unwrap_gc_announce_packet(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t packet_type, const uint8_t *packet, uint16_t length)
{
    uint16_t plain_length;

    switch (packet_type) {
        case NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST: {
            plain_length = GC_ANNOUNCE_REQUEST_PLAIN_SIZE;
        }

        case NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES: {
            plain_length = GC_ANNOUNCE_GETNODES_REQUEST_PLAIN_SIZE;
        }

        case NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES: {
            plain_length = length - (GC_ANNOUNCE_GETNODES_RESPONSE_DHT_SIZE - GC_ANNOUNCE_GETNODES_RESPONSE_PLAIN_SIZE);
        }

        default:
            return -1;
    }

    if (id_equal(packet + 1, ENC_KEY(self_public_key)))
        return -1;

    memcpy(public_key, packet + 1, ENC_PUBLIC_KEY);

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, packet + 1 + ENC_PUBLIC_KEY, crypto_box_NONCEBYTES);

    
    uint8_t plain[plain_length];

    int len = decrypt_data(public_key, ENC_KEY(self_secret_key), nonce,
                            packet + 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES,
                            length - (1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES), plain);

    if (len != plain_length)
        return -1;

    if (plain[0] != packet_type)
        return -1;

    --plain_length;
    memcpy(data, plain + 1, plain_length);
    return plain_length;
}

// Handle all encrypt procedures
int wrap_gc_announce_packet(const uint8_t *send_public_key, const uint8_t *send_secret_key, const uint8_t *recv_public_key,
                        uint8_t *packet, const uint8_t *data, uint32_t length, uint8_t packet_type)
{
    uint8_t plain[length+1];
    plain[0] = packet_type;
    memcpy(plain + 1, data, length);
    
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t encrypt[1 + length + crypto_box_MACBYTES];
    int len = encrypt_data(ENC_KEY(recv_public_key), ENC_KEY(send_secret_key), nonce, plain, length + 1, encrypt);
    if (len != sizeof(encrypt))
        return -1;

    packet[0] = packet_type;
    memcpy(packet + 1, ENC_KEY(send_public_key), ENC_PUBLIC_KEY);
    memcpy(packet + 1 + ENC_PUBLIC_KEY, nonce, crypto_box_NONCEBYTES);
    memcpy(packet + 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES, encrypt, len);

    return 1 + ENC_PUBLIC_KEY + crypto_box_NONCEBYTES + len;
}




int send_gc_announce_request(DHT *dht, const uint8_t node_public_key[],
                             const uint8_t node_private_key[], const uint8_t chat_id[])
{

}

int handle_gc_announce_request(void * _dht, IP_Port ipp, const uint8_t packet[], uint32_t length)
{

}

int send_gc_get_announced_nodes_request(DHT *dht, const uint8_t chat_id[], uint64_t *req_id)
{

}

int handle_gc_get_announced_nodes_request(void * _dht, IP_Port ipp, const uint8_t packet[], uint32_t length)
{

}

int send_gc_get_announced_nodes_response(DHT *dht, const uint8_t chat_id[], uint64_t *req_id)
{

}

int handle_gc_get_announced_nodes_response(void * _dht, IP_Port ipp, const uint8_t packet[], uint32_t length)
{

}

// Function to get announced nodes, should be used for get_announced_nodes_response
// Returns announced nodes number, fills up nodes array
int get_gc_announced_nodes(ANNOUNCE *announce, const uint8_t chat_id[],
                            Announced_Node_format nodes[MAX_SENT_NODES])
{
    uint32_t i, j;
    j = 0;
    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (ipport_isset(&announce->announcements[i].node.ip_port)) 
            if (id_long_equal(announce->announcements[i].chat_id, chat_id)) {
                memcpy(nodes[j].client_id, announce->announcements[i].node.client_id, EXT_PUBLIC_KEY);
                ipport_copy(&nodes[j].ip_port, &announce->announcements[i].node.ip_port);
                j++;
                if (j==MAX_SENT_NODES)
                    return j;
            }
    }

    return j;
}

// This function should be used when handling announce request
// Add announced nodes to announce->announcements
// Returns index of announcements array
int add_gc_announced_node(ANNOUNCE *announce, const uint8_t chat_id[],
                         const Announced_Node_format node, uint64_t timestamp)
{
    uint32_t i, j;
    uint64_t the_oldest_announce;
    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (i==0) {
            the_oldest_announce = announce->announcements[i].timestamp;
            j = i;
        }
        else
            if (the_oldest_announce > announce->announcements[i].timestamp) {
                the_oldest_announce = announce->announcements[i].timestamp;
                j = i;
            }

        if (id_long_equal(announce->announcements[i].node.client_id, node.client_id)
                    && id_long_equal(announce->announcements[i].chat_id, chat_id)) {
            announce->announcements[i].timestamp = timestamp;
            ipport_copy(&announce->announcements[i].node.ip_port, &node.ip_port);
            return i;        
        }

        if (!ipport_isset(&announce->announcements[i].node.ip_port)) {
            memcpy(announce->announcements[i].node.client_id, node.client_id, EXT_PUBLIC_KEY);
            memcpy(announce->announcements[i].chat_id, chat_id, EXT_PUBLIC_KEY);
            ipport_copy(&announce->announcements[i].node.ip_port, &node.ip_port);
            announce->announcements[i].timestamp = timestamp;
            return i;
        }
    }

    memcpy(announce->announcements[j].node.client_id, node.client_id, EXT_PUBLIC_KEY);
    memcpy(announce->announcements[j].chat_id, chat_id, EXT_PUBLIC_KEY);
    ipport_copy(&announce->announcements[j].node.ip_port, &node.ip_port);
    announce->announcements[j].timestamp = timestamp;

    return j;
}


int get_requested_gc_nodes(ANNOUNCE *announce, const uint8_t chat_id[],
                            Announced_Node_format *node, uint32_t *nodes_num)
{

}

int add_requested_gc_nodes(ANNOUNCE *announce, const uint8_t chat_id[],
                         const Announced_Node_format *node, uint64_t req_id, uint32_t nodes_num)
{

}

int do_announce(ANNOUNCE *announce)
{
    uint64_t current_time = unix_time();

    // Reset ip_port for those announced nodes, which expired
    uint32_t i;
    for (i = 0; i < MAX_GC_ANNOUNCED_NODES; i++) {
        if (announce->announcements[i].timestamp + GC_ANNOUNCE_EXPIRATION < current_time)
            ipport_reset(&announce->announcements[i].node.ip_port);
    }
}

ANNOUNCE *new_announce(DHT *dht)
{
    ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

    announce->dht = dht;
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, &handle_gc_announce_request, dht);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, &handle_gc_get_announced_nodes_request, dht);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES, &handle_gc_get_announced_nodes_response, dht);
    
    return announce;
}

void kill_announce(ANNOUNCE *announce)
{
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_GET_ANNOUNCED_NODES, NULL, NULL);
    networking_registerhandler(announce->dht->net, NET_PACKET_GROUPCHAT_SEND_ANNOUNCED_NODES, NULL, NULL);

    free(announce);
}