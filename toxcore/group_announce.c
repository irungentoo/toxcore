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
#include <assert.h>

#include "group_announce.h"

#include "logger.h"
#include "util.h"

#include "network.h"
#include "DHT.h"
#include "ping.h"
#include "ping_array.h"

#define PING_NUM_MAX 512

#define ANNOUNCE_PLAIN_SIZE (1 + GC_ANNOUNCE_SIGNED_SIZE)
#define DHT_ANNOUNCE_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + ANNOUNCE_PLAIN_SIZE + crypto_box_MACBYTES)
#define SEND_ANNOUNCED_NODES_PLAIN_SIZE (1 + sizeof(Node_format) * MAX_SENT_NODES + sizeof(uint64_t))
#define DHT_SEND_ANNOUNCED_NODES_SIZE (1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + SEND_ANNOUNCED_NODES_PLAIN_SIZE + crypto_box_MACBYTES)

#define MAX_CONCURRENT_REQUESTS     10

struct ANNOUNCE {
    DHT *dht;
    Groupchat_announcement_format announced_nodes[MAX_ANNOUNCED_NODES];     /* TODO: Add something like do_announce which cleans up expired */
    uint64_t current_req_id;                                                /* TODO: Initialize at random or something */
    struct 
    {
        uint8_t nodes[MAX_SENT_NODES*CLIENT_ID_EXT_SIZE];
        bool ready;
    }   requests[MAX_CONCURRENT_REQUESTS];
    
};

PAK_DEF(GC_ANNOUNCE)
{
    PAK_ITM(signature, SIGNATURE_SIZE);
    PAK_ITM(announcer_id, CLIENT_ID_EXT_SIZE);
    PAK_ITM(timestamp, sizeof(uint64_t));
    PAK_ITM(chat_id, CLIENT_ID_SIZE);
};

PAK_DEF(GC_ANNOUNCE_GETNODES)
{
    PAK_ITM(chat_id, CLIENT_ID_SIZE);
    PAK_ITM(req_id, sizeof(uint64_t));
};


PAK_DEF(GC_ANNOUNCE_SENDNODES)
{
    PAK_ITM(req_id, sizeof(uint64_t));
    PAK_ITM(nodes_num, sizeof(uint64_t));
    PAK_ITM(nodes, CLIENT_ID_EXT_SIZE*MAX_SENT_NODES);
};

PAK_DEF(COMMON)
{
    PAK_ITM(packtype, sizeof(uint8_t));
    PAK_ITM(sender_id, CLIENT_ID_SIZE);
    PAK_ITM(nonce, crypto_box_NONCEBYTES);
    PAK_ITM(encrypted, 0);                  /* Actual packets define the size here */
};

int send_common_tox_packet(DHT *dht, const uint8_t *destination_id, IP_Port ipp, uint8_t type, uint8_t *payload, size_t length)
{
    /* Check if packet is going to be sent to ourself */
    if (id_equal(destination_id, dht->self_public_key))
        return -1;
    
    /* Generate shared_key for encryption */
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, destination_id);

    /* Filling the common packet fields */
    /* Note glorious C99 variable size arrays and subsequent sizeof on them */
    uint8_t pk[PAK_LEN(COMMON)+length+crypto_box_MACBYTES];
    *PAK(COMMON, pk)->packtype = type;
    memcpy(PAK(COMMON, pk)->sender_id, dht->self_public_key, CLIENT_ID_SIZE);
    
    /* Generate new nonce */
    new_nonce(PAK(COMMON, pk)->nonce);
    
    /* Generate encrypted data */
    int encrypt_length = encrypt_data_symmetric(shared_key,
                                        PAK(COMMON, pk)->nonce,
                                        payload, length,
                                        PAK(COMMON, pk)->encrypt);

    /* Checking if all went well */
    if (encrypt_length != length+crypto_box_MACBYTES )
        return -1;

    /* Actually sending the thing */
    if ((uint32_t)sendpacket(dht->net, ipp, pk, sizeof(pk)) != sizeof(pk))
        return -1;

    return 0;    
}

int recv_common_tox_packet(DHT *dht, const uint8_t *packet, uint8_t *cleartext, size_t clearlength)
{
    /* TODO: check lenght */
    
    /* Check if packet has been sent from ourselves */
    if (id_equal( PAK(COMMON, packet)->sender_id, dht->self_public_key))
        return -1;

    /* Generate key for decryption */
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_recv(dht, shared_key, PAK(COMMON, packet)->sender_id);

    /* Decrypt clear text */   
    int decrypt_length = decrypt_data_symmetric(shared_key,
                                        PAK(COMMON, packet)->nonce,
                                        PAK(COMMON, packet)->encrypt,
                                        clearlength + crypto_box_MACBYTES,
                                        cleartext);

    if (decrypt_length != clearlength)
        return -1;

    return 0;
}

int prepare_gc_announce_request(Groupchat_announcement_format* announcement, const uint8_t *node_private_key)
{
    /* TODO: refactor with PAK_ macros */
    unsigned long long slen;
    uint8_t messagebuf[GC_ANNOUNCE_MESSAGE_SIZE];
    id_copy2(messagebuf, announcement->client_id, 0);    
    U64_to_bytes(messagebuf + CLIENT_ID_EXT_SIZE, announcement->timestamp);
    id_copy(messagebuf + CLIENT_ID_EXT_SIZE + sizeof(uint64_t), announcement->chat_id);
    
    if (crypto_sign(announcement->raw, &slen, messagebuf, GC_ANNOUNCE_MESSAGE_SIZE, node_private_key) != 0 ||
            slen != GC_ANNOUNCE_SIGNED_SIZE) /* Safe to compare, sequence point after || */
            return -1;
    
    return 0;
}

int verify_gc_announce_request(const Groupchat_announcement_format* announcement)
{
    /* TODO: refactor with PAK_ macros */
    uint8_t messagebuf[GC_ANNOUNCE_SIGNED_SIZE];
    unsigned long long mlen;

    if (crypto_sign_open(messagebuf, &mlen, announcement->raw, 
        GC_ANNOUNCE_SIGNED_SIZE, announcement->client_id + CLIENT_ID_SIZE) < 0 ||
            mlen != GC_ANNOUNCE_MESSAGE_SIZE)
        return -1;
    
    return 0;
}

int initiate_gc_announce_request(DHT *dht, const uint8_t *node_public_key, const uint8_t *node_private_key, const uint8_t *chat_id)
{
    /* TODO: check if private corresponds public */
    /* probably undoable at the moment */
    
    /* Generating an announcement */
    Groupchat_announcement_format announcement;
    id_copy2(announcement.client_id, node_public_key, 0);
    id_copy(announcement.chat_id, chat_id);
    announcement.timestamp = unix_time();
        
    /* Signing */
    if (prepare_gc_announce_request(&announcement, node_private_key) < 0)
        return -1;
    
    /* Dispatching the request */
    /*return*/ dispatch_gc_announce_request(dht, &announcement);
    return 0;
}

/* TODO: doc */
int dispatch_gc_announce_request(DHT *dht, const Groupchat_announcement_format* announcement)
{
    static Node_format nodes[MAX_SENT_NODES];
    Node_format *closest_node=NULL;
    int nclosest, j, i, addedToSelf=0;
    nclosest=get_close_nodes(dht, announcement->chat_id, nodes, 0, 1, 1); /* TODO: dehardcode last 3 params */
    
    if (nclosest <= 0)
        return -1;
    
    for (j=0, i=0; j<nclosest; j++, i++)
    {
        /* If our own id is closer to nodes[i], insert ourselves to the queue at this pos */
        if (!addedToSelf || id_closest(announcement->chat_id, nodes[i].client_id, dht->self_public_key)==2)
        {           
            if (add_announced_nodes(dht->announce, announcement, 0) < 0)
            return -1;
            
            addedToSelf++;
        }
        else
        {
            if (send_gc_announce_request(dht, nodes[i].client_id, nodes[i].ip_port, announcement) < 0)
                return -1;
            
            /* Advance the list only if not added to self */
            i++;
        }
    }
}

/* Send announce request
 * For members of group chat, who want to announce being online at the current moment
 *
 * return -1 on failure
 * return 0 on success
 */
int send_gc_announce_request(DHT * dht, const uint8_t *client_id, IP_Port ipp, const Groupchat_announcement_format* announcement)
{
    return send_common_tox_packet(dht, client_id, ipp, NET_PACKET_ANNOUNCE_REQUEST, announcement->raw, PAK_LEN(GC_ANNOUNCE));
}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_gc_announce_request(void * _dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    Groupchat_announcement_format announcement;

    if (recv_common_tox_packet((DHT* )_dht, packet, announcement.raw, sizeof(announcement.raw)) < 0)
        return -1;
    
    /* TODO: do we need packetype duplicated? in encrypted part */

    /* Try to decrypt signature */
    id_copy2(announcement.client_id, PAK(GC_ANNOUNCE, announcement.raw)->announcer_id, 0);
    bytes_to_U64(&announcement.timestamp, PAK(GC_ANNOUNCE, announcement.raw)->timestamp);
    id_copy(announcement.chat_id, PAK(GC_ANNOUNCE, announcement.raw)->chat_id);
    
    /* Verify signature */
    if (verify_gc_announce_request(&announcement) < 0)
    {
        LOGGER_WARNING("handle_gc_ann_req: got a forged signature from %s\n", id_toa(packet + 1));
        return -1;
    }
    
   
    LOGGER_INFO("handle_gc_ann_req: %s at %s:%d claims to be part of chat %s", id_toa(packet + 1), ip_ntoa(&ipp.ip), ipp.port, id_toa(announce_plain + 1));
    
    /* Save (client_id, chat_id) in our ANNOUNCE structure, or pass along */
    return dispatch_gc_announce_request(dht, &announcement);
}

/* Send a getnodes request.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int get_gc_announced_nodes_request(DHT * dht, IP_Port ipp, const uint8_t *client_id, uint8_t *chat_id)
{
    uint8_t payload[PAK_LEN(GC_ANNOUNCE_GETNODES)];
    id_copy(PAK(GC_ANNOUNCE_GETNODES, payload)->chat_id, chat_id);
    /* TODO: fill the request id, stub by now */
    
    return send_common_tox_packet(dht, client_id, ipp, NET_PACKET_GET_ANNOUNCED_NODES, payload, PAK_LEN(GC_ANNOUNCE_GETNODES));
}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_get_gc_announced_nodes_request(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    DHT *dht=(DHT*)_dht;
    
    /* Recieve and decypther packet */
    uint8_t payload[PAK_LEN(GC_ANNOUNCE_GETNODES)];
    
    if (recv_common_tox_packet((DHT*)_dht, packet, payload, sizeof(payload)) < 0))
        return -1;
    
    LOGGER_DEBUG("handle_gc_ann_req: %s at %s:%d requests members of chat %s", 
                 id_toa(PAK(COMMON, packet)->sender_id),
                 ip_ntoa(&ipp.ip), ipp.port,
                 id_toa(PAK(GC_ANNOUNCE_GETNODES, payload)->chat_id);
                 
    /* Send responce */
    uint8_t sending_payload[PAK(GC_ANNOUNCE_SENDNODES)];
    uint64_t nodes_num=get_announced_nodes(dht->announce, 
                                   PAK(GC_ANNOUNCE_GETNODES, payload)->chat_id, 
                                   PAK(GC_ANNOUNCE_SENDNODES, sending_payload)->nodes);
    U64_to_bytes(PAK(GC_ANNOUNCE_GETNODES, sending_payload)->nodes_num, &num_nodes);
    memcpy(PAK(GC_ANNOUNCE_SENDNODES, sending_payload)->req_id, PAK(GC_ANNOUNCE_GETNODES, payload)->req_id, sizeof(uint64_t));
    
    return send_common_tox_packet(dht, PAK(COMMON, packet)->sender_id, ipp, NET_PACKET_SEND_ANNOUNCED_NODES, 
                                  sending_payload, PAK_POS(GC_ANNOUNCE_GETNODES, nodes) + num_nodes * CLIENT_ID_EXT_SIZE);
}

 /*
 * return -1 on failure.
 * return 0 on success.
 */
int handle_send_gc_announced_nodes_response(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    DHT *dht=(DHT*)_dht;
    
    /* Recieve and decypther packet */
    uint8_t payload[PAK_LEN(GC_ANNOUNCE_SENDNODES)];
    
    if (recv_common_tox_packet((DHT*)_dht, packet, payload, sizeof(payload)) < 0))
        return -1;    
}

static void insert_announced_node(Groupchat_announcement_format* where, const Groupchat_announcement_format *what)
{
    id_copy(where->client_id, what->client_id);
    id_copy(where->chat_id, what->chat_id);
    where->timestamp = what->timestamp;
    memcpy(where->raw, what->raw, GC_ANNOUNCE_SIGNED_SIZE);
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
int add_announced_nodes(ANNOUNCE *announce, const Groupchat_announcement_format *announcement, int inner)
{
    Groupchat_announcement_format *announced_nodes;
    if (!inner)
        announced_nodes = announce->announced_nodes;
    else
        announced_nodes = announce->my_announced_nodes;

    uint32_t i;

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        /* Attention time travellers: don't run this 00:00 1 Jan 1970, thank you for your understanding */
        if (announced_nodes[i].timestamp == 0) { 
            insert_announced_node(&announced_nodes[i], announcement);
            return 0;
        }

        /*  1. We don't really need this to be an error
            2. Should check both clauses with AND operator, one chat may contain multiple
            people and one person may be listed in multiple chats
            
        if (memcmp(announced_nodes[i].client_id, client_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        }

        if (memcmp(announced_nodes[i].chat_id, chat_id, CLIENT_ID_SIZE) == 0) {
            return -1;
        } */
        
        /* We've seen that node before in our list */
        if (id_equal(announced_nodes[i].client_id, announcement->client_id) 
            && id_equal(announced_nodes[i].chat_id, announcement->chat_id)
            && announced_nodes[i].timestamp == announcement->timestamp)
            return 0;
    }

    uint32_t r = rand();

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (id_closest(announce->dht->self_public_key, announced_nodes[(i + r) % MAX_ANNOUNCED_NODES].chat_id, announcement->chat_id) == 2) {
            insert_announced_node(&announced_nodes[(i + r) % MAX_ANNOUNCED_NODES], announcement);
            return 0;
        }
    }

    return -1;
}

/* Get nodes from the announced_nodes list given chat_id.
 *
 *  return num_nodes if found.
 *  return 0 if not found.
 */
int get_announced_nodes(ANNOUNCE *announce, const uint8_t *chat_id, uint8_t *nodes_list, int inner)
{
    uint32_t num_nodes = 0;
    uint32_t i;
    #if 0

    Announced_node_format *announced_nodes;
    if (!inner)
        announced_nodes = announce->announced_nodes;
    else 
        announced_nodes = announce->my_announced_nodes;

    for (i = 0; i < MAX_ANNOUNCED_NODES; i++) {
        if (ip_isset(&announced_nodes[i].ip_port.ip)) {
            if (id_equal(chat_id, announced_nodes[i].chat_id)) {
                id_copy(nodes_list[num_nodes].client_id, announced_nodes[i].client_id);
                ipport_copy(&nodes_list[num_nodes].ip_port, &announced_nodes[i].ip_port);
                num_nodes++;
            }
        }
    }
#endif
    return num_nodes;
}

ANNOUNCE *new_announce(DHT *dht)
{
    LOGGER_INIT(LOGGER_OUTPUT_FILE, LOGGER_LEVEL);

	ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

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

    free(announce);
}
