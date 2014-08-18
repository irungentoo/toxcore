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

#define MAX_CONCURRENT_REQUESTS     10
#define ANNOUNCE_EXPIRATION         3600 /* sec */

struct ANNOUNCE {
    DHT *dht;

    /* Binary search tree for announcements */
    /* TODO: balance the tree */
    /* TODO: limit tree growth */
    /* TODO: make it a generalized ADT in separate unit */
    /* WARNING: removing a node directly from the tree is not supported since deletions happen on expiration
                by traversing the list. In case we happen to need this (e.g.: chat-exit announcements), we 
                need to add a link to corresponding ANNOUNCE_Expiration node */
    struct ANNOUNCE_Node
    {
        uint8_t node_id[CLIENT_ID_EXT_SIZE];
        uint8_t chat_id[CLIENT_ID_SIZE];
        uint64_t expiration;       /* Not remembering actual timestamp, change if you need it */
        struct ANNOUNCE_Node *parent, *left, *right;
    }   *announcements;

    /* Expiration control */
    struct ANNOUNCE_Expiration
    {
        struct ANNOUNCE_Node *target;
        struct ANNOUNCE_Expiraton *prev, *next;
    }   *expirations_head, *expirations_tail;

    /* Nodes requests control */
    uint64_t current_req_id;    /* TODO: also make a tree? */
                                /* TODO: more untraceability-by-ids */
    struct ANNOUNCE_Request                                                            
    {
        uint8_t nodes[MAX_SENT_NODES*CLIENT_ID_EXT_SIZE];
        uint32_t nodes_num;
        uint64_t req_id;
        bool ready;
    }   requests[MAX_CONCURRENT_REQUESTS];
    
};

/* Packet definitions */
PAK_DEF(GC_ANNOUNCE)
{
    PAK_ITM(signature, SIGNATURE_SIZE);
    PAK_ITM(announcer_id, CLIENT_ID_EXT_SIZE);
    PAK_ITM(timestamp, sizeof(uint64_t));
    PAK_ITM(chat_id, CLIENT_ID_SIZE);
};

/* TODO: signature
 * TODO: register id-for-chats at DHT */
PAK_DEF(GC_GETNODES)
{
    PAK_ITM(chat_id, CLIENT_ID_SIZE);
    PAK_ITM(requester_id, CLIENT_ID_SIZE);
    PAK_ITM(req_id, sizeof(uint64_t));
    PAK_ITM(timestamp, sizeof(uint64_t));
};


PAK_DEF(GC_SENDNODES)
{
    PAK_ITM(req_id, sizeof(uint64_t));
    PAK_ITM(nodes_num, sizeof(uint32_t));
    PAK_ITM(nodes, CLIENT_ID_EXT_SIZE*MAX_SENT_NODES);
};

/* Announces tree/list operations */
static void     announce_treelist_init(struct ANNOUNCE* announce);
static void     announce_treelist_insert(struct ANNOUNCE* announce, uint8_t client_id[], uint8_t chat_id[], uint64_t timestamp);
static void     announce_treelist_remove(struct ANNOUNCE* announce, struct ANNOUNCE_Expiraton* target);
static size_t   announce_treelist_getnodes(struct ANNOUNCE* announce, uint8_t chatid[]);
static void     announce_treelist_clear(struct ANNOUNCE* announce);

int do_announce(ANNOUNCE *announce)
{
    uint64_t current_time = unix_time();

    /* Check if we've reached a point when some nodes might have expired */
    ANNOUNCE_Expiraton *next_node = announce->expirations_head;
    while (next_node && next_node->target->expiration < current_time)
    {
        /* If a node is expired, we remove both it and the corresponding tree node */
        ANNOUNCE_Expiraton *curnode = next_node;
        next_node = announce->expirations_head->next;
        announce_treelist_remove(announce, curnode);
    }
}

/* Universal packet dispatcher:
    1. Finds MAX_SENT_NODES nodes closest to target_id and not further away to it than previous_id,
    including oneself.
    2. Resends the packet to all foreign destinations
    3. Executes self_action callback for self if it is set

    Fails without error if the timestamp (specified by timestamp offset) + value of expiration
    parameter don't exceed current time

    returns 0 on success
    returns -1 on failure */
static int packet_dispatcher(DHT* dht, const uint8_t target_id[], const uint8_t previous_id[], 
    const uint8_t packet[], size_t length, uint8_t packtype, size_t timestamp_pos, uint64_t expiration,
    void (*self_action)(DHT* dht, const uint8_t packet[]))
{
    update_unix_time(); 

    uint64_t timestamp=0;
    bytes_to_U64(&timestamp, &packet[timestamp_pos]);

    /* If it's already expired, do not bother further */
    if (timestamp + expiration < unix_time())
        return 0; /* Not an error, yet no dispatching needed */

    /* The packet is valid, find a closest nodes to send it to */
    static Node_format nodes[MAX_SENT_NODES];
    Node_format *closest_node=NULL;
    int nclosest, j, i;
    bool addedToSelf=false;
    nclosest=get_close_nodes(dht, PAK(GC_ANNOUNCE, packet)->chat_id, nodes, 0, 1, 1); /* TODO: dehardcode last 3 params */
    
    if (nclosest <= 0)
        return -1;
    
    for (j=0, i=0; j<nclosest; j++, i++)
    {
        /* If our own id is closer to nodes[i], insert ourselves to the queue at this pos.
           Realistically our id should never be further than previous one, so don't bother. TODO: check this */
        if (self_action && (!addedToSelf || id_closest(target_id, node_id, dht->self_public_key)==2))
        {       
            self_action(dht, packet);
            addedToSelf=true;
        }
        else
        {
            /* Only resend to nodes which are further away than previous one */
            if (id_closest(target_id, nodes[i].client_id, previous_id)!=2)
                if (send_common_tox_packet(dht, nodes[i].client_id, nodes[i].ip_port, packtype, packet, length) < 0)
                    return -1;
            
            /* Advance the list only if not added to self */
            i++;
        }
    }
}


/* GC_ANNOUNCE operations */
static void self_gc_announce_action(DHT* dht, const uint8_t packet[])
{
    uint64_t timestamp=0;
    bytes_to_U64(&timestamp, PAK(GC_ANNOUNCE, packet)->timestamp);

    announce_treelist_insert(dht->announce, PAK(GC_ANNOUNCE, packet)->originator_id,
                                            PAK(GC_ANNOUNCE, packet)->chat_id,
                                            timestamp);  
}

int initiate_gc_announce_request(DHT *dht, const uint8_t node_public_key[], const uint8_t node_private_key[], const uint8_t chat_id[])
{
    update_unix_time();
    /* TODO: check if private corresponds public */
    /* probably undoable at the moment */
    
    /* Generating an announcement */
    uint8_t pk[PAK_LEN(GC_ANNOUNCE)];
    id_copy2(PAK(GC_ANNOUNCE, pk)->announcer_id, node_public_key, 0);
    id_copy(PAK(GC_ANNOUNCE, pk)->chat_id, chat_id);
    U64_to_bytes(PAK(GC_ANNOUNCE, pk)->timestamp, unix_time());

    /* Signing the announcement */
    if (sign_packet(pk, PAK_LEN(GC_ANNOUNCE), node_private_key) < 0)
        return -1;
    
    /* Dispatching the request */
    return packet_dispatcher(dht, chat_id, dht->self_public_key, 
        pk, PAK_LEN(GC_ANNOUNCE), NET_PACKET_ANNOUNCE_REQUEST, 
        PAK_POS(GC_ANNOUNCE, timestamp), ANNOUNCE_EXPIRATION, 
        self_gc_announce_action);
}

static int handle_gc_announce_request(void * _dht, IP_Port ipp, const uint8_t packet[], uint32_t length)
{
    uint8_t plaintext[PAK_LEN(GC_ANNOUNCE)];

    if (recv_common_tox_packet((DHT* )_dht, packet, plaintext, sizeof(plaintext)) < 0)
        return -1;
    
    /* TODO: do we need packetype duplicated? in encrypted part */
    
    /* Verify signature */
    if (verify_signed_packet(plaintext, PAK_LEN(GC_ANNOUNCE), PAK(GC_ANNOUNCE, plaintext)->announcer_id) < 0)
    {
        LOGGER_WARNING("handle_gc_ann_req: got a forged signature from %s\n", id_toa(PAK(COMMON, packet)->sender_id));
        return -1;
    }
    
   /* TODO: more infa here */
    //LOGGER_INFO("handle_gc_ann_req: %s at %s:%d claims to be part of chat %s", id_toa(PAK(COMMON, packet)->sender_id), ip_ntoa(&ipp.ip), ipp.port, id_toa(announce_plain + 1));
    
    /* Save (client_id, chat_id) in our ANNOUNCE structure, or pass along */
    return packet_dispatcher(dht, chat_id, PAK(COMMON, packet)->sender_id, 
        plaintext, PAK_LEN(GC_ANNOUNCE), NET_PACKET_ANNOUNCE_REQUEST, 
        PAK_POS(GC_ANNOUNCE, timestamp), ANNOUNCE_EXPIRATION, 
        self_gc_announce_action);
}

/* GC_GETNODES operations */
static size_t lookup_tree(struct ANNOUNCE_Node *origin, uint8_t needle[], uint8_t *nodes, size_t count, size_t max)
{
    /* If no slot is left, quit */
    if (count == max || !origin)
        return count;

    /* Check if current node fits */
    int compr = memcmp(origin->chat_id, needle, CLIENT_ID_SIZE);
    size_t newcount = count;
    if (compr==0)
        id_copy2(nodes[(newcount++)*CLIENT_ID_EXT_SIZE], origin->node_id, 0);
    /* Try left or right subtree depending on sign, both if we got a hit */
    if (compr<=0)
        newcount=lookup_tree(origin->left, needle, nodes, newcount, max);
    if (compr>=0)
        newcount=lookup_tree(origin->right, needle, nodes, newcount, max);

    return newcount;
}

bool self_gc_getnodes_action(DHT* dht, const uint8_t packet[])
{
    /* Only run once, not in the loop */
    uint8_t payload[PAK(GC_SENDNODES)];
    size_t nodes_num = lookup_tree(dht->announce->announcements, PAK(GC_GETNODES, packet)->chat_id, 
        PAK(GC_SENDNODES, payload)->nodes, 0, MAX_SENT_NODES);

    if (nodes_num > 0)
    {
        /* U32_to_bytes(PAK(GC_SENDNODES, payload)->nodes_num, &num_nodes);
        memcpy(PAK(GC_SENDNODES, payload)->req_id, PAK(GC_GETNODES, packet)->req_id, sizeof(uint64_t));
        /* TODO: check output somehow */
        /* TODO: resolve id to ipp */
        /* send_common_tox_packet(dht, PAK(GC_GETNODES, packet)->requester_id, IP_Port ipp, 
            NET_PACKET_SEND_ANNOUNCED_NODES, payload, PAK_POS(GC_SENDNODES, nodes)+CLIENT_ID_EXT_SIZE*nodes_num); */
        printf("We found some nodes he needed\n");

        return true;
    }
    else 
        return false;
}

int initiate_gc_getnodes_request(DHT *dht, const uint8_t chat_id[], uint64_t *req_id)
{
    update_unix_time();

    uint8_t payload[PAK_LEN(GC_GETNODES)];
    id_copy(PAK(GC_GETNODES, payload)->chat_id, chat_id);
    id_copy(PAK(GC_GETNODES, payload)->requester_id, dht->self_public_key);
    U64_to_bytes(PAK(GC_GETNODES)->timestamp, unix_time());
    U64_to_bytes(PAK(GC_GETNODES)->timestamp, ++dht->announce->current_req_id); /* TODO: random untraceable ids */
    ANNOUNCE_Request *record=&dht->announce->requests[dht->announce->current_req_id % MAX_CONCURRENT_REQUESTS];
    record->ready=false;
    record->nodes_num=0;
    record->req_id=dht->announce->current_req_id;
    *req_id=dht->announce->current_req_id;
    
    return self_gc_getnodes_action(dht, payload) ? 0 : packet_dispatcher(dht, chat_id, dht->self_public_key, 
        payload, PAK_LEN(GC_GETNODES), NET_PACKET_GET_ANNOUNCED_NODES, 
        PAK_POS(GC_GETNODES, timestamp), GETNODES_REQUEST_EXPIRATION, 
        NULL);
}

static int handle_get_gc_announced_nodes_request(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    DHT *dht=(DHT*)_dht;
    
    /* Recieve and decypther packet */
    uint8_t payload[PAK_LEN(GC_GETNODES)];
    
    if (recv_common_tox_packet((DHT*)_dht, packet, payload, sizeof(payload)) < 0))
        return -1;
    
    LOGGER_DEBUG("handle_gc_ann_req: %s at %s:%d requests members of chat %s", 
                 id_toa(PAK(COMMON, packet)->sender_id),
                 ip_ntoa(&ipp.ip), ipp.port,
                 id_toa(PAK(GC_GETNODES, payload)->chat_id);
                 
    return self_gc_getnodes_action(dht, payload) ? 0 : packet_dispatcher(dht, PAK(GC_GETNODES, payload)->chat_id, PAK(COMMON, packet)->sender_id, 
        payload, PAK_LEN(GC_GETNODES), NET_PACKET_GET_ANNOUNCED_NODES, 
        PAK_POS(GC_GETNODES, timestamp), GETNODES_REQUEST_EXPIRATION, 
        NULL);
}

int handle_send_gc_announced_nodes_response(void *_dht, IP_Port ipp, const uint8_t *packet, uint32_t length)
{
    DHT *dht=(DHT*)_dht;
    
    /* Recieve and decypther packet */
    uint8_t payload[PAK_LEN(GC_SENDNODES)];
    
    if (recv_common_tox_packet((DHT*)_dht, packet, payload, sizeof(payload)) < 0))
        return -1;
    
    ANNOUNCE_Request *record=&dht->announce->requests[PAK(GC_SENDNODES, payload)->req_id % MAX_CONCURRENT_REQUESTS];

    /* Check if we really expect a packet with that request id */
    if (PAK(GC_SENDNODES, payload)->req_id != record->req_id)
    {
        LOGGER_DEBUG("handle_send_gc_ann_resp: corrupt or forged packet received from %s:%d", ip_ntoa(&ipp.ip), ipp.port);
        return -1;
    }

    /* TODO: if somebody already replied on our request, probably add? */
    if (!record->ready)
    {
        bytes_to_U32(&record->nodes_num, PAK(GC_SENDNODES, payload)->nodes_num);
        memcpy(record->nodes, PAK(GC_SENDNODES, payload)->nodes, length - PAK_POS(GC_SENDNODES, nodes));
        /* TODO: check that nodes_num = length of nodes/CLIENT_ID_EXT_SIZE and report error if not */
        record->ready=true;
    }
}

uint32_t retrieve_gc_nodes(DHT* dht, uint64_t req_id, uint8_t *nodes)
{
    ANNOUNCE_Request *record=&dht->announce->requests[req_id % MAX_CONCURRENT_REQUESTS];

    if (record->ready)
    {
        /* Assuming we checked that amount of nodes is legit */
        memcpy(nodes, record->nodes, CLIENT_ID_EXT_SIZE * record->nodes_num);
        return record->nodes_num;
    }
    else
        return 0;
}

ANNOUNCE *new_announce(DHT *dht)
{
    LOGGER_INIT(LOGGER_OUTPUT_FILE, LOGGER_LEVEL);

	ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

    /* Note that on some archs zero bytes are not NULL */
    announce_treelist_init(announce);
    announce->current_req_id=0;

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

    announce_treelist_clear(announce);

    free(announce);
}
