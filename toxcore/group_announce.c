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
#define MAX_ANNOUNCED_NODES 20

 /* Ping newly announced nodes every TIME_TO_PING seconds*/
#define TIME_TO_PING 20

struct ANNOUNCE {
    DHT *dht;

    Ping_Array ping_array;
    Announced_node_format announced_nodes[MAX_ANNOUNCED_NODES];
    uint64_t last_to_ping;
};

/* Send announce request
 * For members of group chat, who want to announce being online now
 * Announcing node should send chat_id together with other info
 */
int send_announce_request(PING *ping, IP_Port ipp, uint8_t *client_id)
{
}

static int handle_announce_request(DHT * dht, IP_Port source, uint8_t *packet, uint32_t length)
{
}

static int get_announced_nodes_request(DHT * dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, Node_format *sendback_node)
{
}

static int handle_get_announced_nodes_request(DHT * dht, IP_Port source, uint8_t *packet, uint32_t length)
{
}


/*
 * static int sendnodes_ipv6(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, uint8_t *sendback_data,
 *                         uint16_t length, uint8_t *shared_encryption_key)
 */


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
int add_announced_nodes(ANNOUNCE *announce, uint8_t *client_id, IP_Port ip_port)
{
}

/* Ping all the valid nodes in the announced_nodes list every TIME_TO_PING seconds.
 * This function must be run at least once every TIME_TO_PING seconds.
 */
void do_announced_nodes(ANNOUNCE *announce)
{
}

ANNOUNCE *new_announce(DHT *dht)
{
	ANNOUNCE *announce = calloc(1, sizeof(ANNOUNCE));

    if (announce == NULL)
        return NULL;

    if (ping_array_init(&ping->ping_array, PING_NUM_MAX, PING_TIMEOUT) != 0) {
        free(ping);
        return NULL;
    }

    ping->dht = dht;
    networking_registerhandler(ping->dht->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_announce_request, dht);
    networking_registerhandler(ping->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, &handle_ping_response, dht);

    return ping;
}

void kill_announce(ANNOUNCE *announce)
{
	networking_registerhandler(ping->dht->net, NET_PACKET_ANNOUNCE_REQUEST, NULL, NULL);
    networking_registerhandler(ping->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, NULL, NULL);
    ping_array_free_all(&announce->ping_array);

    free(announce);
}
