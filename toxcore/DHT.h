/* DHT.h
 *
 * An implementation of the DHT as seen in http://wiki.tox.im/index.php/DHT
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

#ifndef DHT_H
#define DHT_H

#include "net_crypto.h"


/* Size of the client_id in bytes. */
#define CLIENT_ID_SIZE crypto_box_PUBLICKEYBYTES

/* Maximum number of clients stored per friend. */
#define MAX_FRIEND_CLIENTS 8

/* A list of the clients mathematically closest to ours. */
#define LCLIENT_LIST 32

/* The list of ip ports along with the ping_id of what we sent them and a timestamp. */
#define LPING_ARRAY 256 // NOTE: Deprecated (doesn't do anything).

#define LSEND_NODES_ARRAY LPING_ARRAY/2

/* Maximum newly announced nodes to ping per TIME_TOPING seconds. */
#define MAX_TOPING 16

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    IP_Port     ip_port;
    uint64_t    timestamp;
    uint64_t    last_pinged;

    /* Returned by this node. Either our friend or us. */
    IP_Port     ret_ip_port;
    uint64_t    ret_timestamp;
} Client_data;

/*----------------------------------------------------------------------------------*/

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    Client_data client_list[MAX_FRIEND_CLIENTS];

    /* Time at which the last get_nodes request was sent. */
    uint64_t    lastgetnode;

    /* Symetric NAT hole punching stuff. */

    /* 1 if currently hole punching, otherwise 0 */
    uint8_t     hole_punching;
    uint32_t    punching_index;
    uint64_t    punching_timestamp;
    uint64_t    recvNATping_timestamp;
    uint64_t    NATping_id;
    uint64_t    NATping_timestamp;
} DHT_Friend;

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    IP_Port     ip_port;
} Node_format;

typedef struct {
    IP_Port     ip_port;
    uint64_t    ping_id;
    uint64_t    timestamp;
} Pinged;

/*----------------------------------------------------------------------------------*/
typedef struct {
    Net_Crypto *c;
    Client_data  close_clientlist[LCLIENT_LIST];
    DHT_Friend      *friends_list;
    uint16_t     num_friends;
    Pinged       send_nodes[LSEND_NODES_ARRAY];
    Node_format  toping[MAX_TOPING];
    uint64_t     last_toping;
    uint64_t close_lastgetnodes;
    void *ping;
} DHT;
/*----------------------------------------------------------------------------------*/


Client_data *DHT_get_close_list(DHT *dht);

/* Add a new friend to the friends list.
 * client_id must be CLIENT_ID_SIZE bytes long.
 *
 *  return 0 if success.
 *  return 1 if failure (friends list is full).
 */
int DHT_addfriend(DHT *dht, uint8_t *client_id);

/* Delete a friend from the friends list.
 * client_id must be CLIENT_ID_SIZE bytes long.
 *
 *  return 0 if success.
 *  return 1 if failure (client_id not in friends list).
 */
int DHT_delfriend(DHT *dht, uint8_t *client_id);

/* Get ip of friend.
 *  client_id must be CLIENT_ID_SIZE bytes long.
 *  ip must be 4 bytes long.
 *  port must be 2 bytes long.
 *
 *  return ip if success.
 *  return ip of 0 if failure (This means the friend is either offline or we have not found him yet).
 *  return ip of 1 if friend is not in list.
 */
IP_Port DHT_getfriendip(DHT *dht, uint8_t *client_id);

/* Run this function at least a couple times per second (It's the main loop). */
void do_DHT(DHT *dht);

/* Use this function to bootstrap the client.
 *  Sends a get nodes request to the given node with ip port and public_key.
 */
void DHT_bootstrap(DHT *dht, IP_Port ip_port, uint8_t *public_key);

/* Add nodes to the toping list.
 * All nodes in this list are pinged every TIME_TOPING seconds
 * and are then removed from the list.
 * If the list is full the nodes farthest from our client_id are replaced.
 * The purpose of this list is to enable quick integration of new nodes into the
 * network while preventing amplification attacks.
 *
 *  return 0 if node was added.
 *  return -1 if node was not added.
 */
int add_toping(DHT *dht, uint8_t *client_id, IP_Port ip_port);

/* ROUTING FUNCTIONS */

/* Send the given packet to node with client_id.
 *
 *  return -1 if failure.
 */
int route_packet(DHT *dht, uint8_t *client_id, uint8_t *packet, uint32_t length);

/* Send the following packet to everyone who tells us they are connected to friend_id.
 *
 *  return number of nodes it sent the packet to.
 */
int route_tofriend(DHT *dht, uint8_t *friend_id, uint8_t *packet, uint32_t length);

/* NAT PUNCHING FUNCTIONS */

/* Puts all the different ips returned by the nodes for a friend_id into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 *  returns number of ips returned.
 *  returns -1 if no such friend.
 */
int friend_ips(DHT *dht, IP_Port *ip_portlist, uint8_t *friend_id);

/* SAVE/LOAD functions */

/* Get the size of the DHT (for saving). */
uint32_t DHT_size(DHT *dht);

/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(DHT *dht, uint8_t *data);

/* Initialize DHT. */
DHT *new_DHT(Net_Crypto *c);

void kill_DHT(DHT *dht);

/* Load the DHT from data of size size.
 *
 *  return -1 if failure.
 *  return 0 if success.
 */
int DHT_load(DHT *dht, uint8_t *data, uint32_t size);

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int DHT_isconnected(DHT *dht);

void addto_lists(DHT *dht, IP_Port ip_port, uint8_t *client_id);


#endif
