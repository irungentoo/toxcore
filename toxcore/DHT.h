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

#include "crypto_core.h"
#include "network.h"
#include "ping_array.h"

/* Size of the client_id in bytes. */
#define CLIENT_ID_SIZE crypto_box_PUBLICKEYBYTES

/* Maximum number of clients stored per friend. */
#define MAX_FRIEND_CLIENTS 8

/* A list of the clients mathematically closest to ours. */
#define LCLIENT_LIST 32

/* The max number of nodes to send with send nodes. */
#define MAX_SENT_NODES 4

/* Ping timeout in seconds */
#define PING_TIMEOUT 3

/* size of DHT ping arrays. */
#define DHT_PING_ARRAY_SIZE 512

/* Ping interval in seconds for each node in our lists. */
#define PING_INTERVAL 60

/* The number of seconds for a non responsive node to become bad. */
#define PINGS_MISSED_NODE_GOES_BAD 1
#define PING_ROUNDTRIP 2
#define BAD_NODE_TIMEOUT (PING_INTERVAL + PINGS_MISSED_NODE_GOES_BAD * (PING_INTERVAL + PING_ROUNDTRIP))

/* Redefinitions of variables for safe transfer over wire. */
#define TOX_AF_INET 2
#define TOX_AF_INET6 10
#define TOX_TCP_INET 130
#define TOX_TCP_INET6 138

/* The number of "fake" friends to add (for optimization purposes and so our paths for the onion part are more random) */
#define DHT_FAKE_FRIEND_NUMBER 4

/* Functions to transfer ips safely across wire. */
void to_net_family(IP *ip);
void to_host_family(IP *ip);

typedef struct {
    IP_Port     ip_port;
    uint64_t    timestamp;
} IPPTs;

typedef struct {
    /* Node routes request correctly (true (1) or false/didn't check (0)) */
    uint8_t     routes_requests_ok;
    /* Time which we last checked this.*/
    uint64_t    routes_requests_timestamp;
    uint8_t     routes_requests_pingedid[CLIENT_ID_SIZE];
    /* Node sends correct send_node (true (1) or false/didn't check (0)) */
    uint8_t     send_nodes_ok;
    /* Time which we last checked this.*/
    uint64_t    send_nodes_timestamp;
    uint8_t     send_nodes_pingedid[CLIENT_ID_SIZE];
    /* Node can be used to test other nodes (true (1) or false/didn't check (0)) */
    uint8_t     testing_requests;
    /* Time which we last checked this.*/
    uint64_t    testing_timestamp;
    uint8_t     testing_pingedid[CLIENT_ID_SIZE];
} Hardening;

typedef struct {
    IP_Port     ip_port;
    uint64_t    timestamp;
    uint64_t    last_pinged;

    Hardening hardening;
    /* Returned by this node. Either our friend or us. */
    IP_Port     ret_ip_port;
    uint64_t    ret_timestamp;
} IPPTsPng;

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    IPPTsPng    assoc4;
    IPPTsPng    assoc6;
} Client_data;

/*----------------------------------------------------------------------------------*/

typedef struct {
    /* 1 if currently hole punching, otherwise 0 */
    uint8_t     hole_punching;
    uint32_t    punching_index;
    uint32_t    tries;
    uint32_t    punching_index2;

    uint64_t    punching_timestamp;
    uint64_t    recvNATping_timestamp;
    uint64_t    NATping_id;
    uint64_t    NATping_timestamp;
} NAT;

typedef struct {
    uint8_t     client_id[CLIENT_ID_SIZE];
    Client_data client_list[MAX_FRIEND_CLIENTS];

    /* Time at which the last get_nodes request was sent. */
    uint64_t    lastgetnode;
    /* number of times get_node packets were sent. */
    uint32_t    bootstrap_times;

    /* Symetric NAT hole punching stuff. */
    NAT         nat;
} DHT_Friend;

typedef struct __attribute__ ((__packed__))
{
    uint8_t     client_id[CLIENT_ID_SIZE];
    IP_Port     ip_port;
}
Node_format;

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes(uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number);

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_nodes(Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
                 uint16_t length, uint8_t tcp_enabled);


/*----------------------------------------------------------------------------------*/
/* struct to store some shared keys so we don't have to regenerate them for each request. */
#define MAX_KEYS_PER_SLOT 4
#define KEYS_TIMEOUT 600
typedef struct {
    struct {
        uint8_t client_id[CLIENT_ID_SIZE];
        uint8_t shared_key[crypto_box_BEFORENMBYTES];
        uint32_t times_requested;
        uint8_t  stored; /* 0 if not, 1 if is */
        uint64_t time_last_requested;
    } keys[256 * MAX_KEYS_PER_SLOT];
} Shared_Keys;

/*----------------------------------------------------------------------------------*/

typedef int (*cryptopacket_handler_callback)(void *object, IP_Port ip_port, const uint8_t *source_pubkey,
        const uint8_t *data, uint32_t len);

typedef struct {
    cryptopacket_handler_callback function;
    void *object;
} Cryptopacket_Handles;

typedef struct {
    Networking_Core *net;

    Client_data    close_clientlist[LCLIENT_LIST];
    uint64_t       close_lastgetnodes;
    uint32_t       close_bootstrap_times;

    /* Note: this key should not be/is not used to transmit any sensitive materials */
    uint8_t      secret_symmetric_key[crypto_box_KEYBYTES];
    /* DHT keypair */
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];

    DHT_Friend    *friends_list;
    uint16_t       num_friends;

    Shared_Keys shared_keys_recv;
    Shared_Keys shared_keys_sent;

    struct PING   *ping;
    Ping_Array    dht_ping_array;
    Ping_Array    dht_harden_ping_array;
#ifdef ENABLE_ASSOC_DHT
    struct Assoc  *assoc;
#endif
    uint64_t       last_run;

    Cryptopacket_Handles cryptopackethandlers[256];
} DHT;
/*----------------------------------------------------------------------------------*/

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key(Shared_Keys *shared_keys, uint8_t *shared_key, const uint8_t *secret_key, const uint8_t *client_id);

/* Copy shared_key to encrypt/decrypt DHT packet from client_id into shared_key
 * for packets that we receive.
 */
void DHT_get_shared_key_recv(DHT *dht, uint8_t *shared_key, const uint8_t *client_id);

/* Copy shared_key to encrypt/decrypt DHT packet from client_id into shared_key
 * for packets that we send.
 */
void DHT_get_shared_key_sent(DHT *dht, uint8_t *shared_key, const uint8_t *client_id);

void DHT_getnodes(DHT *dht, const IP_Port *from_ipp, const uint8_t *from_id, const uint8_t *which_id);

/* Add a new friend to the friends list.
 * client_id must be CLIENT_ID_SIZE bytes long.
 *
 *  return 0 if success.
 *  return 1 if failure (friends list is full).
 */
int DHT_addfriend(DHT *dht, const uint8_t *client_id);

/* Delete a friend from the friends list.
 * client_id must be CLIENT_ID_SIZE bytes long.
 *
 *  return 0 if success.
 *  return 1 if failure (client_id not in friends list).
 */
int DHT_delfriend(DHT *dht, const uint8_t *client_id);

/* Get ip of friend.
 *  client_id must be CLIENT_ID_SIZE bytes long.
 *  ip must be 4 bytes long.
 *  port must be 2 bytes long.
 *
 * !!! Signature changed !!!
 *
 * OLD: IP_Port DHT_getfriendip(DHT *dht, uint8_t *client_id);
 *
 *  return ip if success.
 *  return ip of 0 if failure (This means the friend is either offline or we have not found him yet).
 *  return ip of 1 if friend is not in list.
 *
 * NEW: int DHT_getfriendip(DHT *dht, uint8_t *client_id, IP_Port *ip_port);
 *
 *  return -1, -- if client_id does NOT refer to a friend
 *  return  0, -- if client_id refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if client_id refers to a friend and we found him
 */
int DHT_getfriendip(const DHT *dht, const uint8_t *client_id, IP_Port *ip_port);

/* Compares client_id1 and client_id2 with client_id.
 *
 *  return 0 if both are same distance.
 *  return 1 if client_id1 is closer.
 *  return 2 if client_id2 is closer.
 */
int id_closest(const uint8_t *id, const uint8_t *id1, const uint8_t *id2);

/* Get the (maximum MAX_SENT_NODES) closest nodes to client_id we know
 * and put them in nodes_list (must be MAX_SENT_NODES big).
 *
 * sa_family = family (IPv4 or IPv6) (0 if we don't care)?
 * is_LAN = return some LAN ips (true or false)
 * want_good = do we want tested nodes or not? (TODO)
 *
 * return the number of nodes returned.
 *
 */
int get_close_nodes(const DHT *dht, const uint8_t *client_id, Node_format *nodes_list, sa_family_t sa_family,
                    uint8_t is_LAN, uint8_t want_good);


/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t closelist_nodes(DHT *dht, Node_format *nodes, uint16_t max_num);

/* Put up to max_num random nodes in nodes.
 *
 * return the number of nodes.
 *
 * NOTE:this is used to pick nodes for paths.
 */
uint16_t random_nodes_path(const DHT *dht, Node_format *nodes, uint16_t max_num);

/* Run this function at least a couple times per second (It's the main loop). */
void do_DHT(DHT *dht);

/*
 *  Use these two functions to bootstrap the client.
 */
/* Sends a "get nodes" request to the given node with ip, port and public_key
 *   to setup connections
 */
void DHT_bootstrap(DHT *dht, IP_Port ip_port, const uint8_t *public_key);
/* Resolves address into an IP address. If successful, sends a "get nodes"
 *   request to the given node with ip, port and public_key to setup connections
 *
 * address can be a hostname or an IP address (IPv4 or IPv6).
 * if ipv6enabled is 0 (zero), the resolving sticks STRICTLY to IPv4 addresses
 * if ipv6enabled is not 0 (zero), the resolving looks for IPv6 addresses first,
 *   then IPv4 addresses.
 *
 *  returns 1 if the address could be converted into an IP address
 *  returns 0 otherwise
 */
int DHT_bootstrap_from_address(DHT *dht, const char *address, uint8_t ipv6enabled,
                               uint16_t port, const uint8_t *public_key);


/* ROUTING FUNCTIONS */

/* Send the given packet to node with client_id.
 *
 *  return -1 if failure.
 */
int route_packet(const DHT *dht, const uint8_t *client_id, const uint8_t *packet, uint32_t length);

/* Send the following packet to everyone who tells us they are connected to friend_id.
 *
 *  return number of nodes it sent the packet to.
 */
int route_tofriend(const DHT *dht, const uint8_t *friend_id, const uint8_t *packet, uint32_t length);

/* Function to handle crypto packets.
 */
void cryptopacket_registerhandler(DHT *dht, uint8_t byte, cryptopacket_handler_callback cb, void *object);

/* NAT PUNCHING FUNCTIONS */

/* Puts all the different ips returned by the nodes for a friend_id into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 *  returns number of ips returned.
 *  returns -1 if no such friend.
 */
int friend_ips(const DHT *dht, IP_Port *ip_portlist, const uint8_t *friend_id);

/* SAVE/LOAD functions */

/* Get the size of the DHT (for saving). */
uint32_t DHT_size(const DHT *dht);

/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(DHT *dht, uint8_t *data);

/* Load the DHT from data of size size.
 *
 *  return -1 if failure.
 *  return 0 if success.
 */
int DHT_load(DHT *dht, const uint8_t *data, uint32_t length);

/* Initialize DHT. */
DHT *new_DHT(Networking_Core *net);

void kill_DHT(DHT *dht);

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int DHT_isconnected(const DHT *dht);

int addto_lists(DHT *dht, IP_Port ip_port, const uint8_t *client_id);

#endif

