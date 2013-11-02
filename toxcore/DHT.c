/* DHT.c
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

/*----------------------------------------------------------------------------------*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"
#include "assoc.h"
#include "ping.h"

#include "network.h"
#include "LAN_discovery.h"
#include "misc_tools.h"
#include "util.h"

/* The max number of nodes to send with send nodes. */
#define MAX_SENT_NODES 8

/* Ping timeout in seconds */
#define PING_TIMEOUT 5

/* Ping interval in seconds for each node in our lists. */
#define PING_INTERVAL 60

/* Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 5

#define MAX_PUNCHING_PORTS 128

/* Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 10

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/* Used in the comparison function for sorting lists of Client_data. */
typedef struct {
    Client_data c1;
    Client_data c2;
} ClientPair;

/* Create the declaration for a quick sort for ClientPair structures. */
declare_quick_sort(ClientPair);
/* Create the quicksort function. See misc_tools.h for the definition. */
make_quick_sort(ClientPair);

Client_data *DHT_get_close_list(DHT *dht)
{
    return dht->close_clientlist;
}

/* Compares client_id1 and client_id2 with client_id.
 *
 *  return 0 if both are same distance.
 *  return 1 if client_id1 is closer.
 *  return 2 if client_id2 is closer.
 */
int id_closest(uint8_t *id, uint8_t *id1, uint8_t *id2)
{
    size_t   i;
    uint8_t distance1, distance2;

    for (i = 0; i < CLIENT_ID_SIZE; ++i) {

        distance1 = abs(((int8_t *)id)[i] ^ ((int8_t *)id1)[i]);
        distance2 = abs(((int8_t *)id)[i] ^ ((int8_t *)id2)[i]);

        if (distance1 < distance2)
            return 1;

        if (distance1 > distance2)
            return 2;
    }

    return 0;
}

/* Turns the result of id_closest into something quick_sort can use.
 * Assumes p1->c1 == p2->c1.
 */
static int client_id_cmp(ClientPair p1, ClientPair p2)
{
    int c = id_closest(p1.c1.client_id, p1.c2.client_id, p2.c2.client_id);

    if (c == 2)
        return -1;

    return c;
}

static int client_in_list(Client_data *list, uint32_t length, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < length; i++)

        /* Dead nodes are considered dead (not in the list)*/
        if (!is_timeout(list[i].assoc4.timestamp, KILL_NODE_TIMEOUT) ||
                !is_timeout(list[i].assoc6.timestamp, KILL_NODE_TIMEOUT))
            if (id_equal(list[i].client_id, client_id))
                return 1;

    return 0;
}

/* Check if client with client_id is already in list of length length.
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 *  TODO: Maybe optimize this.
 *
 *  return True(1) or False(0)
 */
static int client_or_ip_port_in_list(Client_data *list, uint32_t length, uint8_t *client_id, IP_Port ip_port)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    /* if client_id is in list, find it and maybe overwrite ip_port */
    for (i = 0; i < length; ++i)
        if (id_equal(list[i].client_id, client_id)) {
            /* Refresh the client timestamp. */
            if (ip_port.ip.family == AF_INET) {

#ifdef LOGGING

                if (!ipport_equal(&list[i].assoc4.ip_port, &ip_port)) {
                    size_t x;
                    x = sprintf(logbuffer, "coipil[%u]: switching ipv4 from %s:%u ", i,
                                ip_ntoa(&list[i].assoc4.ip_port.ip), ntohs(list[i].assoc4.ip_port.port));
                    sprintf(logbuffer + x, "to %s:%u\n",
                            ip_ntoa(&ip_port.ip), ntohs(ip_port.port));
                    loglog(logbuffer);
                }

#endif

                if (LAN_ip(list[i].assoc4.ip_port.ip) != 0 && LAN_ip(ip_port.ip) == 0)
                    return 1;

                list[i].assoc4.ip_port = ip_port;
                list[i].assoc4.timestamp = temp_time;
            } else if (ip_port.ip.family == AF_INET6) {

#ifdef LOGGING

                if (!ipport_equal(&list[i].assoc6.ip_port, &ip_port)) {
                    size_t x;
                    x = sprintf(logbuffer, "coipil[%u]: switching ipv6 from %s:%u ", i,
                                ip_ntoa(&list[i].assoc6.ip_port.ip), ntohs(list[i].assoc6.ip_port.port));
                    sprintf(logbuffer + x, "to %s:%u\n",
                            ip_ntoa(&ip_port.ip), ntohs(ip_port.port));
                    loglog(logbuffer);
                }

#endif

                if (LAN_ip(list[i].assoc6.ip_port.ip) != 0 && LAN_ip(ip_port.ip) == 0)
                    return 1;

                list[i].assoc6.ip_port = ip_port;
                list[i].assoc6.timestamp = temp_time;
            }

            return 1;
        }

    /* client_id not in list yet: see if we can find an identical ip_port, in
     * that case we kill the old client_id by overwriting it with the new one
     * TODO: maybe we SHOULDN'T do that if that client_id is in a friend_list
     * and the one who is the actual friend's client_id/address set? */
    for (i = 0; i < length; ++i) {
        /* MAYBE: check the other address, if valid, don't nuke? */
        if ((ip_port.ip.family == AF_INET) && ipport_equal(&list[i].assoc4.ip_port, &ip_port)) {
            /* Initialize client timestamp. */
            list[i].assoc4.timestamp = temp_time;
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
#ifdef LOGGING
            sprintf(logbuffer, "coipil[%u]: switching client_id (ipv4) \n", i);
            loglog(logbuffer);
#endif
            /* kill the other address, if it was set */
            memset(&list[i].assoc6, 0, sizeof(list[i].assoc6));
            return 1;
        } else if ((ip_port.ip.family == AF_INET6) && ipport_equal(&list[i].assoc6.ip_port, &ip_port)) {
            /* Initialize client timestamp. */
            list[i].assoc6.timestamp = temp_time;
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
#ifdef LOGGING
            sprintf(logbuffer, "coipil[%u]: switching client_id (ipv6) \n", i);
            loglog(logbuffer);
#endif
            /* kill the other address, if it was set */
            memset(&list[i].assoc4, 0, sizeof(list[i].assoc4));
            return 1;
        }
    }

    return 0;
}

/* Check if client with client_id is already in node format list of length length.
 *
 *  return 1 if true.
 *  return 2 if false.
 */
static int client_in_nodelist(Node_format *list, uint32_t length, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (id_equal(list[i].client_id, client_id))
            return 1;
    }

    return 0;
}

/*  return friend number from the client_id.
 *  return -1 if a failure occurs.
 */
static int friend_number(DHT *dht, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < dht->num_friends; ++i) {
        if (id_equal(dht->friends_list[i].client_id, client_id))
            return i;
    }

    return -1;
}

/*
 * helper for get_close_nodes(). argument list is a monster :D
 */
static void get_close_nodes_inner(DHT *dht, uint8_t *client_id, Node_format *nodes_list,
                                  sa_family_t sa_family, Client_data *client_list, uint32_t client_list_length,
                                  int *num_nodes_ptr, uint8_t is_LAN)
{
    if ((sa_family != AF_INET) && (sa_family != AF_INET6))
        return;

    int num_nodes = *num_nodes_ptr;
    int ipv46x, j, closest;
    uint32_t i;

    for (i = 0; i < client_list_length; i++) {
        Client_data *client = &client_list[i];

        /* node already in list? */
        if (client_in_nodelist(nodes_list, MAX_SENT_NODES, client->client_id))
            continue;

        IPPTsPng *ipptp = NULL;

        if (sa_family == AF_INET)
            ipptp = &client->assoc4;
        else
            ipptp = &client->assoc6;

        /* node not in a good condition? */
        if (is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT))
            continue;

        IP *client_ip = &ipptp->ip_port.ip;

        /*
         * Careful: AF_INET isn't seen as AF_INET on dual-stack sockets for
         * our connections, instead we have to look if it is an embedded
         * IPv4-in-IPv6 here and convert it down in sendnodes().
         */
        sa_family_t ip_treat_as_family = client_ip->family;

        if ((dht->c->lossless_udp->net->family == AF_INET6) &&
                (client_ip->family == AF_INET6)) {
            /* socket is AF_INET6, address claims AF_INET6:
             * check for embedded IPv4-in-IPv6 (shouldn't happen anymore,
             * all storing functions should already convert down to IPv4) */
            if (IN6_IS_ADDR_V4MAPPED(&client_ip->ip6.in6_addr))
                ip_treat_as_family = AF_INET;
        }

        ipv46x = !(sa_family == ip_treat_as_family);

        /* node address of the wrong family? */
        if (ipv46x)
            continue;

        if (!LAN_ip(ipptp->ip_port.ip) && !is_LAN)
            continue;

        if (num_nodes < MAX_SENT_NODES) {
            memcpy(nodes_list[num_nodes].client_id,
                   client->client_id,
                   CLIENT_ID_SIZE );

            nodes_list[num_nodes].ip_port = ipptp->ip_port;
            num_nodes++;
        } else {
            /* see if node_list contains a client_id that's "further away"
             * compared to the one we're looking at at the moment, if there
             * is, replace it
             */
            for (j = 0; j < MAX_SENT_NODES; ++j) {
                closest = id_closest(   client_id,
                                        nodes_list[j].client_id,
                                        client->client_id );

                /* second client_id is closer than current: change to it */
                if (closest == 2) {
                    memcpy( nodes_list[j].client_id,
                            client->client_id,
                            CLIENT_ID_SIZE);

                    nodes_list[j].ip_port = ipptp->ip_port;
                    break;
                }
            }
        }
    }

    *num_nodes_ptr = num_nodes;
}

/* Find MAX_SENT_NODES nodes closest to the client_id for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * TODO: For the love of based <your favorite deity, in doubt use "love"> make
 * this function cleaner and much more efficient.
 */
static int get_close_nodes(DHT *dht, uint8_t *client_id, Node_format *nodes_list, sa_family_t sa_family, uint8_t is_LAN)
{
    int num_nodes = 0, i;
    get_close_nodes_inner(dht, client_id, nodes_list, sa_family,
                          dht->close_clientlist, LCLIENT_LIST, &num_nodes, is_LAN);

    for (i = 0; i < dht->num_friends; ++i)
        get_close_nodes_inner(dht, client_id, nodes_list, sa_family,
                              dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                              &num_nodes, is_LAN);

    return num_nodes;
}

/* Replace first bad (or empty) node with this one.
 *
 *  return 0 if successful.
 *  return 1 if not (list contains no bad nodes).
 */
static int replace_bad(    Client_data    *list,
                           uint32_t        length,
                           uint8_t        *client_id,
                           IP_Port         ip_port )
{
    if ((ip_port.ip.family != AF_INET) && (ip_port.ip.family != AF_INET6))
        return 1;

    uint32_t i;

    for (i = 0; i < length; ++i) {
        /* If node is bad */
        Client_data *client = &list[i];
        IPPTsPng *ipptp = NULL;

        if (ip_port.ip.family == AF_INET)
            ipptp = &client->assoc4;
        else
            ipptp = &client->assoc6;

        if (is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT)) {
            memcpy(client->client_id, client_id, CLIENT_ID_SIZE);
            ipptp->ip_port = ip_port;
            ipptp->timestamp = unix_time();

            ip_reset(&ipptp->ret_ip_port.ip);
            ipptp->ret_ip_port.port = 0;
            ipptp->ret_timestamp = 0;

            return 0;
        }
    }

    return 1;
}

/* Sort the list. It will be sorted from furthest to closest.
 *  Turns list into data that quick sort can use and reverts it back.
 */
static void sort_list(Client_data *list, uint32_t length, uint8_t *comp_client_id)
{
    Client_data cd;
    ClientPair pairs[length];
    uint32_t i;

    memcpy(cd.client_id, comp_client_id, CLIENT_ID_SIZE);

    for (i = 0; i < length; ++i) {
        pairs[i].c1 = cd;
        pairs[i].c2 = list[i];
    }

    ClientPair_quick_sort(pairs, length, client_id_cmp);

    for (i = 0; i < length; ++i)
        list[i] = pairs[i].c2;
}

/* Replace the first good node that is further to the comp_client_id than that of the client_id in the list */
static int replace_good(   Client_data    *list,
                           uint32_t        length,
                           uint8_t        *client_id,
                           IP_Port         ip_port,
                           uint8_t        *comp_client_id )
{
    if ((ip_port.ip.family != AF_INET) && (ip_port.ip.family != AF_INET6))
        return 1;

    sort_list(list, length, comp_client_id);

    int8_t replace = -1;

    /* Because the list is sorted, we can simply check the client_id at the
     * border, either it is closer, then every other one is as well, or it is
     * further, then it gets pushed out in favor of the new address, which
     * will with the next sort() move to its "rightful" position
     *
     * CAVEAT: weirdly enough, the list is sorted DESCENDING in distance
     * so the furthest element is the first, NOT the last (at least that's
     * what the comment above sort_list() claims)
     */
    if (id_closest(comp_client_id, list[0].client_id, client_id) == 2)
        replace = 0;

    if (replace != -1) {
#ifdef DEBUG
        assert(replace >= 0 && replace < length);
#endif
        Client_data *client = &list[replace];
        IPPTsPng *ipptp = NULL;

        if (ip_port.ip.family == AF_INET)
            ipptp = &client->assoc4;
        else
            ipptp = &client->assoc6;

        memcpy(client->client_id, client_id, CLIENT_ID_SIZE);
        ipptp->ip_port = ip_port;
        ipptp->timestamp = unix_time();

        ip_reset(&ipptp->ret_ip_port.ip);
        ipptp->ret_ip_port.port = 0;
        ipptp->ret_timestamp = 0;
        return 0;
    }

    return 1;
}

/* Attempt to add client with ip_port and client_id to the friends client list
 * and close_clientlist.
 */
void addto_lists(DHT *dht, IP_Port ip_port, uint8_t *client_id)
{
    uint32_t i;

    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == AF_INET6) && IN6_IS_ADDR_V4MAPPED(&ip_port.ip.ip6.in6_addr)) {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */
    if (!client_or_ip_port_in_list(dht->close_clientlist, LCLIENT_LIST, client_id, ip_port)) {
        if (replace_bad(dht->close_clientlist, LCLIENT_LIST, client_id, ip_port)) {
            /* If we can't replace bad nodes we try replacing good ones. */
            replace_good(dht->close_clientlist, LCLIENT_LIST, client_id, ip_port,
                         dht->c->self_public_key);
        }
    }

    for (i = 0; i < dht->num_friends; ++i) {
        if (!client_or_ip_port_in_list(dht->friends_list[i].client_list,
                                       MAX_FRIEND_CLIENTS, client_id, ip_port)) {

            if (replace_bad(dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                            client_id, ip_port)) {
                /* If we can't replace bad nodes we try replacing good ones. */
                replace_good(dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                             client_id, ip_port, dht->friends_list[i].client_id);
            }
        }
    }
}

/* If client_id is a friend or us, update ret_ip_port
 * nodeclient_id is the id of the node that sent us this info.
 */
static void returnedip_ports(DHT *dht, IP_Port ip_port, uint8_t *client_id, uint8_t *nodeclient_id)
{
    uint32_t i, j;
    uint64_t temp_time = unix_time();

    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == AF_INET6) && IN6_IS_ADDR_V4MAPPED(&ip_port.ip.ip6.in6_addr)) {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    if (id_equal(client_id, dht->c->self_public_key)) {
        for (i = 0; i < LCLIENT_LIST; ++i) {
            if (id_equal(nodeclient_id, dht->close_clientlist[i].client_id)) {
                if (ip_port.ip.family == AF_INET) {
                    dht->close_clientlist[i].assoc4.ret_ip_port = ip_port;
                    dht->close_clientlist[i].assoc4.ret_timestamp = temp_time;
                } else if (ip_port.ip.family == AF_INET6) {
                    dht->close_clientlist[i].assoc6.ret_ip_port = ip_port;
                    dht->close_clientlist[i].assoc6.ret_timestamp = temp_time;
                }

                return;
            }
        }

    } else {
        for (i = 0; i < dht->num_friends; ++i) {
            if (id_equal(client_id, dht->friends_list[i].client_id)) {
                for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                    if (id_equal(nodeclient_id, dht->friends_list[i].client_list[j].client_id)) {
                        if (ip_port.ip.family == AF_INET) {
                            dht->friends_list[i].client_list[j].assoc4.ret_ip_port = ip_port;
                            dht->friends_list[i].client_list[j].assoc4.ret_timestamp = temp_time;
                        } else if (ip_port.ip.family == AF_INET6) {
                            dht->friends_list[i].client_list[j].assoc6.ret_ip_port = ip_port;
                            dht->friends_list[i].client_list[j].assoc6.ret_timestamp = temp_time;
                        }

                        return;
                    }
                }
            }
        }

    }
}

static int is_gettingnodes(DHT *dht, IP_Port ip_port, uint64_t ping_id)
{
    uint32_t i;
    uint8_t pinging;

    for (i = 0; i < LSEND_NODES_ARRAY; ++i ) {
        if (!is_timeout(dht->send_nodes[i].timestamp, PING_TIMEOUT)) {
            pinging = 0;

            if (ping_id != 0 && dht->send_nodes[i].id == ping_id)
                ++pinging;

            if (ip_isset(&ip_port.ip) && ipport_equal(&dht->send_nodes[i].ip_port, &ip_port))
                ++pinging;

            if (pinging == (ping_id != 0) + ip_isset(&ip_port.ip))
                return 1;
        }
    }

    return 0;
}

/* Same but for get node requests. */
static uint64_t add_gettingnodes(DHT *dht, IP_Port ip_port)
{
    uint32_t i, j;
    uint64_t ping_id = ((uint64_t)random_int() << 32) + random_int();

    for (i = 0; i < PING_TIMEOUT; ++i ) {
        for (j = 0; j < LSEND_NODES_ARRAY; ++j ) {
            if (is_timeout(dht->send_nodes[j].timestamp, PING_TIMEOUT - i)) {
                dht->send_nodes[j].timestamp = unix_time();
                dht->send_nodes[j].ip_port = ip_port;
                dht->send_nodes[j].id = ping_id;
                return ping_id;
            }
        }
    }

    return 0;
}

/* Send a getnodes request to public_key to get nodes "close to" client_id. */
static int getnodes(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->c->self_public_key) || is_gettingnodes(dht, ip_port, 0))
        return -1;

    uint64_t ping_id = add_gettingnodes(dht, ip_port);

    if (ping_id == 0)
        return -1;

    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t plain[sizeof(ping_id) + CLIENT_ID_SIZE];
    uint8_t encrypt[sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    memcpy(plain, &ping_id, sizeof(ping_id));
    memcpy(plain + sizeof(ping_id), client_id, CLIENT_ID_SIZE);

    int len = encrypt_data( public_key,
                            dht->c->self_secret_key,
                            nonce,
                            plain,
                            sizeof(ping_id) + CLIENT_ID_SIZE,
                            encrypt );

    if (len != sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING)
        return -1;

    data[0] = NET_PACKET_GET_NODES;
    memcpy(data + 1, dht->c->self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->c->lossless_udp->net, ip_port, data, sizeof(data));
}

int DHT_request_nodes(DHT *dht, uint8_t *known_id, IP_Port *ipp, uint8_t *wanted_id)
{
    return getnodes(dht, *ipp, known_id, wanted_id);
}

/* Send a sendnodes response to public_key with nodes "close to" client_id.
 * Because of binary compatibility, the Node_format MUST BE Node4_format,
 * IPv6 nodes are sent in a different message */
static int sendnodes(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, uint64_t ping_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->c->self_public_key))
        return -1;

    size_t Node4_format_size = sizeof(Node4_format);
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id)
                 + Node4_format_size * MAX_SENT_NODES + ENCRYPTION_PADDING];

    Node_format nodes_list[MAX_SENT_NODES];
    int num_nodes = get_close_nodes(dht, client_id, nodes_list, AF_INET, LAN_ip(ip_port.ip) == 0);

    if (num_nodes == 0)
        return 0;

    uint8_t plain[sizeof(ping_id) + Node4_format_size * MAX_SENT_NODES];
    uint8_t encrypt[sizeof(ping_id) + Node4_format_size * MAX_SENT_NODES + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    memcpy(plain, &ping_id, sizeof(ping_id));

    Node4_format *nodes4_list = (Node4_format *)(plain + sizeof(ping_id));
    int i, num_nodes_ok = 0;

    for (i = 0; i < num_nodes; i++) {
        memcpy(nodes4_list[num_nodes_ok].client_id, nodes_list[i].client_id, CLIENT_ID_SIZE);
        nodes4_list[num_nodes_ok].ip_port.port = nodes_list[i].ip_port.port;

        IP *node_ip = &nodes_list[i].ip_port.ip;

        if ((node_ip->family == AF_INET6) && IN6_IS_ADDR_V4MAPPED(&node_ip->ip6.in6_addr))
            /* embedded IPv4-in-IPv6 address: return it in regular sendnodes packet */
            nodes4_list[num_nodes_ok].ip_port.ip.uint32 = node_ip->ip6.uint32[3];
        else if (node_ip->family == AF_INET)
            nodes4_list[num_nodes_ok].ip_port.ip.uint32 = node_ip->ip4.uint32;
        else /* shouldn't happen */
            continue;

        num_nodes_ok++;
    }

    if (num_nodes_ok < num_nodes) {
        /* shouldn't happen */
        num_nodes = num_nodes_ok;
    }

    int len = encrypt_data( public_key,
                            dht->c->self_secret_key,
                            nonce,
                            plain,
                            sizeof(ping_id) + num_nodes * Node4_format_size,
                            encrypt );

    if (len == -1)
        return -1;

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * Node4_format_size + ENCRYPTION_PADDING)
        return -1;

    data[0] = NET_PACKET_SEND_NODES;
    memcpy(data + 1, dht->c->self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->c->lossless_udp->net, ip_port, data, 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + len);
}

/* Send a send nodes response: message for IPv6 nodes */
static int sendnodes_ipv6(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, uint64_t ping_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->c->self_public_key))
        return -1;

    size_t Node_format_size = sizeof(Node_format);
    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id)
                 + Node_format_size * MAX_SENT_NODES + ENCRYPTION_PADDING];

    Node_format nodes_list[MAX_SENT_NODES];
    int num_nodes = get_close_nodes(dht, client_id, nodes_list, AF_INET6, LAN_ip(ip_port.ip) == 0);

    if (num_nodes == 0)
        return 0;

    uint8_t plain[sizeof(ping_id) + Node_format_size * MAX_SENT_NODES];
    uint8_t encrypt[sizeof(ping_id) + Node_format_size * MAX_SENT_NODES + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    memcpy(plain, &ping_id, sizeof(ping_id));
    memcpy(plain + sizeof(ping_id), nodes_list, num_nodes * Node_format_size);

    int len = encrypt_data( public_key,
                            dht->c->self_secret_key,
                            nonce,
                            plain,
                            sizeof(ping_id) + num_nodes * Node_format_size,
                            encrypt );

    if (len == -1)
        return -1;

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * Node_format_size + ENCRYPTION_PADDING)
        return -1;

    data[0] = NET_PACKET_SEND_NODES_IPV6;
    memcpy(data + 1, dht->c->self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->c->lossless_udp->net, ip_port, data, 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + len);
}

static int handle_getnodes(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    uint64_t ping_id;

    if (length != ( 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES
                    + sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING ))
        return 1;

    /* Check if packet is from ourself. */
    if (id_equal(packet + 1, dht->c->self_public_key))
        return 1;

    uint8_t plain[sizeof(ping_id) + CLIENT_ID_SIZE];

    int len = decrypt_data( packet + 1,
                            dht->c->self_secret_key,
                            packet + 1 + CLIENT_ID_SIZE,
                            packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                            sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING,
                            plain );

    if (len != sizeof(ping_id) + CLIENT_ID_SIZE)
        return 1;

    memcpy(&ping_id, plain, sizeof(ping_id));
    sendnodes(dht, source, packet + 1, plain + sizeof(ping_id), ping_id);
    sendnodes_ipv6(dht, source, packet + 1, plain + sizeof(ping_id),
                   ping_id); /* TODO: prevent possible amplification attacks */

    add_toping(dht->ping, packet + 1, source);
    //send_ping_request(dht, source, packet + 1); /* TODO: make this smarter? */

    return 0;
}

static int handle_sendnodes(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    uint64_t ping_id;
    uint32_t cid_size = 1 + CLIENT_ID_SIZE;
    cid_size += crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING;

    size_t Node4_format_size = sizeof(Node4_format);

    if (length > (cid_size + Node4_format_size * MAX_SENT_NODES) ||
            ((length - cid_size) % Node4_format_size) != 0 ||
            (length < cid_size + Node4_format_size))
        return 1;

    uint32_t num_nodes = (length - cid_size) / Node4_format_size;
    uint8_t plain[sizeof(ping_id) + Node4_format_size * MAX_SENT_NODES];

    int len = decrypt_data(
                  packet + 1,
                  dht->c->self_secret_key,
                  packet + 1 + CLIENT_ID_SIZE,
                  packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                  sizeof(ping_id) + num_nodes * Node4_format_size + ENCRYPTION_PADDING, plain );

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * Node4_format_size)
        return 1;

    memcpy(&ping_id, plain, sizeof(ping_id));

    if (!is_gettingnodes(dht, source, ping_id))
        return 1;

    Node4_format *nodes4_list = (Node4_format *)(plain + sizeof(ping_id));
    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t i, num_nodes_ok = 0;

    /* blow up from Node4 (IPv4) wire format to Node (IPv4/IPv6) structure */
    for (i = 0; i < num_nodes; i++)
        if ((nodes4_list[i].ip_port.ip.uint32 != 0) && (nodes4_list[i].ip_port.ip.uint32 != (uint32_t)~0)) {
            memcpy(nodes_list[num_nodes_ok].client_id, nodes4_list[i].client_id, CLIENT_ID_SIZE);
            nodes_list[num_nodes_ok].ip_port.ip.family = AF_INET;
            nodes_list[num_nodes_ok].ip_port.ip.ip4.uint32 = nodes4_list[i].ip_port.ip.uint32;
            nodes_list[num_nodes_ok].ip_port.port = nodes4_list[i].ip_port.port;

            num_nodes_ok++;
        }

    if (num_nodes_ok < num_nodes) {
        /* shouldn't happen */
        num_nodes = num_nodes_ok;
    }

    addto_lists(dht, source, packet + 1);

    if (dht->dhtassoc)
        DHT_assoc_candidate_new(dht->dhtassoc, packet + 1, &source, 1);

    for (i = 0; i < num_nodes; ++i)  {
        if (dht->dhtassoc)
            DHT_assoc_candidate_new(dht->dhtassoc, nodes_list[i].client_id, &nodes_list[i].ip_port, 0);

        send_ping_request(dht->ping, nodes_list[i].ip_port, nodes_list[i].client_id);
        returnedip_ports(dht, nodes_list[i].ip_port, nodes_list[i].client_id, packet + 1);
    }

    return 0;
}

static int handle_sendnodes_ipv6(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    uint64_t ping_id;
    uint32_t cid_size = 1 + CLIENT_ID_SIZE;
    cid_size += crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING;

    size_t Node_format_size = sizeof(Node_format);

    if (length > (cid_size + Node_format_size * MAX_SENT_NODES) ||
            ((length - cid_size) % Node_format_size) != 0 ||
            (length < cid_size + Node_format_size))
        return 1;

    uint32_t num_nodes = (length - cid_size) / Node_format_size;
    uint8_t plain[sizeof(ping_id) + Node_format_size * MAX_SENT_NODES];

    int len = decrypt_data(
                  packet + 1,
                  dht->c->self_secret_key,
                  packet + 1 + CLIENT_ID_SIZE,
                  packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                  sizeof(ping_id) + num_nodes * Node_format_size + ENCRYPTION_PADDING, plain );

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * Node_format_size)
        return 1;

    memcpy(&ping_id, plain, sizeof(ping_id));

    if (!is_gettingnodes(dht, source, ping_id))
        return 1;

    uint32_t i;
    Node_format nodes_list[MAX_SENT_NODES];
    memcpy(nodes_list, plain + sizeof(ping_id), num_nodes * sizeof(Node_format));

    addto_lists(dht, source, packet + 1);

    if (dht->dhtassoc)
        DHT_assoc_candidate_new(dht->dhtassoc, packet + 1, &source, 1);

    for (i = 0; i < num_nodes; ++i)  {
        if (dht->dhtassoc)
            DHT_assoc_candidate_new(dht->dhtassoc, nodes_list[i].client_id, &nodes_list[i].ip_port, 0);

        send_ping_request(dht->ping, nodes_list[i].ip_port, nodes_list[i].client_id);
        returnedip_ports(dht, nodes_list[i].ip_port, nodes_list[i].client_id, packet + 1);
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

/*
 * Send get nodes requests with client_id to max_num peers in list of length length
 */
static void get_bunchnodes(DHT *dht, Client_data *list, uint16_t length, uint16_t max_num, uint8_t *client_id)
{
    uint32_t i, num = 0;

    for (i = 0; i < length; ++i) {
        IPPTsPng *assoc;
        uint32_t a;

        for (a = 0, assoc = &list[i].assoc6; a < 2; a++, assoc = &list[i].assoc4)
            if (ipport_isset(&(assoc->ip_port)) &&
                    !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                getnodes(dht, assoc->ip_port, list[i].client_id, client_id);
                ++num;

                if (num >= max_num)
                    return;
            }
    }
}

int DHT_addfriend(DHT *dht, uint8_t *client_id)
{
    if (friend_number(dht, client_id) != -1) /* Is friend already in DHT? */
        return 1;

    DHT_Friend *temp;
    temp = realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends + 1));

    if (temp == NULL)
        return 1;

    dht->friends_list = temp;
    memset(&dht->friends_list[dht->num_friends], 0, sizeof(DHT_Friend));
    memcpy(dht->friends_list[dht->num_friends].client_id, client_id, CLIENT_ID_SIZE);

    dht->friends_list[dht->num_friends].nat.NATping_id = ((uint64_t)random_int() << 32) + random_int();
    ++dht->num_friends;

    if (dht->dhtassoc) {
        /* get up to MAX_FRIEND_CLIENTS connectable nodes */
        DHT_Friend *friend = &dht->friends_list[dht->num_friends - 1];

        DHT_assoc_close_nodes_simple state;
        memset(&state, 0, sizeof(state));
        state.close_count = MAX_FRIEND_CLIENTS;
        state.close_indices = calloc(MAX_FRIEND_CLIENTS, sizeof(size_t));

        uint8_t i, found = DHT_assoc_close_nodes_find(dht->dhtassoc, client_id, &state);

        for (i = 0; i < found; i++) {
            Client_data *data = DHT_assoc_client(dht->dhtassoc, state.close_indices[i]);

            if (data)
                memcpy(&friend->client_list[i], data, sizeof(*data));
        }
    }

    /*TODO: make this better?*/
    get_bunchnodes(dht, dht->close_clientlist, LCLIENT_LIST, MAX_FRIEND_CLIENTS, client_id);

    return 0;
}

int DHT_delfriend(DHT *dht, uint8_t *client_id)
{
    uint32_t i;
    DHT_Friend *temp;

    for (i = 0; i < dht->num_friends; ++i) {
        /* Equal */
        if (id_equal(dht->friends_list[i].client_id, client_id)) {
            --dht->num_friends;

            if (dht->num_friends != i) {
                memcpy( dht->friends_list[i].client_id,
                        dht->friends_list[dht->num_friends].client_id,
                        CLIENT_ID_SIZE );
            }

            if (dht->num_friends == 0) {
                free(dht->friends_list);
                dht->friends_list = NULL;
                return 0;
            }

            temp = realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends));

            if (temp == NULL)
                return 1;

            dht->friends_list = temp;
            return 0;
        }
    }

    return 1;
}

/* TODO: Optimize this. */
int DHT_getfriendip(DHT *dht, uint8_t *client_id, IP_Port *ip_port)
{
    uint32_t i, j;

    ip_reset(&ip_port->ip);
    ip_port->port = 0;

    for (i = 0; i < dht->num_friends; ++i) {
        /* Equal */
        if (id_equal(dht->friends_list[i].client_id, client_id)) {
            for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                Client_data *client = &dht->friends_list[i].client_list[j];

                if (id_equal(client->client_id, client_id)) {
                    IPPTsPng *assoc = NULL;
                    uint32_t a;

                    for (a = 0, assoc = &client->assoc6; a < 2; a++, assoc = &client->assoc4)
                        if (!is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT)) {
                            *ip_port = assoc->ip_port;
                            return 1;
                        }
                }
            }

            return 0;
        }
    }

    return -1;
}

static void do_ping_and_sendnode_requests(DHT *dht, uint64_t *lastgetnode, uint8_t *client_id,
        Client_data *list, uint32_t list_count)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    uint32_t num_nodes = 0;
    Client_data *client_list[list_count * 2];
    IPPTsPng    *assoc_list[list_count * 2];

    for (i = 0; i < list_count; i++) {
        /* If node is not dead. */
        Client_data *client = &list[i];
        IPPTsPng *assoc;
        uint32_t a;

        for (a = 0, assoc = &client->assoc6; a < 2; a++, assoc = &client->assoc4)
            if (!is_timeout(assoc->timestamp, KILL_NODE_TIMEOUT)) {
                if (is_timeout(assoc->last_pinged, PING_INTERVAL)) {
                    send_ping_request(dht->ping, assoc->ip_port, client->client_id );
                    assoc->last_pinged = temp_time;
                }

                /* If node is good. */
                if (!is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT)) {
                    client_list[num_nodes] = client;
                    assoc_list[num_nodes] = assoc;
                    ++num_nodes;
                }
            }
    }

    if ((num_nodes != 0) && is_timeout(*lastgetnode, GET_NODE_INTERVAL)) {
        uint32_t rand_node = rand() % num_nodes;
        getnodes(dht, assoc_list[rand_node]->ip_port, client_list[rand_node]->client_id,
                 client_id);
        *lastgetnode = temp_time;
    }
}

/* Ping each client in the "friends" list every PING_INTERVAL seconds. Send a get nodes request
 * every GET_NODE_INTERVAL seconds to a random good node for each "friend" in our "friends" list.
 */
static void do_DHT_friends(DHT *dht)
{
    uint32_t i;

    for (i = 0; i < dht->num_friends; ++i)
        do_ping_and_sendnode_requests(dht, &dht->friends_list[i].lastgetnode, dht->friends_list[i].client_id,
                                      dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS);
}

/* Ping each client in the close nodes list every PING_INTERVAL seconds.
 * Send a get nodes request every GET_NODE_INTERVAL seconds to a random good node in the list.
 */
static void do_Close(DHT *dht)
{
    do_ping_and_sendnode_requests(dht, &dht->close_lastgetnodes, dht->c->self_public_key,
                                  dht->close_clientlist, LCLIENT_LIST);
}

void DHT_bootstrap(DHT *dht, IP_Port ip_port, uint8_t *public_key)
{
    if (dht->dhtassoc)
        DHT_assoc_candidate_new(dht->dhtassoc, public_key, &ip_port, 0);

    getnodes(dht, ip_port, public_key, dht->c->self_public_key);
}
int DHT_bootstrap_from_address(DHT *dht, const char *address, uint8_t ipv6enabled,
                               uint16_t port, uint8_t *public_key)
{
    IP_Port ip_port_v64;
    IP *ip_extra = NULL;
    IP_Port ip_port_v4;
    ip_init(&ip_port_v64.ip, ipv6enabled);

    if (ipv6enabled) {
        /* setup for getting BOTH: an IPv6 AND an IPv4 address */
        ip_port_v64.ip.family = AF_UNSPEC;
        ip_reset(&ip_port_v4.ip);
        ip_extra = &ip_port_v4.ip;
    }

    if (addr_resolve_or_parse_ip(address, &ip_port_v64.ip, ip_extra)) {
        ip_port_v64.port = port;
        DHT_bootstrap(dht, ip_port_v64, public_key);

        if ((ip_extra != NULL) && ip_isset(ip_extra)) {
            ip_port_v4.port = port;
            DHT_bootstrap(dht, ip_port_v4, public_key);
        }

        return 1;
    } else
        return 0;
}

/* Send the given packet to node with client_id
 *
 *  return -1 if failure.
 */
int route_packet(DHT *dht, uint8_t *client_id, uint8_t *packet, uint32_t length)
{
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (id_equal(client_id, dht->close_clientlist[i].client_id)) {
            Client_data *client = &dht->close_clientlist[i];

            if (ip_isset(&client->assoc6.ip_port.ip))
                return sendpacket(dht->c->lossless_udp->net, client->assoc6.ip_port, packet, length);
            else if (ip_isset(&client->assoc4.ip_port.ip))
                return sendpacket(dht->c->lossless_udp->net, client->assoc4.ip_port, packet, length);
            else
                break;
        }
    }

    return -1;
}

/* Puts all the different ips returned by the nodes for a friend_num into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 *  return the number of ips returned.
 *  return 0 if we are connected to friend or if no ips were found.
 *  return -1 if no such friend.
 */
static int friend_iplist(DHT *dht, IP_Port *ip_portlist, uint16_t friend_num)
{
    if (friend_num >= dht->num_friends)
        return -1;

    DHT_Friend *friend = &dht->friends_list[friend_num];
    Client_data *client;
    IP_Port ipv4s[MAX_FRIEND_CLIENTS];
    int num_ipv4s = 0;
    IP_Port ipv6s[MAX_FRIEND_CLIENTS];
    int num_ipv6s = 0;
    uint8_t connected;
    int i;

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        client = &(friend->client_list[i]);
        connected = 0;

        /* If ip is not zero and node is good. */
        if (ip_isset(&client->assoc4.ret_ip_port.ip) && !is_timeout(client->assoc4.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv4s[num_ipv4s] = client->assoc4.ret_ip_port;
            ++num_ipv4s;

            connected = 1;
        }

        if (ip_isset(&client->assoc6.ret_ip_port.ip) && !is_timeout(client->assoc6.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv6s[num_ipv6s] = client->assoc6.ret_ip_port;
            ++num_ipv6s;

            connected = 1;
        }

        if (connected && id_equal(client->client_id, friend->client_id))
            return 0; /* direct connectivity */
    }

#ifdef FRIEND_IPLIST_PAD
    memcpy(ip_portlist, ipv6s, num_ipv6s * sizeof(IP_Port));

    if (num_ipv6s == MAX_FRIEND_CLIENTS)
        return MAX_FRIEND_CLIENTS;

    int num_ipv4s_used = MAX_FRIEND_CLIENTS - num_ipv6s;

    if (num_ipv4s_used > num_ipv4s)
        num_ipv4s_used = num_ipv4s;

    memcpy(&ip_portlist[num_ipv6s], ipv4s, num_ipv4s_used * sizeof(IP_Port));
    return num_ipv6s + num_ipv4s_used;

#else /* !FRIEND_IPLIST_PAD */

    /* there must be some secret reason why we can't pad the longer list
     * with the shorter one...
     */
    if (num_ipv6s >= num_ipv4s) {
        memcpy(ip_portlist, ipv6s, num_ipv6s * sizeof(IP_Port));
        return num_ipv6s;
    }

    memcpy(ip_portlist, ipv4s, num_ipv4s * sizeof(IP_Port));
    return num_ipv4s;

#endif /* !FRIEND_IPLIST_PAD */
}


/* Send the following packet to everyone who tells us they are connected to friend_id.
 *
 *  return ip for friend.
 *  return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 2).
 */
int route_tofriend(DHT *dht, uint8_t *friend_id, uint8_t *packet, uint32_t length)
{
    int num = friend_number(dht, friend_id);

    if (num == -1)
        return 0;

    uint32_t i, sent = 0;
    uint8_t friend_sent[MAX_FRIEND_CLIENTS] = {0};

    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    int ip_num = friend_iplist(dht, ip_list, num);

    if (ip_num < (MAX_FRIEND_CLIENTS / 2))
        return 0; /* Reason for that? */

    DHT_Friend *friend = &dht->friends_list[num];
    Client_data *client;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */
    uint32_t a;

    for (a = 0; a < 2; a++)
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            if (friend_sent[i])/* Send one packet per client.*/
                continue;

            client = &friend->client_list[i];
            IPPTsPng *assoc = NULL;

            if (!a)
                assoc = &client->assoc4;
            else
                assoc = &client->assoc6;

            /* If ip is not zero and node is good. */
            if (ip_isset(&assoc->ret_ip_port.ip) &&
                    !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                int retval = sendpacket(dht->c->lossless_udp->net, assoc->ip_port, packet, length);

                if ((unsigned int)retval == length) {
                    ++sent;
                    friend_sent[i] = 1;
                }
            }
        }

    return sent;
}

/* Send the following packet to one random person who tells us they are connected to friend_id.
 *
 *  return number of nodes the packet was sent to.
 */
static int routeone_tofriend(DHT *dht, uint8_t *friend_id, uint8_t *packet, uint32_t length)
{
    int num = friend_number(dht, friend_id);

    if (num == -1)
        return 0;

    DHT_Friend *friend = &dht->friends_list[num];
    Client_data *client;

    IP_Port ip_list[MAX_FRIEND_CLIENTS * 2];
    int n = 0;
    uint32_t i;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */
    uint32_t a;

    for (a = 0; a < 2; a++)
        for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
            client = &friend->client_list[i];
            IPPTsPng *assoc = NULL;

            if (!a)
                assoc = &client->assoc4;
            else
                assoc = &client->assoc6;

            /* If ip is not zero and node is good. */
            if (ip_isset(&assoc->ret_ip_port.ip) && !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                ip_list[n] = assoc->ip_port;
                ++n;
            }
        }

    if (n < 1)
        return 0;

    int retval = sendpacket(dht->c->lossless_udp->net, ip_list[rand() % n], packet, length);

    if ((unsigned int)retval == length)
        return 1;

    return 0;
}

/* Puts all the different ips returned by the nodes for a friend_id into array ip_portlist.
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 *  return number of ips returned.
 *  return 0 if we are connected to friend or if no ips were found.
 *  return -1 if no such friend.
 */
int friend_ips(DHT *dht, IP_Port *ip_portlist, uint8_t *friend_id)
{
    uint32_t i;

    for (i = 0; i < dht->num_friends; ++i) {
        /* Equal */
        if (id_equal(dht->friends_list[i].client_id, friend_id))
            return friend_iplist(dht, ip_portlist, i);
    }

    return -1;
}

/*----------------------------------------------------------------------------------*/
/*---------------------BEGINNING OF NAT PUNCHING FUNCTIONS--------------------------*/

static int send_NATping(DHT *dht, uint8_t *public_key, uint64_t ping_id, uint8_t type)
{
    uint8_t data[sizeof(uint64_t) + 1];
    uint8_t packet[MAX_DATA_SIZE];

    int num = 0;

    data[0] = type;
    memcpy(data + 1, &ping_id, sizeof(uint64_t));
    /* 254 is NAT ping request packet id */
    int len = create_request(dht->c->self_public_key, dht->c->self_secret_key, packet, public_key, data,
                             sizeof(uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

    if (len == -1)
        return -1;

    if (type == 0) /* If packet is request use many people to route it. */
        num = route_tofriend(dht, public_key, packet, len);
    else if (type == 1) /* If packet is response use only one person to route it */
        num = routeone_tofriend(dht, public_key, packet, len);

    if (num == 0)
        return -1;

    return num;
}

/* Handle a received ping request for. */
static int handle_NATping(void *object, IP_Port source, uint8_t *source_pubkey, uint8_t *packet, uint32_t length)
{
    if (length != sizeof(uint64_t) + 1)
        return 1;

    DHT *dht = object;
    uint64_t ping_id;
    memcpy(&ping_id, packet + 1, sizeof(uint64_t));

    int friendnumber = friend_number(dht, source_pubkey);

    if (friendnumber == -1)
        return 1;

    DHT_Friend *friend = &dht->friends_list[friendnumber];

    if (packet[0] == NAT_PING_REQUEST) {
        /* 1 is reply */
        send_NATping(dht, source_pubkey, ping_id, NAT_PING_RESPONSE);
        friend->nat.recvNATping_timestamp = unix_time();
        return 0;
    } else if (packet[0] == NAT_PING_RESPONSE) {
        if (friend->nat.NATping_id == ping_id) {
            friend->nat.NATping_id = ((uint64_t)random_int() << 32) + random_int();
            friend->nat.hole_punching = 1;
            return 0;
        }
    }

    return 1;
}

/* Get the most common ip in the ip_portlist.
 * Only return ip if it appears in list min_num or more.
 * len must not be bigger than MAX_FRIEND_CLIENTS.
 *
 *  return ip of 0 if failure.
 */
static IP NAT_commonip(IP_Port *ip_portlist, uint16_t len, uint16_t min_num)
{
    IP zero;
    ip_reset(&zero);

    if (len > MAX_FRIEND_CLIENTS)
        return zero;

    uint32_t i, j;
    uint16_t numbers[MAX_FRIEND_CLIENTS] = {0};

    for (i = 0; i < len; ++i) {
        for (j = 0; j < len; ++j) {
            if (ip_equal(&ip_portlist[i].ip, &ip_portlist[j].ip))
                ++numbers[i];
        }

        if (numbers[i] >= min_num)
            return ip_portlist[i].ip;
    }

    return zero;
}

/* Return all the ports for one ip in a list.
 * portlist must be at least len long,
 * where len is the length of ip_portlist.
 *
 *  return number of ports and puts the list of ports in portlist.
 */
static uint16_t NAT_getports(uint16_t *portlist, IP_Port *ip_portlist, uint16_t len, IP ip)
{
    uint32_t i;
    uint16_t num = 0;

    for (i = 0; i < len; ++i) {
        if (ip_equal(&ip_portlist[i].ip, &ip)) {
            portlist[num] = ntohs(ip_portlist[i].port);
            ++num;
        }
    }

    return num;
}

static void punch_holes(DHT *dht, IP ip, uint16_t *port_list, uint16_t numports, uint16_t friend_num)
{
    if (numports > MAX_FRIEND_CLIENTS || numports == 0)
        return;

    uint32_t i;
    uint32_t top = dht->friends_list[friend_num].nat.punching_index + MAX_PUNCHING_PORTS;
    uint16_t firstport = port_list[0];

    for (i = 0; i < numports; ++i) {
        if (firstport != port_list[0])
            break;
    }

    if (i == numports) { /* If all ports are the same, only try that one port. */
        IP_Port pinging;
        ip_copy(&pinging.ip, &ip);
        pinging.port = htons(firstport);
        send_ping_request(dht->ping, pinging, dht->friends_list[friend_num].client_id);
    } else {
        for (i = dht->friends_list[friend_num].nat.punching_index; i != top; i++) {
            /* TODO: Improve port guessing algorithm. */
            uint16_t port = port_list[(i / 2) % numports] + (i / (2 * numports)) * ((i % 2) ? -1 : 1);
            IP_Port pinging;
            ip_copy(&pinging.ip, &ip);
            pinging.port = htons(port);
            send_ping_request(dht->ping, pinging, dht->friends_list[friend_num].client_id);
        }

        dht->friends_list[friend_num].nat.punching_index = i;
    }
}

static void do_NAT(DHT *dht)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < dht->num_friends; ++i) {
        IP_Port ip_list[MAX_FRIEND_CLIENTS];
        int num = friend_iplist(dht, ip_list, i);

        /* If already connected or friend is not online don't try to hole punch. */
        if (num < MAX_FRIEND_CLIENTS / 2)
            continue;

        if (dht->friends_list[i].nat.NATping_timestamp + PUNCH_INTERVAL < temp_time) {
            send_NATping(dht, dht->friends_list[i].client_id, dht->friends_list[i].nat.NATping_id, NAT_PING_REQUEST);
            dht->friends_list[i].nat.NATping_timestamp = temp_time;
        }

        if (dht->friends_list[i].nat.hole_punching == 1 &&
                dht->friends_list[i].nat.punching_timestamp + PUNCH_INTERVAL < temp_time &&
                dht->friends_list[i].nat.recvNATping_timestamp + PUNCH_INTERVAL * 2 >= temp_time) {

            IP ip = NAT_commonip(ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (!ip_isset(&ip))
                continue;

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            uint16_t numports = NAT_getports(port_list, ip_list, num, ip);
            punch_holes(dht, ip, port_list, numports, i);

            dht->friends_list[i].nat.punching_timestamp = temp_time;
            dht->friends_list[i].nat.hole_punching = 0;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/

PING *DHT_ping(DHT *dht)
{
    if (dht)
        return dht->ping;

    return NULL;
}

Networking_Core *DHT_net(DHT *dht)
{
    if (dht)
        return dht->c->lossless_udp->net;

    return NULL;
}

/* return 1 for "store in dhtassoc" (when the storing has moved there) */
static uint8_t assoc_check_new_callback(DHT_assoc *dhtassoc, void *custom_data, uint32_t hash, uint8_t *client_id,
                                        uint8_t seen, IP_Port *ipp)
{
    DHT *dht = custom_data;

    if (!seen) {
        /* not a valid address, but check if it is the id of a friend */
        if (LAN_ip(ipp->ip) < 0) {
            size_t i;

            for (i = 0; i < dht->num_friends; i++)
                if (id_equal(client_id, dht->friends_list[i].client_id))
                    if (!dht->friends_list[i].lastgetnode)
                        add_toping(dht->ping, client_id, *ipp);
        }

        return 0;
    }

    /* valid reachable address: copy sh*t
     * if we made this address known, this function runs twice at the moment */
    addto_lists(dht, *ipp, client_id);

    return 0;
}

static uint8_t dhtassoc_callbacks_init = 0;
static DHT_assoc_callbacks dhtassoc_callbacks;

DHT *new_DHT(Net_Crypto *c)
{
    /* init time */
    unix_time_update();

    if (c == NULL)
        return NULL;

    DHT *dht = calloc(1, sizeof(DHT));

    if (dht == NULL)
        return NULL;

    dht->ping = new_ping(dht, c);

    if (dht->ping == NULL) {
        kill_DHT(dht);
        return NULL;
    }

    dht->c = c;
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_GET_NODES, &handle_getnodes, dht);
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_SEND_NODES, &handle_sendnodes, dht);
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, dht);

    init_cryptopackets(dht);
    cryptopacket_registerhandler(c, CRYPTO_PACKET_NAT_PING, &handle_NATping, dht);

    /* dhtassoc is not mandatory for now */
    dht->dhtassoc = DHT_assoc_new(dht);

    if (dht->dhtassoc) {
        /* overwritten in messenger_load if a state can be loaded */
        DHT_assoc_self(dht->dhtassoc, c->self_public_key);

        if (!dhtassoc_callbacks_init) {
            memset(&dhtassoc_callbacks, 0, sizeof(dhtassoc_callbacks));
            dhtassoc_callbacks.check_funcs.check_new_func = assoc_check_new_callback;
            dhtassoc_callbacks_init = 1;
        }

        DHT_assoc_register_callback(dht->dhtassoc, "DHT", dht, &dhtassoc_callbacks);
    }

    return dht;
}

void do_DHT(DHT *dht)
{
    unix_time_update();

    do_Close(dht);
    do_DHT_friends(dht);
    do_NAT(dht);
    do_toping(dht->ping);
}
void kill_DHT(DHT *dht)
{
    if (dht->dhtassoc)
        DHT_assoc_unregister_callback(dht->dhtassoc, dht, &dhtassoc_callbacks);

    kill_ping(dht->ping);
    free(dht->friends_list);
    free(dht);
}

/* Get the size of the DHT (for saving). */
uint32_t DHT_size_old(DHT *dht)
{
    return sizeof(dht->close_clientlist) + sizeof(DHT_Friend) * dht->num_friends;
}

/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save_old(DHT *dht, uint8_t *data)
{
    memcpy(data, dht->close_clientlist, sizeof(dht->close_clientlist));
    memcpy(data + sizeof(dht->close_clientlist), dht->friends_list, sizeof(DHT_Friend) * dht->num_friends);
}

/* Load the DHT from data of size size.
 *
 *  return -1 if failure.
 *  return 0 if success.
 */
int DHT_load_old(DHT *dht, uint8_t *data, uint32_t size)
{
    size_t clientlist_oldsize = sizeof(Client_data_old) * LCLIENT_LIST;

    if (size < clientlist_oldsize) {
#ifdef DEBUG
        fprintf(stderr, "DHT_load: Expected at least %u bytes, got %u.\n", sizeof(dht->close_clientlist), size);
#endif
        return -1;
    }

    uint32_t friendlistsize = size - clientlist_oldsize;

    if (friendlistsize % sizeof(DHT_Friend_old) != 0) {
#ifdef DEBUG
        fprintf(stderr, "DHT_load: Expected a multiple of %u, got %u.\n", sizeof(DHT_Friend), friendlistsize);
#endif
        return -1;
    }

    uint32_t i, j;
    Client_data_old *client;
    uint16_t friends_num = friendlistsize / sizeof(DHT_Friend_old);

    if (friends_num != 0) {
        DHT_Friend_old *tempfriends_list = (DHT_Friend_old *)(data + sizeof(dht->close_clientlist));

        for (i = 0; i < friends_num; ++i) {
            DHT_addfriend(dht, tempfriends_list[i].client_id);

            for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                client = &tempfriends_list[i].client_list[j];

                if (client->assoc.timestamp != 0)
                    getnodes(dht, client->assoc.ip_port, client->client_id, tempfriends_list[i].client_id);
            }
        }
    }

    Client_data_old *tempclose_clientlist = (Client_data_old *)data;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (tempclose_clientlist[i].assoc.timestamp != 0)
            DHT_bootstrap(dht, tempclose_clientlist[i].assoc.ip_port,
                          tempclose_clientlist[i].client_id );
    }

    return 0;
}


/* new DHT format for load/save, more robust and forward compatible */

#define DHT_STATE_COOKIE_GLOBAL 0x159000d

#define DHT_STATE_COOKIE_TYPE      0x11ce
#define DHT_STATE_TYPE_FRIENDS          1
#define DHT_STATE_TYPE_CLIENTS          2
#define DHT_STATE_TYPE_FRIENDS_ASSOC46  3
#define DHT_STATE_TYPE_CLIENTS_ASSOC46  4

/* Get the size of the DHT (for saving). */
uint32_t DHT_size(DHT *dht)
{
    uint32_t num = 0, i;

    for (i = 0; i < LCLIENT_LIST; ++i)
        if ((dht->close_clientlist[i].assoc4.timestamp != 0) ||
                (dht->close_clientlist[i].assoc6.timestamp != 0))
            num++;

    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    return size32
           + sizesubhead + sizeof(DHT_Friend) * dht->num_friends
           + sizesubhead + sizeof(Client_data) * num;
}

static uint8_t *z_state_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    uint32_t *data32 = (uint32_t *)data;
    data32[0] = len;
    data32[1] = (DHT_STATE_COOKIE_TYPE << 16) | type;
    data += sizeof(uint32_t) * 2;
    return data;
}

/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(DHT *dht, uint8_t *data)
{
    uint32_t len;
    uint16_t type;
    *(uint32_t *)data = DHT_STATE_COOKIE_GLOBAL;
    data += sizeof(uint32_t);

    len = sizeof(DHT_Friend) * dht->num_friends;
    type = DHT_STATE_TYPE_FRIENDS_ASSOC46;
    data = z_state_save_subheader(data, len, type);
    memcpy(data, dht->friends_list, len);
    data += len;

    uint32_t num = 0, i;

    for (i = 0; i < LCLIENT_LIST; ++i)
        if ((dht->close_clientlist[i].assoc4.timestamp != 0) ||
                (dht->close_clientlist[i].assoc6.timestamp != 0))
            num++;

    len = num * sizeof(Client_data);
    type = DHT_STATE_TYPE_CLIENTS_ASSOC46;
    data = z_state_save_subheader(data, len, type);

    if (num) {
        Client_data *clients = (Client_data *)data;

        for (num = 0, i = 0; i < LCLIENT_LIST; ++i)
            if ((dht->close_clientlist[i].assoc4.timestamp != 0) ||
                    (dht->close_clientlist[i].assoc6.timestamp != 0))
                memcpy(&clients[num++], &dht->close_clientlist[i], sizeof(Client_data));
    }

    data += len;
}

static int dht_load_state_callback(void *outer, uint8_t *data, uint32_t length, uint16_t type)
{
    DHT *dht = outer;
    uint32_t num, i, j;

    switch (type) {
        case DHT_STATE_TYPE_FRIENDS:
            if (length % sizeof(DHT_Friend_old) != 0)
                break;

            { /* localize declarations */
                DHT_Friend_old *friend_list = (DHT_Friend_old *)data;
                num = length / sizeof(DHT_Friend_old);

                for (i = 0; i < num; ++i) {
                    DHT_addfriend(dht, friend_list[i].client_id);

                    for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                        Client_data_old *client = &friend_list[i].client_list[j];

                        if (client->assoc.timestamp != 0)
                            getnodes(dht, client->assoc.ip_port, client->client_id, friend_list[i].client_id);
                    }
                }
            } /* localize declarations */

            break;

        case DHT_STATE_TYPE_CLIENTS:
            if ((length % sizeof(Client_data_old)) != 0)
                break;

            { /* localize declarations */
                num = length / sizeof(Client_data_old);
                Client_data_old *client_list = (Client_data_old *)data;

                for (i = 0; i < num; ++i)
                    if (client_list[i].assoc.timestamp != 0)
                        DHT_bootstrap(dht, client_list[i].assoc.ip_port, client_list[i].client_id);
            } /* localize declarations */

            break;

        case DHT_STATE_TYPE_FRIENDS_ASSOC46:
            if (length % sizeof(DHT_Friend) != 0)
                break;

            { /* localize declarations */
                DHT_Friend *friend_list = (DHT_Friend *)data;
                num = length / sizeof(DHT_Friend);

                for (i = 0; i < num; ++i) {
                    DHT_addfriend(dht, friend_list[i].client_id);

                    for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                        Client_data *client = &friend_list[i].client_list[j];

                        if (client->assoc4.timestamp != 0)
                            getnodes(dht, client->assoc4.ip_port, client->client_id, friend_list[i].client_id);

                        if (client->assoc6.timestamp != 0)
                            getnodes(dht, client->assoc6.ip_port, client->client_id, friend_list[i].client_id);
                    }
                }
            } /* localize declarations */

            break;

        case DHT_STATE_TYPE_CLIENTS_ASSOC46:
            if ((length % sizeof(Client_data)) != 0)
                break;

            { /* localize declarations */
                num = length / sizeof(Client_data);
                Client_data *client_list = (Client_data *)data;

                for (i = 0; i < num; ++i) {
                    if (client_list[i].assoc4.timestamp != 0)
                        DHT_bootstrap(dht, client_list[i].assoc4.ip_port, client_list[i].client_id);

                    if (client_list[i].assoc6.timestamp != 0)
                        DHT_bootstrap(dht, client_list[i].assoc6.ip_port, client_list[i].client_id);
                }
            } /* localize declarations */

            break;

#ifdef DEBUG

        default:
            fprintf(stderr, "Load state (DHT): contains unrecognized part (len %u, type %u)\n",
                    length, type);
            break;
#endif
    }

    return 0;
}

/* Load the DHT from data of size size.
 *
 *  return -1 if failure.
 *  return 0 if success.
 */
int DHT_load_new(DHT *dht, uint8_t *data, uint32_t length)
{
    uint32_t cookie_len = sizeof(uint32_t);

    if (length > cookie_len) {
        uint32_t *data32 = (uint32_t *)data;

        if (data32[0] == DHT_STATE_COOKIE_GLOBAL)
            return load_state(dht_load_state_callback, dht, data + cookie_len,
                              length - cookie_len, DHT_STATE_COOKIE_TYPE);
    }

    return DHT_load_old(dht, data, length);
}
/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int DHT_isconnected(DHT *dht)
{
    uint32_t i;
    unix_time_update();

    for (i = 0; i < LCLIENT_LIST; ++i) {
        Client_data *client = &dht->close_clientlist[i];

        if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) ||
                !is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT))
            return 1;
    }

    return 0;
}
