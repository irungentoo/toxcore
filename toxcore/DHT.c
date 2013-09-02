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

#include "DHT.h"
#include "ping.h"
#include "misc_tools.h"

/* The number of seconds for a non responsive node to become bad. */
#define BAD_NODE_TIMEOUT 70

/* The max number of nodes to send with send nodes. */
#define MAX_SENT_NODES 8

/* Ping timeout in seconds */
#define PING_TIMEOUT 5

/* The timeout after which a node is discarded completely. */
#define Kill_NODE_TIMEOUT 300

/* Ping interval in seconds for each node in our lists. */
#define PING_INTERVAL 60

/* Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 10

#define MAX_PUNCHING_PORTS 32

/* Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 10

/* Ping newly announced nodes to ping per TIME_TOPING seconds*/
#define TIME_TOPING 5

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
static int id_closest(uint8_t *id, uint8_t *id1, uint8_t *id2)
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

static int ipport_equal(IP_Port a, IP_Port b)
{
    return (a.ip.uint32 == b.ip.uint32) && (a.port == b.port);
}

static int id_equal(uint8_t *a, uint8_t *b)
{
    return memcmp(a, b, CLIENT_ID_SIZE) == 0;
}

static int is_timeout(uint64_t time_now, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= time_now;
}

/* Check if client with client_id is already in list of length length.
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 *  TODO: Maybe optimize this.
 *
 *  return True(1) or False(0)
 */
static int client_in_list(Client_data *list, uint32_t length, uint8_t *client_id, IP_Port ip_port)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < length; ++i) {
        /* If ip_port is assigned to a different client_id replace it */
        if (ipport_equal(list[i].ip_port, ip_port)) {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
        }

        if (id_equal(list[i].client_id, client_id)) {
            /* Refresh the client timestamp. */
            list[i].timestamp = temp_time;
            list[i].ip_port.ip.uint32 = ip_port.ip.uint32;
            list[i].ip_port.port = ip_port.port;
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

/* Find MAX_SENT_NODES nodes closest to the client_id for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * TODO: For the love of based Allah make this function cleaner and much more efficient.
 */
static int get_close_nodes(DHT *dht, uint8_t *client_id, Node_format *nodes_list)
{
    uint32_t    i, j, k;
    uint64_t    temp_time = unix_time();
    int         num_nodes = 0, closest, tout, inlist;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        tout = is_timeout(temp_time, dht->close_clientlist[i].timestamp, BAD_NODE_TIMEOUT);
        inlist = client_in_nodelist(nodes_list, MAX_SENT_NODES, dht->close_clientlist[i].client_id);

        /* If node isn't good or is already in list. */
        if (tout || inlist)
            continue;

        if (num_nodes < MAX_SENT_NODES) {

            memcpy( nodes_list[num_nodes].client_id,
                    dht->close_clientlist[i].client_id,
                    CLIENT_ID_SIZE );

            nodes_list[num_nodes].ip_port = dht->close_clientlist[i].ip_port;
            num_nodes++;

        } else {

            for (j = 0; j < MAX_SENT_NODES; ++j) {
                closest = id_closest(   client_id,
                                        nodes_list[j].client_id,
                                        dht->close_clientlist[i].client_id );

                if (closest == 2) {
                    memcpy( nodes_list[j].client_id,
                            dht->close_clientlist[i].client_id,
                            CLIENT_ID_SIZE);

                    nodes_list[j].ip_port = dht->close_clientlist[i].ip_port;
                    break;
                }
            }
        }
    }

    for (i = 0; i < dht->num_friends; ++i) {
        for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {

            tout = is_timeout(temp_time, dht->friends_list[i].client_list[j].timestamp, BAD_NODE_TIMEOUT);
            inlist = client_in_nodelist(    nodes_list,
                                            MAX_SENT_NODES,
                                            dht->friends_list[i].client_list[j].client_id);

            /* If node isn't good or is already in list. */
            if (tout || inlist)
                continue;

            if (num_nodes < MAX_SENT_NODES) {

                memcpy( nodes_list[num_nodes].client_id,
                        dht->friends_list[i].client_list[j].client_id,
                        CLIENT_ID_SIZE);

                nodes_list[num_nodes].ip_port = dht->friends_list[i].client_list[j].ip_port;
                num_nodes++;
            } else  {
                for (k = 0; k < MAX_SENT_NODES; ++k) {

                    closest = id_closest(   client_id,
                                            nodes_list[k].client_id,
                                            dht->friends_list[i].client_list[j].client_id );

                    if (closest == 2) {
                        memcpy( nodes_list[k].client_id,
                                dht->friends_list[i].client_list[j].client_id,
                                CLIENT_ID_SIZE );

                        nodes_list[k].ip_port = dht->friends_list[i].client_list[j].ip_port;
                        break;
                    }
                }
            }
        }
    }

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
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < length; ++i) {
        /* If node is bad */
        if (is_timeout(temp_time, list[i].timestamp, BAD_NODE_TIMEOUT)) {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = temp_time;
            list[i].ret_ip_port.ip.uint32 = 0;
            list[i].ret_ip_port.port = 0;
            list[i].ret_timestamp = 0;
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
    uint32_t i;
    uint64_t temp_time = unix_time();
    sort_list(list, length, comp_client_id);

    for (i = 0; i < length; ++i)
        if (id_closest(comp_client_id, list[i].client_id, client_id) == 2) {
            memcpy(list[i].client_id, client_id, CLIENT_ID_SIZE);
            list[i].ip_port = ip_port;
            list[i].timestamp = temp_time;
            list[i].ret_ip_port.ip.uint32 = 0;
            list[i].ret_ip_port.port = 0;
            list[i].ret_timestamp = 0;
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

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */
    if (!client_in_list(dht->close_clientlist, LCLIENT_LIST, client_id, ip_port)) {
        if (replace_bad(dht->close_clientlist, LCLIENT_LIST, client_id, ip_port)) {
            /* If we can't replace bad nodes we try replacing good ones. */
            replace_good(   dht->close_clientlist,
                            LCLIENT_LIST,
                            client_id,
                            ip_port,
                            dht->c->self_public_key );
        }
    }

    for (i = 0; i < dht->num_friends; ++i) {
        if (!client_in_list(    dht->friends_list[i].client_list,
                                MAX_FRIEND_CLIENTS,
                                client_id,
                                ip_port )) {

            if (replace_bad(    dht->friends_list[i].client_list,
                                MAX_FRIEND_CLIENTS,
                                client_id,
                                ip_port )) {
                /* If we can't replace bad nodes we try replacing good ones. */
                replace_good(   dht->friends_list[i].client_list,
                                MAX_FRIEND_CLIENTS,
                                client_id,
                                ip_port,
                                dht->friends_list[i].client_id );
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

    if (id_equal(client_id, dht->c->self_public_key)) {

        for (i = 0; i < LCLIENT_LIST; ++i) {
            if (id_equal(nodeclient_id, dht->close_clientlist[i].client_id)) {
                dht->close_clientlist[i].ret_ip_port = ip_port;
                dht->close_clientlist[i].ret_timestamp = temp_time;
                return;
            }
        }

    } else {

        for (i = 0; i < dht->num_friends; ++i) {
            if (id_equal(client_id, dht->friends_list[i].client_id)) {

                for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                    if (id_equal(nodeclient_id, dht->friends_list[i].client_list[j].client_id)) {
                        dht->friends_list[i].client_list[j].ret_ip_port = ip_port;
                        dht->friends_list[i].client_list[j].ret_timestamp = temp_time;
                        return;
                    }
                }
            }
        }

    }
}

/* Same as last function but for get_node requests. */
static int is_gettingnodes(DHT *dht, IP_Port ip_port, uint64_t ping_id)
{
    uint32_t i;
    uint8_t pinging;
    uint64_t temp_time = unix_time();

    for (i = 0; i < LSEND_NODES_ARRAY; ++i ) {
        if (!is_timeout(temp_time, dht->send_nodes[i].timestamp, PING_TIMEOUT)) {
            pinging = 0;

            if (ip_port.ip.uint32 != 0 && ipport_equal(dht->send_nodes[i].ip_port, ip_port))
                ++pinging;

            if (ping_id != 0 && dht->send_nodes[i].ping_id == ping_id)
                ++pinging;

            if (pinging == (ping_id != 0) + (ip_port.ip.uint32 != 0))
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
    uint64_t temp_time = unix_time();

    for (i = 0; i < PING_TIMEOUT; ++i ) {
        for (j = 0; j < LSEND_NODES_ARRAY; ++j ) {
            if (is_timeout(temp_time, dht->send_nodes[j].timestamp, PING_TIMEOUT - i)) {
                dht->send_nodes[j].timestamp = temp_time;
                dht->send_nodes[j].ip_port = ip_port;
                dht->send_nodes[j].ping_id = ping_id;
                return ping_id;
            }
        }
    }

    return 0;
}

/* Send a getnodes request. */
static int getnodes(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->c->self_public_key) || is_gettingnodes(dht, ip_port, 0))
        return 1;

    uint64_t ping_id = add_gettingnodes(dht, ip_port);

    if (ping_id == 0)
        return 1;

    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t plain[sizeof(ping_id) + CLIENT_ID_SIZE];
    uint8_t encrypt[sizeof(ping_id) + CLIENT_ID_SIZE + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

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

    return sendpacket(dht->c->lossless_udp->net->sock, ip_port, data, sizeof(data));
}

/* Send a send nodes response. */
static int sendnodes(DHT *dht, IP_Port ip_port, uint8_t *public_key, uint8_t *client_id, uint64_t ping_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->c->self_public_key))
        return 1;

    uint8_t data[1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + sizeof(ping_id)
                 + sizeof(Node_format) * MAX_SENT_NODES + ENCRYPTION_PADDING];

    Node_format nodes_list[MAX_SENT_NODES];
    int num_nodes = get_close_nodes(dht, client_id, nodes_list);

    if (num_nodes == 0)
        return 0;

    uint8_t plain[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES];
    uint8_t encrypt[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES + ENCRYPTION_PADDING];
    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    memcpy(plain, &ping_id, sizeof(ping_id));
    memcpy(plain + sizeof(ping_id), nodes_list, num_nodes * sizeof(Node_format));

    int len = encrypt_data( public_key,
                            dht->c->self_secret_key,
                            nonce,
                            plain,
                            sizeof(ping_id) + num_nodes * sizeof(Node_format),
                            encrypt );

    if (len == -1)
        return -1;

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * sizeof(Node_format) + ENCRYPTION_PADDING)
        return -1;

    data[0] = NET_PACKET_SEND_NODES;
    memcpy(data + 1, dht->c->self_public_key, CLIENT_ID_SIZE);
    memcpy(data + 1 + CLIENT_ID_SIZE, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->c->lossless_udp->net->sock, ip_port, data, 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES + len);
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

    //send_ping_request(dht, source, packet + 1); /* TODO: make this smarter? */

    return 0;
}

static int handle_sendnodes(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;
    uint64_t ping_id;
    uint32_t cid_size = 1 + CLIENT_ID_SIZE;
    cid_size += crypto_box_NONCEBYTES + sizeof(ping_id) + ENCRYPTION_PADDING;

    if (length > (cid_size + sizeof(Node_format) * MAX_SENT_NODES) ||
            ((length - cid_size) % sizeof(Node_format)) != 0 ||
            (length < cid_size + sizeof(Node_format)))
        return 1;

    uint32_t num_nodes = (length - cid_size) / sizeof(Node_format);
    uint8_t plain[sizeof(ping_id) + sizeof(Node_format) * MAX_SENT_NODES];

    int len = decrypt_data(
                  packet + 1,
                  dht->c->self_secret_key,
                  packet + 1 + CLIENT_ID_SIZE,
                  packet + 1 + CLIENT_ID_SIZE + crypto_box_NONCEBYTES,
                  sizeof(ping_id) + num_nodes * sizeof(Node_format) + ENCRYPTION_PADDING, plain );

    if ((unsigned int)len != sizeof(ping_id) + num_nodes * sizeof(Node_format))
        return 1;

    memcpy(&ping_id, plain, sizeof(ping_id));

    if (!is_gettingnodes(dht, source, ping_id))
        return 1;

    Node_format nodes_list[MAX_SENT_NODES];
    memcpy(nodes_list, plain + sizeof(ping_id), num_nodes * sizeof(Node_format));

    addto_lists(dht, source, packet + 1);

    uint32_t i;

    for (i = 0; i < num_nodes; ++i)  {
        send_ping_request(dht->ping, dht->c, nodes_list[i].ip_port, nodes_list[i].client_id);
        returnedip_ports(dht, nodes_list[i].ip_port, nodes_list[i].client_id, packet + 1);
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

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

    dht->friends_list[dht->num_friends].NATping_id = ((uint64_t)random_int() << 32) + random_int();
    ++dht->num_friends;
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
IP_Port DHT_getfriendip(DHT *dht, uint8_t *client_id)
{
    uint32_t i, j;
    uint64_t temp_time = unix_time();
    IP_Port empty = {{{{0}}, 0, 0}};

    for (i = 0; i < dht->num_friends; ++i) {
        /* Equal */
        if (id_equal(dht->friends_list[i].client_id, client_id)) {
            for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                if (id_equal(dht->friends_list[i].client_list[j].client_id, client_id)
                        && !is_timeout(temp_time, dht->friends_list[i].client_list[j].timestamp, BAD_NODE_TIMEOUT))
                    return dht->friends_list[i].client_list[j].ip_port;
            }

            return empty;
        }
    }

    empty.ip.uint32 = 1;
    return empty;
}

/* Ping each client in the "friends" list every PING_INTERVAL seconds. Send a get nodes request
 * every GET_NODE_INTERVAL seconds to a random good node for each "friend" in our "friends" list.
 */
static void do_DHT_friends(DHT *dht)
{
    uint32_t i, j;
    uint64_t temp_time = unix_time();
    uint32_t rand_node;
    uint32_t index[MAX_FRIEND_CLIENTS];

    for (i = 0; i < dht->num_friends; ++i) {
        uint32_t num_nodes = 0;

        for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
            /* If node is not dead. */
            if (!is_timeout(temp_time, dht->friends_list[i].client_list[j].timestamp, Kill_NODE_TIMEOUT)) {
                if ((dht->friends_list[i].client_list[j].last_pinged + PING_INTERVAL) <= temp_time) {
                    send_ping_request(dht->ping, dht->c, dht->friends_list[i].client_list[j].ip_port,
                                      dht->friends_list[i].client_list[j].client_id );
                    dht->friends_list[i].client_list[j].last_pinged = temp_time;
                }

                /* If node is good. */
                if (!is_timeout(temp_time, dht->friends_list[i].client_list[j].timestamp, BAD_NODE_TIMEOUT)) {
                    index[num_nodes] = j;
                    ++num_nodes;
                }
            }
        }

        if (dht->friends_list[i].lastgetnode + GET_NODE_INTERVAL <= temp_time && num_nodes != 0) {
            rand_node = rand() % num_nodes;
            getnodes(dht, dht->friends_list[i].client_list[index[rand_node]].ip_port,
                     dht->friends_list[i].client_list[index[rand_node]].client_id,
                     dht->friends_list[i].client_id );
            dht->friends_list[i].lastgetnode = temp_time;
        }
    }
}

/* Ping each client in the close nodes list every PING_INTERVAL seconds.
 * Send a get nodes request every GET_NODE_INTERVAL seconds to a random good node in the list.
 */
static void do_Close(DHT *dht)
{
    uint32_t i;
    uint64_t temp_time = unix_time();
    uint32_t num_nodes = 0;
    uint32_t rand_node;
    uint32_t index[LCLIENT_LIST];

    for (i = 0; i < LCLIENT_LIST; ++i) {
        /* If node is not dead. */
        if (!is_timeout(temp_time, dht->close_clientlist[i].timestamp, Kill_NODE_TIMEOUT)) {
            if ((dht->close_clientlist[i].last_pinged + PING_INTERVAL) <= temp_time) {
                send_ping_request(dht->ping, dht->c, dht->close_clientlist[i].ip_port,
                                  dht->close_clientlist[i].client_id );
                dht->close_clientlist[i].last_pinged = temp_time;
            }

            /* If node is good. */
            if (!is_timeout(temp_time, dht->close_clientlist[i].timestamp, BAD_NODE_TIMEOUT)) {
                index[num_nodes] = i;
                ++num_nodes;
            }
        }
    }

    if (dht->close_lastgetnodes + GET_NODE_INTERVAL <= temp_time && num_nodes != 0) {
        rand_node = rand() % num_nodes;
        getnodes(dht, dht->close_clientlist[index[rand_node]].ip_port,
                 dht->close_clientlist[index[rand_node]].client_id,
                 dht->c->self_public_key );
        dht->close_lastgetnodes = temp_time;
    }
}

void DHT_bootstrap(DHT *dht, IP_Port ip_port, uint8_t *public_key)
{
    getnodes(dht, ip_port, public_key, dht->c->self_public_key);
    send_ping_request(dht->ping, dht->c, ip_port, public_key);
}

/* Send the given packet to node with client_id
 *
 *  return -1 if failure.
 */
int route_packet(DHT *dht, uint8_t *client_id, uint8_t *packet, uint32_t length)
{
    uint32_t i;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (id_equal(client_id, dht->close_clientlist[i].client_id))
            return sendpacket(dht->c->lossless_udp->net->sock, dht->close_clientlist[i].ip_port, packet, length);
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
    int num_ips = 0;
    uint32_t i;
    uint64_t temp_time = unix_time();

    if (friend_num >= dht->num_friends)
        return -1;

    DHT_Friend *friend = &dht->friends_list[friend_num];
    Client_data *client;

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        client = &friend->client_list[i];

        /* If ip is not zero and node is good. */
        if (client->ret_ip_port.ip.uint32 != 0 && !is_timeout(temp_time, client->ret_timestamp, BAD_NODE_TIMEOUT)) {

            if (id_equal(client->client_id, friend->client_id))
                return 0;

            ip_portlist[num_ips] = client->ret_ip_port;
            ++num_ips;
        }
    }

    return num_ips;
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

    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    int ip_num = friend_iplist(dht, ip_list, num);

    if (ip_num < (MAX_FRIEND_CLIENTS / 2))
        return 0;

    uint64_t temp_time = unix_time();
    DHT_Friend *friend = &dht->friends_list[num];
    Client_data *client;

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        client = &friend->client_list[i];

        /* If ip is not zero and node is good. */
        if (client->ret_ip_port.ip.uint32 != 0 && !is_timeout(temp_time, client->ret_timestamp, BAD_NODE_TIMEOUT)) {
            int retval = sendpacket(dht->c->lossless_udp->net->sock, client->ip_port, packet, length);

            if ((unsigned int)retval == length)
                ++sent;
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

    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    int n = 0;
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        client = &friend->client_list[i];

        /* If ip is not zero and node is good. */
        if (client->ret_ip_port.ip.uint32 != 0 && !is_timeout(temp_time, client->ret_timestamp, BAD_NODE_TIMEOUT)) {
            ip_list[n] = client->ip_port;
            ++n;
        }
    }

    if (n < 1)
        return 0;

    int retval = sendpacket(dht->c->lossless_udp->net->sock, ip_list[rand() % n], packet, length);

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
        friend->recvNATping_timestamp = unix_time();
        return 0;
    } else if (packet[0] == NAT_PING_RESPONSE) {
        if (friend->NATping_id == ping_id) {
            friend->NATping_id = ((uint64_t)random_int() << 32) + random_int();
            friend->hole_punching = 1;
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
    IP zero = {{0}};

    if (len > MAX_FRIEND_CLIENTS)
        return zero;

    uint32_t i, j;
    uint16_t numbers[MAX_FRIEND_CLIENTS] = {0};

    for (i = 0; i < len; ++i) {
        for (j = 0; j < len; ++j) {
            if (ip_portlist[i].ip.uint32 == ip_portlist[j].ip.uint32)
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
        if (ip_portlist[i].ip.uint32 == ip.uint32) {
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
    uint32_t top = dht->friends_list[friend_num].punching_index + MAX_PUNCHING_PORTS;

    for (i = dht->friends_list[friend_num].punching_index; i != top; i++) {
        /* TODO: Improve port guessing algorithm. */
        uint16_t port = port_list[(i / 2) % numports] + (i / (2 * numports)) * ((i % 2) ? -1 : 1);
        IP_Port pinging = {{ip, htons(port), 0}};
        send_ping_request(dht->ping, dht->c, pinging, dht->friends_list[friend_num].client_id);
    }

    dht->friends_list[friend_num].punching_index = i;
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

        if (dht->friends_list[i].NATping_timestamp + PUNCH_INTERVAL < temp_time) {
            send_NATping(dht, dht->friends_list[i].client_id, dht->friends_list[i].NATping_id, NAT_PING_REQUEST);
            dht->friends_list[i].NATping_timestamp = temp_time;
        }

        if (dht->friends_list[i].hole_punching == 1 &&
                dht->friends_list[i].punching_timestamp + PUNCH_INTERVAL < temp_time &&
                dht->friends_list[i].recvNATping_timestamp + PUNCH_INTERVAL * 2 >= temp_time) {

            IP ip = NAT_commonip(ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (ip.uint32 == 0)
                continue;

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            uint16_t numports = NAT_getports(port_list, ip_list, num, ip);
            punch_holes(dht, ip, port_list, numports, i);

            dht->friends_list[i].punching_timestamp = temp_time;
            dht->friends_list[i].hole_punching = 0;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/


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
int add_toping(DHT *dht, uint8_t *client_id, IP_Port ip_port)
{
    if (ip_port.ip.uint32 == 0)
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TOPING; ++i) {
        if (dht->toping[i].ip_port.ip.uint32 == 0) {
            memcpy(dht->toping[i].client_id, client_id, CLIENT_ID_SIZE);
            dht->toping[i].ip_port.ip.uint32 = ip_port.ip.uint32;
            dht->toping[i].ip_port.port = ip_port.port;
            return 0;
        }
    }

    for (i = 0; i < MAX_TOPING; ++i) {
        if (id_closest(dht->c->self_public_key, dht->toping[i].client_id, client_id) == 2) {
            memcpy(dht->toping[i].client_id, client_id, CLIENT_ID_SIZE);
            dht->toping[i].ip_port.ip.uint32 = ip_port.ip.uint32;
            dht->toping[i].ip_port.port = ip_port.port;
            return 0;
        }
    }

    return -1;
}

/* Ping all the valid nodes in the toping list every TIME_TOPING seconds.
 * This function must be run at least once every TIME_TOPING seconds.
 */
static void do_toping(DHT *dht)
{
    uint64_t temp_time = unix_time();

    if (!is_timeout(temp_time, dht->last_toping, TIME_TOPING))
        return;

    dht->last_toping = temp_time;
    uint32_t i;

    for (i = 0; i < MAX_TOPING; ++i) {
        if (dht->toping[i].ip_port.ip.uint32 == 0)
            return;

        send_ping_request(dht->ping, dht->c, dht->toping[i].ip_port, dht->toping[i].client_id);
        dht->toping[i].ip_port.ip.uint32 = 0;
    }
}


DHT *new_DHT(Net_Crypto *c)
{
    if (c == NULL)
        return NULL;

    DHT *temp = calloc(1, sizeof(DHT));

    if (temp == NULL)
        return NULL;

    temp->ping = new_ping();

    if (temp->ping == NULL) {
        kill_DHT(temp);
        return NULL;
    }

    temp->c = c;
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_PING_REQUEST, &handle_ping_request, temp);
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_PING_RESPONSE, &handle_ping_response, temp);
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_GET_NODES, &handle_getnodes, temp);
    networking_registerhandler(c->lossless_udp->net, NET_PACKET_SEND_NODES, &handle_sendnodes, temp);
    init_cryptopackets(temp);
    cryptopacket_registerhandler(c, CRYPTO_PACKET_NAT_PING, &handle_NATping, temp);
    return temp;
}

void do_DHT(DHT *dht)
{
    do_Close(dht);
    do_DHT_friends(dht);
    do_NAT(dht);
    do_toping(dht);
}
void kill_DHT(DHT *dht)
{
    kill_ping(dht->ping);
    free(dht->friends_list);
    free(dht);
}

/* Get the size of the DHT (for saving). */
uint32_t DHT_size(DHT *dht)
{
    return sizeof(dht->close_clientlist) + sizeof(DHT_Friend) * dht->num_friends;
}

/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(DHT *dht, uint8_t *data)
{
    memcpy(data, dht->close_clientlist, sizeof(dht->close_clientlist));
    memcpy(data + sizeof(dht->close_clientlist), dht->friends_list, sizeof(DHT_Friend) * dht->num_friends);
}

/* Load the DHT from data of size size.
 *
 *  return -1 if failure.
 *  return 0 if success.
 */
int DHT_load(DHT *dht, uint8_t *data, uint32_t size)
{
    if (size < sizeof(dht->close_clientlist))
        return -1;

    if ((size - sizeof(dht->close_clientlist)) % sizeof(DHT_Friend) != 0)
        return -1;

    uint32_t i, j;
    uint16_t temp;
    /* uint64_t temp_time = unix_time(); */

    Client_data *client;

    temp = (size - sizeof(dht->close_clientlist)) / sizeof(DHT_Friend);

    if (temp != 0) {
        DHT_Friend *tempfriends_list = (DHT_Friend *)(data + sizeof(dht->close_clientlist));

        for (i = 0; i < temp; ++i) {
            DHT_addfriend(dht, tempfriends_list[i].client_id);

            for (j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
                client = &tempfriends_list[i].client_list[j];

                if (client->timestamp != 0)
                    getnodes(dht, client->ip_port, client->client_id, tempfriends_list[i].client_id);
            }
        }
    }

    Client_data *tempclose_clientlist = (Client_data *)data;

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (tempclose_clientlist[i].timestamp != 0)
            DHT_bootstrap(dht, tempclose_clientlist[i].ip_port,
                          tempclose_clientlist[i].client_id );
    }

    return 0;
}

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int DHT_isconnected(DHT *dht)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < LCLIENT_LIST; ++i) {
        if (!is_timeout(temp_time, dht->close_clientlist[i].timestamp, BAD_NODE_TIMEOUT))
            return 1;
    }

    return 0;
}
