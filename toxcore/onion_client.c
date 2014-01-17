/*
* onion_client.c -- Implementation of the client part of docs/Prevent_Tracking.txt
*                   (The part that uses the onion stuff to connect to the friend)
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_client.h"
#include "util.h"
#include "LAN_discovery.h"

#define ANNOUNCE_TIMEOUT 10

static uint8_t zero_ping[ONION_PING_ID_SIZE];

/* Creates a sendback for use in an announce request.
 *
 * num is 0 if we used our secret public key for the announce
 * num is 1 + friendnum if we use a temporary one.
 *
 * Public key is the key we will be sending it to.
 * ip_port is the ip_port of the node we will be sending
 * it to.
 *
 * sendback must be at least ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 *
 * return -1 on failure
 * return 0 on success
 *
 */
static int new_sendback(Onion_Client *onion_c, uint32_t num, uint8_t *public_key, IP_Port ip_port, uint8_t *sendback)
{
    uint8_t plain[sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES + sizeof(IP_Port)];
    uint64_t time = unix_time();
    new_nonce(sendback);
    memcpy(plain, &num, sizeof(uint32_t));
    memcpy(plain + sizeof(uint32_t), &time, sizeof(uint64_t));
    memcpy(plain + sizeof(uint32_t) + sizeof(uint64_t), public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES, &ip_port, sizeof(IP_Port));

    int len = encrypt_data_symmetric(onion_c->secret_symmetric_key, sendback, plain, sizeof(plain),
                                     sendback + crypto_secretbox_NONCEBYTES);

    if ((uint32_t)len + crypto_secretbox_NONCEBYTES != ONION_ANNOUNCE_SENDBACK_DATA_LENGTH)
        return -1;

    return 0;
}

/* Checks if the sendback is valid and returns the public key contained in it in ret_pubkey and the
 * ip contained in it in ret_ip_port
 *
 * sendback is the sendback ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 * ret_pubkey must be at least crypto_box_PUBLICKEYBYTES big
 * ret_ip_port must be at least 1 big
 *
 * return ~0 on failure
 * return num (see new_sendback(...)) on success
 */
static uint32_t check_sendback(Onion_Client *onion_c, uint8_t *sendback, uint8_t *ret_pubkey, IP_Port *ret_ip_port)
{
    uint8_t plain[sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES + sizeof(IP_Port)];
    int len = decrypt_data_symmetric(onion_c->secret_symmetric_key, sendback, sendback + crypto_secretbox_NONCEBYTES,
                                     ONION_ANNOUNCE_SENDBACK_DATA_LENGTH - crypto_secretbox_NONCEBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return ~0;

    uint64_t timestamp;
    memcpy(&timestamp, plain + sizeof(uint32_t), sizeof(uint64_t));
    uint64_t temp_time = unix_time();

    if (timestamp + ANNOUNCE_TIMEOUT < temp_time || temp_time < timestamp)
        return ~0;

    memcpy(ret_pubkey, plain + sizeof(uint32_t) + sizeof(uint64_t), crypto_box_PUBLICKEYBYTES);
    memcpy(ret_ip_port, plain + sizeof(uint32_t) + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES, sizeof(IP_Port));
    uint32_t num;
    memcpy(&num, plain, sizeof(uint32_t));
    return num;
}

static int client_send_announce_request(Onion_Client *onion_c, uint32_t num, IP_Port dest, uint8_t *dest_pubkey,
                                        uint8_t *ping_id)
{
    if (num > onion_c->num_friends)
        return -1;

    uint8_t sendback[ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];

    if (new_sendback(onion_c, num, dest_pubkey, dest, sendback) == -1)
        return -1;

    uint8_t zero_ping_id[ONION_PING_ID_SIZE] = {0};

    if (ping_id == NULL)
        ping_id = zero_ping_id;

    Node_format nodes[4];

    if (random_path(onion_c, nodes) == -1)
        return -1;

    nodes[3].ip_port = dest;
    memcpy(nodes[3].client_id, dest_pubkey, crypto_box_PUBLICKEYBYTES);

    if (num == 0) {
        return send_announce_request(onion_c->dht, nodes, onion_c->dht->c->self_public_key,
                                     onion_c->dht->c->self_secret_key, ping_id,
                                     onion_c->dht->c->self_public_key, sendback);
    } else {
        return send_announce_request(onion_c->dht, nodes, onion_c->friends_list[num - 1].temp_public_key,
                                     onion_c->friends_list[num - 1].temp_secret_key, ping_id,
                                     onion_c->friends_list[num - 1].real_client_id, sendback);
    }
}

static uint8_t cmp_public_key[crypto_box_PUBLICKEYBYTES];
static int cmp_entry(const void *a, const void *b)
{
    Onion_Node entry1, entry2;
    memcpy(&entry1, a, sizeof(Onion_Node));
    memcpy(&entry2, b, sizeof(Onion_Node));
    int t1 = is_timeout(entry1.timestamp, ONION_NODE_TIMEOUT);
    int t2 = is_timeout(entry2.timestamp, ONION_NODE_TIMEOUT);

    if (t1 && t2)
        return 0;

    if (t1)
        return -1;

    if (t2)
        return 1;

    int close = id_closest(cmp_public_key, entry1.client_id, entry2.client_id);

    if (close == 1)
        return 1;

    if (close == 2)
        return -1;

    return 0;
}

static int client_add_to_list(Onion_Client *onion_c, uint32_t num, uint8_t *public_key, IP_Port ip_port,
                              uint8_t *ping_id)
{
    if (num > onion_c->num_friends)
        return -1;

    Onion_Node *list_nodes = NULL;
    uint8_t *reference_id = NULL;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = onion_c->dht->c->self_public_key;
    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_client_id;
    }

    memcpy(cmp_public_key, reference_id, crypto_box_PUBLICKEYBYTES);
    qsort(list_nodes, MAX_ONION_CLIENTS, sizeof(Onion_Node), cmp_entry);

    int index = -1;

    if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
            || id_closest(reference_id, list_nodes[0].client_id, public_key) == 2) {
        index = 0;
    }

    uint32_t i;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (memcmp(list_nodes[i].client_id, public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1)
        return 0;

    memcpy(list_nodes[index].client_id, public_key, CLIENT_ID_SIZE);
    list_nodes[index].ip_port = ip_port;
    memcpy(list_nodes[index].ping_id, ping_id, ONION_PING_ID_SIZE);
    list_nodes[index].timestamp = unix_time();
    list_nodes[index].last_pinged = 0;
    return 0;
}

static int client_ping_nodes(Onion_Client *onion_c, uint32_t num, Node_format *nodes, uint16_t num_nodes,
                             IP_Port source)
{
    if (num > onion_c->num_friends)
        return -1;

    if (num_nodes == 0)
        return 0;

    Onion_Node *list_nodes = NULL;
    uint8_t *reference_id = NULL;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = onion_c->dht->c->self_public_key;
    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_client_id;
    }

    uint32_t i, j;
    int lan_ips_accepted = (LAN_ip(source.ip) == 0);

    for (i = 0; i < num_nodes; ++i) {
        to_host_family(&nodes[i].ip_port.ip);

        if (!lan_ips_accepted)
            if (LAN_ip(nodes[i].ip_port.ip) == 0)
                continue;

        if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
                || id_closest(reference_id, list_nodes[0].client_id, nodes[i].client_id) == 2) {
            /* check if node is already in list. */
            for (j = 0; j < MAX_ONION_CLIENTS; ++j) {
                if (memcmp(list_nodes[j].client_id, nodes[i].client_id, crypto_box_PUBLICKEYBYTES) == 0) {
                    break;
                }
            }

            if (j == MAX_ONION_CLIENTS)
                client_send_announce_request(onion_c, num, nodes[i].ip_port, nodes[i].client_id, NULL);
        }
    }

    return 0;
}

static int handle_announce_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < ONION_ANNOUNCE_RESPONSE_MIN_SIZE || length > ONION_ANNOUNCE_RESPONSE_MAX_SIZE)
        return 1;

    if ((length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE) % sizeof(Node_format) != 0)
        return 1;

    uint16_t num_nodes = (length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE) / sizeof(Node_format);

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    IP_Port ip_port;
    uint32_t num = check_sendback(onion_c, packet + 1, public_key, &ip_port);

    if (num > onion_c->num_friends)
        return 1;

    uint8_t plain[ONION_PING_ID_SIZE + num_nodes * sizeof(Node_format)];
    int len = -1;

    if (num == 0) {
        len = decrypt_data(public_key, onion_c->dht->c->self_secret_key, packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    } else {
        if (onion_c->friends_list[num - 1].status == 0)
            return 1;

        len = decrypt_data(public_key, onion_c->friends_list[num - 1].temp_secret_key,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES), plain);
    }

    if ((uint32_t)len != sizeof(plain))
        return 1;


    if (client_add_to_list(onion_c, num, public_key, ip_port, plain) == -1)
        return 1;

    if (client_ping_nodes(onion_c, num, (Node_format *)plain + ONION_PING_ID_SIZE, num_nodes, source) == -1)
        return 1;

    return 0;
}

#define DATA_IN_RESPONSE_MIN_SIZE (crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)

static int handle_data_response(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length <= (ONION_DATA_RESPONSE_MIN_SIZE + DATA_IN_RESPONSE_MIN_SIZE))
        return 1;

    if (length > MAX_DATA_SIZE)
        return 1;

    uint8_t temp_plain[length - ONION_DATA_RESPONSE_MIN_SIZE];
    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion_c->dht->c->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), temp_plain);

    if ((uint32_t)len != sizeof(temp_plain))
        return 1;

    uint8_t plain[sizeof(temp_plain) - DATA_IN_RESPONSE_MIN_SIZE];
    len = decrypt_data(temp_plain, onion_c->dht->c->self_secret_key, packet + 1, temp_plain + crypto_box_PUBLICKEYBYTES,
                       sizeof(temp_plain) - crypto_box_PUBLICKEYBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    if (!onion_c->Onion_Data_Handlers[plain[0]].function)
        return 1;

    return onion_c->Onion_Data_Handlers[plain[0]].function(onion_c->Onion_Data_Handlers[plain[0]].object, temp_plain, plain,
            sizeof(plain));
}

#define FAKEID_DATA_ID 156
#define FAKEID_DATA_MIN_LENGTH (1 + crypto_box_PUBLICKEYBYTES)
#define FAKEID_DATA_MAX_LENGTH (FAKEID_DATA_MIN_LENGTH + sizeof(Node_format)*MAX_SENT_NODES)
static int handle_fakeid_announce(void *object, uint8_t *source_pubkey, uint8_t *data, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < FAKEID_DATA_MIN_LENGTH)
        return 1;

    if (length > FAKEID_DATA_MAX_LENGTH)
        return 1;

    if ((length - FAKEID_DATA_MIN_LENGTH) % sizeof(Node_format) != 0)
        return 1;

    int friend_num = onion_friend_num(onion_c, source_pubkey);

    if (friend_num == -1)
        return 1;

    if (memcmp(data + 1, onion_c->friends_list[friend_num].fake_client_id, crypto_box_PUBLICKEYBYTES) != 0) {
        DHT_delfriend(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id);

        if (DHT_addfriend(onion_c->dht, data + 1) == 1) {
            return 1;
        }

        memcpy(onion_c->friends_list[friend_num].fake_client_id, data + 1, crypto_box_PUBLICKEYBYTES);
    }

    uint16_t num_nodes = (length - FAKEID_DATA_MIN_LENGTH) / sizeof(Node_format);
    Node_format nodes[num_nodes];
    memcpy(nodes, data + 1 + crypto_box_PUBLICKEYBYTES, sizeof(nodes));
    uint32_t i;

    for (i = 0; i < num_nodes; ++i) {
        to_host_family(&nodes[i].ip_port.ip);
        DHT_getnodes(onion_c->dht, &nodes[i].ip_port, nodes[i].client_id, onion_c->friends_list[friend_num].fake_client_id);
    }

    //TODO replay protection
    return 0;
}
/* Send data of length length to friendnum.
 * This data will be recieved by the friend using the Onion_Data_Handlers callbacks.
 *
 * Even if this function succeeds, the friend might not recieve any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int send_onion_data(Onion_Client *onion_c, int friend_num, uint8_t *data, uint32_t length)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (length + DATA_IN_RESPONSE_MIN_SIZE + ONION_DATA_RESPONSE_MIN_SIZE + ONION_SEND_1 > MAX_DATA_SIZE)
        return -1;

    if (length == 0)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t packet[DATA_IN_RESPONSE_MIN_SIZE + length];
    memcpy(packet, onion_c->dht->c->self_public_key, crypto_box_PUBLICKEYBYTES);
    int len = encrypt_data(onion_c->friends_list[friend_num].real_client_id, onion_c->dht->c->self_secret_key, nonce, data,
                           length, packet + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len + crypto_box_PUBLICKEYBYTES != sizeof(packet))
        return -1;

    uint32_t i, good = 0;
    Onion_Node *list_nodes = onion_c->friends_list[friend_num].clients_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        if (memcmp(list_nodes[i].ping_id, zero_ping, ONION_PING_ID_SIZE) == 0) {
            Node_format nodes[4];

            if (random_path(onion_c, nodes) == -1)
                continue;

            memcpy(nodes[3].client_id, list_nodes[i].client_id, crypto_box_PUBLICKEYBYTES);
            nodes[3].ip_port = list_nodes[i].ip_port;

            if (send_data_request(onion_c->dht, nodes, onion_c->friends_list[friend_num].real_client_id, nonce, packet,
                                  sizeof(packet)) == 0)
                ++good;
        }
    }

    return good;
}

/* Send the packets to tell our friends
 * return the number of packets sent on success
 * return -1 on failure.
 */
static int send_fakeid_announce(Onion_Client *onion_c, uint16_t friend_num)
{
    if (friend_num >= onion_c->num_friends)
        return -1;

    uint8_t data[FAKEID_DATA_MAX_LENGTH];
    data[0] = FAKEID_DATA_ID;
    memcpy(data + 1, onion_c->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    Node_format nodes[MAX_SENT_NODES];
    uint16_t num_nodes = closelist_nodes(onion_c->dht, nodes, MAX_SENT_NODES);
    memcpy(data + FAKEID_DATA_MIN_LENGTH, nodes, sizeof(Node_format) * num_nodes);
    return send_onion_data(onion_c, friend_num, data, FAKEID_DATA_MIN_LENGTH + sizeof(Node_format) * num_nodes);
    //TODO: somehow make this function send our DHT client id directly to the other if we know theirs but they don't
    //seem to know ours.
}

/* Get the friend_num of a friend.
 *
 * return -1 on failure.
 * return friend number on success.
 */
int onion_friend_num(Onion_Client *onion_c, uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < onion_c->num_friends; ++i) {
        if (onion_c->friends_list[i].status == 0)
            continue;

        if (memcmp(client_id, onion_c->friends_list[i].real_client_id, crypto_box_PUBLICKEYBYTES) == 0)
            return i;
    }

    return -1;
}

/* Set the size of the friend list to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_onion_friends(Onion_Client *onion_c, uint32_t num)
{
    if (num == 0) {
        free(onion_c->friends_list);
        onion_c->friends_list = NULL;
        return 0;
    }

    Onion_Friend *newonion_friends = realloc(onion_c->friends_list, num * sizeof(Onion_Friend));

    if (newonion_friends == NULL)
        return -1;

    onion_c->friends_list = newonion_friends;
    return 0;
}

/* Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success or if the friend was already added.
 */
int onion_addfriend(Onion_Client *onion_c, uint8_t *client_id)
{
    int num = onion_friend_num(onion_c, client_id);

    if (num != -1)
        return num;

    uint32_t i, index = ~0;

    for (i = 0; i < onion_c->num_friends; ++i) {
        if (onion_c->friends_list[i].status == 0) {
            index = i;
            break;
        }
    }

    if (index == (uint32_t)~0) {
        if (realloc_onion_friends(onion_c, onion_c->num_friends + 1) == -1)
            return -1;

        index = onion_c->num_friends;
        memset(&(onion_c->friends_list[onion_c->num_friends]), 0, sizeof(Onion_Friend));
        ++onion_c->num_friends;
    }

    onion_c->friends_list[index].status = 1;
    memcpy(onion_c->friends_list[index].real_client_id, client_id, crypto_box_PUBLICKEYBYTES);
    crypto_box_keypair(onion_c->friends_list[index].temp_public_key, onion_c->friends_list[index].temp_secret_key);
    return index;
}

/* Delete a friend.
 *
 * return -1 on failure.
 * return the deleted friend number on success.
 */
int onion_delfriend(Onion_Client *onion_c, int friend_num)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    DHT_delfriend(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id);
    memset(&(onion_c->friends_list[friend_num]), 0, sizeof(Onion_Friend));
    uint32_t i;

    for (i = onion_c->num_friends; i != 0; --i) {
        if (onion_c->friends_list[i].status != 0)
            break;
    }

    if (onion_c->num_friends != i) {
        onion_c->num_friends = i;
        realloc_onion_friends(onion_c, onion_c->num_friends);
    }

    return friend_num;
}

/* Get the ip of friend friendnum and put it in ip_port
 *
 *  return -1, -- if client_id does NOT refer to a friend
 *  return  0, -- if client_id refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if client_id refers to a friend and we found him
 *
 */
int onion_getfriendip(Onion_Client *onion_c, int friend_num, IP_Port *ip_port)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (onion_c->friends_list[friend_num].status == 0)
        return -1;

    return DHT_getfriendip(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id, ip_port);
}

/* Takes 3 random nodes that we know and puts them in nodes
 *
 * nodes must be longer than 3.
 *
 * return -1 on failure
 * return 0 on success
 *
 */
int random_path(Onion_Client *onion_c, Node_format *nodes)
{
    if (random_nodes_path(onion_c->dht, nodes, 3) != 3)
        return -1;

    return 0;
}

#define ANNOUNCE_FRIEND 30

static void do_friend(Onion_Client *onion_c, uint16_t friendnum)
{
    if (friendnum >= onion_c->num_friends)
        return;

    if (onion_c->friends_list[friendnum].status == 0)
        return;

    uint32_t i, count = 0;
    Onion_Node *list_nodes = onion_c->friends_list[friendnum].clients_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++count;

        if (is_timeout(list_nodes[i].last_pinged, ANNOUNCE_FRIEND)) {
            if (client_send_announce_request(onion_c, friendnum + 1, list_nodes[i].ip_port, list_nodes[i].client_id, 0) == 0) {
                list_nodes[i].last_pinged = unix_time();
            }
        }
    }

    if (count < MAX_ONION_CLIENTS / 2) {
        Node_format nodes_list[MAX_SENT_NODES];
        uint32_t num_nodes = get_close_nodes(onion_c->dht, onion_c->friends_list[i].real_client_id, nodes_list,
                                             rand() % 2 ? AF_INET : AF_INET6, 1, 0);

        for (i = 0; i < num_nodes; ++i)
            client_send_announce_request(onion_c, friendnum + 1, nodes_list[i].ip_port, nodes_list[i].client_id, 0);
    }

    /* send packets to friend telling them our fake DHT id. */
    if (is_timeout(onion_c->friends_list[friendnum].last_fakeid_sent, ONION_FAKEID_INTERVAL))
        if (send_fakeid_announce(onion_c, friendnum) > 1)
            onion_c->friends_list[friendnum].last_fakeid_sent = unix_time();
}
/* Function to call when onion data packet with contents beginning with byte is received. */
void oniondata_registerhandler(Onion_Client *onion_c, uint8_t byte, oniondata_handler_callback cb, void *object)
{
    onion_c->Onion_Data_Handlers[byte].function = cb;
    onion_c->Onion_Data_Handlers[byte].object = object;
}

#define ANNOUNCE_INTERVAL_NOT_ANNOUNCED 10
#define ANNOUNCE_INTERVAL_ANNOUNCED 60

static void do_announce(Onion_Client *onion_c)
{
    uint32_t i, count = 0;
    Onion_Node *list_nodes = onion_c->clients_announce_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++count;
        uint32_t interval = ANNOUNCE_INTERVAL_NOT_ANNOUNCED;

        if (memcmp(list_nodes[i].ping_id, zero_ping, ONION_PING_ID_SIZE) == 0) {
            interval = ANNOUNCE_INTERVAL_ANNOUNCED;
        }

        if (is_timeout(list_nodes[i].last_pinged, interval)) {
            if (client_send_announce_request(onion_c, 0, list_nodes[i].ip_port, list_nodes[i].client_id,
                                             list_nodes[i].ping_id) == 0) {
                list_nodes[i].last_pinged = unix_time();
            }
        }
    }

    if (count < MAX_ONION_CLIENTS / 2) {
        Node_format nodes_list[MAX_SENT_NODES];
        uint32_t num_nodes = get_close_nodes(onion_c->dht, onion_c->dht->c->self_public_key, nodes_list,
                                             rand() % 2 ? AF_INET : AF_INET6, 1, 0);

        for (i = 0; i < num_nodes; ++i)
            client_send_announce_request(onion_c, 0, nodes_list[i].ip_port, nodes_list[i].client_id, 0);
    }
}

void do_onion_client(Onion_Client *onion_c)
{
    uint32_t i;

    if (onion_c->last_run == unix_time())
        return;

    do_announce(onion_c);

    for (i = 0; i < onion_c->num_friends; ++i) {
        do_friend(onion_c, i);
    }

    onion_c->last_run = unix_time();
}

Onion_Client *new_onion_client(DHT *dht)
{
    if (dht == NULL)
        return NULL;

    Onion_Client *onion_c = calloc(1, sizeof(Onion_Client));

    if (onion_c == NULL)
        return NULL;

    onion_c->dht = dht;
    onion_c->net = dht->c->lossless_udp->net;
    new_symmetric_key(onion_c->secret_symmetric_key);

    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, onion_c);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, onion_c);
    oniondata_registerhandler(onion_c, FAKEID_DATA_ID, &handle_fakeid_announce, onion_c);

    return onion_c;
}

void kill_onion_client(Onion_Client *onion_c)
{
    if (onion_c == NULL)
        return;

    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, NULL, NULL);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, NULL, NULL);
    free(onion_c);
}
