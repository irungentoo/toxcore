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

/* defines for the array size and
   timeout for onion announce packets. */
#define ANNOUNCE_ARRAY_SIZE 256
#define ANNOUNCE_TIMEOUT 10


/*
 * return -1 if nodes are suitable for creating a new path.
 * return path number of already existing similar path if one already exists.
 */
static int is_path_used(const Onion_Client_Paths *onion_paths, const Node_format *nodes)
{
    uint32_t i;

    for (i = 0; i < NUMBER_ONION_PATHS; ++i) {
        if (is_timeout(onion_paths->last_path_success[i], ONION_PATH_TIMEOUT)) {
            continue;
        }

        if (is_timeout(onion_paths->path_creation_time[i], ONION_PATH_MAX_LIFETIME)) {
            continue;
        }

        if (ipport_equal(&onion_paths->paths[i].ip_port1, &nodes[0].ip_port)) {
            return i;
        }
    }

    return -1;
}

/* Create a new path or use an old suitable one (if pathnum is valid)
 * or a rondom one from onion_paths.
 *
 * return -1 on failure
 * return 0 on success
 *
 * TODO: Make this function better, it currently probably is vulnerable to some attacks that
 * could de anonimize us.
 */
static int random_path(const DHT *dht, Onion_Client_Paths *onion_paths, uint32_t pathnum, Onion_Path *path)
{
    if (pathnum >= NUMBER_ONION_PATHS)
        pathnum = rand() % NUMBER_ONION_PATHS;

    if (is_timeout(onion_paths->last_path_success[pathnum], ONION_PATH_TIMEOUT)
            || is_timeout(onion_paths->path_creation_time[pathnum], ONION_PATH_MAX_LIFETIME)) {
        Node_format nodes[3];

        if (random_nodes_path(dht, nodes, 3) != 3)
            return -1;

        int n = is_path_used(onion_paths, nodes);

        if (n == -1) {
            if (create_onion_path(dht, &onion_paths->paths[pathnum], nodes) == -1)
                return -1;

            onion_paths->last_path_success[pathnum] = unix_time() + ONION_PATH_FIRST_TIMEOUT - ONION_PATH_TIMEOUT;
            onion_paths->path_creation_time[pathnum] = unix_time();
        } else {
            pathnum = n;
        }
    }

    memcpy(path, &onion_paths->paths[pathnum], sizeof(Onion_Path));
    return 0;
}

/* Set path timeouts, return the path number.
 *
 */
static uint32_t set_path_timeouts(Onion_Client *onion_c, uint32_t num, IP_Port source)
{
    if (num > onion_c->num_friends)
        return -1;

    Onion_Client_Paths *onion_paths;

    if (num == 0) {
        onion_paths = &onion_c->onion_paths;
    } else {
        onion_paths = &onion_c->friends_list[num - 1].onion_paths;
    }

    uint32_t i;

    for (i = 0; i < NUMBER_ONION_PATHS; ++i) {
        if (ipport_equal(&onion_paths->paths[i].ip_port1, &source)) {
            onion_paths->last_path_success[i] = unix_time();
            return i;
        }
    }

    return ~0;
}

/* Function to send onion packet via TCP and UDP.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_onion_packet_tcp_udp(const Onion_Client *onion_c, IP_Port ip_port, const uint8_t *data, uint32_t length)
{
    if (ip_port.ip.family == AF_INET || ip_port.ip.family == AF_INET6) {
        if ((uint32_t)sendpacket(onion_c->net, ip_port, data, length) != length)
            return -1;

        return 0;
    } else {
        return -1; //TODO: TCP
    }
}

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
static int new_sendback(Onion_Client *onion_c, uint32_t num, const uint8_t *public_key, IP_Port ip_port,
                        uint64_t *sendback)
{
    uint8_t data[sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + sizeof(IP_Port)];
    memcpy(data, &num, sizeof(uint32_t));
    memcpy(data + sizeof(uint32_t), public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(data + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES, &ip_port, sizeof(IP_Port));
    *sendback = ping_array_add(&onion_c->announce_ping_array, data, sizeof(data));

    if (*sendback == 0)
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
static uint32_t check_sendback(Onion_Client *onion_c, const uint8_t *sendback, uint8_t *ret_pubkey,
                               IP_Port *ret_ip_port)
{
    uint64_t sback;
    memcpy(&sback, sendback, sizeof(uint64_t));
    uint8_t data[sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES + sizeof(IP_Port)];

    if (ping_array_check(data, sizeof(data), &onion_c->announce_ping_array, sback) != sizeof(data))
        return ~0;

    memcpy(ret_pubkey, data + sizeof(uint32_t), crypto_box_PUBLICKEYBYTES);
    memcpy(ret_ip_port, data + sizeof(uint32_t) + crypto_box_PUBLICKEYBYTES, sizeof(IP_Port));
    uint32_t num;
    memcpy(&num, data, sizeof(uint32_t));
    return num;
}

static int client_send_announce_request(Onion_Client *onion_c, uint32_t num, IP_Port dest, const uint8_t *dest_pubkey,
                                        const uint8_t *ping_id, uint32_t pathnum)
{
    if (num > onion_c->num_friends)
        return -1;

    uint64_t sendback;

    if (new_sendback(onion_c, num, dest_pubkey, dest, &sendback) == -1)
        return -1;

    uint8_t zero_ping_id[ONION_PING_ID_SIZE] = {0};

    if (ping_id == NULL)
        ping_id = zero_ping_id;

    Onion_Path path;

    Node_format dest_node;
    dest_node.ip_port = dest;
    memcpy(dest_node.client_id, dest_pubkey, crypto_box_PUBLICKEYBYTES);

    if (num == 0) {
        if (random_path(onion_c->dht, &onion_c->onion_paths, pathnum, &path) == -1)
            return -1;

        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = create_announce_request(packet, sizeof(packet), &path, dest_node, onion_c->c->self_public_key,
                                          onion_c->c->self_secret_key, ping_id, onion_c->c->self_public_key, onion_c->temp_public_key, sendback);

        if (len == -1) {
            return -1;
        }

        return send_onion_packet_tcp_udp(onion_c, path.ip_port1, packet, len);
    } else {
        if (random_path(onion_c->dht, &onion_c->friends_list[num - 1].onion_paths, pathnum, &path) == -1)
            return -1;

        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = create_announce_request(packet, sizeof(packet), &path, dest_node,
                                          onion_c->friends_list[num - 1].temp_public_key, onion_c->friends_list[num - 1].temp_secret_key, ping_id,
                                          onion_c->friends_list[num - 1].real_client_id, zero_ping_id, sendback);

        if (len == -1) {
            return -1;
        }

        return send_onion_packet_tcp_udp(onion_c, path.ip_port1, packet, len);
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

static int client_add_to_list(Onion_Client *onion_c, uint32_t num, const uint8_t *public_key, IP_Port ip_port,
                              uint8_t is_stored, const uint8_t *pingid_or_key, IP_Port source)
{
    if (num > onion_c->num_friends)
        return -1;

    Onion_Node *list_nodes = NULL;
    uint8_t *reference_id = NULL;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = onion_c->c->self_public_key;

        if (is_stored && memcmp(pingid_or_key, onion_c->temp_public_key, crypto_box_PUBLICKEYBYTES) != 0) {
            is_stored = 0;
        }

    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_client_id;
    }

    memcpy(cmp_public_key, reference_id, crypto_box_PUBLICKEYBYTES);
    qsort(list_nodes, MAX_ONION_CLIENTS, sizeof(Onion_Node), cmp_entry);

    int index = -1;
    uint32_t i;

    if (is_timeout(list_nodes[0].timestamp, ONION_NODE_TIMEOUT)
            || id_closest(reference_id, list_nodes[0].client_id, public_key) == 2) {
        index = 0;
    }

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

    if (is_stored) {
        memcpy(list_nodes[index].data_public_key, pingid_or_key, crypto_box_PUBLICKEYBYTES);
    } else {
        memcpy(list_nodes[index].ping_id, pingid_or_key, ONION_PING_ID_SIZE);
    }

    list_nodes[index].is_stored = is_stored;
    list_nodes[index].timestamp = unix_time();
    list_nodes[index].last_pinged = 0;
    list_nodes[index].path_used = set_path_timeouts(onion_c, num, source);
    return 0;
}

static int good_to_ping(Last_Pinged *last_pinged, uint8_t *last_pinged_index, const uint8_t *client_id)
{
    uint32_t i;

    for (i = 0; i < MAX_STORED_PINGED_NODES; ++i) {
        if (!is_timeout(last_pinged[i].timestamp, MIN_NODE_PING_TIME))
            if (memcmp(last_pinged[i].client_id, client_id, crypto_box_PUBLICKEYBYTES) == 0)
                return 0;
    }

    memcpy(last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].client_id, client_id, crypto_box_PUBLICKEYBYTES);
    last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].timestamp = unix_time();
    ++*last_pinged_index;
    return 1;
}

static int client_ping_nodes(Onion_Client *onion_c, uint32_t num, const Node_format *nodes, uint16_t num_nodes,
                             IP_Port source)
{
    if (num > onion_c->num_friends)
        return -1;

    if (num_nodes == 0)
        return 0;

    Onion_Node *list_nodes = NULL;
    uint8_t *reference_id = NULL;

    Last_Pinged *last_pinged = NULL;
    uint8_t *last_pinged_index = NULL;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = onion_c->c->self_public_key;
        last_pinged = onion_c->last_pinged;
        last_pinged_index = &onion_c->last_pinged_index;
    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_client_id;
        last_pinged = onion_c->friends_list[num - 1].last_pinged;
        last_pinged_index = &onion_c->friends_list[num - 1].last_pinged_index;
    }

    uint32_t i, j;
    int lan_ips_accepted = (LAN_ip(source.ip) == 0);

    for (i = 0; i < num_nodes; ++i) {

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

            if (j == MAX_ONION_CLIENTS && good_to_ping(last_pinged, last_pinged_index, nodes[i].client_id)) {
                client_send_announce_request(onion_c, num, nodes[i].ip_port, nodes[i].client_id, NULL, ~0);
            }
        }
    }

    return 0;
}

static int handle_announce_response(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < ONION_ANNOUNCE_RESPONSE_MIN_SIZE || length > ONION_ANNOUNCE_RESPONSE_MAX_SIZE)
        return 1;

    uint16_t len_nodes = length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE;

    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    IP_Port ip_port;
    uint32_t num = check_sendback(onion_c, packet + 1, public_key, &ip_port);

    if (num > onion_c->num_friends)
        return 1;

    uint8_t plain[1 + ONION_PING_ID_SIZE + len_nodes];
    int len = -1;

    if (num == 0) {
        len = decrypt_data(public_key, onion_c->c->self_secret_key, packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
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

    if (client_add_to_list(onion_c, num, public_key, ip_port, plain[0], plain + 1, source) == -1)
        return 1;

    if (len_nodes != 0) {
        Node_format nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, 0, plain + 1 + ONION_PING_ID_SIZE, len_nodes, 0);

        if (num_nodes <= 0)
            return 1;

        if (client_ping_nodes(onion_c, num, nodes, num_nodes, source) == -1)
            return 1;
    }

    return 0;
}

#define DATA_IN_RESPONSE_MIN_SIZE ONION_DATA_IN_RESPONSE_MIN_SIZE

static int handle_data_response(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length <= (ONION_DATA_RESPONSE_MIN_SIZE + DATA_IN_RESPONSE_MIN_SIZE))
        return 1;

    if (length > MAX_DATA_REQUEST_SIZE)
        return 1;

    uint8_t temp_plain[length - ONION_DATA_RESPONSE_MIN_SIZE];
    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion_c->temp_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           length - (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES), temp_plain);

    if ((uint32_t)len != sizeof(temp_plain))
        return 1;

    uint8_t plain[sizeof(temp_plain) - DATA_IN_RESPONSE_MIN_SIZE];
    len = decrypt_data(temp_plain, onion_c->c->self_secret_key, packet + 1, temp_plain + crypto_box_PUBLICKEYBYTES,
                       sizeof(temp_plain) - crypto_box_PUBLICKEYBYTES, plain);

    if ((uint32_t)len != sizeof(plain))
        return 1;

    if (!onion_c->Onion_Data_Handlers[plain[0]].function)
        return 1;

    return onion_c->Onion_Data_Handlers[plain[0]].function(onion_c->Onion_Data_Handlers[plain[0]].object, temp_plain, plain,
            sizeof(plain));
}

#define FAKEID_DATA_ID 156
#define FAKEID_DATA_MIN_LENGTH (1 + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES)
#define FAKEID_DATA_MAX_LENGTH (FAKEID_DATA_MIN_LENGTH + sizeof(Node_format)*MAX_SENT_NODES)
static int handle_fakeid_announce(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < FAKEID_DATA_MIN_LENGTH)
        return 1;

    if (length > FAKEID_DATA_MAX_LENGTH)
        return 1;

    int friend_num = onion_friend_num(onion_c, source_pubkey);

    if (friend_num == -1)
        return 1;

    uint64_t no_replay;
    memcpy(&no_replay, data + 1, sizeof(uint64_t));
    net_to_host((uint8_t *) &no_replay, sizeof(no_replay));

    if (no_replay <= onion_c->friends_list[friend_num].last_noreplay)
        return 1;

    onion_c->friends_list[friend_num].last_noreplay = no_replay;
    onion_set_friend_DHT_pubkey(onion_c, friend_num, data + 1 + sizeof(uint64_t), current_time_monotonic());
    onion_c->friends_list[friend_num].last_seen = unix_time();

    uint16_t len_nodes = length - FAKEID_DATA_MIN_LENGTH;

    if (len_nodes != 0) {
        Node_format nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, 0, data + 1 + sizeof(uint64_t) + crypto_box_PUBLICKEYBYTES,
                                     len_nodes, 1);

        if (num_nodes <= 0)
            return 1;

        int i;

        for (i = 0; i < num_nodes; ++i) {
            uint8_t family = nodes[i].ip_port.ip.family;

            if (family == AF_INET || family == AF_INET6) {
                DHT_getnodes(onion_c->dht, &nodes[i].ip_port, nodes[i].client_id, onion_c->friends_list[friend_num].fake_client_id);
            } else if (family == TCP_INET || family == TCP_INET6) {
                if (onion_c->friends_list[friend_num].tcp_relay_node_callback) {
                    void *obj = onion_c->friends_list[friend_num].tcp_relay_node_callback_object;
                    uint32_t number = onion_c->friends_list[friend_num].tcp_relay_node_callback_number;
                    onion_c->friends_list[friend_num].tcp_relay_node_callback(obj, number, nodes[i].ip_port, nodes[i].client_id);
                }
            }
        }
    }

    return 0;
}
/* Send data of length length to friendnum.
 * This data will be received by the friend using the Onion_Data_Handlers callbacks.
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int send_onion_data(const Onion_Client *onion_c, int friend_num, const uint8_t *data, uint32_t length)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (length + DATA_IN_RESPONSE_MIN_SIZE > MAX_DATA_REQUEST_SIZE)
        return -1;

    if (length == 0)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    random_nonce(nonce);

    uint8_t packet[DATA_IN_RESPONSE_MIN_SIZE + length];
    memcpy(packet, onion_c->c->self_public_key, crypto_box_PUBLICKEYBYTES);
    int len = encrypt_data(onion_c->friends_list[friend_num].real_client_id, onion_c->c->self_secret_key, nonce, data,
                           length, packet + crypto_box_PUBLICKEYBYTES);

    if ((uint32_t)len + crypto_box_PUBLICKEYBYTES != sizeof(packet))
        return -1;

    uint32_t i, good_nodes[MAX_ONION_CLIENTS], num_good = 0, num_nodes = 0;
    Onion_Path path[MAX_ONION_CLIENTS];
    Onion_Node *list_nodes = onion_c->friends_list[friend_num].clients_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++num_nodes;

        if (list_nodes[i].is_stored) {
            if (random_path(onion_c->dht, &onion_c->friends_list[friend_num].onion_paths, ~0, &path[num_good]) == -1)
                continue;

            good_nodes[num_good] = i;
            ++num_good;
        }
    }

    if (num_good < (num_nodes / 4) + 1)
        return -1;

    uint32_t good = 0;

    for (i = 0; i < num_good; ++i) {
        uint8_t o_packet[ONION_MAX_PACKET_SIZE];
        len = create_data_request(o_packet, sizeof(o_packet), &path[i], list_nodes[good_nodes[i]].ip_port,
                                  onion_c->friends_list[friend_num].real_client_id, list_nodes[good_nodes[i]].data_public_key, nonce, packet,
                                  sizeof(packet));

        if (len == -1)
            continue;

        if (send_onion_packet_tcp_udp(onion_c, path[i].ip_port1, o_packet, len) == 0)
            ++good;
    }

    return good;
}

/* Try to send the fakeid via the DHT instead of onion
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
static int send_dht_fakeid(const Onion_Client *onion_c, int friend_num, const uint8_t *data, uint32_t length)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (!onion_c->friends_list[friend_num].is_fake_clientid)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    uint8_t temp[DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES + length];
    memcpy(temp, onion_c->c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    int len = encrypt_data(onion_c->friends_list[friend_num].real_client_id, onion_c->c->self_secret_key, nonce, data,
                           length, temp + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

    if ((uint32_t)len + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES != sizeof(temp))
        return -1;

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    len = create_request(onion_c->dht->self_public_key, onion_c->dht->self_secret_key, packet,
                         onion_c->friends_list[friend_num].fake_client_id, temp, sizeof(temp), FAKEID_DATA_ID);

    if (len == -1)
        return -1;

    return route_tofriend(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id, packet, len);
}

static int handle_dht_fakeid(void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                             uint32_t length)
{
    Onion_Client *onion_c = object;

    if (length < FAKEID_DATA_MIN_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES)
        return 1;

    if (length > FAKEID_DATA_MAX_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES)
        return 1;

    uint8_t plain[FAKEID_DATA_MAX_LENGTH];
    int len = decrypt_data(packet, onion_c->c->self_secret_key, packet + crypto_box_PUBLICKEYBYTES,
                           packet + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                           length - (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES), plain);

    if ((uint32_t)len != length - (DATA_IN_RESPONSE_MIN_SIZE + crypto_box_NONCEBYTES))
        return 1;

    if (memcmp(source_pubkey, plain + 1 + sizeof(uint64_t), crypto_box_PUBLICKEYBYTES) != 0)
        return 1;

    return handle_fakeid_announce(onion_c, packet, plain, len);
}
/* Send the packets to tell our friends what our DHT public key is.
 *
 * if onion_dht_both is 0, use only the onion to send the packet.
 * if it is 1, use only the dht.
 * if it is something else, use both.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
static int send_fakeid_announce(const Onion_Client *onion_c, uint16_t friend_num, uint8_t onion_dht_both)
{
    if (friend_num >= onion_c->num_friends)
        return -1;

    uint8_t data[FAKEID_DATA_MAX_LENGTH];
    data[0] = FAKEID_DATA_ID;
    uint64_t no_replay = unix_time();
    host_to_net((uint8_t *)&no_replay, sizeof(no_replay));
    memcpy(data + 1, &no_replay, sizeof(no_replay));
    memcpy(data + 1 + sizeof(uint64_t), onion_c->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    Node_format nodes[MAX_SENT_NODES];
    uint16_t num_relays = copy_connected_tcp_relays(onion_c->c, nodes, (MAX_SENT_NODES / 2));
    uint16_t num_nodes = closelist_nodes(onion_c->dht, &nodes[num_relays], MAX_SENT_NODES - num_relays);
    num_nodes += num_relays;
    int nodes_len = 0;

    if (num_nodes != 0) {
        nodes_len = pack_nodes(data + FAKEID_DATA_MIN_LENGTH, FAKEID_DATA_MAX_LENGTH - FAKEID_DATA_MIN_LENGTH, nodes,
                               num_nodes);

        if (nodes_len <= 0)
            return -1;
    }

    int num1 = -1, num2 = -1;

    if (onion_dht_both != 1)
        num1 = send_onion_data(onion_c, friend_num, data, FAKEID_DATA_MIN_LENGTH + nodes_len);

    if (onion_dht_both != 0)
        num2 = send_dht_fakeid(onion_c, friend_num, data, FAKEID_DATA_MIN_LENGTH + nodes_len);

    if (num1 == -1)
        return num2;

    if (num2 == -1)
        return num1;

    return num1 + num2;
}

/* Get the friend_num of a friend.
 *
 * return -1 on failure.
 * return friend number on success.
 */
int onion_friend_num(const Onion_Client *onion_c, const uint8_t *client_id)
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
int onion_addfriend(Onion_Client *onion_c, const uint8_t *client_id)
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

    if (onion_c->friends_list[friend_num].is_fake_clientid)
        DHT_delfriend(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id);

    memset(&(onion_c->friends_list[friend_num]), 0, sizeof(Onion_Friend));
    uint32_t i;

    for (i = onion_c->num_friends; i != 0; --i) {
        if (onion_c->friends_list[i - 1].status != 0)
            break;
    }

    if (onion_c->num_friends != i) {
        onion_c->num_friends = i;
        realloc_onion_friends(onion_c, onion_c->num_friends);
    }

    return friend_num;
}

/* Set the function for this friend that will be callbacked with object and number
 * when that friends gives us one of the TCP relays he is connected to.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int recv_tcp_relay_handler(Onion_Client *onion_c, int friend_num, int (*tcp_relay_node_callback)(void *object,
                           uint32_t number, IP_Port ip_port, const uint8_t *public_key), void *object, uint32_t number)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    onion_c->friends_list[friend_num].tcp_relay_node_callback = tcp_relay_node_callback;
    onion_c->friends_list[friend_num].tcp_relay_node_callback_object = object;
    onion_c->friends_list[friend_num].tcp_relay_node_callback_number = number;
    return 0;
}

/* Set a friends DHT public key.
 * timestamp is the time (current_time_monotonic()) at which the key was last confirmed belonging to
 * the other peer.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_set_friend_DHT_pubkey(Onion_Client *onion_c, int friend_num, const uint8_t *dht_key, uint64_t timestamp)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (onion_c->friends_list[friend_num].status == 0)
        return -1;

    if (onion_c->friends_list[friend_num].fake_client_id_timestamp >= timestamp)
        return -1;

    if (onion_c->friends_list[friend_num].is_fake_clientid) {
        if (memcmp(dht_key, onion_c->friends_list[friend_num].fake_client_id, crypto_box_PUBLICKEYBYTES) == 0) {
            return -1;
        }

        DHT_delfriend(onion_c->dht, onion_c->friends_list[friend_num].fake_client_id);
    }

    if (DHT_addfriend(onion_c->dht, dht_key) == 1) {
        return -1;
    }

    onion_c->friends_list[friend_num].last_seen = unix_time();
    onion_c->friends_list[friend_num].is_fake_clientid = 1;
    onion_c->friends_list[friend_num].fake_client_id_timestamp = timestamp;
    memcpy(onion_c->friends_list[friend_num].fake_client_id, dht_key, crypto_box_PUBLICKEYBYTES);

    return 0;
}

/* Copy friends DHT public key into dht_key.
 *
 * return 0 on failure (no key copied).
 * return timestamp on success (key copied).
 */
uint64_t onion_getfriend_DHT_pubkey(const Onion_Client *onion_c, int friend_num, uint8_t *dht_key)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return 0;

    if (onion_c->friends_list[friend_num].status == 0)
        return 0;

    if (!onion_c->friends_list[friend_num].is_fake_clientid)
        return 0;

    memcpy(dht_key, onion_c->friends_list[friend_num].fake_client_id, crypto_box_PUBLICKEYBYTES);
    return onion_c->friends_list[friend_num].fake_client_id_timestamp;
}

/* Get the ip of friend friendnum and put it in ip_port
 *
 *  return -1, -- if client_id does NOT refer to a friend
 *  return  0, -- if client_id refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if client_id refers to a friend and we found him
 *
 */
int onion_getfriendip(const Onion_Client *onion_c, int friend_num, IP_Port *ip_port)
{
    uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];

    if (onion_getfriend_DHT_pubkey(onion_c, friend_num, dht_public_key) == 0)
        return -1;

    return DHT_getfriendip(onion_c->dht, dht_public_key, ip_port);
}


/* Set if friend is online or not.
 * NOTE: This function is there and should be used so that we don't send useless packets to the friend if he is online.
 *
 * is_online 1 means friend is online.
 * is_online 0 means friend is offline
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_set_friend_online(Onion_Client *onion_c, int friend_num, uint8_t is_online)
{
    if ((uint32_t)friend_num >= onion_c->num_friends)
        return -1;

    if (is_online == 0 && onion_c->friends_list[friend_num].is_online == 1)
        onion_c->friends_list[friend_num].last_seen = unix_time();

    onion_c->friends_list[friend_num].is_online = is_online;

    /* This should prevent some clock related issues */
    if (!is_online)
        onion_c->friends_list[friend_num].last_noreplay = 0;

    return 0;
}


#define ANNOUNCE_FRIEND (ONION_NODE_PING_INTERVAL * 3)
#define FRIEND_ONION_NODE_TIMEOUT (ONION_NODE_TIMEOUT * 3)

static void do_friend(Onion_Client *onion_c, uint16_t friendnum)
{
    if (friendnum >= onion_c->num_friends)
        return;

    if (onion_c->friends_list[friendnum].status == 0)
        return;

    uint32_t i, count = 0;
    Onion_Node *list_nodes = onion_c->friends_list[friendnum].clients_list;

    if (!onion_c->friends_list[friendnum].is_online) {
        for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
            if (is_timeout(list_nodes[i].timestamp, FRIEND_ONION_NODE_TIMEOUT))
                continue;

            ++count;

            if (list_nodes[i].last_pinged == 0) {
                list_nodes[i].last_pinged = unix_time();
                continue;
            }

            if (is_timeout(list_nodes[i].last_pinged, ANNOUNCE_FRIEND)) {
                if (client_send_announce_request(onion_c, friendnum + 1, list_nodes[i].ip_port, list_nodes[i].client_id, 0, ~0) == 0) {
                    list_nodes[i].last_pinged = unix_time();
                }
            }
        }

        if (count != MAX_ONION_CLIENTS) {
            if (count < (uint32_t)rand() % MAX_ONION_CLIENTS) {
                Node_format nodes_list[MAX_SENT_NODES];
                uint32_t num_nodes = get_close_nodes(onion_c->dht, onion_c->friends_list[friendnum].real_client_id, nodes_list,
                                                     (rand() % 2) ? AF_INET : AF_INET6, 1, 0);

                for (i = 0; i < num_nodes; ++i)
                    client_send_announce_request(onion_c, friendnum + 1, nodes_list[i].ip_port, nodes_list[i].client_id, 0, ~0);
            }
        }

        /* send packets to friend telling them our fake DHT id. */
        if (is_timeout(onion_c->friends_list[friendnum].last_fakeid_onion_sent, ONION_FAKEID_INTERVAL))
            if (send_fakeid_announce(onion_c, friendnum, 0) >= 1)
                onion_c->friends_list[friendnum].last_fakeid_onion_sent = unix_time();

        if (is_timeout(onion_c->friends_list[friendnum].last_fakeid_dht_sent, DHT_FAKEID_INTERVAL))
            if (send_fakeid_announce(onion_c, friendnum, 1) >= 1)
                onion_c->friends_list[friendnum].last_fakeid_dht_sent = unix_time();

    }
}

/* Timeout before which a peer is considered dead and removed from the DHT search. */
#define DEAD_ONION_TIMEOUT (10 * 60)

static void cleanup_friend(Onion_Client *onion_c, uint16_t friendnum)
{
    if (friendnum >= onion_c->num_friends)
        return;

    if (onion_c->friends_list[friendnum].status == 0)
        return;

    if (onion_c->friends_list[friendnum].is_fake_clientid && !onion_c->friends_list[friendnum].is_online
            && is_timeout(onion_c->friends_list[friendnum].last_seen, DEAD_ONION_TIMEOUT)) {
        onion_c->friends_list[friendnum].is_fake_clientid = 0;
        DHT_delfriend(onion_c->dht, onion_c->friends_list[friendnum].fake_client_id);
    }
}

/* Function to call when onion data packet with contents beginning with byte is received. */
void oniondata_registerhandler(Onion_Client *onion_c, uint8_t byte, oniondata_handler_callback cb, void *object)
{
    onion_c->Onion_Data_Handlers[byte].function = cb;
    onion_c->Onion_Data_Handlers[byte].object = object;
}

#define ANNOUNCE_INTERVAL_NOT_ANNOUNCED 10
#define ANNOUNCE_INTERVAL_ANNOUNCED ONION_NODE_PING_INTERVAL

static void do_announce(Onion_Client *onion_c)
{
    uint32_t i, count = 0;
    Onion_Node *list_nodes = onion_c->clients_announce_list;

    for (i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (is_timeout(list_nodes[i].timestamp, ONION_NODE_TIMEOUT))
            continue;

        ++count;

        /* Don't announce ourselves the first time this is run to new peers */
        if (list_nodes[i].last_pinged == 0) {
            list_nodes[i].last_pinged = 1;
            continue;
        }

        uint32_t interval = ANNOUNCE_INTERVAL_NOT_ANNOUNCED;

        if (list_nodes[i].is_stored) {
            interval = ANNOUNCE_INTERVAL_ANNOUNCED;
        }

        if (is_timeout(list_nodes[i].last_pinged, interval)) {
            if (client_send_announce_request(onion_c, 0, list_nodes[i].ip_port, list_nodes[i].client_id,
                                             list_nodes[i].ping_id, list_nodes[i].path_used) == 0) {
                list_nodes[i].last_pinged = unix_time();
            }
        }
    }

    if (count != MAX_ONION_CLIENTS) {
        if (count < (uint32_t)rand() % MAX_ONION_CLIENTS) {
            Node_format nodes_list[MAX_SENT_NODES];
            uint32_t num_nodes = get_close_nodes(onion_c->dht, onion_c->c->self_public_key, nodes_list,
                                                 (rand() % 2) ? AF_INET : AF_INET6, 1, 0);

            for (i = 0; i < num_nodes; ++i) {
                client_send_announce_request(onion_c, 0, nodes_list[i].ip_port, nodes_list[i].client_id, 0, ~0);
            }
        }
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
        cleanup_friend(onion_c, i);
    }

    onion_c->last_run = unix_time();
}

Onion_Client *new_onion_client(Net_Crypto *c)
{
    if (c == NULL)
        return NULL;

    Onion_Client *onion_c = calloc(1, sizeof(Onion_Client));

    if (onion_c == NULL)
        return NULL;

    if (ping_array_init(&onion_c->announce_ping_array, ANNOUNCE_ARRAY_SIZE, ANNOUNCE_TIMEOUT) != 0) {
        free(onion_c);
        return NULL;
    }

    onion_c->dht = c->dht;
    onion_c->net = c->dht->net;
    onion_c->c = c;
    new_symmetric_key(onion_c->secret_symmetric_key);
    crypto_box_keypair(onion_c->temp_public_key, onion_c->temp_secret_key);
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, onion_c);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, onion_c);
    oniondata_registerhandler(onion_c, FAKEID_DATA_ID, &handle_fakeid_announce, onion_c);
    cryptopacket_registerhandler(onion_c->dht, FAKEID_DATA_ID, &handle_dht_fakeid, onion_c);

    return onion_c;
}

void kill_onion_client(Onion_Client *onion_c)
{
    if (onion_c == NULL)
        return;

    ping_array_free_all(&onion_c->announce_ping_array);
    realloc_onion_friends(onion_c, 0);
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, NULL, NULL);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, NULL, NULL);
    oniondata_registerhandler(onion_c, FAKEID_DATA_ID, NULL, NULL);
    cryptopacket_registerhandler(onion_c->dht, FAKEID_DATA_ID, NULL, NULL);
    memset(onion_c, 0, sizeof(Onion_Client));
    free(onion_c);
}
