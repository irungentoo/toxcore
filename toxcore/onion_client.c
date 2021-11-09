/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Implementation of the client part of docs/Prevent_Tracking.txt (The part that
 * uses the onion stuff to connect to the friend)
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "onion_client.h"

#include <stdlib.h>
#include <string.h>

#include "LAN_discovery.h"
#include "mono_time.h"
#include "util.h"

/* defines for the array size and
 * timeout for onion announce packets. */
#define ANNOUNCE_ARRAY_SIZE 256
#define ANNOUNCE_TIMEOUT 10

typedef struct Onion_Node {
    uint8_t     public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port     ip_port;
    uint8_t     ping_id[ONION_PING_ID_SIZE];
    uint8_t     data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t     is_stored;

    uint64_t    added_time;

    uint64_t    timestamp;

    uint64_t    last_pinged;

    uint8_t     unsuccessful_pings;

    uint32_t    path_used;
} Onion_Node;

typedef struct Onion_Client_Paths {
    Onion_Path paths[NUMBER_ONION_PATHS];
    uint64_t last_path_success[NUMBER_ONION_PATHS];
    uint64_t last_path_used[NUMBER_ONION_PATHS];
    uint64_t path_creation_time[NUMBER_ONION_PATHS];
    /* number of times used without success. */
    unsigned int last_path_used_times[NUMBER_ONION_PATHS];
} Onion_Client_Paths;

typedef struct Last_Pinged {
    uint8_t     public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t    timestamp;
} Last_Pinged;

typedef struct Onion_Friend {
    uint8_t status; /* 0 if friend is not valid, 1 if friend is valid.*/
    uint8_t is_online; /* Set by the onion_set_friend_status function. */

    uint8_t know_dht_public_key; /* 0 if we don't know the dht public key of the other, 1 if we do. */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t real_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    Onion_Node clients_list[MAX_ONION_CLIENTS];
    uint8_t temp_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];

    uint64_t last_dht_pk_onion_sent;
    uint64_t last_dht_pk_dht_sent;

    uint64_t last_noreplay;

    uint64_t last_seen;

    Last_Pinged last_pinged[MAX_STORED_PINGED_NODES];
    uint8_t last_pinged_index;

    recv_tcp_relay_cb *tcp_relay_node_callback;
    void *tcp_relay_node_callback_object;
    uint32_t tcp_relay_node_callback_number;

    onion_dht_pk_cb *dht_pk_callback;
    void *dht_pk_callback_object;
    uint32_t dht_pk_callback_number;

    uint32_t run_count;
} Onion_Friend;

typedef struct Onion_Data_Handler {
    oniondata_handler_cb *function;
    void *object;
} Onion_Data_Handler;

struct Onion_Client {
    Mono_Time *mono_time;
    const Logger *logger;

    DHT     *dht;
    Net_Crypto *c;
    Networking_Core *net;
    Onion_Friend    *friends_list;
    uint16_t       num_friends;

    Onion_Node clients_announce_list[MAX_ONION_CLIENTS_ANNOUNCE];
    uint64_t last_announce;

    Onion_Client_Paths onion_paths_self;
    Onion_Client_Paths onion_paths_friends;

    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];
    uint64_t last_run;
    uint64_t first_run;

    uint8_t temp_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];

    Last_Pinged last_pinged[MAX_STORED_PINGED_NODES];

    Node_format path_nodes[MAX_PATH_NODES];
    uint16_t path_nodes_index;

    Node_format path_nodes_bs[MAX_PATH_NODES];
    uint16_t path_nodes_index_bs;

    Ping_Array *announce_ping_array;
    uint8_t last_pinged_index;
    Onion_Data_Handler onion_data_handlers[256];

    uint64_t last_packet_recv;

    unsigned int onion_connected;
    bool udp_connected;
};

DHT *onion_get_dht(const Onion_Client *onion_c)
{
    return onion_c->dht;
}

Net_Crypto *onion_get_net_crypto(const Onion_Client *onion_c)
{
    return onion_c->c;
}

/* Add a node to the path_nodes bootstrap array.
 *
 * return -1 on failure
 * return 0 on success
 */
int onion_add_bs_path_node(Onion_Client *onion_c, IP_Port ip_port, const uint8_t *public_key)
{
    if (!net_family_is_ipv4(ip_port.ip.family) && !net_family_is_ipv6(ip_port.ip.family)) {
        return -1;
    }

    unsigned int i;

    for (i = 0; i < MAX_PATH_NODES; ++i) {
        if (public_key_cmp(public_key, onion_c->path_nodes_bs[i].public_key) == 0) {
            return -1;
        }
    }

    onion_c->path_nodes_bs[onion_c->path_nodes_index_bs % MAX_PATH_NODES].ip_port = ip_port;
    memcpy(onion_c->path_nodes_bs[onion_c->path_nodes_index_bs % MAX_PATH_NODES].public_key, public_key,
           CRYPTO_PUBLIC_KEY_SIZE);

    uint16_t last = onion_c->path_nodes_index_bs;
    ++onion_c->path_nodes_index_bs;

    if (onion_c->path_nodes_index_bs < last) {
        onion_c->path_nodes_index_bs = MAX_PATH_NODES + 1;
    }

    return 0;
}

/* Add a node to the path_nodes array.
 *
 * return -1 on failure
 * return 0 on success
 */
static int onion_add_path_node(Onion_Client *onion_c, IP_Port ip_port, const uint8_t *public_key)
{
    if (!net_family_is_ipv4(ip_port.ip.family) && !net_family_is_ipv6(ip_port.ip.family)) {
        return -1;
    }

    unsigned int i;

    for (i = 0; i < MAX_PATH_NODES; ++i) {
        if (public_key_cmp(public_key, onion_c->path_nodes[i].public_key) == 0) {
            return -1;
        }
    }

    onion_c->path_nodes[onion_c->path_nodes_index % MAX_PATH_NODES].ip_port = ip_port;
    memcpy(onion_c->path_nodes[onion_c->path_nodes_index % MAX_PATH_NODES].public_key, public_key,
           CRYPTO_PUBLIC_KEY_SIZE);

    uint16_t last = onion_c->path_nodes_index;
    ++onion_c->path_nodes_index;

    if (onion_c->path_nodes_index < last) {
        onion_c->path_nodes_index = MAX_PATH_NODES + 1;
    }

    return 0;
}

/* Put up to max_num nodes in nodes.
 *
 * return the number of nodes.
 */
uint16_t onion_backup_nodes(const Onion_Client *onion_c, Node_format *nodes, uint16_t max_num)
{
    if (!max_num) {
        return 0;
    }

    const uint16_t num_nodes = min_u16(onion_c->path_nodes_index, MAX_PATH_NODES);
    uint16_t i = 0;

    while (i < max_num && i < num_nodes) {
        nodes[i] = onion_c->path_nodes[(onion_c->path_nodes_index - (1 + i)) % num_nodes];
        ++i;
    }

    for (uint16_t j = 0; i < max_num && j < MAX_PATH_NODES && j < onion_c->path_nodes_index_bs; ++j) {
        bool already_saved = false;

        for (uint16_t k = 0; k < num_nodes; ++k) {
            if (public_key_cmp(nodes[k].public_key, onion_c->path_nodes_bs[j].public_key) == 0) {
                already_saved = true;
                break;
            }
        }

        if (!already_saved) {
            nodes[i] = onion_c->path_nodes_bs[j];
            ++i;
        }
    }

    return i;
}

/* Put up to max_num random nodes in nodes.
 *
 * return the number of nodes.
 */
static uint16_t random_nodes_path_onion(const Onion_Client *onion_c, Node_format *nodes, uint16_t max_num)
{
    unsigned int i;

    if (!max_num) {
        return 0;
    }

    const uint16_t num_nodes = min_u16(onion_c->path_nodes_index, MAX_PATH_NODES);

    // if (dht_non_lan_connected(onion_c->dht)) {
    if (dht_isconnected(onion_c->dht)) {
        if (num_nodes == 0) {
            return 0;
        }

        for (i = 0; i < max_num; ++i) {
            nodes[i] = onion_c->path_nodes[random_u32() % num_nodes];
        }
    } else {
        int random_tcp = get_random_tcp_con_number(onion_c->c);

        if (random_tcp == -1) {
            return 0;
        }

        if (num_nodes >= 2) {
            nodes[0].ip_port.ip.family = net_family_tcp_family;
            nodes[0].ip_port.ip.ip.v4.uint32 = random_tcp;

            for (i = 1; i < max_num; ++i) {
                nodes[i] = onion_c->path_nodes[random_u32() % num_nodes];
            }
        } else {
            const uint16_t num_nodes_bs = min_u16(onion_c->path_nodes_index_bs, MAX_PATH_NODES);

            if (num_nodes_bs == 0) {
                return 0;
            }

            nodes[0].ip_port.ip.family = net_family_tcp_family;
            nodes[0].ip_port.ip.ip.v4.uint32 = random_tcp;

            for (i = 1; i < max_num; ++i) {
                nodes[i] = onion_c->path_nodes_bs[random_u32() % num_nodes_bs];
            }
        }
    }

    return max_num;
}

/*
 * return -1 if nodes are suitable for creating a new path.
 * return path number of already existing similar path if one already exists.
 */
static int is_path_used(const Mono_Time *mono_time, const Onion_Client_Paths *onion_paths, const Node_format *nodes)
{
    unsigned int i;

    for (i = 0; i < NUMBER_ONION_PATHS; ++i) {
        if (mono_time_is_timeout(mono_time, onion_paths->last_path_success[i], ONION_PATH_TIMEOUT)) {
            continue;
        }

        if (mono_time_is_timeout(mono_time, onion_paths->path_creation_time[i], ONION_PATH_MAX_LIFETIME)) {
            continue;
        }

        // TODO(irungentoo): do we really have to check it with the last node?
        if (ipport_equal(&onion_paths->paths[i].ip_port1, &nodes[ONION_PATH_LENGTH - 1].ip_port)) {
            return i;
        }
    }

    return -1;
}

/* is path timed out */
static bool path_timed_out(const Mono_Time *mono_time, Onion_Client_Paths *onion_paths, uint32_t pathnum)
{
    pathnum = pathnum % NUMBER_ONION_PATHS;

    bool is_new = onion_paths->last_path_success[pathnum] == onion_paths->path_creation_time[pathnum];
    uint64_t timeout = is_new ? ONION_PATH_FIRST_TIMEOUT : ONION_PATH_TIMEOUT;

    return ((onion_paths->last_path_used_times[pathnum] >= ONION_PATH_MAX_NO_RESPONSE_USES
             && mono_time_is_timeout(mono_time, onion_paths->last_path_used[pathnum], timeout))
            || mono_time_is_timeout(mono_time, onion_paths->path_creation_time[pathnum], ONION_PATH_MAX_LIFETIME));
}

/* should node be considered to have timed out */
static bool onion_node_timed_out(const Onion_Node *node, const Mono_Time *mono_time)
{
    return (node->timestamp == 0
            || (node->unsuccessful_pings >= ONION_NODE_MAX_PINGS
                && mono_time_is_timeout(mono_time, node->last_pinged, ONION_NODE_TIMEOUT)));
}

/* Create a new path or use an old suitable one (if pathnum is valid)
 * or a random one from onion_paths.
 *
 * return -1 on failure
 * return 0 on success
 *
 * TODO(irungentoo): Make this function better, it currently probably is
 * vulnerable to some attacks that could deanonimize us.
 */
static int random_path(const Onion_Client *onion_c, Onion_Client_Paths *onion_paths, uint32_t pathnum, Onion_Path *path)
{
    if (pathnum == UINT32_MAX) {
        pathnum = random_u32() % NUMBER_ONION_PATHS;
    } else {
        pathnum = pathnum % NUMBER_ONION_PATHS;
    }

    if (path_timed_out(onion_c->mono_time, onion_paths, pathnum)) {
        Node_format nodes[ONION_PATH_LENGTH];

        if (random_nodes_path_onion(onion_c, nodes, ONION_PATH_LENGTH) != ONION_PATH_LENGTH) {
            return -1;
        }

        int n = is_path_used(onion_c->mono_time, onion_paths, nodes);

        if (n == -1) {
            if (create_onion_path(onion_c->dht, &onion_paths->paths[pathnum], nodes) == -1) {
                return -1;
            }

            onion_paths->path_creation_time[pathnum] = mono_time_get(onion_c->mono_time);
            onion_paths->last_path_success[pathnum] = onion_paths->path_creation_time[pathnum];
            onion_paths->last_path_used_times[pathnum] = ONION_PATH_MAX_NO_RESPONSE_USES / 2;

            uint32_t path_num = random_u32();
            path_num /= NUMBER_ONION_PATHS;
            path_num *= NUMBER_ONION_PATHS;
            path_num += pathnum;

            onion_paths->paths[pathnum].path_num = path_num;
        } else {
            pathnum = n;
        }
    }

    if (onion_paths->last_path_used_times[pathnum] < ONION_PATH_MAX_NO_RESPONSE_USES) {
        onion_paths->last_path_used[pathnum] = mono_time_get(onion_c->mono_time);
    }

    ++onion_paths->last_path_used_times[pathnum];
    memcpy(path, &onion_paths->paths[pathnum], sizeof(Onion_Path));
    return 0;
}

/* Does path with path_num exist. */
static bool path_exists(const Mono_Time *mono_time, Onion_Client_Paths *onion_paths, uint32_t path_num)
{
    if (path_timed_out(mono_time, onion_paths, path_num)) {
        return 0;
    }

    return onion_paths->paths[path_num % NUMBER_ONION_PATHS].path_num == path_num;
}

/* Set path timeouts, return the path number.
 *
 */
static uint32_t set_path_timeouts(Onion_Client *onion_c, uint32_t num, uint32_t path_num)
{
    if (num > onion_c->num_friends) {
        return -1;
    }

    Onion_Client_Paths *onion_paths;

    if (num == 0) {
        onion_paths = &onion_c->onion_paths_self;
    } else {
        onion_paths = &onion_c->onion_paths_friends;
    }

    if (onion_paths->paths[path_num % NUMBER_ONION_PATHS].path_num == path_num) {
        onion_paths->last_path_success[path_num % NUMBER_ONION_PATHS] = mono_time_get(onion_c->mono_time);
        onion_paths->last_path_used_times[path_num % NUMBER_ONION_PATHS] = 0;

        Node_format nodes[ONION_PATH_LENGTH];

        if (onion_path_to_nodes(nodes, ONION_PATH_LENGTH, &onion_paths->paths[path_num % NUMBER_ONION_PATHS]) == 0) {
            unsigned int i;

            for (i = 0; i < ONION_PATH_LENGTH; ++i) {
                onion_add_path_node(onion_c, nodes[i].ip_port, nodes[i].public_key);
            }
        }

        return path_num;
    }

    return -1;
}

/* Function to send onion packet via TCP and UDP.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_onion_packet_tcp_udp(const Onion_Client *onion_c, const Onion_Path *path, IP_Port dest,
                                     const uint8_t *data, uint16_t length)
{
    if (net_family_is_ipv4(path->ip_port1.ip.family) || net_family_is_ipv6(path->ip_port1.ip.family)) {
        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = create_onion_packet(packet, sizeof(packet), path, dest, data, length);

        if (len == -1) {
            return -1;
        }

        if (sendpacket(onion_c->net, path->ip_port1, packet, len) != len) {
            return -1;
        }

        return 0;
    }

    if (net_family_is_tcp_family(path->ip_port1.ip.family)) {
        uint8_t packet[ONION_MAX_PACKET_SIZE];
        int len = create_onion_packet_tcp(packet, sizeof(packet), path, dest, data, length);

        if (len == -1) {
            return -1;
        }

        return send_tcp_onion_request(onion_c->c, path->ip_port1.ip.ip.v4.uint32, packet, len);
    }

    return -1;
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
                        uint32_t path_num, uint64_t *sendback)
{
    uint8_t data[sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port) + sizeof(uint32_t)];
    memcpy(data, &num, sizeof(uint32_t));
    memcpy(data + sizeof(uint32_t), public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(data + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE, &ip_port, sizeof(IP_Port));
    memcpy(data + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port), &path_num, sizeof(uint32_t));
    *sendback = ping_array_add(onion_c->announce_ping_array, onion_c->mono_time, data, sizeof(data));

    if (*sendback == 0) {
        return -1;
    }

    return 0;
}

/* Checks if the sendback is valid and returns the public key contained in it in ret_pubkey and the
 * ip contained in it in ret_ip_port
 *
 * sendback is the sendback ONION_ANNOUNCE_SENDBACK_DATA_LENGTH big
 * ret_pubkey must be at least CRYPTO_PUBLIC_KEY_SIZE big
 * ret_ip_port must be at least 1 big
 *
 * return -1 on failure
 * return num (see new_sendback(...)) on success
 */
static uint32_t check_sendback(Onion_Client *onion_c, const uint8_t *sendback, uint8_t *ret_pubkey,
                               IP_Port *ret_ip_port, uint32_t *path_num)
{
    uint64_t sback;
    memcpy(&sback, sendback, sizeof(uint64_t));
    uint8_t data[sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port) + sizeof(uint32_t)];

    if (ping_array_check(onion_c->announce_ping_array, onion_c->mono_time, data, sizeof(data), sback) != sizeof(data)) {
        return -1;
    }

    memcpy(ret_pubkey, data + sizeof(uint32_t), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(ret_ip_port, data + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE, sizeof(IP_Port));
    memcpy(path_num, data + sizeof(uint32_t) + CRYPTO_PUBLIC_KEY_SIZE + sizeof(IP_Port), sizeof(uint32_t));

    uint32_t num;
    memcpy(&num, data, sizeof(uint32_t));
    return num;
}

static int client_send_announce_request(Onion_Client *onion_c, uint32_t num, IP_Port dest, const uint8_t *dest_pubkey,
                                        const uint8_t *ping_id, uint32_t pathnum)
{
    if (num > onion_c->num_friends) {
        return -1;
    }

    uint64_t sendback;
    Onion_Path path;

    if (num == 0) {
        if (random_path(onion_c, &onion_c->onion_paths_self, pathnum, &path) == -1) {
            return -1;
        }
    } else {
        if (random_path(onion_c, &onion_c->onion_paths_friends, pathnum, &path) == -1) {
            return -1;
        }
    }

    if (new_sendback(onion_c, num, dest_pubkey, dest, path.path_num, &sendback) == -1) {
        return -1;
    }

    uint8_t zero_ping_id[ONION_PING_ID_SIZE] = {0};

    if (ping_id == nullptr) {
        ping_id = zero_ping_id;
    }

    uint8_t request[ONION_ANNOUNCE_REQUEST_SIZE];
    int len;

    if (num == 0) {
        len = create_announce_request(request, sizeof(request), dest_pubkey, nc_get_self_public_key(onion_c->c),
                                      nc_get_self_secret_key(onion_c->c), ping_id, nc_get_self_public_key(onion_c->c),
                                      onion_c->temp_public_key, sendback);
    } else {
        len = create_announce_request(request, sizeof(request), dest_pubkey, onion_c->friends_list[num - 1].temp_public_key,
                                      onion_c->friends_list[num - 1].temp_secret_key, ping_id,
                                      onion_c->friends_list[num - 1].real_public_key, zero_ping_id, sendback);
    }

    if (len == -1) {
        return -1;
    }

    return send_onion_packet_tcp_udp(onion_c, &path, dest, request, len);
}

typedef struct Onion_Client_Cmp_data {
    const Mono_Time *mono_time;
    const uint8_t *base_public_key;
    Onion_Node entry;
} Onion_Client_Cmp_data;

static int onion_client_cmp_entry(const void *a, const void *b)
{
    Onion_Client_Cmp_data cmp1;
    Onion_Client_Cmp_data cmp2;
    memcpy(&cmp1, a, sizeof(Onion_Client_Cmp_data));
    memcpy(&cmp2, b, sizeof(Onion_Client_Cmp_data));
    Onion_Node entry1 = cmp1.entry;
    Onion_Node entry2 = cmp2.entry;
    const uint8_t *cmp_public_key = cmp1.base_public_key;

    int t1 = onion_node_timed_out(&entry1, cmp1.mono_time);
    int t2 = onion_node_timed_out(&entry2, cmp2.mono_time);

    if (t1 && t2) {
        return 0;
    }

    if (t1) {
        return -1;
    }

    if (t2) {
        return 1;
    }

    int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (close == 1) {
        return 1;
    }

    if (close == 2) {
        return -1;
    }

    return 0;
}

static void sort_onion_node_list(Onion_Node *list, unsigned int length, const Mono_Time *mono_time,
                                 const uint8_t *comp_public_key)
{
    // Pass comp_public_key to qsort with each Client_data entry, so the
    // comparison function can use it as the base of comparison.
    VLA(Onion_Client_Cmp_data, cmp_list, length);

    for (uint32_t i = 0; i < length; ++i) {
        cmp_list[i].mono_time = mono_time;
        cmp_list[i].base_public_key = comp_public_key;
        cmp_list[i].entry = list[i];
    }

    qsort(cmp_list, length, sizeof(Onion_Client_Cmp_data), onion_client_cmp_entry);

    for (uint32_t i = 0; i < length; ++i) {
        list[i] = cmp_list[i].entry;
    }
}

static int client_add_to_list(Onion_Client *onion_c, uint32_t num, const uint8_t *public_key, IP_Port ip_port,
                              uint8_t is_stored, const uint8_t *pingid_or_key, uint32_t path_used)
{
    if (num > onion_c->num_friends) {
        return -1;
    }

    Onion_Node *list_nodes = nullptr;
    const uint8_t *reference_id = nullptr;
    unsigned int list_length;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = nc_get_self_public_key(onion_c->c);
        list_length = MAX_ONION_CLIENTS_ANNOUNCE;

        if (is_stored == 1 && public_key_cmp(pingid_or_key, onion_c->temp_public_key) != 0) {
            is_stored = 0;
        }
    } else {
        if (is_stored >= 2) {
            return -1;
        }

        if (is_stored == 1) {
            onion_c->friends_list[num - 1].last_seen = mono_time_get(onion_c->mono_time);
        }

        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_public_key;
        list_length = MAX_ONION_CLIENTS;
    }

    sort_onion_node_list(list_nodes, list_length, onion_c->mono_time, reference_id);

    int index = -1;
    int stored = 0;
    unsigned int i;

    if (onion_node_timed_out(&list_nodes[0], onion_c->mono_time)
            || id_closest(reference_id, list_nodes[0].public_key, public_key) == 2) {
        index = 0;
    }

    for (i = 0; i < list_length; ++i) {
        if (public_key_cmp(list_nodes[i].public_key, public_key) == 0) {
            index = i;
            stored = 1;
            break;
        }
    }

    if (index == -1) {
        return 0;
    }

    memcpy(list_nodes[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    list_nodes[index].ip_port = ip_port;

    // TODO(irungentoo): remove this and find a better source of nodes to use for paths.
    onion_add_path_node(onion_c, ip_port, public_key);

    if (is_stored == 1) {
        memcpy(list_nodes[index].data_public_key, pingid_or_key, CRYPTO_PUBLIC_KEY_SIZE);
    } else {
        memcpy(list_nodes[index].ping_id, pingid_or_key, ONION_PING_ID_SIZE);
    }

    list_nodes[index].is_stored = is_stored;
    list_nodes[index].timestamp = mono_time_get(onion_c->mono_time);
    list_nodes[index].unsuccessful_pings = 0;

    if (!stored) {
        list_nodes[index].last_pinged = 0;
        list_nodes[index].added_time = mono_time_get(onion_c->mono_time);
    }

    list_nodes[index].path_used = path_used;
    return 0;
}

static int good_to_ping(Mono_Time *mono_time, Last_Pinged *last_pinged, uint8_t *last_pinged_index,
                        const uint8_t *public_key)
{
    unsigned int i;

    for (i = 0; i < MAX_STORED_PINGED_NODES; ++i) {
        if (!mono_time_is_timeout(mono_time, last_pinged[i].timestamp, MIN_NODE_PING_TIME)) {
            if (public_key_cmp(last_pinged[i].public_key, public_key) == 0) {
                return 0;
            }
        }
    }

    memcpy(last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    last_pinged[*last_pinged_index % MAX_STORED_PINGED_NODES].timestamp = mono_time_get(mono_time);
    ++*last_pinged_index;
    return 1;
}

static int client_ping_nodes(Onion_Client *onion_c, uint32_t num, const Node_format *nodes, uint16_t num_nodes,
                             IP_Port source)
{
    if (num > onion_c->num_friends) {
        return -1;
    }

    if (num_nodes == 0) {
        return 0;
    }

    Onion_Node *list_nodes = nullptr;
    const uint8_t *reference_id = nullptr;
    unsigned int list_length;

    Last_Pinged *last_pinged = nullptr;
    uint8_t *last_pinged_index = nullptr;

    if (num == 0) {
        list_nodes = onion_c->clients_announce_list;
        reference_id = nc_get_self_public_key(onion_c->c);
        list_length = MAX_ONION_CLIENTS_ANNOUNCE;
        last_pinged = onion_c->last_pinged;
        last_pinged_index = &onion_c->last_pinged_index;
    } else {
        list_nodes = onion_c->friends_list[num - 1].clients_list;
        reference_id = onion_c->friends_list[num - 1].real_public_key;
        list_length = MAX_ONION_CLIENTS;
        last_pinged = onion_c->friends_list[num - 1].last_pinged;
        last_pinged_index = &onion_c->friends_list[num - 1].last_pinged_index;
    }

    const bool lan_ips_accepted = ip_is_lan(source.ip);

    for (uint32_t i = 0; i < num_nodes; ++i) {
        if (!lan_ips_accepted) {
            if (ip_is_lan(nodes[i].ip_port.ip)) {
                continue;
            }
        }

        if (onion_node_timed_out(&list_nodes[0], onion_c->mono_time)
                || id_closest(reference_id, list_nodes[0].public_key, nodes[i].public_key) == 2
                || onion_node_timed_out(&list_nodes[1], onion_c->mono_time)
                || id_closest(reference_id, list_nodes[1].public_key, nodes[i].public_key) == 2) {
            uint32_t j;

            /* check if node is already in list. */
            for (j = 0; j < list_length; ++j) {
                if (public_key_cmp(list_nodes[j].public_key, nodes[i].public_key) == 0) {
                    break;
                }
            }

            if (j == list_length && good_to_ping(onion_c->mono_time, last_pinged, last_pinged_index, nodes[i].public_key)) {
                client_send_announce_request(onion_c, num, nodes[i].ip_port, nodes[i].public_key, nullptr, -1);
            }
        }
    }

    return 0;
}

static int handle_announce_response(void *object, IP_Port source, const uint8_t *packet, uint16_t length,
                                    void *userdata)
{
    Onion_Client *onion_c = (Onion_Client *)object;

    if (length < ONION_ANNOUNCE_RESPONSE_MIN_SIZE || length > ONION_ANNOUNCE_RESPONSE_MAX_SIZE) {
        return 1;
    }

    uint16_t len_nodes = length - ONION_ANNOUNCE_RESPONSE_MIN_SIZE;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port ip_port;
    uint32_t path_num;
    uint32_t num = check_sendback(onion_c, packet + 1, public_key, &ip_port, &path_num);

    if (num > onion_c->num_friends) {
        return 1;
    }

    VLA(uint8_t, plain, 1 + ONION_PING_ID_SIZE + len_nodes);
    int len;

    if (num == 0) {
        len = decrypt_data(public_key, nc_get_self_secret_key(onion_c->c),
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE), plain);
    } else {
        if (onion_c->friends_list[num - 1].status == 0) {
            return 1;
        }

        len = decrypt_data(public_key, onion_c->friends_list[num - 1].temp_secret_key,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE,
                           length - (1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + CRYPTO_NONCE_SIZE), plain);
    }

    if ((uint32_t)len != SIZEOF_VLA(plain)) {
        return 1;
    }

    uint32_t path_used = set_path_timeouts(onion_c, num, path_num);

    if (client_add_to_list(onion_c, num, public_key, ip_port, plain[0], plain + 1, path_used) == -1) {
        return 1;
    }

    if (len_nodes != 0) {
        Node_format nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, nullptr, plain + 1 + ONION_PING_ID_SIZE, len_nodes, 0);

        if (num_nodes <= 0) {
            return 1;
        }

        if (client_ping_nodes(onion_c, num, nodes, num_nodes, source) == -1) {
            return 1;
        }
    }

    // TODO(irungentoo): LAN vs non LAN ips?, if we are connected only to LAN, are we offline?
    onion_c->last_packet_recv = mono_time_get(onion_c->mono_time);
    return 0;
}

#define DATA_IN_RESPONSE_MIN_SIZE ONION_DATA_IN_RESPONSE_MIN_SIZE

static int handle_data_response(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    Onion_Client *onion_c = (Onion_Client *)object;

    if (length <= (ONION_DATA_RESPONSE_MIN_SIZE + DATA_IN_RESPONSE_MIN_SIZE)) {
        return 1;
    }

    if (length > MAX_DATA_REQUEST_SIZE) {
        return 1;
    }

    VLA(uint8_t, temp_plain, length - ONION_DATA_RESPONSE_MIN_SIZE);
    int len = decrypt_data(packet + 1 + CRYPTO_NONCE_SIZE, onion_c->temp_secret_key, packet + 1,
                           packet + 1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE,
                           length - (1 + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE), temp_plain);

    if ((uint32_t)len != SIZEOF_VLA(temp_plain)) {
        return 1;
    }

    VLA(uint8_t, plain, SIZEOF_VLA(temp_plain) - DATA_IN_RESPONSE_MIN_SIZE);
    len = decrypt_data(temp_plain, nc_get_self_secret_key(onion_c->c),
                       packet + 1, temp_plain + CRYPTO_PUBLIC_KEY_SIZE,
                       SIZEOF_VLA(temp_plain) - CRYPTO_PUBLIC_KEY_SIZE, plain);

    if ((uint32_t)len != SIZEOF_VLA(plain)) {
        return 1;
    }

    if (!onion_c->onion_data_handlers[plain[0]].function) {
        return 1;
    }

    return onion_c->onion_data_handlers[plain[0]].function(onion_c->onion_data_handlers[plain[0]].object, temp_plain, plain,
            SIZEOF_VLA(plain), userdata);
}

#define DHTPK_DATA_MIN_LENGTH (1 + sizeof(uint64_t) + CRYPTO_PUBLIC_KEY_SIZE)
#define DHTPK_DATA_MAX_LENGTH (DHTPK_DATA_MIN_LENGTH + sizeof(Node_format)*MAX_SENT_NODES)
static int handle_dhtpk_announce(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t length,
                                 void *userdata)
{
    Onion_Client *onion_c = (Onion_Client *)object;

    if (length < DHTPK_DATA_MIN_LENGTH) {
        return 1;
    }

    if (length > DHTPK_DATA_MAX_LENGTH) {
        return 1;
    }

    int friend_num = onion_friend_num(onion_c, source_pubkey);

    if (friend_num == -1) {
        return 1;
    }

    uint64_t no_replay;
    net_unpack_u64(data + 1, &no_replay);

    if (no_replay <= onion_c->friends_list[friend_num].last_noreplay) {
        return 1;
    }

    onion_c->friends_list[friend_num].last_noreplay = no_replay;

    if (onion_c->friends_list[friend_num].dht_pk_callback) {
        onion_c->friends_list[friend_num].dht_pk_callback(onion_c->friends_list[friend_num].dht_pk_callback_object,
                onion_c->friends_list[friend_num].dht_pk_callback_number, data + 1 + sizeof(uint64_t), userdata);
    }

    onion_set_friend_DHT_pubkey(onion_c, friend_num, data + 1 + sizeof(uint64_t));
    onion_c->friends_list[friend_num].last_seen = mono_time_get(onion_c->mono_time);

    uint16_t len_nodes = length - DHTPK_DATA_MIN_LENGTH;

    if (len_nodes != 0) {
        Node_format nodes[MAX_SENT_NODES];
        int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, nullptr, data + 1 + sizeof(uint64_t) + CRYPTO_PUBLIC_KEY_SIZE,
                                     len_nodes, 1);

        if (num_nodes <= 0) {
            return 1;
        }

        int i;

        for (i = 0; i < num_nodes; ++i) {
            const Family family = nodes[i].ip_port.ip.family;

            if (net_family_is_ipv4(family) || net_family_is_ipv6(family)) {
                dht_getnodes(onion_c->dht, &nodes[i].ip_port, nodes[i].public_key, onion_c->friends_list[friend_num].dht_public_key);
            } else if (net_family_is_tcp_ipv4(family) || net_family_is_tcp_ipv6(family)) {
                if (onion_c->friends_list[friend_num].tcp_relay_node_callback) {
                    void *obj = onion_c->friends_list[friend_num].tcp_relay_node_callback_object;
                    uint32_t number = onion_c->friends_list[friend_num].tcp_relay_node_callback_number;
                    onion_c->friends_list[friend_num].tcp_relay_node_callback(obj, number, nodes[i].ip_port, nodes[i].public_key);
                }
            }
        }
    }

    return 0;
}

static int handle_tcp_onion(void *object, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 0) {
        return 1;
    }

    IP_Port ip_port = {{{0}}};
    ip_port.ip.family = net_family_tcp_family;

    if (data[0] == NET_PACKET_ANNOUNCE_RESPONSE) {
        return handle_announce_response(object, ip_port, data, length, userdata);
    }

    if (data[0] == NET_PACKET_ONION_DATA_RESPONSE) {
        return handle_data_response(object, ip_port, data, length, userdata);
    }

    return 1;
}

/* Send data of length length to friendnum.
 * This data will be received by the friend using the onion_data_handlers callbacks.
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int send_onion_data(Onion_Client *onion_c, int friend_num, const uint8_t *data, uint16_t length)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    if (length + DATA_IN_RESPONSE_MIN_SIZE > MAX_DATA_REQUEST_SIZE) {
        return -1;
    }

    if (length == 0) {
        return -1;
    }

    unsigned int good_nodes[MAX_ONION_CLIENTS];
    unsigned int num_good = 0;
    unsigned int num_nodes = 0;
    Onion_Node *list_nodes = onion_c->friends_list[friend_num].clients_list;

    for (unsigned int i = 0; i < MAX_ONION_CLIENTS; ++i) {
        if (onion_node_timed_out(&list_nodes[i], onion_c->mono_time)) {
            continue;
        }

        ++num_nodes;

        if (list_nodes[i].is_stored) {
            good_nodes[num_good] = i;
            ++num_good;
        }
    }

    if (num_good < (num_nodes - 1) / 4 + 1) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    VLA(uint8_t, packet, DATA_IN_RESPONSE_MIN_SIZE + length);
    memcpy(packet, nc_get_self_public_key(onion_c->c), CRYPTO_PUBLIC_KEY_SIZE);
    int len = encrypt_data(onion_c->friends_list[friend_num].real_public_key,
                           nc_get_self_secret_key(onion_c->c), nonce, data,
                           length, packet + CRYPTO_PUBLIC_KEY_SIZE);

    if ((uint32_t)len + CRYPTO_PUBLIC_KEY_SIZE != SIZEOF_VLA(packet)) {
        return -1;
    }

    unsigned int good = 0;

    for (unsigned int i = 0; i < num_good; ++i) {
        Onion_Path path;

        if (random_path(onion_c, &onion_c->onion_paths_friends, -1, &path) == -1) {
            continue;
        }

        uint8_t o_packet[ONION_MAX_PACKET_SIZE];
        len = create_data_request(o_packet, sizeof(o_packet), onion_c->friends_list[friend_num].real_public_key,
                                  list_nodes[good_nodes[i]].data_public_key, nonce, packet, SIZEOF_VLA(packet));

        if (len == -1) {
            continue;
        }

        if (send_onion_packet_tcp_udp(onion_c, &path, list_nodes[good_nodes[i]].ip_port, o_packet, len) == 0) {
            ++good;
        }
    }

    return good;
}

/* Try to send the dht public key via the DHT instead of onion
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
static int send_dht_dhtpk(const Onion_Client *onion_c, int friend_num, const uint8_t *data, uint16_t length)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    if (!onion_c->friends_list[friend_num].know_dht_public_key) {
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    VLA(uint8_t, temp, DATA_IN_RESPONSE_MIN_SIZE + CRYPTO_NONCE_SIZE + length);
    memcpy(temp, nc_get_self_public_key(onion_c->c), CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(temp + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    int len = encrypt_data(onion_c->friends_list[friend_num].real_public_key,
                           nc_get_self_secret_key(onion_c->c), nonce, data,
                           length, temp + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);

    if ((uint32_t)len + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE != SIZEOF_VLA(temp)) {
        return -1;
    }

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    len = create_request(dht_get_self_public_key(onion_c->dht), dht_get_self_secret_key(onion_c->dht), packet,
                         onion_c->friends_list[friend_num].dht_public_key, temp, SIZEOF_VLA(temp), CRYPTO_PACKET_DHTPK);

    if (len == -1) {
        return -1;
    }

    return route_tofriend(onion_c->dht, onion_c->friends_list[friend_num].dht_public_key, packet, len);
}

static int handle_dht_dhtpk(void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                            uint16_t length, void *userdata)
{
    Onion_Client *onion_c = (Onion_Client *)object;

    if (length < DHTPK_DATA_MIN_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + CRYPTO_NONCE_SIZE) {
        return 1;
    }

    if (length > DHTPK_DATA_MAX_LENGTH + DATA_IN_RESPONSE_MIN_SIZE + CRYPTO_NONCE_SIZE) {
        return 1;
    }

    uint8_t plain[DHTPK_DATA_MAX_LENGTH];
    int len = decrypt_data(packet, nc_get_self_secret_key(onion_c->c),
                           packet + CRYPTO_PUBLIC_KEY_SIZE,
                           packet + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                           length - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE), plain);

    if (len != length - (DATA_IN_RESPONSE_MIN_SIZE + CRYPTO_NONCE_SIZE)) {
        return 1;
    }

    if (public_key_cmp(source_pubkey, plain + 1 + sizeof(uint64_t)) != 0) {
        return 1;
    }

    return handle_dhtpk_announce(onion_c, packet, plain, len, userdata);
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
static int send_dhtpk_announce(Onion_Client *onion_c, uint16_t friend_num, uint8_t onion_dht_both)
{
    if (friend_num >= onion_c->num_friends) {
        return -1;
    }

    uint8_t data[DHTPK_DATA_MAX_LENGTH];
    data[0] = ONION_DATA_DHTPK;
    const uint64_t no_replay = mono_time_get(onion_c->mono_time);
    net_pack_u64(data + 1, no_replay);
    memcpy(data + 1 + sizeof(uint64_t), dht_get_self_public_key(onion_c->dht), CRYPTO_PUBLIC_KEY_SIZE);
    Node_format nodes[MAX_SENT_NODES];
    uint16_t num_relays = copy_connected_tcp_relays(onion_c->c, nodes, (MAX_SENT_NODES / 2));
    uint16_t num_nodes = closelist_nodes(onion_c->dht, &nodes[num_relays], MAX_SENT_NODES - num_relays);
    num_nodes += num_relays;
    int nodes_len = 0;

    if (num_nodes != 0) {
        nodes_len = pack_nodes(data + DHTPK_DATA_MIN_LENGTH, DHTPK_DATA_MAX_LENGTH - DHTPK_DATA_MIN_LENGTH, nodes,
                               num_nodes);

        if (nodes_len <= 0) {
            return -1;
        }
    }

    int num1 = -1;
    int num2 = -1;

    if (onion_dht_both != 1) {
        num1 = send_onion_data(onion_c, friend_num, data, DHTPK_DATA_MIN_LENGTH + nodes_len);
    }

    if (onion_dht_both != 0) {
        num2 = send_dht_dhtpk(onion_c, friend_num, data, DHTPK_DATA_MIN_LENGTH + nodes_len);
    }

    if (num1 == -1) {
        return num2;
    }

    if (num2 == -1) {
        return num1;
    }

    return num1 + num2;
}

/* Get the friend_num of a friend.
 *
 * return -1 on failure.
 * return friend number on success.
 */
int onion_friend_num(const Onion_Client *onion_c, const uint8_t *public_key)
{
    unsigned int i;

    for (i = 0; i < onion_c->num_friends; ++i) {
        if (onion_c->friends_list[i].status == 0) {
            continue;
        }

        if (public_key_cmp(public_key, onion_c->friends_list[i].real_public_key) == 0) {
            return i;
        }
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
        onion_c->friends_list = nullptr;
        return 0;
    }

    Onion_Friend *newonion_friends = (Onion_Friend *)realloc(onion_c->friends_list, num * sizeof(Onion_Friend));

    if (newonion_friends == nullptr) {
        return -1;
    }

    onion_c->friends_list = newonion_friends;
    return 0;
}

/* Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success or if the friend was already added.
 */
int onion_addfriend(Onion_Client *onion_c, const uint8_t *public_key)
{
    int num = onion_friend_num(onion_c, public_key);

    if (num != -1) {
        return num;
    }

    unsigned int index = -1;

    for (unsigned int i = 0; i < onion_c->num_friends; ++i) {
        if (onion_c->friends_list[i].status == 0) {
            index = i;
            break;
        }
    }

    if (index == (uint32_t) -1) {
        if (realloc_onion_friends(onion_c, onion_c->num_friends + 1) == -1) {
            return -1;
        }

        index = onion_c->num_friends;
        memset(&onion_c->friends_list[onion_c->num_friends], 0, sizeof(Onion_Friend));
        ++onion_c->num_friends;
    }

    onion_c->friends_list[index].status = 1;
    memcpy(onion_c->friends_list[index].real_public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    crypto_new_keypair(onion_c->friends_list[index].temp_public_key, onion_c->friends_list[index].temp_secret_key);
    return index;
}

/* Delete a friend.
 *
 * return -1 on failure.
 * return the deleted friend number on success.
 */
int onion_delfriend(Onion_Client *onion_c, int friend_num)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

#if 0

    if (onion_c->friends_list[friend_num].know_dht_public_key) {
        dht_delfriend(onion_c->dht, onion_c->friends_list[friend_num].dht_public_key, 0);
    }

#endif

    crypto_memzero(&onion_c->friends_list[friend_num], sizeof(Onion_Friend));
    unsigned int i;

    for (i = onion_c->num_friends; i != 0; --i) {
        if (onion_c->friends_list[i - 1].status != 0) {
            break;
        }
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
int recv_tcp_relay_handler(Onion_Client *onion_c, int friend_num,
                           recv_tcp_relay_cb *callback, void *object, uint32_t number)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    onion_c->friends_list[friend_num].tcp_relay_node_callback = callback;
    onion_c->friends_list[friend_num].tcp_relay_node_callback_object = object;
    onion_c->friends_list[friend_num].tcp_relay_node_callback_number = number;
    return 0;
}

/* Set the function for this friend that will be callbacked with object and number
 * when that friend gives us his DHT temporary public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_dht_pk_callback(Onion_Client *onion_c, int friend_num,
                          onion_dht_pk_cb *function, void *object, uint32_t number)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    onion_c->friends_list[friend_num].dht_pk_callback = function;
    onion_c->friends_list[friend_num].dht_pk_callback_object = object;
    onion_c->friends_list[friend_num].dht_pk_callback_number = number;
    return 0;
}

/* Set a friend's DHT public key.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_set_friend_DHT_pubkey(Onion_Client *onion_c, int friend_num, const uint8_t *dht_key)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    if (onion_c->friends_list[friend_num].status == 0) {
        return -1;
    }

    if (onion_c->friends_list[friend_num].know_dht_public_key) {
        if (public_key_cmp(dht_key, onion_c->friends_list[friend_num].dht_public_key) == 0) {
            return -1;
        }
    }

    onion_c->friends_list[friend_num].last_seen = mono_time_get(onion_c->mono_time);
    onion_c->friends_list[friend_num].know_dht_public_key = 1;
    memcpy(onion_c->friends_list[friend_num].dht_public_key, dht_key, CRYPTO_PUBLIC_KEY_SIZE);

    return 0;
}

/* Copy friends DHT public key into dht_key.
 *
 * return 0 on failure (no key copied).
 * return 1 on success (key copied).
 */
unsigned int onion_getfriend_DHT_pubkey(const Onion_Client *onion_c, int friend_num, uint8_t *dht_key)
{
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return 0;
    }

    if (onion_c->friends_list[friend_num].status == 0) {
        return 0;
    }

    if (!onion_c->friends_list[friend_num].know_dht_public_key) {
        return 0;
    }

    memcpy(dht_key, onion_c->friends_list[friend_num].dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    return 1;
}

/* Get the ip of friend friendnum and put it in ip_port
 *
 *  return -1, -- if public_key does NOT refer to a friend
 *  return  0, -- if public_key refers to a friend and we failed to find the friend (yet)
 *  return  1, ip if public_key refers to a friend and we found him
 *
 */
int onion_getfriendip(const Onion_Client *onion_c, int friend_num, IP_Port *ip_port)
{
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE];

    if (onion_getfriend_DHT_pubkey(onion_c, friend_num, dht_public_key) == 0) {
        return -1;
    }

    return dht_getfriendip(onion_c->dht, dht_public_key, ip_port);
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
    if ((uint32_t)friend_num >= onion_c->num_friends) {
        return -1;
    }

    if (is_online == 0 && onion_c->friends_list[friend_num].is_online == 1) {
        onion_c->friends_list[friend_num].last_seen = mono_time_get(onion_c->mono_time);
    }

    onion_c->friends_list[friend_num].is_online = is_online;

    /* This should prevent some clock related issues */
    if (!is_online) {
        onion_c->friends_list[friend_num].last_noreplay = 0;
        onion_c->friends_list[friend_num].run_count = 0;
    }

    return 0;
}

static void populate_path_nodes(Onion_Client *onion_c)
{
    Node_format nodes_list[MAX_FRIEND_CLIENTS];

    unsigned int num_nodes = randfriends_nodes(onion_c->dht, nodes_list, MAX_FRIEND_CLIENTS);

    unsigned int i;

    for (i = 0; i < num_nodes; ++i) {
        onion_add_path_node(onion_c, nodes_list[i].ip_port, nodes_list[i].public_key);
    }
}

static void populate_path_nodes_tcp(Onion_Client *onion_c)
{
    Node_format nodes_list[MAX_SENT_NODES];

    unsigned int num_nodes = copy_connected_tcp_relays(onion_c->c, nodes_list, MAX_SENT_NODES);
    unsigned int i;

    for (i = 0; i < num_nodes; ++i) {
        onion_add_bs_path_node(onion_c, nodes_list[i].ip_port, nodes_list[i].public_key);
    }
}

#define ANNOUNCE_FRIEND (ONION_NODE_PING_INTERVAL * 6)
#define ANNOUNCE_FRIEND_BEGINNING 3

#define RUN_COUNT_FRIEND_ANNOUNCE_BEGINNING 17

#define ONION_FRIEND_BACKOFF_FACTOR 4
#define ONION_FRIEND_MAX_PING_INTERVAL (5*60*MAX_ONION_CLIENTS)

static void do_friend(Onion_Client *onion_c, uint16_t friendnum)
{
    if (friendnum >= onion_c->num_friends) {
        return;
    }

    if (onion_c->friends_list[friendnum].status == 0) {
        return;
    }

    unsigned int interval = ANNOUNCE_FRIEND;

    if (onion_c->friends_list[friendnum].run_count < RUN_COUNT_FRIEND_ANNOUNCE_BEGINNING) {
        interval = ANNOUNCE_FRIEND_BEGINNING;
    } else {
        if (onion_c->friends_list[friendnum].last_seen == 0) {
            onion_c->friends_list[friendnum].last_seen = mono_time_get(onion_c->mono_time);
        }

        uint64_t backoff_interval = (mono_time_get(onion_c->mono_time) -
                                     onion_c->friends_list[friendnum].last_seen)
                                    / ONION_FRIEND_BACKOFF_FACTOR;

        if (backoff_interval > ONION_FRIEND_MAX_PING_INTERVAL) {
            backoff_interval = ONION_FRIEND_MAX_PING_INTERVAL;
        }

        if (interval < backoff_interval) {
            interval = backoff_interval;
        }
    }

    if (!onion_c->friends_list[friendnum].is_online) {
        unsigned int count = 0;
        Onion_Node *list_nodes = onion_c->friends_list[friendnum].clients_list;

        // ensure we get a response from some node roughly once per
        // (interval / MAX_ONION_CLIENTS)
        bool ping_random = true;

        for (unsigned i = 0; i < MAX_ONION_CLIENTS; ++i) {
            if (!(mono_time_is_timeout(onion_c->mono_time, list_nodes[i].timestamp, interval / MAX_ONION_CLIENTS)
                    && mono_time_is_timeout(onion_c->mono_time, list_nodes[i].last_pinged, ONION_NODE_PING_INTERVAL))) {
                ping_random = false;
                break;
            }
        }

        for (unsigned i = 0; i < MAX_ONION_CLIENTS; ++i) {
            if (onion_node_timed_out(&list_nodes[i], onion_c->mono_time)) {
                continue;
            }

            ++count;


            if (list_nodes[i].last_pinged == 0) {
                list_nodes[i].last_pinged = mono_time_get(onion_c->mono_time);
                continue;
            }

            if (list_nodes[i].unsuccessful_pings >= ONION_NODE_MAX_PINGS) {
                continue;
            }

            if (mono_time_is_timeout(onion_c->mono_time, list_nodes[i].last_pinged, interval)
                    || (ping_random && random_u32() % (MAX_ONION_CLIENTS - i) == 0)) {
                if (client_send_announce_request(onion_c, friendnum + 1, list_nodes[i].ip_port,
                                                 list_nodes[i].public_key, nullptr, -1) == 0) {
                    list_nodes[i].last_pinged = mono_time_get(onion_c->mono_time);
                    ++list_nodes[i].unsuccessful_pings;
                    ping_random = false;
                }
            }
        }

        if (count != MAX_ONION_CLIENTS) {
            const uint16_t num_nodes = min_u16(onion_c->path_nodes_index, MAX_PATH_NODES);
            uint16_t n = num_nodes;

            if (num_nodes > (MAX_ONION_CLIENTS / 2)) {
                n = (MAX_ONION_CLIENTS / 2);
            }

            if (count <= random_u32() % MAX_ONION_CLIENTS) {
                if (num_nodes != 0) {
                    unsigned int j;

                    for (j = 0; j < n; ++j) {
                        const uint32_t num = random_u32() % num_nodes;
                        client_send_announce_request(onion_c, friendnum + 1, onion_c->path_nodes[num].ip_port,
                                                     onion_c->path_nodes[num].public_key, nullptr, -1);
                    }

                    ++onion_c->friends_list[friendnum].run_count;
                }
            }
        } else {
            ++onion_c->friends_list[friendnum].run_count;
        }

        /* send packets to friend telling them our DHT public key. */
        if (mono_time_is_timeout(onion_c->mono_time, onion_c->friends_list[friendnum].last_dht_pk_onion_sent,
                                 ONION_DHTPK_SEND_INTERVAL)) {
            if (send_dhtpk_announce(onion_c, friendnum, 0) >= 1) {
                onion_c->friends_list[friendnum].last_dht_pk_onion_sent = mono_time_get(onion_c->mono_time);
            }
        }

        if (mono_time_is_timeout(onion_c->mono_time, onion_c->friends_list[friendnum].last_dht_pk_dht_sent,
                                 DHT_DHTPK_SEND_INTERVAL)) {
            if (send_dhtpk_announce(onion_c, friendnum, 1) >= 1) {
                onion_c->friends_list[friendnum].last_dht_pk_dht_sent = mono_time_get(onion_c->mono_time);
            }
        }
    }
}


/* Function to call when onion data packet with contents beginning with byte is received. */
void oniondata_registerhandler(Onion_Client *onion_c, uint8_t byte, oniondata_handler_cb *cb, void *object)
{
    onion_c->onion_data_handlers[byte].function = cb;
    onion_c->onion_data_handlers[byte].object = object;
}

#define ANNOUNCE_INTERVAL_NOT_ANNOUNCED 3
#define ANNOUNCE_INTERVAL_ANNOUNCED ONION_NODE_PING_INTERVAL

#define TIME_TO_STABLE (ONION_NODE_PING_INTERVAL * 6)
#define ANNOUNCE_INTERVAL_STABLE (ONION_NODE_PING_INTERVAL * 8)

static void do_announce(Onion_Client *onion_c)
{
    unsigned int count = 0;
    Onion_Node *list_nodes = onion_c->clients_announce_list;

    for (unsigned int i = 0; i < MAX_ONION_CLIENTS_ANNOUNCE; ++i) {
        if (onion_node_timed_out(&list_nodes[i], onion_c->mono_time)) {
            continue;
        }

        ++count;

        /* Don't announce ourselves the first time this is run to new peers */
        if (list_nodes[i].last_pinged == 0) {
            list_nodes[i].last_pinged = 1;
            continue;
        }

        if (list_nodes[i].unsuccessful_pings >= ONION_NODE_MAX_PINGS) {
            continue;
        }


        unsigned int interval = ANNOUNCE_INTERVAL_NOT_ANNOUNCED;

        if (list_nodes[i].is_stored && path_exists(onion_c->mono_time, &onion_c->onion_paths_self, list_nodes[i].path_used)) {
            interval = ANNOUNCE_INTERVAL_ANNOUNCED;

            uint32_t pathnum = list_nodes[i].path_used % NUMBER_ONION_PATHS;

            /* A node/path is considered "stable", and can be pinged less
             * aggressively, if it has survived for at least TIME_TO_STABLE
             * and the latest packets sent to it are not timing out.
             */
            if (mono_time_is_timeout(onion_c->mono_time, list_nodes[i].added_time, TIME_TO_STABLE)
                    && !(list_nodes[i].unsuccessful_pings > 0
                         && mono_time_is_timeout(onion_c->mono_time, list_nodes[i].last_pinged, ONION_NODE_TIMEOUT))
                    && mono_time_is_timeout(onion_c->mono_time, onion_c->onion_paths_self.path_creation_time[pathnum], TIME_TO_STABLE)
                    && !(onion_c->onion_paths_self.last_path_used_times[pathnum] > 0
                         && mono_time_is_timeout(onion_c->mono_time, onion_c->onion_paths_self.last_path_used[pathnum], ONION_PATH_TIMEOUT))) {
                interval = ANNOUNCE_INTERVAL_STABLE;
            }
        }

        if (mono_time_is_timeout(onion_c->mono_time, list_nodes[i].last_pinged, interval)
                || (mono_time_is_timeout(onion_c->mono_time, onion_c->last_announce, ONION_NODE_PING_INTERVAL)
                    && random_u32() % (MAX_ONION_CLIENTS_ANNOUNCE - i) == 0)) {
            uint32_t path_to_use = list_nodes[i].path_used;

            if (list_nodes[i].unsuccessful_pings == ONION_NODE_MAX_PINGS - 1
                    && mono_time_is_timeout(onion_c->mono_time, list_nodes[i].added_time, TIME_TO_STABLE)) {
                /* Last chance for a long-lived node - try a random path */
                path_to_use = -1;
            }

            if (client_send_announce_request(onion_c, 0, list_nodes[i].ip_port, list_nodes[i].public_key,
                                             list_nodes[i].ping_id, path_to_use) == 0) {
                list_nodes[i].last_pinged = mono_time_get(onion_c->mono_time);
                ++list_nodes[i].unsuccessful_pings;
                onion_c->last_announce = mono_time_get(onion_c->mono_time);
            }
        }
    }

    if (count != MAX_ONION_CLIENTS_ANNOUNCE) {
        uint16_t num_nodes;
        Node_format *path_nodes;

        if (random_u08() % 2 == 0 || onion_c->path_nodes_index == 0) {
            num_nodes = min_u16(onion_c->path_nodes_index_bs, MAX_PATH_NODES);
            path_nodes = onion_c->path_nodes_bs;
        } else {
            num_nodes = min_u16(onion_c->path_nodes_index, MAX_PATH_NODES);
            path_nodes = onion_c->path_nodes;
        }

        if (count <= random_u32() % MAX_ONION_CLIENTS_ANNOUNCE) {
            if (num_nodes != 0) {
                for (unsigned int i = 0; i < (MAX_ONION_CLIENTS_ANNOUNCE / 2); ++i) {
                    const uint32_t num = random_u32() % num_nodes;
                    client_send_announce_request(onion_c, 0, path_nodes[num].ip_port, path_nodes[num].public_key, nullptr, -1);
                }
            }
        }
    }
}

/*  return 0 if we are not connected to the network.
 *  return 1 if we are.
 */
static int onion_isconnected(const Onion_Client *onion_c)
{
    unsigned int num = 0;
    unsigned int announced = 0;

    if (mono_time_is_timeout(onion_c->mono_time, onion_c->last_packet_recv, ONION_OFFLINE_TIMEOUT)) {
        return 0;
    }

    if (onion_c->path_nodes_index == 0) {
        return 0;
    }

    for (unsigned int i = 0; i < MAX_ONION_CLIENTS_ANNOUNCE; ++i) {
        if (!onion_node_timed_out(&onion_c->clients_announce_list[i], onion_c->mono_time)) {
            ++num;

            if (onion_c->clients_announce_list[i].is_stored) {
                ++announced;
            }
        }
    }

    unsigned int pnodes = onion_c->path_nodes_index;

    if (pnodes > MAX_ONION_CLIENTS_ANNOUNCE) {
        pnodes = MAX_ONION_CLIENTS_ANNOUNCE;
    }

    /* Consider ourselves online if we are announced to half or more nodes
     * we are connected to */
    if (num && announced) {
        if ((num / 2) <= announced && (pnodes / 2) <= num) {
            return 1;
        }
    }

    return 0;
}

#define ONION_CONNECTION_SECONDS 3

/*  return 0 if we are not connected to the network.
 *  return 1 if we are connected with TCP only.
 *  return 2 if we are also connected with UDP.
 */
unsigned int onion_connection_status(const Onion_Client *onion_c)
{
    if (onion_c->onion_connected >= ONION_CONNECTION_SECONDS) {
        if (onion_c->udp_connected) {
            return 2;
        }

        return 1;
    }

    return 0;
}

void do_onion_client(Onion_Client *onion_c)
{
    if (onion_c->last_run == mono_time_get(onion_c->mono_time)) {
        return;
    }

    if (mono_time_is_timeout(onion_c->mono_time, onion_c->first_run, ONION_CONNECTION_SECONDS)) {
        populate_path_nodes(onion_c);
        do_announce(onion_c);
    }

    if (onion_isconnected(onion_c)) {
        if (onion_c->onion_connected < ONION_CONNECTION_SECONDS * 2) {
            ++onion_c->onion_connected;
        }
    } else {
        populate_path_nodes_tcp(onion_c);

        if (onion_c->onion_connected != 0) {
            --onion_c->onion_connected;
        }
    }

    onion_c->udp_connected = dht_non_lan_connected(onion_c->dht);

    if (mono_time_is_timeout(onion_c->mono_time, onion_c->first_run, ONION_CONNECTION_SECONDS * 2)) {
        set_tcp_onion_status(nc_get_tcp_c(onion_c->c), !onion_c->udp_connected);
    }

    if (onion_connection_status(onion_c)) {
        for (unsigned i = 0; i < onion_c->num_friends; ++i) {
            do_friend(onion_c, i);
        }
    }

    if (onion_c->last_run == 0) {
        onion_c->first_run = mono_time_get(onion_c->mono_time);
    }

    onion_c->last_run = mono_time_get(onion_c->mono_time);
}

Onion_Client *new_onion_client(const Logger *logger, Mono_Time *mono_time, Net_Crypto *c)
{
    if (c == nullptr) {
        return nullptr;
    }

    Onion_Client *onion_c = (Onion_Client *)calloc(1, sizeof(Onion_Client));

    if (onion_c == nullptr) {
        return nullptr;
    }

    onion_c->announce_ping_array = ping_array_new(ANNOUNCE_ARRAY_SIZE, ANNOUNCE_TIMEOUT);

    if (onion_c->announce_ping_array == nullptr) {
        free(onion_c);
        return nullptr;
    }

    onion_c->mono_time = mono_time;
    onion_c->logger = logger;
    onion_c->dht = nc_get_dht(c);
    onion_c->net = dht_get_net(onion_c->dht);
    onion_c->c = c;
    new_symmetric_key(onion_c->secret_symmetric_key);
    crypto_new_keypair(onion_c->temp_public_key, onion_c->temp_secret_key);
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_announce_response, onion_c);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_data_response, onion_c);
    oniondata_registerhandler(onion_c, ONION_DATA_DHTPK, &handle_dhtpk_announce, onion_c);
    cryptopacket_registerhandler(onion_c->dht, CRYPTO_PACKET_DHTPK, &handle_dht_dhtpk, onion_c);
    set_onion_packet_tcp_connection_callback(nc_get_tcp_c(onion_c->c), &handle_tcp_onion, onion_c);

    return onion_c;
}

void kill_onion_client(Onion_Client *onion_c)
{
    if (onion_c == nullptr) {
        return;
    }

    ping_array_kill(onion_c->announce_ping_array);
    realloc_onion_friends(onion_c, 0);
    networking_registerhandler(onion_c->net, NET_PACKET_ANNOUNCE_RESPONSE, nullptr, nullptr);
    networking_registerhandler(onion_c->net, NET_PACKET_ONION_DATA_RESPONSE, nullptr, nullptr);
    oniondata_registerhandler(onion_c, ONION_DATA_DHTPK, nullptr, nullptr);
    cryptopacket_registerhandler(onion_c->dht, CRYPTO_PACKET_DHTPK, nullptr, nullptr);
    set_onion_packet_tcp_connection_callback(nc_get_tcp_c(onion_c->c), nullptr, nullptr);
    crypto_memzero(onion_c, sizeof(Onion_Client));
    free(onion_c);
}
