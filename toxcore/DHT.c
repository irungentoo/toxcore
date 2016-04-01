/* DHT.c
 *
 * An implementation of the DHT as seen in docs/updates/DHT.md
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

#ifdef DEBUG
#include <assert.h>
#endif

#include "logger.h"

#include "DHT.h"
#include "ping.h"

#include "network.h"
#include "LAN_discovery.h"
#include "misc_tools.h"
#include "util.h"

/* The timeout after which a node is discarded completely. */
#define KILL_NODE_TIMEOUT (BAD_NODE_TIMEOUT + PING_INTERVAL)

/* Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 5

#define MAX_PUNCHING_PORTS 48

/* Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 3

#define MAX_NORMAL_PUNCHING_TRIES 5

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/* Number of get node requests to send to quickly find close nodes. */
#define MAX_BOOTSTRAP_TIMES 5

/* Compares pk1 and pk2 with pk.
 *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
int id_closest(const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2)
{
    size_t   i;
    uint8_t distance1, distance2;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES; ++i) {

        distance1 = pk[i] ^ pk1[i];
        distance2 = pk[i] ^ pk2[i];

        if (distance1 < distance2)
            return 1;

        if (distance1 > distance2)
            return 2;
    }

    return 0;
}

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key(Shared_Keys *shared_keys, uint8_t *shared_key, const uint8_t *secret_key, const uint8_t *public_key)
{
    uint32_t i, num = ~0, curr = 0;

    for (i = 0; i < MAX_KEYS_PER_SLOT; ++i) {
        int index = public_key[30] * MAX_KEYS_PER_SLOT + i;

        if (shared_keys->keys[index].stored) {
            if (public_key_cmp(public_key, shared_keys->keys[index].public_key) == 0) {
                memcpy(shared_key, shared_keys->keys[index].shared_key, crypto_box_BEFORENMBYTES);
                ++shared_keys->keys[index].times_requested;
                shared_keys->keys[index].time_last_requested = unix_time();
                return;
            }

            if (num != 0) {
                if (is_timeout(shared_keys->keys[index].time_last_requested, KEYS_TIMEOUT)) {
                    num = 0;
                    curr = index;
                } else if (num > shared_keys->keys[index].times_requested) {
                    num = shared_keys->keys[index].times_requested;
                    curr = index;
                }
            }
        } else {
            if (num != 0) {
                num = 0;
                curr = index;
            }
        }
    }

    encrypt_precompute(public_key, secret_key, shared_key);

    if (num != (uint32_t)~0) {
        shared_keys->keys[curr].stored = 1;
        shared_keys->keys[curr].times_requested = 1;
        memcpy(shared_keys->keys[curr].public_key, public_key, crypto_box_PUBLICKEYBYTES);
        memcpy(shared_keys->keys[curr].shared_key, shared_key, crypto_box_BEFORENMBYTES);
        shared_keys->keys[curr].time_last_requested = unix_time();
    }
}

/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we receive.
 */
void DHT_get_shared_key_recv(DHT *dht, uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key(&dht->shared_keys_recv, shared_key, dht->self_secret_key, public_key);
}

/* Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we send.
 */
void DHT_get_shared_key_sent(DHT *dht, uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key(&dht->shared_keys_sent, shared_key, dht->self_secret_key, public_key);
}

void to_net_family(IP *ip)
{
    if (ip->family == AF_INET)
        ip->family = TOX_AF_INET;
    else if (ip->family == AF_INET6)
        ip->family = TOX_AF_INET6;
}

int to_host_family(IP *ip)
{
    if (ip->family == TOX_AF_INET) {
        ip->family = AF_INET;
        return 0;
    } else if (ip->family == TOX_AF_INET6) {
        ip->family = AF_INET6;
        return 0;
    } else {
        return -1;
    }
}

#define PACKED_NODE_SIZE_IP4 (1 + SIZE_IP4 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)
#define PACKED_NODE_SIZE_IP6 (1 + SIZE_IP6 + sizeof(uint16_t) + crypto_box_PUBLICKEYBYTES)

/* Return packet size of packed node with ip_family on success.
 * Return -1 on failure.
 */
int packed_node_size(uint8_t ip_family)
{
    if (ip_family == AF_INET) {
        return PACKED_NODE_SIZE_IP4;
    } else if (ip_family == TCP_INET) {
        return PACKED_NODE_SIZE_IP4;
    } else if (ip_family == AF_INET6) {
        return PACKED_NODE_SIZE_IP6;
    } else if (ip_family == TCP_INET6) {
        return PACKED_NODE_SIZE_IP6;
    } else {
        return -1;
    }
}


/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes(uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number)
{
    uint32_t i, packed_length = 0;

    for (i = 0; i < number; ++i) {
        int ipv6 = -1;
        uint8_t net_family;

        // FIXME use functions to convert endianness
        if (nodes[i].ip_port.ip.family == AF_INET) {
            ipv6 = 0;
            net_family = TOX_AF_INET;
        } else if (nodes[i].ip_port.ip.family == TCP_INET) {
            ipv6 = 0;
            net_family = TOX_TCP_INET;
        } else if (nodes[i].ip_port.ip.family == AF_INET6) {
            ipv6 = 1;
            net_family = TOX_AF_INET6;
        } else if (nodes[i].ip_port.ip.family == TCP_INET6) {
            ipv6 = 1;
            net_family = TOX_TCP_INET6;
        } else {
            return -1;
        }

        if (ipv6 == 0) {
            uint32_t size = PACKED_NODE_SIZE_IP4;

            if (packed_length + size > length)
                return -1;

            data[packed_length] = net_family;
            memcpy(data + packed_length + 1, &nodes[i].ip_port.ip.ip4, SIZE_IP4);
            memcpy(data + packed_length + 1 + SIZE_IP4, &nodes[i].ip_port.port, sizeof(uint16_t));
            memcpy(data + packed_length + 1 + SIZE_IP4 + sizeof(uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
            packed_length += size;
        } else if (ipv6 == 1) {
            uint32_t size = PACKED_NODE_SIZE_IP6;

            if (packed_length + size > length)
                return -1;

            data[packed_length] = net_family;
            memcpy(data + packed_length + 1, &nodes[i].ip_port.ip.ip6, SIZE_IP6);
            memcpy(data + packed_length + 1 + SIZE_IP6, &nodes[i].ip_port.port, sizeof(uint16_t));
            memcpy(data + packed_length + 1 + SIZE_IP6 + sizeof(uint16_t), nodes[i].public_key, crypto_box_PUBLICKEYBYTES);
            packed_length += size;
        } else {
            return -1;
        }
    }

    return packed_length;
}

/* Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * return number of unpacked nodes on success.
 * return -1 on failure.
 */
int unpack_nodes(Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
                 uint16_t length, uint8_t tcp_enabled)
{
    uint32_t num = 0, len_processed = 0;

    while (num < max_num_nodes && len_processed < length) {
        int ipv6 = -1;
        uint8_t host_family;

        if (data[len_processed] == TOX_AF_INET) {
            ipv6 = 0;
            host_family = AF_INET;
        } else if (data[len_processed] == TOX_TCP_INET) {
            if (!tcp_enabled)
                return -1;

            ipv6 = 0;
            host_family = TCP_INET;
        } else if (data[len_processed] == TOX_AF_INET6) {
            ipv6 = 1;
            host_family = AF_INET6;
        } else if (data[len_processed] == TOX_TCP_INET6) {
            if (!tcp_enabled)
                return -1;

            ipv6 = 1;
            host_family = TCP_INET6;
        } else {
            return -1;
        }

        if (ipv6 == 0) {
            uint32_t size = PACKED_NODE_SIZE_IP4;

            if (len_processed + size > length)
                return -1;

            nodes[num].ip_port.ip.family = host_family;
            memcpy(&nodes[num].ip_port.ip.ip4, data + len_processed + 1, SIZE_IP4);
            memcpy(&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP4, sizeof(uint16_t));
            memcpy(nodes[num].public_key, data + len_processed + 1 + SIZE_IP4 + sizeof(uint16_t), crypto_box_PUBLICKEYBYTES);
            len_processed += size;
            ++num;
        } else if (ipv6 == 1) {
            uint32_t size = PACKED_NODE_SIZE_IP6;

            if (len_processed + size > length)
                return -1;

            nodes[num].ip_port.ip.family = host_family;
            memcpy(&nodes[num].ip_port.ip.ip6, data + len_processed + 1, SIZE_IP6);
            memcpy(&nodes[num].ip_port.port, data + len_processed + 1 + SIZE_IP6, sizeof(uint16_t));
            memcpy(nodes[num].public_key, data + len_processed + 1 + SIZE_IP6 + sizeof(uint16_t), crypto_box_PUBLICKEYBYTES);
            len_processed += size;
            ++num;
        } else {
            return -1;
        }
    }

    if (processed_data_len)
        *processed_data_len = len_processed;

    return num;
}

static int get_bit_at(const uint8_t *pk, unsigned int index)
{
    if (index >= crypto_box_PUBLICKEYBYTES * 8)
        return -1;

    return !!(pk[index / 8] & (1 << (7 - (index % 8))));
}

static int set_bit_at(uint8_t *pk, unsigned int index)
{
    if (index >= crypto_box_PUBLICKEYBYTES * 8)
        return -1;

    pk[index / 8] |= (1 << (7 - (index % 8)));
    return 0;
}

static int unset_bit_at(uint8_t *pk, unsigned int index)
{
    if (index >= crypto_box_PUBLICKEYBYTES * 8)
        return -1;

    pk[index / 8] &= ~(1 << (7 - (index % 8)));
    return 0;
}

static int alloc_buckets(DHT_Bucket *bucket)
{
    DHT_Bucket *b0 = calloc(1, sizeof(DHT_Bucket));
    DHT_Bucket *b1 = calloc(1, sizeof(DHT_Bucket));

    if (b0 && b1) {
        bucket->buckets[0] = b0;
        bucket->buckets[1] = b1;

        b0->deepness = bucket->deepness + 1;
        b1->deepness = bucket->deepness + 1;

        unsigned int i, b0_ind = 0, b1_ind = 0;

        for (i = 0; i < DHT_BUCKET_NODES; ++i) {
            if (!is_timeout(bucket->client_list[i].timestamp, BAD_NODE_TIMEOUT)) {
                int bit = get_bit_at(bucket->client_list[i].public_key, bucket->deepness);

                if (bit == 0) {
                    memcpy(&b0->client_list[b0_ind], &bucket->client_list[i], sizeof(Client_data));
                    ++b0_ind;
                } else if (bit == 1) {
                    memcpy(&b1->client_list[b1_ind], &bucket->client_list[i], sizeof(Client_data));
                    ++b1_ind;
                }
            }
        }

        if (bucket->public_key) {
            int bit = get_bit_at(bucket->searched_public_key, bucket->deepness);

            if (bit == 0) {
                memcpy(b0->searched_public_key, bucket->searched_public_key, crypto_box_PUBLICKEYBYTES);
                b0->public_key = 1;
            } else if (bit == 1) {
                memcpy(b1->searched_public_key, bucket->searched_public_key, crypto_box_PUBLICKEYBYTES);
                b1->public_key = 1;
            }
        }

        bucket->empty = 1;
        bucket->public_key = 0;

        memset(bucket->client_list, 0, sizeof(bucket->client_list));

        return 0;
    } else {
        free(b0);
        free(b1);
        return -1;
    }
}

static void recursive_free_buckets(DHT_Bucket *bucket)
{
    if (bucket) {
        recursive_free_buckets(bucket->buckets[0]);
        recursive_free_buckets(bucket->buckets[1]);

        free(bucket->buckets[0]);
        free(bucket->buckets[1]);

        bucket->buckets[0] = 0;
        bucket->buckets[1] = 0;
    }
}

void free_buckets(DHT_Bucket *bucket)
{
    recursive_free_buckets(bucket);
}


static int recursive_DHT_bucket_add_key(DHT_Bucket *bucket, const uint8_t *public_key)
{
    int bit = get_bit_at(public_key, bucket->deepness);

    if (bit == -1)
        return -1;

    if (bucket->empty) {
        return recursive_DHT_bucket_add_key(bucket->buckets[bit], public_key);
    }

    if (bucket->public_key) {
        if (id_equal(bucket->searched_public_key, public_key))
            return -1;

        if (alloc_buckets(bucket) == -1)
            return -1;

        return recursive_DHT_bucket_add_key(bucket->buckets[bit], public_key);
    } else {
        memcpy(bucket->searched_public_key, public_key, crypto_box_PUBLICKEYBYTES);
        bucket->public_key = 1;
        return 0;
    }
}


int DHT_bucket_add_key(DHT_Bucket *bucket, const uint8_t *public_key)
{
    return recursive_DHT_bucket_add_key(bucket, public_key);
}

static int recursive_DHT_bucket_add_node(DHT_Bucket *bucket, const uint8_t *public_key, IP_Port ip_port, _Bool pretend)
{
    int bit = get_bit_at(public_key, bucket->deepness);

    if (bit == -1)
        return -1;

    if (bucket->empty) {
        return recursive_DHT_bucket_add_node(bucket->buckets[bit], public_key, ip_port, pretend);
    } else {
        unsigned int i, store_index = DHT_BUCKET_NODES;

        for (i = 0; i < DHT_BUCKET_NODES; ++i) {
            Client_data *client = &bucket->client_list[i];

            if (is_timeout(client->timestamp, BAD_NODE_TIMEOUT)) {
                store_index = i;
            } else {
                if (id_equal(client->public_key, public_key)) {
                    if (pretend) {
                        return -1;
                    }

                    client->ip_port = ip_port;
                    client->timestamp = unix_time();
                    return 0;
                }
            }
        }

        if (store_index < DHT_BUCKET_NODES) {
            if (pretend) {
                return 0;
            }

            Client_data *client = &bucket->client_list[store_index];
            memset(client, 0, sizeof(Client_data));
            id_copy(client->public_key, public_key);
            client->ip_port = ip_port;
            client->last_pinged = client->timestamp = unix_time();

            return 0;
        }

        if (bucket->public_key) {
            if (pretend) {
                return 0;
            }

            /* Bucket Full */
            if (alloc_buckets(bucket) == -1)
                return -1;

            return recursive_DHT_bucket_add_node(bucket->buckets[bit], public_key, ip_port, pretend);
        } else {
            return -1;
        }
    }
}

int DHT_bucket_add_node(DHT_Bucket *bucket, const uint8_t *public_key, IP_Port ip_port, _Bool pretend)
{
    return recursive_DHT_bucket_add_node(bucket, public_key, ip_port, pretend);
}

/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
static _Bool add_to_ret_ip_list(Client_data *client, const uint8_t *node_public_key, const uint8_t *public_key,
                                IP_Port ret_ip_port, uint64_t timestamp)
{
    uint8_t pk_bak[crypto_box_PUBLICKEYBYTES];
    IP_Port ip_port_bak;
    uint64_t timestamp_bak;

    unsigned int i, length = DHT_BUCKET_NODES;

    for (i = 0; i < length; ++i) {
        if (id_closest(node_public_key, client->ret[i].pk, public_key) == 2) {
            id_copy(pk_bak, client->ret[i].pk);
            ip_port_bak = client->ret[i].ip_port;
            timestamp_bak = client->ret[i].timestamp;
            id_copy(client->ret[i].pk, public_key);
            client->ret[i].ip_port = ret_ip_port;
            client->ret[i].timestamp = timestamp;

            if (i != (length - 1))
                add_to_ret_ip_list(client, node_public_key, pk_bak, ip_port_bak, timestamp_bak);

            return 1;
        }
    }

    return 0;
}

static int recursive_DHT_bucket_set_node_ret_ip_port(DHT_Bucket *bucket, const uint8_t *node_public_key,
        const uint8_t *public_key, IP_Port ret_ip_port)
{
    int bit = get_bit_at(node_public_key, bucket->deepness);

    if (bit == -1)
        return -1;

    if (bucket->empty) {
        return recursive_DHT_bucket_set_node_ret_ip_port(bucket->buckets[bit], node_public_key, public_key, ret_ip_port);
    } else {
        unsigned int i, j;

        for (i = 0; (i < DHT_BUCKET_NODES); ++i) {
            Client_data *client = &bucket->client_list[i];

            if (!is_timeout(client->timestamp, BAD_NODE_TIMEOUT)) {
                if (id_equal(client->public_key, node_public_key)) {
                    uint64_t smallest_timestamp = ~0;
                    unsigned int index_dht = DHT_BUCKET_NODES;

                    for (j = 0; j < DHT_BUCKET_NODES; ++j) {
                        if (id_equal(public_key, client->ret[j].pk)) {
                            client->ret[j].ip_port = ret_ip_port;
                            client->ret[j].timestamp = unix_time();
                            return 0;
                        }

                        if (smallest_timestamp > client->ret[j].timestamp) {
                            index_dht = j;
                            smallest_timestamp = client->ret[j].timestamp;
                        }
                    }

                    if (index_dht < DHT_BUCKET_NODES && is_timeout(smallest_timestamp, BAD_NODE_TIMEOUT * 2)) {
                        id_copy(client->ret[index_dht].pk, public_key);
                        client->ret[index_dht].ip_port = ret_ip_port;
                        client->ret[index_dht].timestamp = unix_time();
                    } else {
                        if (add_to_ret_ip_list(client, node_public_key, public_key, ret_ip_port, unix_time()))
                            return 0;

                        return -1;
                    }

                    return 0;
                }
            }
        }
    }

    return -1;
}

static int DHT_bucket_set_node_ret_ip_port(DHT_Bucket *bucket, const uint8_t *node_public_key,
        const uint8_t *public_key, IP_Port ret_ip_port)
{
    return recursive_DHT_bucket_set_node_ret_ip_port(bucket, node_public_key, public_key, ret_ip_port);
}

static int recursive_DHT_bucket_get_nodes(const DHT_Bucket *bucket, Client_data *nodes, unsigned int number,
        const uint8_t *public_key)
{
    int bit = get_bit_at(public_key, bucket->deepness);

    if (bit == -1)
        return -1;

    if (bucket->empty) {
        int ret = recursive_DHT_bucket_get_nodes(bucket->buckets[bit], nodes, number, public_key);

        if (ret < 0)
            return -1;

        if (ret < number) {
            number -= ret;
            int ret1 = recursive_DHT_bucket_get_nodes(bucket->buckets[!bit], nodes, number, public_key);

            if (ret < 0)
                return -1;

            return ret1 + ret;
        } else {
            return ret;
        }
    } else {
        unsigned int i, counter = 0;

        for (i = 0; (i < DHT_BUCKET_NODES) && (counter < number); ++i) {
            if (!is_timeout(bucket->client_list[i].timestamp, BAD_NODE_TIMEOUT)) {
                memcpy(&nodes[number - (counter + 1)], &bucket->client_list[i], sizeof(Client_data));
                ++counter;
            }
        }

        return counter;
    }
}


int DHT_bucket_get_nodes(const DHT_Bucket *bucket, Client_data *nodes, unsigned int number, const uint8_t *public_key)
{
    return recursive_DHT_bucket_get_nodes(bucket, nodes, number, public_key);
}

static int dealloc_buckets(DHT_Bucket *bucket)
{
    if (!bucket->empty)
        return -1;

    if (bucket->buckets[0]->public_key || bucket->buckets[1]->public_key)
        return -1;

    if (bucket->buckets[0]->empty || bucket->buckets[1]->empty)
        return -1;

    /* pk doesn't matter, want any nodes from both lower buckets. */
    uint8_t pk[crypto_box_PUBLICKEYBYTES] = {0};
    int ret = recursive_DHT_bucket_get_nodes(bucket, bucket->client_list, DHT_BUCKET_NODES, pk);

    recursive_free_buckets(bucket);
    bucket->empty = 0;

    if (ret >= 0) {
        return 0;
    } else {
        return -1;
    }
}


static int recursive_DHT_bucket_rm_key(DHT_Bucket *bucket, const uint8_t *public_key)
{
    int bit = get_bit_at(public_key, bucket->deepness);

    if (bit == -1)
        return -1;

    if (bucket->empty) {
        int ret = recursive_DHT_bucket_rm_key(bucket->buckets[bit], public_key);

        if (ret == 0) {
            if (dealloc_buckets(bucket) == -1) {
                return -1;
            }

            return 0;
        }
    }

    if (bucket->public_key) {
        if (!id_equal(bucket->searched_public_key, public_key))
            return -1;

        bucket->public_key = 0;
        return 0;
    } else {
        return -1;
    }
}


int DHT_bucket_rm_key(DHT_Bucket *bucket, const uint8_t *public_key)
{
    return recursive_DHT_bucket_rm_key(bucket, public_key);
}

static int getnodes(DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                    const Node_format *sendback_node);

static int recursive_do_ping_nodes(DHT *dht, DHT_Bucket *bucket, uint8_t *key)
{
    if (bucket->empty) {
        if (recursive_do_ping_nodes(dht, bucket->buckets[0], key) == -1)
            return -1;

        set_bit_at(key, bucket->deepness);

        if (recursive_do_ping_nodes(dht, bucket->buckets[1], key) == -1)
            return -1;

        unset_bit_at(key, bucket->deepness);
        return 0;
    } else {
        uint8_t *search_key = key;

        if (bucket->public_key) {
            search_key = bucket->searched_public_key;
        }

        unsigned int i;

        for (i = 0; i < DHT_BUCKET_NODES; ++i) {
            Client_data *client = &bucket->client_list[i];

            if (!is_timeout(client->timestamp, BAD_NODE_TIMEOUT)) {
                if (is_timeout(client->last_pinged, PING_INTERVAL)) {
                    getnodes(dht, client->ip_port, client->public_key, search_key, NULL);
                    client->last_pinged = unix_time();
                }
            }
        }

        return 0;
    }
}

static int do_ping_nodes(DHT *dht, DHT_Bucket *bucket)
{
    uint8_t key[crypto_box_PUBLICKEYBYTES];
    memset(key, 0, sizeof(key));

    return recursive_do_ping_nodes(dht, bucket, key);
}

/* TODO: count ips */



/* Check if client with public_key is already in node format list of length length.
 *
 *  return 1 if true.
 *  return 0 if false.
 */
static int client_in_nodelist(const Node_format *list, uint16_t length, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < length; ++i) {
        if (id_equal(list[i].public_key, public_key))
            return 1;
    }

    return 0;
}

/*  return friend number from the public_key.
 *  return -1 if a failure occurs.
 */
static int friend_number(const DHT *dht, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < dht->num_friends; ++i) {
        if (id_equal(dht->friends_list[i].public_key, public_key))
            return i;
    }

    return -1;
}

/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
_Bool add_to_list(Node_format *nodes_list, unsigned int length, const uint8_t *pk, IP_Port ip_port,
                  const uint8_t *cmp_pk)
{
    uint8_t pk_bak[crypto_box_PUBLICKEYBYTES];
    IP_Port ip_port_bak;

    unsigned int i;

    for (i = 0; i < length; ++i) {
        if (id_closest(cmp_pk, nodes_list[i].public_key, pk) == 2) {
            memcpy(pk_bak, nodes_list[i].public_key, crypto_box_PUBLICKEYBYTES);
            ip_port_bak = nodes_list[i].ip_port;
            memcpy(nodes_list[i].public_key, pk, crypto_box_PUBLICKEYBYTES);
            nodes_list[i].ip_port = ip_port;

            if (i != (length - 1))
                add_to_list(nodes_list, length, pk_bak, ip_port_bak, cmp_pk);

            return 1;
        }
    }

    return 0;
}


int get_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list, sa_family_t sa_family,
                    uint8_t is_LAN, uint8_t want_good)
{
    memset(nodes_list, 0, MAX_SENT_NODES * sizeof(Node_format));
    Client_data client_data[DHT_BUCKET_NODES * 3] = {0};

    if (sa_family == AF_INET) {
        DHT_bucket_get_nodes(&dht->bucket_v4, client_data, DHT_BUCKET_NODES, public_key);
    } else if (sa_family == AF_INET6) {
        DHT_bucket_get_nodes(&dht->bucket_v6, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    } else {
        if (rand() % 2) {
            DHT_bucket_get_nodes(&dht->bucket_v4, client_data, DHT_BUCKET_NODES, public_key);
            DHT_bucket_get_nodes(&dht->bucket_v6, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
        } else {
            DHT_bucket_get_nodes(&dht->bucket_v6, client_data, DHT_BUCKET_NODES, public_key);
            DHT_bucket_get_nodes(&dht->bucket_v4, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
        }
    }

    if (is_LAN) {
        DHT_bucket_get_nodes(&dht->bucket_lan, client_data + (DHT_BUCKET_NODES * 2), DHT_BUCKET_NODES, public_key);
    }

    unsigned int i, num_nodes = 0;

    for (i = DHT_BUCKET_NODES * 3; i != 0; --i) {
        unsigned int index = i - 1;

        if (client_data[index].timestamp == 0 || client_in_nodelist(nodes_list, MAX_SENT_NODES, client_data[index].public_key))
            continue;

        if (num_nodes < MAX_SENT_NODES) {
            id_copy(nodes_list[num_nodes].public_key, client_data[index].public_key);
            nodes_list[num_nodes].ip_port = client_data[index].ip_port;
            num_nodes++;
        } else {
            add_to_list(nodes_list, MAX_SENT_NODES, client_data[index].public_key, client_data[index].ip_port, public_key);
        }
    }

    return num_nodes;
}

static DHT_Bucket *ip_bucket(DHT *dht, IP_Port ip_port)
{
    if (LAN_ip(ip_port.ip) == 0) {
        return &dht->bucket_lan;
    } else if (ip_port.ip.family == AF_INET) {
        return &dht->bucket_v4;
    } else if (ip_port.ip.family == AF_INET6) {
        return &dht->bucket_v6;
    }

    return 0;
}

/* Add node to close list.
 *
 * simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *
 * return 0 on failure.
 * return 1 on success.
 */
static _Bool add_to_close(DHT *dht, const uint8_t *public_key, IP_Port ip_port, _Bool simulate)
{
    DHT_Bucket *bucket = ip_bucket(dht, ip_port);

    if (bucket)
        return (DHT_bucket_add_node(bucket, public_key, ip_port, simulate) == 0);

    return 0;
}

/* Return 1 if node can be added to close list, 0 if it can't.
 */
_Bool node_addable_to_close_list(DHT *dht, const uint8_t *public_key, IP_Port ip_port)
{
    return add_to_close(dht, public_key, ip_port, 1);
}

/* Check if the node obtained with a get_nodes with public_key should be pinged.
 * NOTE: for best results call it after addto_lists;
 *
 * return 0 if the node should not be pinged.
 * return 1 if it should.
 */
static unsigned int ping_node_from_getnodes_ok(DHT *dht, const uint8_t *public_key, IP_Port ip_port)
{
    if (add_to_close(dht, public_key, ip_port, 1)) {
        //TODO: make less wasteful.
        if (client_in_nodelist(dht->to_bootstrap, dht->num_to_bootstrap, public_key)) {
            if (dht->num_to_bootstrap < MAX_CLOSE_TO_BOOTSTRAP_NODES) {
                memcpy(dht->to_bootstrap[dht->num_to_bootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
                dht->to_bootstrap[dht->num_to_bootstrap].ip_port = ip_port;
                ++dht->num_to_bootstrap;
            } else {
                //TODO: ipv6 vs v4
                add_to_list(dht->to_bootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES, public_key, ip_port, dht->self_public_key);
            }
        }

        unsigned int i;

        for (i = 0; i < dht->num_friends; ++i) {
            DHT_Friend *friend = &dht->friends_list[i];

            if (!client_in_nodelist(friend->to_bootstrap, friend->num_to_bootstrap, public_key)) {
                if (friend->num_to_bootstrap < MAX_SENT_NODES) {
                    memcpy(friend->to_bootstrap[friend->num_to_bootstrap].public_key, public_key, crypto_box_PUBLICKEYBYTES);
                    friend->to_bootstrap[friend->num_to_bootstrap].ip_port = ip_port;
                    ++friend->num_to_bootstrap;
                } else {
                    add_to_list(friend->to_bootstrap, MAX_SENT_NODES, public_key, ip_port, friend->public_key);
                }
            }
        }

        return 1;
    }

    return 0;
}

/* Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.
 *
 *  returns 1+ if the item is used in any list, 0 else
 */
int addto_lists(DHT *dht, IP_Port ip_port, const uint8_t *public_key)
{
    unsigned int used = 0;

    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip6)) {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */

    if (add_to_close(dht, public_key, ip_port, 0))
        used++;

    int friend_num = friend_number(dht, public_key);

    if (friend_num != -1) {
        DHT_Friend *friend_foundip = &dht->friends_list[friend_num];

        unsigned int j;

        for (j = 0; j < friend_foundip->lock_count; ++j) {
            if (friend_foundip->callbacks[j].ip_callback)
                friend_foundip->callbacks[j].ip_callback(friend_foundip->callbacks[j].data, friend_foundip->callbacks[j].number,
                        ip_port);
        }
    }

    return used;
}

/* If public_key is a friend or us, update ret_ip_port
 * nodepublic_key is the id of the node that sent us this info.
 */
static int returnedip_ports(DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *node_public_key)
{
    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip6)) {
        ip_port.ip.family = AF_INET;
        ip_port.ip.ip4.uint32 = ip_port.ip.ip6.uint32[3];
    }

    /* Only set ret ips for known nodes. */
    if (id_equal(public_key, dht->self_public_key) || friend_number(dht, public_key) != -1) {
        DHT_Bucket *bucket = ip_bucket(dht, ip_port);

        if (bucket)
            return DHT_bucket_set_node_ret_ip_port(bucket, node_public_key, public_key, ip_port);
    }

    return -1;
}

/* Send a getnodes request.
   sendback_node is the node that it will send back the response to (set to NULL to disable this) */
static int getnodes(DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                    const Node_format *sendback_node)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->self_public_key))
        return -1;

    uint8_t plain_message[sizeof(Node_format) * 2] = {0};

    Node_format receiver;
    memcpy(receiver.public_key, public_key, crypto_box_PUBLICKEYBYTES);
    receiver.ip_port = ip_port;
    memcpy(plain_message, &receiver, sizeof(receiver));

    uint64_t ping_id = 0;

    if (sendback_node != NULL) {
        memcpy(plain_message + sizeof(receiver), sendback_node, sizeof(Node_format));
        ping_id = ping_array_add(&dht->dht_harden_ping_array, plain_message, sizeof(plain_message));
    } else {
        ping_id = ping_array_add(&dht->dht_ping_array, plain_message, sizeof(receiver));
    }

    if (ping_id == 0)
        return -1;

    uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof(ping_id)];
    uint8_t encrypt[sizeof(plain) + crypto_box_MACBYTES];
    uint8_t data[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + sizeof(encrypt)];

    memcpy(plain, client_id, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + crypto_box_PUBLICKEYBYTES, &ping_id, sizeof(ping_id));

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, public_key);

    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    int len = encrypt_data_symmetric( shared_key,
                                      nonce,
                                      plain,
                                      sizeof(plain),
                                      encrypt );

    if (len != sizeof(encrypt))
        return -1;

    data[0] = NET_PACKET_GET_NODES;
    memcpy(data + 1, dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->net, ip_port, data, sizeof(data));
}

/* Send a send nodes response: message for IPv6 nodes */
static int sendnodes_ipv6(const DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                          const uint8_t *sendback_data, uint16_t length, const uint8_t *shared_encryption_key)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->self_public_key))
        return -1;

    if (length != sizeof(uint64_t))
        return -1;

    size_t Node_format_size = sizeof(Node_format);
    uint8_t data[1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES
                 + Node_format_size * MAX_SENT_NODES + length + crypto_box_MACBYTES];

    Node_format nodes_list[MAX_SENT_NODES];
    uint32_t num_nodes = get_close_nodes(dht, client_id, nodes_list, 0, LAN_ip(ip_port.ip) == 0, 1);

    uint8_t plain[1 + Node_format_size * MAX_SENT_NODES + length];
    uint8_t encrypt[sizeof(plain) + crypto_box_MACBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);

    int nodes_length = 0;

    if (num_nodes) {
        nodes_length = pack_nodes(plain + 1, Node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);

        if (nodes_length <= 0)
            return -1;
    }

    plain[0] = num_nodes;
    memcpy(plain + 1 + nodes_length, sendback_data, length);
    int len = encrypt_data_symmetric( shared_encryption_key,
                                      nonce,
                                      plain,
                                      1 + nodes_length + length,
                                      encrypt );

    if (len != 1 + nodes_length + length + crypto_box_MACBYTES)
        return -1;

    data[0] = NET_PACKET_SEND_NODES_IPV6;
    memcpy(data + 1, dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    memcpy(data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, encrypt, len);

    return sendpacket(dht->net, ip_port, data, 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + len);
}

static int handle_getnodes(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    if (length != (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + sizeof(
                       uint64_t) + crypto_box_MACBYTES))
        return 1;

    DHT *dht = object;

    /* Check if packet is from ourself. */
    if (id_equal(packet + 1, dht->self_public_key))
        return 1;

    uint8_t plain[crypto_box_PUBLICKEYBYTES + sizeof(uint64_t)];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    DHT_get_shared_key_recv(dht, shared_key, packet + 1);
    int len = decrypt_data_symmetric( shared_key,
                                      packet + 1 + crypto_box_PUBLICKEYBYTES,
                                      packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                                      crypto_box_PUBLICKEYBYTES + sizeof(uint64_t) + crypto_box_MACBYTES,
                                      plain );

    if (len != crypto_box_PUBLICKEYBYTES + sizeof(uint64_t))
        return 1;

    sendnodes_ipv6(dht, source, packet + 1, plain, plain + crypto_box_PUBLICKEYBYTES, sizeof(uint64_t), shared_key);

    add_to_ping(dht->ping, packet + 1, source);

    return 0;
}
/* return 0 if no
   return 1 if yes */
static uint8_t sent_getnode_to_node(DHT *dht, const uint8_t *public_key, IP_Port node_ip_port, uint64_t ping_id,
                                    Node_format *sendback_node)
{
    uint8_t data[sizeof(Node_format) * 2];

    if (ping_array_check(data, sizeof(data), &dht->dht_ping_array, ping_id) == sizeof(Node_format)) {
        memset(sendback_node, 0, sizeof(Node_format));
    } else if (ping_array_check(data, sizeof(data), &dht->dht_harden_ping_array, ping_id) == sizeof(data)) {
        memcpy(sendback_node, data + sizeof(Node_format), sizeof(Node_format));
    } else {
        return 0;
    }

    Node_format test;
    memcpy(&test, data, sizeof(Node_format));

    if (!ipport_equal(&test.ip_port, &node_ip_port) || public_key_cmp(test.public_key, public_key) != 0)
        return 0;

    return 1;
}

static int handle_sendnodes_core(void *object, IP_Port source, const uint8_t *packet, uint16_t length,
                                 Node_format *plain_nodes, uint16_t size_plain_nodes, uint32_t *num_nodes_out)
{
    DHT *dht = object;
    uint32_t cid_size = 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + 1 + sizeof(uint64_t) + crypto_box_MACBYTES;

    if (length < cid_size) /* too short */
        return 1;

    uint32_t data_size = length - cid_size;

    if (data_size == 0)
        return 1;

    if (data_size > sizeof(Node_format) * MAX_SENT_NODES) /* invalid length */
        return 1;

    uint8_t plain[1 + data_size + sizeof(uint64_t)];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    DHT_get_shared_key_sent(dht, shared_key, packet + 1);
    int len = decrypt_data_symmetric(
                  shared_key,
                  packet + 1 + crypto_box_PUBLICKEYBYTES,
                  packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                  1 + data_size + sizeof(uint64_t) + crypto_box_MACBYTES,
                  plain);

    if ((unsigned int)len != sizeof(plain))
        return 1;

    if (plain[0] > size_plain_nodes)
        return 1;

    Node_format sendback_node;

    uint64_t ping_id;
    memcpy(&ping_id, plain + 1 + data_size, sizeof(ping_id));

    if (!sent_getnode_to_node(dht, packet + 1, source, ping_id, &sendback_node))
        return 1;

    uint16_t length_nodes = 0;
    int num_nodes = unpack_nodes(plain_nodes, plain[0], &length_nodes, plain + 1, data_size, 0);

    if (length_nodes != data_size)
        return 1;

    if (num_nodes != plain[0])
        return 1;

    if (num_nodes < 0)
        return 1;

    /* store the address the *request* was sent to */
    addto_lists(dht, source, packet + 1);

    *num_nodes_out = num_nodes;

    return 0;
}

static int handle_sendnodes_ipv6(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT *dht = object;
    Node_format plain_nodes[MAX_SENT_NODES];
    uint32_t num_nodes;

    if (handle_sendnodes_core(object, source, packet, length, plain_nodes, MAX_SENT_NODES, &num_nodes))
        return 1;

    if (num_nodes == 0)
        return 0;

    uint32_t i;

    for (i = 0; i < num_nodes; i++) {

        if (ipport_isset(&plain_nodes[i].ip_port)) {
            ping_node_from_getnodes_ok(dht, plain_nodes[i].public_key, plain_nodes[i].ip_port);
            returnedip_ports(dht, plain_nodes[i].ip_port, plain_nodes[i].public_key, packet + 1);
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

static int DHT_add_key_all_buckets(DHT *dht, const uint8_t *public_key)
{
    if (DHT_bucket_add_key(&dht->bucket_lan, public_key) == -1)
        return -1;

    if (DHT_bucket_add_key(&dht->bucket_v4, public_key) == -1)
        return -1;

    if (DHT_bucket_add_key(&dht->bucket_v6, public_key) == -1)
        return -1;

    return 0;
}

static int DHT_rm_key_all_buckets(DHT *dht, const uint8_t *public_key)
{
    if (DHT_bucket_rm_key(&dht->bucket_lan, public_key) == -1)
        return -1;

    if (DHT_bucket_rm_key(&dht->bucket_v4, public_key) == -1)
        return -1;

    if (DHT_bucket_rm_key(&dht->bucket_v6, public_key) == -1)
        return -1;

    return 0;
}

int DHT_addfriend(DHT *dht, const uint8_t *public_key, void (*ip_callback)(void *data, int32_t number, IP_Port),
                  void *data, int32_t number, uint16_t *lock_count)
{
    int friend_num = friend_number(dht, public_key);

    uint16_t lock_num;

    if (friend_num != -1) { /* Is friend already in DHT? */
        DHT_Friend *friend = &dht->friends_list[friend_num];

        if (friend->lock_count == DHT_FRIEND_MAX_LOCKS)
            return -1;

        lock_num = friend->lock_count;
        ++friend->lock_count;
        friend->callbacks[lock_num].ip_callback = ip_callback;
        friend->callbacks[lock_num].data = data;
        friend->callbacks[lock_num].number = number;

        if (lock_count)
            *lock_count = lock_num + 1;

        return 0;
    }

    DHT_Friend *temp;
    temp = realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends + 1));

    if (temp == NULL)
        return -1;

    dht->friends_list = temp;
    DHT_Friend *friend = &dht->friends_list[dht->num_friends];
    memset(friend, 0, sizeof(DHT_Friend));
    memcpy(friend->public_key, public_key, crypto_box_PUBLICKEYBYTES);

    friend->NATping_id = random_64b();

    if (DHT_add_key_all_buckets(dht, public_key) == -1)
        return -1;

    ++dht->num_friends;

    lock_num = friend->lock_count;
    ++friend->lock_count;
    friend->callbacks[lock_num].ip_callback = ip_callback;
    friend->callbacks[lock_num].data = data;
    friend->callbacks[lock_num].number = number;

    if (lock_count)
        *lock_count = lock_num + 1;

    friend->num_to_bootstrap = get_close_nodes(dht, friend->public_key, friend->to_bootstrap, 0, 1, 0);

    return 0;
}

int DHT_delfriend(DHT *dht, const uint8_t *public_key, uint16_t lock_count)
{
    int friend_num = friend_number(dht, public_key);

    if (friend_num == -1) {
        return -1;
    }

    DHT_Friend *friend = &dht->friends_list[friend_num];
    --friend->lock_count;

    if (friend->lock_count && lock_count) { /* DHT friend is still in use.*/
        --lock_count;
        friend->callbacks[lock_count].ip_callback = NULL;
        friend->callbacks[lock_count].data = NULL;
        friend->callbacks[lock_count].number = 0;
        return 0;
    }

    DHT_Friend *temp;

    DHT_rm_key_all_buckets(dht, friend->public_key);
    --dht->num_friends;

    if (dht->num_friends != friend_num) {
        memcpy( &dht->friends_list[friend_num],
                &dht->friends_list[dht->num_friends],
                sizeof(DHT_Friend) );
    }

    if (dht->num_friends == 0) {
        free(dht->friends_list);
        dht->friends_list = NULL;
        return 0;
    }

    temp = realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends));

    if (temp == NULL)
        return -1;

    dht->friends_list = temp;
    return 0;
}

int DHT_getfriendip(const DHT *dht, const uint8_t *public_key, IP_Port *ip_port)
{
    Client_data client_data[DHT_BUCKET_NODES * 3] = {0};

    if (friend_number(dht, public_key) == -1)
        return -1;

    if (rand() % 2) {
        DHT_bucket_get_nodes(&dht->bucket_v4, client_data, DHT_BUCKET_NODES, public_key);
        DHT_bucket_get_nodes(&dht->bucket_v6, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    } else {
        DHT_bucket_get_nodes(&dht->bucket_v6, client_data, DHT_BUCKET_NODES, public_key);
        DHT_bucket_get_nodes(&dht->bucket_v4, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    }

    DHT_bucket_get_nodes(&dht->bucket_lan, client_data + (DHT_BUCKET_NODES * 2), DHT_BUCKET_NODES, public_key);

    unsigned int i;

    for (i = DHT_BUCKET_NODES * 3; i != 0; --i) {
        unsigned int index = i - 1;

        if (client_data[index].timestamp != 0 && id_equal(client_data[index].public_key, public_key)) {
            *ip_port = client_data[index].ip_port;
            return 1;
        }
    }

    return 0;
}

void DHT_getnodes(DHT *dht, const IP_Port *from_ipp, const uint8_t *from_id, const uint8_t *which_id)
{
    getnodes(dht, *from_ipp, from_id, which_id, NULL);
}

void DHT_bootstrap(DHT *dht, IP_Port ip_port, const uint8_t *public_key)
{
    getnodes(dht, ip_port, public_key, dht->self_public_key, NULL);
}

int DHT_bootstrap_from_address(DHT *dht, const char *address, uint8_t ipv6enabled,
                               uint16_t port, const uint8_t *public_key)
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

/* Send the given packet to node with public_key
 *
 *  return -1 if failure.
 */
int route_packet(const DHT *dht, const uint8_t *public_key, const uint8_t *packet, uint16_t length)
{
    Client_data client_data[DHT_BUCKET_NODES * 3] = {0};

    if (friend_number(dht, public_key) == -1)
        return -1;

    DHT_bucket_get_nodes(&dht->bucket_v4, client_data, DHT_BUCKET_NODES, public_key);
    DHT_bucket_get_nodes(&dht->bucket_v6, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    DHT_bucket_get_nodes(&dht->bucket_lan, client_data + (DHT_BUCKET_NODES * 2), DHT_BUCKET_NODES, public_key);

    unsigned int i;

    for (i = DHT_BUCKET_NODES * 3; i != 0; --i) {
        unsigned int index = i - 1;

        if (client_data[index].timestamp != 0 && id_equal(client_data[index].public_key, public_key)) {
            return sendpacket(dht->net, client_data[index].ip_port, packet, length);
        }
    }

    return -1;
}

static _Bool get_ret_ip_port(Client_data *client, const uint8_t *public_key, IP_Port *ip_port)
{
    unsigned int i;

    for (i = 0; i < DHT_BUCKET_NODES; ++i) {
        if (client->ret[i].timestamp != 0 && !is_timeout(client->ret[i].timestamp, BAD_NODE_TIMEOUT * 2)
                && id_equal(client->ret[i].pk, public_key)) {
            *ip_port = client->ret[i].ip_port;
            return 1;
        }
    }

    return 0;
}

/* Puts all the different ips returned by the nodes for a friend_num into array ip_portlist.
 * ip_portlist must be at least (DHT_BUCKET_NODES * 2) big.
 *
 *  return the number of ips returned.
 *  return 0 if we are connected to friend or if no ips were found.
 *  return -1 if no such friend.
 */
static int friend_iplist(const DHT *dht, IP_Port *ip_portlist, uint16_t friend_num, _Bool v6)
{
    if (friend_num >= dht->num_friends)
        return -1;

    DHT_Friend *friend = &dht->friends_list[friend_num];

    Client_data client_data[(DHT_BUCKET_NODES * 2)] = {0};

    const DHT_Bucket *bucket;

    if (v6) {
        bucket = &dht->bucket_v6;
    } else {
        bucket = &dht->bucket_v4;
    }

    DHT_bucket_get_nodes(bucket, client_data, (DHT_BUCKET_NODES * 2), friend->public_key);

    unsigned int i, count = 0;
    IP_Port ip_ports[(DHT_BUCKET_NODES * 2)];

    for (i = (DHT_BUCKET_NODES * 2); i != 0; --i) {
        unsigned int index = i - 1;

        if (client_data[index].timestamp != 0) {
            if (id_equal(client_data[index].public_key, friend->public_key))
                return 0;

            if (get_ret_ip_port(&client_data[index], friend->public_key, &ip_ports[count]))
                ++count;
        }
    }

    memcpy(ip_portlist, ip_ports, sizeof(IP_Port) * count);
    return count;
}


/* Send the following packet to X nodes who tells us they are connected to friend_pk.
 *
 *  return number of nodes the packet was sent to.
 */
int route_tofriend(const DHT *dht, const uint8_t *friend_pk, const uint8_t *packet, uint16_t length,
                   unsigned int num_to_send)
{
    Client_data client_data[(DHT_BUCKET_NODES * 2) * 3] = {0};

    if (num_to_send >= (DHT_BUCKET_NODES * 2))
        return 0;

    if (friend_number(dht, friend_pk) == -1)
        return 0;

    DHT_bucket_get_nodes(&dht->bucket_v4, client_data, (DHT_BUCKET_NODES * 2), friend_pk);
    DHT_bucket_get_nodes(&dht->bucket_v6, client_data + (DHT_BUCKET_NODES * 2), (DHT_BUCKET_NODES * 2), friend_pk);
    DHT_bucket_get_nodes(&dht->bucket_lan, client_data + ((DHT_BUCKET_NODES * 2) * 2), (DHT_BUCKET_NODES * 2), friend_pk);

    unsigned int i, count = 0, r = rand();

    IP_Port ip_ports[num_to_send];

    for (i = (DHT_BUCKET_NODES * 2) * 3; i != 0; --i) {
        unsigned int index = (i + r) % ((DHT_BUCKET_NODES * 2) * 3);

        if (count == num_to_send)
            break;

        if (client_data[index].timestamp != 0) {
            if (get_ret_ip_port(&client_data[index], friend_pk, &ip_ports[count]))
                ++count;
        }
    }

    if (count != num_to_send)
        return 0;

    unsigned int sent = 0;

    for (i = 0; i < count; ++i) {
        int retval = sendpacket(dht->net, ip_ports[i], packet, length);

        if ((unsigned int)retval == length) {
            ++sent;
        }
    }

    return sent;
}

/*----------------------------------------------------------------------------------*/
/*---------------------BEGINNING OF NAT PUNCHING FUNCTIONS--------------------------*/

static int send_NATping(DHT *dht, const uint8_t *public_key, uint64_t ping_id, uint8_t type)
{
    uint8_t data[sizeof(uint64_t) + 1];
    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];

    int num = 0;

    data[0] = type;
    memcpy(data + 1, &ping_id, sizeof(uint64_t));
    /* 254 is NAT ping request packet id */
    int len = create_request(dht->self_public_key, dht->self_secret_key, packet, public_key, data,
                             sizeof(uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

    if (len == -1)
        return -1;

    if (type == NAT_PING_REQUEST) /* If packet is request use many people to route it. */
        num = route_tofriend(dht, public_key, packet, len, DHT_BUCKET_NODES / 2);
    else if (type == NAT_PING_RESPONSE) /* If packet is response use only one person to route it */
        num = route_tofriend(dht, public_key, packet, len, 1);

    if (num == 0)
        return -1;

    return num;
}

/* Handle a received ping request for. */
static int handle_NATping(void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                          uint16_t length)
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
            friend->NATping_id = random_64b();
            friend->nat_v4.hole_punching = 1;
            friend->nat_v6.hole_punching = 1;
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

static void punch_holes(DHT *dht, IP ip, uint16_t *port_list, uint16_t numports, uint16_t friendnumber, _Bool v6)
{
    if (numports > MAX_FRIEND_CLIENTS || numports == 0)
        return;

    DHT_Friend *friend = &dht->friends_list[friendnumber];

    NAT *nat;

    if (v6) {
        nat = &friend->nat_v6;
    } else {
        nat = &friend->nat_v4;
    }

    unsigned int i;
    unsigned int top = nat->punching_index + MAX_PUNCHING_PORTS;
    uint16_t firstport = port_list[0];

    for (i = 0; i < numports; ++i) {
        if (firstport != port_list[i])
            break;
    }

    if (i == numports) { /* If all ports are the same, only try that one port. */
        IP_Port pinging;
        ip_copy(&pinging.ip, &ip);
        pinging.port = htons(firstport);
        send_ping_request(dht->ping, pinging, friend->public_key);
    } else {
        for (i = nat->punching_index; i != top; ++i) {
            /* TODO: Improve port guessing algorithm. */
            uint16_t port = port_list[(i / 2) % numports] + (i / (2 * numports)) * ((i % 2) ? -1 : 1);
            IP_Port pinging;
            ip_copy(&pinging.ip, &ip);
            pinging.port = htons(port);
            send_ping_request(dht->ping, pinging, friend->public_key);
        }

        nat->punching_index = i;
    }

    if (nat->tries > MAX_NORMAL_PUNCHING_TRIES) {
        top = nat->punching_index2 + MAX_PUNCHING_PORTS;
        uint16_t port = 1024;
        IP_Port pinging;
        ip_copy(&pinging.ip, &ip);

        for (i = nat->punching_index2; i != top; ++i) {
            pinging.port = htons(port + i);
            send_ping_request(dht->ping, pinging, friend->public_key);
        }

        nat->punching_index2 = i - (MAX_PUNCHING_PORTS / 2);
    }

    ++nat->tries;
}

static void do_NAT(DHT *dht, _Bool v6)
{

    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < dht->num_friends; ++i) {
        IP_Port ip_list[DHT_BUCKET_NODES * 2];
        int num = friend_iplist(dht, ip_list, i, v6);

        /* If already connected or friend is not online don't try to hole punch. */
        if (num < MAX_FRIEND_CLIENTS / 2)
            continue;

        DHT_Friend *friend = &dht->friends_list[i];

        NAT *nat;

        if (v6) {
            nat = &friend->nat_v6;
        } else {
            nat = &friend->nat_v4;
        }

        if (friend->NATping_timestamp + PUNCH_INTERVAL < temp_time) {
            send_NATping(dht, friend->public_key, friend->NATping_id, NAT_PING_REQUEST);
            friend->NATping_timestamp = temp_time;
        }

        if (nat->hole_punching == 1 &&
                nat->punching_timestamp + PUNCH_INTERVAL < temp_time &&
                friend->recvNATping_timestamp + PUNCH_INTERVAL * 2 >= temp_time) {

            IP ip = NAT_commonip(ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (!ip_isset(&ip))
                continue;

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            uint16_t numports = NAT_getports(port_list, ip_list, num, ip);
            punch_holes(dht, ip, port_list, numports, i, v6);

            nat->punching_timestamp = temp_time;
            nat->hole_punching = 0;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/


/* Return a random node from all the nodes we are connected to.
 * TODO: improve this function.
 */
Node_format random_node(DHT *dht, sa_family_t sa_family)
{
    uint8_t id[crypto_box_PUBLICKEYBYTES];
    uint32_t i;

    for (i = 0; i < crypto_box_PUBLICKEYBYTES / 4; ++i) { /* populate the id with pseudorandom bytes.*/
        uint32_t t = rand();
        memcpy(id + i * sizeof(t), &t, sizeof(t));
    }

    Node_format nodes_list[MAX_SENT_NODES];
    memset(nodes_list, 0, sizeof(nodes_list));
    uint32_t num_nodes = get_close_nodes(dht, id, nodes_list, sa_family, 1, 0);

    if (num_nodes == 0)
        return nodes_list[0];
    else
        return nodes_list[rand() % num_nodes];
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
static uint16_t list_nodes(const DHT *dht, uint8_t *public_key, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0)
        return 0;

    Client_data client_data[DHT_BUCKET_NODES * 2] = {0};

    if (rand() % 2) {
        DHT_bucket_get_nodes(&dht->bucket_v4, client_data, DHT_BUCKET_NODES, public_key);
        DHT_bucket_get_nodes(&dht->bucket_v6, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    } else {
        DHT_bucket_get_nodes(&dht->bucket_v6, client_data, DHT_BUCKET_NODES, public_key);
        DHT_bucket_get_nodes(&dht->bucket_v4, client_data + DHT_BUCKET_NODES, DHT_BUCKET_NODES, public_key);
    }

    unsigned int i, num_nodes = 0, r = rand();

    for (i = DHT_BUCKET_NODES * 2; i != 0 && (num_nodes < max_num); --i) {
        unsigned int index = (i + r) % (DHT_BUCKET_NODES * 2);

        if (client_data[index].timestamp != 0) {
            id_copy(nodes[num_nodes].public_key, client_data[index].public_key);
            nodes[num_nodes].ip_port = client_data[index].ip_port;
            ++num_nodes;
        }
    }

    return num_nodes;
}

/* Put up to max_num nodes in nodes from the random friends.
 *
 * return the number of nodes.
 */
uint16_t randfriends_nodes(const DHT *dht, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0)
        return 0;

    uint16_t count = 0;
    unsigned int i, r = rand();

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        count += list_nodes(dht, dht->friends_list[(i + r) % DHT_FAKE_FRIEND_NUMBER].public_key, nodes + count,
                            max_num - count);

        if (count >= max_num)
            break;
    }

    return count;
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t closelist_nodes(DHT *dht, Node_format *nodes, uint16_t max_num)
{
    return list_nodes(dht, dht->self_public_key, nodes, max_num);
}

/*----------------------------------------------------------------------------------*/

void cryptopacket_registerhandler(DHT *dht, uint8_t byte, cryptopacket_handler_callback cb, void *object)
{
    dht->cryptopackethandlers[byte].function = cb;
    dht->cryptopackethandlers[byte].object = object;
}

static int cryptopacket_handle(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    DHT *dht = object;

    if (packet[0] == NET_PACKET_CRYPTO) {
        if (length <= crypto_box_PUBLICKEYBYTES * 2 + crypto_box_NONCEBYTES + 1 + crypto_box_MACBYTES ||
                length > MAX_CRYPTO_REQUEST_SIZE + crypto_box_MACBYTES)
            return 1;

        if (public_key_cmp(packet + 1, dht->self_public_key) == 0) { // Check if request is for us.
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
            uint8_t number;
            int len = handle_request(dht->self_public_key, dht->self_secret_key, public_key, data, &number, packet, length);

            if (len == -1 || len == 0)
                return 1;

            if (!dht->cryptopackethandlers[number].function) return 1;

            return dht->cryptopackethandlers[number].function(dht->cryptopackethandlers[number].object, source, public_key,
                    data, len);

        } else { /* If request is not for us, try routing it. */
            int retval = route_packet(dht, packet + 1, packet, length);

            if ((unsigned int)retval == length)
                return 0;
        }
    }

    return 1;
}

static void do_DHT_pings(DHT *dht)
{
    do_ping_nodes(dht, &dht->bucket_lan);
    do_ping_nodes(dht, &dht->bucket_v4);
    do_ping_nodes(dht, &dht->bucket_v6);
}


/* Do get nodes for friends.
 */
static void do_DHT_friends(DHT *dht)
{
    unsigned int i, j;

    for (i = 0; i < dht->num_friends; ++i) {
        DHT_Friend *friend = &dht->friends_list[i];

        for (j = 0; j < friend->num_to_bootstrap; ++j) {
            if (add_to_close(dht, friend->to_bootstrap[j].public_key, friend->to_bootstrap[j].ip_port, 1)) {
                getnodes(dht, friend->to_bootstrap[j].ip_port, friend->to_bootstrap[j].public_key, friend->public_key, NULL);
            }
        }

        friend->num_to_bootstrap = 0;

        if (is_timeout(friend->lastgetnode, GET_NODE_INTERVAL)) {
            Node_format node;

            if (list_nodes(dht, friend->public_key, &node, 1) == 1) {
                getnodes(dht, node.ip_port, node.public_key, dht->self_public_key, NULL);
                friend->lastgetnode = unix_time();
            }
        }
    }
}

/* Do get nodes for self.
 */
static void do_Close(DHT *dht)
{
    unsigned int i;

    for (i = 0; i < dht->num_to_bootstrap; ++i) {
        if (add_to_close(dht, dht->to_bootstrap[i].public_key, dht->to_bootstrap[i].ip_port, 1)) {
            getnodes(dht, dht->to_bootstrap[i].ip_port, dht->to_bootstrap[i].public_key, dht->self_public_key, NULL);
        }
    }

    dht->num_to_bootstrap = 0;

    Node_format node;

    if (is_timeout(dht->close_lastgetnodes, GET_NODE_INTERVAL)) {
        if (closelist_nodes(dht, &node, 1) == 1) {
            getnodes(dht, node.ip_port, node.public_key, dht->self_public_key, NULL);
            dht->close_lastgetnodes = unix_time();
        }
    }
}

/*----------------------------------------------------------------------------------*/

DHT *new_DHT(Networking_Core *net)
{
    /* init time */
    unix_time_update();

    if (net == NULL)
        return NULL;

    DHT *dht = calloc(1, sizeof(DHT));

    if (dht == NULL)
        return NULL;

    dht->net = net;
    dht->ping = new_ping(dht);

    if (dht->ping == NULL) {
        kill_DHT(dht);
        return NULL;
    }

    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, &handle_getnodes, dht);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, dht);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO, &cryptopacket_handle, dht);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, &handle_NATping, dht);

    new_symmetric_key(dht->secret_symmetric_key);
    crypto_box_keypair(dht->self_public_key, dht->self_secret_key);

    ping_array_init(&dht->dht_ping_array, DHT_PING_ARRAY_SIZE, PING_TIMEOUT);
    ping_array_init(&dht->dht_harden_ping_array, DHT_PING_ARRAY_SIZE, PING_TIMEOUT);

    if (DHT_add_key_all_buckets(dht, dht->self_public_key) == -1) {
        kill_DHT(dht);
        return NULL;
    }

    unsigned int i;

    for (i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        uint8_t random_key_bytes[crypto_box_PUBLICKEYBYTES];
        randombytes(random_key_bytes, sizeof(random_key_bytes));

        if (DHT_addfriend(dht, random_key_bytes, 0, 0, 0, 0) != 0) {
            kill_DHT(dht);
            return NULL;
        }
    }

    return dht;
}

void do_DHT(DHT *dht)
{
    unix_time_update();

    if (dht->last_run == unix_time()) {
        return;
    }

    // Load friends/clients if first call to do_DHT
    if (dht->loaded_num_nodes) {
        DHT_connect_after_load(dht);
    }

    do_DHT_pings(dht);
    do_Close(dht);
    do_DHT_friends(dht);
    do_NAT(dht, 0);
    do_NAT(dht, 1);
    do_to_ping(dht->ping);
    dht->last_run = unix_time();
}

void kill_DHT(DHT *dht)
{
    free_buckets(&dht->bucket_v4);
    free_buckets(&dht->bucket_v6);
    free_buckets(&dht->bucket_lan);
    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, NULL, NULL);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, NULL, NULL);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, NULL, NULL);
    ping_array_free_all(&dht->dht_ping_array);
    ping_array_free_all(&dht->dht_harden_ping_array);
    kill_ping(dht->ping);
    free(dht->friends_list);
    free(dht->loaded_nodes_list);
    free(dht);
}

/* new DHT format for load/save, more robust and forward compatible */
//TODO: Move this closer to Messenger.
#define DHT_STATE_COOKIE_GLOBAL 0x159000d

#define DHT_STATE_COOKIE_TYPE      0x11ce
#define DHT_STATE_TYPE_NODES       4

#define MAX_SAVED_V4_DHT_NODES (DHT_BUCKET_NODES * DHT_FAKE_FRIEND_NUMBER)
#define MAX_SAVED_V6_DHT_NODES (DHT_BUCKET_NODES * DHT_FAKE_FRIEND_NUMBER)


/* Get the size of the DHT (for saving). */
uint32_t DHT_size(const DHT *dht)
{
    uint8_t data[(packed_node_size(AF_INET) * MAX_SAVED_V4_DHT_NODES) + (packed_node_size(
                     AF_INET6) * MAX_SAVED_V6_DHT_NODES)];

    uint32_t size32 = sizeof(uint32_t), sizesubhead = size32 * 2;
    Node_format clients[MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES];
    unsigned int num = randfriends_nodes(dht, clients, MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES);

    return size32 + sizesubhead + pack_nodes(data, sizeof(Node_format) * num, clients, num);
}

static uint8_t *z_state_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(DHT_STATE_COOKIE_TYPE) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}


/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(DHT *dht, uint8_t *data)
{
    host_to_lendian32(data,  DHT_STATE_COOKIE_GLOBAL);
    data += sizeof(uint32_t);

    unsigned int num = 0;

    uint8_t *old_data = data;

    /* get right offset. we write the actual header later. */
    data = z_state_save_subheader(data, 0, 0);

    Node_format clients[MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES];

    num = randfriends_nodes(dht, clients, MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES);
    z_state_save_subheader(old_data, pack_nodes(data, sizeof(Node_format) * num, clients, num), DHT_STATE_TYPE_NODES);
}

/* Bootstrap from this number of nodes every time DHT_connect_after_load() is called */
#define SAVE_BOOTSTAP_FREQUENCY 8

/* Start sending packets after DHT loaded_friends_list and loaded_clients_list are set */
int DHT_connect_after_load(DHT *dht)
{
    if (dht == NULL)
        return -1;

    if (!dht->loaded_nodes_list)
        return -1;

    /* DHT is connected, stop. */
    if (DHT_non_lan_connected(dht)) {
        free(dht->loaded_nodes_list);
        dht->loaded_nodes_list = NULL;
        dht->loaded_num_nodes = 0;
        return 0;
    }

    unsigned int i;

    for (i = 0; i < dht->loaded_num_nodes && i < SAVE_BOOTSTAP_FREQUENCY; ++i) {
        unsigned int index = dht->loaded_nodes_index % dht->loaded_num_nodes;
        DHT_bootstrap(dht, dht->loaded_nodes_list[index].ip_port, dht->loaded_nodes_list[index].public_key);
        ++dht->loaded_nodes_index;
    }

    return 0;
}

static int dht_load_state_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    DHT *dht = outer;

    switch (type) {
        case DHT_STATE_TYPE_NODES:
            if (length == 0)
                break;

            {
                free(dht->loaded_nodes_list);
                // Copy to loaded_clients_list
                dht->loaded_nodes_list = calloc(MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES, sizeof(Node_format));

                int num = unpack_nodes(dht->loaded_nodes_list, MAX_SAVED_V4_DHT_NODES + MAX_SAVED_V6_DHT_NODES, NULL, data, length, 0);

                if (num > 0) {
                    dht->loaded_num_nodes = num;
                } else {
                    dht->loaded_num_nodes = 0;
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
int DHT_load(DHT *dht, const uint8_t *data, uint32_t length)
{
    uint32_t cookie_len = sizeof(uint32_t);

    if (length > cookie_len) {
        uint32_t data32;
        lendian_to_host32(&data32, data);

        if (data32 == DHT_STATE_COOKIE_GLOBAL)
            return load_state(dht_load_state_callback, dht, data + cookie_len,
                              length - cookie_len, DHT_STATE_COOKIE_TYPE);
    }

    return -1;
}

/*  return 0 if we are not connected or only connected to lan peers with the DHT.
 *  return 1 if we are.
 */
int DHT_non_lan_connected(const DHT *dht)
{
    Client_data cd;

    if (DHT_bucket_get_nodes(&dht->bucket_v4, &cd, 1, dht->self_public_key) == 1)
        return 1;

    if (DHT_bucket_get_nodes(&dht->bucket_v6, &cd, 1, dht->self_public_key) == 1)
        return 1;

    return 0;
}

/*  return 0 if we are not connected to the DHT.
 *  return 1 if we are.
 */
int DHT_isconnected(const DHT *dht)
{
    unix_time_update();

    if (DHT_non_lan_connected(dht))
        return 1;

    Client_data cd;

    if (DHT_bucket_get_nodes(&dht->bucket_lan, &cd, 1, dht->self_public_key) == 1)
        return 1;

    return 0;
}

