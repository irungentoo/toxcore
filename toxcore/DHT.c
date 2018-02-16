/*
 * An implementation of the DHT as seen in docs/updates/DHT.md
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "DHT.h"

#include "LAN_discovery.h"
#include "logger.h"
#include "network.h"
#include "ping.h"
#include "util.h"

#include <assert.h>

/* The timeout after which a node is discarded completely. */
#define KILL_NODE_TIMEOUT (BAD_NODE_TIMEOUT + PING_INTERVAL)

/* Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 20

#define MAX_PUNCHING_PORTS 48

/* Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 3

/* Time in seconds after which punching parameters will be reset */
#define PUNCH_RESET_TIME 40

#define MAX_NORMAL_PUNCHING_TRIES 5

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/* Number of get node requests to send to quickly find close nodes. */
#define MAX_BOOTSTRAP_TIMES 5

#define ASSOC_COUNT 2

struct DHT {
    Logger *log;
    Networking_Core *net;

    bool hole_punching_enabled;

    Client_data    close_clientlist[LCLIENT_LIST];
    uint64_t       close_lastgetnodes;
    uint32_t       close_bootstrap_times;

    /* DHT keypair */
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    DHT_Friend    *friends_list;
    uint16_t       num_friends;

    Node_format   *loaded_nodes_list;
    uint32_t       loaded_num_nodes;
    unsigned int   loaded_nodes_index;

    Shared_Keys shared_keys_recv;
    Shared_Keys shared_keys_sent;

    struct Ping   *ping;
    Ping_Array    *dht_ping_array;
    Ping_Array    *dht_harden_ping_array;
    uint64_t       last_run;

    Cryptopacket_Handles cryptopackethandlers[256];

    Node_format to_bootstrap[MAX_CLOSE_TO_BOOTSTRAP_NODES];
    unsigned int num_to_bootstrap;
};

const uint8_t *dht_get_self_public_key(const DHT *dht)
{
    return dht->self_public_key;
}
const uint8_t *dht_get_self_secret_key(const DHT *dht)
{
    return dht->self_secret_key;
}

void dht_set_self_public_key(DHT *dht, const uint8_t *key)
{
    memcpy(dht->self_public_key, key, CRYPTO_PUBLIC_KEY_SIZE);
}
void dht_set_self_secret_key(DHT *dht, const uint8_t *key)
{
    memcpy(dht->self_secret_key, key, CRYPTO_SECRET_KEY_SIZE);
}

Networking_Core *dht_get_net(const DHT *dht)
{
    return dht->net;
}
struct Ping *dht_get_ping(const DHT *dht)
{
    return dht->ping;
}
const Client_data *dht_get_close_clientlist(const DHT *dht)
{
    return dht->close_clientlist;
}
const Client_data *dht_get_close_client(const DHT *dht, uint32_t client_num)
{
    assert(client_num < sizeof(dht->close_clientlist) / sizeof(dht->close_clientlist[0]));
    return &dht->close_clientlist[client_num];
}
uint16_t dht_get_num_friends(const DHT *dht)
{
    return dht->num_friends;
}

DHT_Friend *dht_get_friend(DHT *dht, uint32_t friend_num)
{
    assert(friend_num < dht->num_friends);
    return &dht->friends_list[friend_num];
}
const uint8_t *dht_get_friend_public_key(const DHT *dht, uint32_t friend_num)
{
    assert(friend_num < dht->num_friends);
    return dht->friends_list[friend_num].public_key;
}

/* Compares pk1 and pk2 with pk.
 *
 *  return 0 if both are same distance.
 *  return 1 if pk1 is closer.
 *  return 2 if pk2 is closer.
 */
int id_closest(const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2)
{
    for (size_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        const uint8_t distance1 = pk[i] ^ pk1[i];
        const uint8_t distance2 = pk[i] ^ pk2[i];

        if (distance1 < distance2) {
            return 1;
        }

        if (distance1 > distance2) {
            return 2;
        }
    }

    return 0;
}

/* Return index of first unequal bit number.
 */
static unsigned int bit_by_bit_cmp(const uint8_t *pk1, const uint8_t *pk2)
{
    unsigned int i;
    unsigned int j = 0;

    for (i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        if (pk1[i] == pk2[i]) {
            continue;
        }

        for (j = 0; j < 8; ++j) {
            const uint8_t mask = 1 << (7 - j);

            if ((pk1[i] & mask) != (pk2[i] & mask)) {
                break;
            }
        }

        break;
    }

    return i * 8 + j;
}

/* Shared key generations are costly, it is therefor smart to store commonly used
 * ones so that they can re used later without being computed again.
 *
 * If shared key is already in shared_keys, copy it to shared_key.
 * else generate it into shared_key and copy it to shared_keys
 */
void get_shared_key(Shared_Keys *shared_keys, uint8_t *shared_key, const uint8_t *secret_key, const uint8_t *public_key)
{
    uint32_t num = ~0;
    uint32_t curr = 0;

    for (uint32_t i = 0; i < MAX_KEYS_PER_SLOT; ++i) {
        const int index = public_key[30] * MAX_KEYS_PER_SLOT + i;
        Shared_Key *const key = &shared_keys->keys[index];

        if (key->stored) {
            if (id_equal(public_key, key->public_key)) {
                memcpy(shared_key, key->shared_key, CRYPTO_SHARED_KEY_SIZE);
                ++key->times_requested;
                key->time_last_requested = unix_time();
                return;
            }

            if (num != 0) {
                if (is_timeout(key->time_last_requested, KEYS_TIMEOUT)) {
                    num = 0;
                    curr = index;
                } else if (num > key->times_requested) {
                    num = key->times_requested;
                    curr = index;
                }
            }
        } else if (num != 0) {
            num = 0;
            curr = index;
        }
    }

    encrypt_precompute(public_key, secret_key, shared_key);

    if (num != UINT32_MAX) {
        Shared_Key *const key = &shared_keys->keys[curr];
        key->stored = 1;
        key->times_requested = 1;
        memcpy(key->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(key->shared_key, shared_key, CRYPTO_SHARED_KEY_SIZE);
        key->time_last_requested = unix_time();
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

#define CRYPTO_SIZE 1 + CRYPTO_PUBLIC_KEY_SIZE * 2 + CRYPTO_NONCE_SIZE

/* Create a request to peer.
 * send_public_key and send_secret_key are the pub/secret keys of the sender.
 * recv_public_key is public key of receiver.
 * packet must be an array of MAX_CRYPTO_REQUEST_SIZE big.
 * Data represents the data we send with the request with length being the length of the data.
 * request_id is the id of the request (32 = friend request, 254 = ping request).
 *
 *  return -1 on failure.
 *  return the length of the created packet on success.
 */
int create_request(const uint8_t *send_public_key, const uint8_t *send_secret_key, uint8_t *packet,
                   const uint8_t *recv_public_key, const uint8_t *data, uint32_t length, uint8_t request_id)
{
    if (!send_public_key || !packet || !recv_public_key || !data) {
        return -1;
    }

    if (MAX_CRYPTO_REQUEST_SIZE < length + CRYPTO_SIZE + 1 + CRYPTO_MAC_SIZE) {
        return -1;
    }

    uint8_t *const nonce = packet + 1 + CRYPTO_PUBLIC_KEY_SIZE * 2;
    random_nonce(nonce);
    uint8_t temp[MAX_CRYPTO_REQUEST_SIZE];
    memcpy(temp + 1, data, length);
    temp[0] = request_id;
    const int len = encrypt_data(recv_public_key, send_secret_key, nonce, temp, length + 1,
                                 CRYPTO_SIZE + packet);

    if (len == -1) {
        crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
        return -1;
    }

    packet[0] = NET_PACKET_CRYPTO;
    memcpy(packet + 1, recv_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, send_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
    return len + CRYPTO_SIZE;
}

/* Puts the senders public key in the request in public_key, the data from the request
 * in data if a friend or ping request was sent to us and returns the length of the data.
 * packet is the request packet and length is its length.
 *
 *  return -1 if not valid request.
 */
int handle_request(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *request_id, const uint8_t *packet, uint16_t length)
{
    if (!self_public_key || !public_key || !data || !request_id || !packet) {
        return -1;
    }

    if (length <= CRYPTO_SIZE + CRYPTO_MAC_SIZE || length > MAX_CRYPTO_REQUEST_SIZE) {
        return -1;
    }

    if (!id_equal(packet + 1, self_public_key)) {
        return -1;
    }

    memcpy(public_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
    const uint8_t *const nonce = packet + 1 + CRYPTO_PUBLIC_KEY_SIZE * 2;
    uint8_t temp[MAX_CRYPTO_REQUEST_SIZE];
    int len1 = decrypt_data(public_key, self_secret_key, nonce,
                            packet + CRYPTO_SIZE, length - CRYPTO_SIZE, temp);

    if (len1 == -1 || len1 == 0) {
        crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
        return -1;
    }

    request_id[0] = temp[0];
    --len1;
    memcpy(data, temp + 1, len1);
    crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
    return len1;
}

#define PACKED_NODE_SIZE_IP4 (1 + SIZE_IP4 + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE)
#define PACKED_NODE_SIZE_IP6 (1 + SIZE_IP6 + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE)

/* Return packet size of packed node with ip_family on success.
 * Return -1 on failure.
 */
int packed_node_size(uint8_t ip_family)
{
    switch (ip_family) {
        case TOX_AF_INET:
        case TCP_INET:
            return PACKED_NODE_SIZE_IP4;

        case TOX_AF_INET6:
        case TCP_INET6:
            return PACKED_NODE_SIZE_IP6;

        default:
            return -1;
    }
}


/* Packs an IP_Port structure into data of max size length.
 *
 * Returns size of packed IP_Port data on success
 * Return -1 on failure.
 */
int pack_ip_port(uint8_t *data, uint16_t length, const IP_Port *ip_port)
{
    if (data == nullptr) {
        return -1;
    }

    bool is_ipv4;
    uint8_t net_family;

    if (ip_port->ip.family == TOX_AF_INET) {
        // TODO(irungentoo): use functions to convert endianness
        is_ipv4 = true;
        net_family = TOX_AF_INET;
    } else if (ip_port->ip.family == TCP_INET) {
        is_ipv4 = true;
        net_family = TOX_TCP_INET;
    } else if (ip_port->ip.family == TOX_AF_INET6) {
        is_ipv4 = false;
        net_family = TOX_AF_INET6;
    } else if (ip_port->ip.family == TCP_INET6) {
        is_ipv4 = false;
        net_family = TOX_TCP_INET6;
    } else {
        return -1;
    }

    if (is_ipv4) {
        const uint32_t size = 1 + SIZE_IP4 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        data[0] = net_family;
        memcpy(data + 1, &ip_port->ip.ip.v4, SIZE_IP4);
        memcpy(data + 1 + SIZE_IP4, &ip_port->port, sizeof(uint16_t));
        return size;
    } else {
        const uint32_t size = 1 + SIZE_IP6 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        data[0] = net_family;
        memcpy(data + 1, &ip_port->ip.ip.v6, SIZE_IP6);
        memcpy(data + 1 + SIZE_IP6, &ip_port->port, sizeof(uint16_t));
        return size;
    }
}

static int DHT_create_packet(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                             const uint8_t *shared_key, const uint8_t type, uint8_t *plain, size_t plain_length, uint8_t *packet)
{
    VLA(uint8_t, encrypted, plain_length + CRYPTO_MAC_SIZE);
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    random_nonce(nonce);

    const int encrypted_length = encrypt_data_symmetric(shared_key, nonce, plain, plain_length, encrypted);

    if (encrypted_length == -1) {
        return -1;
    }

    packet[0] = type;
    memcpy(packet + 1, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypted, encrypted_length);

    return 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encrypted_length;
}

/* Unpack IP_Port structure from data of max size length into ip_port.
 *
 * Return size of unpacked ip_port on success.
 * Return -1 on failure.
 */
int unpack_ip_port(IP_Port *ip_port, const uint8_t *data, uint16_t length, uint8_t tcp_enabled)
{
    if (data == nullptr) {
        return -1;
    }

    bool is_ipv4;
    uint8_t host_family;

    if (data[0] == TOX_AF_INET) {
        is_ipv4 = true;
        host_family = TOX_AF_INET;
    } else if (data[0] == TOX_TCP_INET) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = true;
        host_family = TCP_INET;
    } else if (data[0] == TOX_AF_INET6) {
        is_ipv4 = false;
        host_family = TOX_AF_INET6;
    } else if (data[0] == TOX_TCP_INET6) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = false;
        host_family = TCP_INET6;
    } else {
        return -1;
    }

    if (is_ipv4) {
        const uint32_t size = 1 + SIZE_IP4 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        ip_port->ip.family = host_family;
        memcpy(&ip_port->ip.ip.v4, data + 1, SIZE_IP4);
        memcpy(&ip_port->port, data + 1 + SIZE_IP4, sizeof(uint16_t));
        return size;
    } else {
        const uint32_t size = 1 + SIZE_IP6 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        ip_port->ip.family = host_family;
        memcpy(&ip_port->ip.ip.v6, data + 1, SIZE_IP6);
        memcpy(&ip_port->port, data + 1 + SIZE_IP6, sizeof(uint16_t));
        return size;
    }
}

/* Pack number of nodes into data of maxlength length.
 *
 * return length of packed nodes on success.
 * return -1 on failure.
 */
int pack_nodes(uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number)
{
    uint32_t packed_length = 0;

    for (uint32_t i = 0; i < number && packed_length < length; ++i) {
        const int ipp_size = pack_ip_port(data + packed_length, length - packed_length, &nodes[i].ip_port);

        if (ipp_size == -1) {
            return -1;
        }

        packed_length += ipp_size;

        if (packed_length + CRYPTO_PUBLIC_KEY_SIZE > length) {
            return -1;
        }

        memcpy(data + packed_length, nodes[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
        packed_length += CRYPTO_PUBLIC_KEY_SIZE;

        const uint32_t increment = ipp_size + CRYPTO_PUBLIC_KEY_SIZE;
        assert(increment == PACKED_NODE_SIZE_IP4 || increment == PACKED_NODE_SIZE_IP6);
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
        const int ipp_size = unpack_ip_port(&nodes[num].ip_port, data + len_processed, length - len_processed, tcp_enabled);

        if (ipp_size == -1) {
            return -1;
        }

        len_processed += ipp_size;

        if (len_processed + CRYPTO_PUBLIC_KEY_SIZE > length) {
            return -1;
        }

        memcpy(nodes[num].public_key, data + len_processed, CRYPTO_PUBLIC_KEY_SIZE);
        len_processed += CRYPTO_PUBLIC_KEY_SIZE;
        ++num;

        const uint32_t increment = ipp_size + CRYPTO_PUBLIC_KEY_SIZE;
        assert(increment == PACKED_NODE_SIZE_IP4 || increment == PACKED_NODE_SIZE_IP6);
    }

    if (processed_data_len) {
        *processed_data_len = len_processed;
    }

    return num;
}

/* Find index of ##type with public_key equal to pk.
 *
 *  return index or UINT32_MAX if not found.
 */
#define INDEX_OF_PK \
    for (uint32_t i = 0; i < size; i++) { \
        if (id_equal(array[i].public_key, pk)) { \
            return i; \
        } \
    } \
 \
    return UINT32_MAX;

static uint32_t index_of_client_pk(const Client_data *array, uint32_t size, const uint8_t *pk)
{
    INDEX_OF_PK
}

static uint32_t index_of_friend_pk(const DHT_Friend *array, uint32_t size, const uint8_t *pk)
{
    INDEX_OF_PK
}

static uint32_t index_of_node_pk(const Node_format *array, uint32_t size, const uint8_t *pk)
{
    INDEX_OF_PK
}

/* Find index of Client_data with ip_port equal to param ip_port.
 *
 * return index or UINT32_MAX if not found.
 */
static uint32_t index_of_client_ip_port(const Client_data *array, uint32_t size, const IP_Port *ip_port)
{
    for (uint32_t i = 0; i < size; ++i) {
        if (ip_port->ip.family == TOX_AF_INET  && ipport_equal(&array[i].assoc4.ip_port, ip_port) ||
                ip_port->ip.family == TOX_AF_INET6 && ipport_equal(&array[i].assoc6.ip_port, ip_port)) {
            return i;
        }
    }

    return UINT32_MAX;
}

/* Update ip_port of client if it's needed.
 */
static void update_client(Logger *log, int index, Client_data *client, IP_Port ip_port)
{
    IPPTsPng *assoc;
    int ip_version;

    if (ip_port.ip.family == TOX_AF_INET) {
        assoc = &client->assoc4;
        ip_version = 4;
    } else if (ip_port.ip.family == TOX_AF_INET6) {
        assoc = &client->assoc6;
        ip_version = 6;
    } else {
        return;
    }

    if (!ipport_equal(&assoc->ip_port, &ip_port)) {
        char ip_str[IP_NTOA_LEN];
        LOGGER_TRACE(log, "coipil[%u]: switching ipv%d from %s:%u to %s:%u",
                     index, ip_version,
                     ip_ntoa(&assoc->ip_port.ip, ip_str, sizeof(ip_str)),
                     net_ntohs(assoc->ip_port.port),
                     ip_ntoa(&ip_port.ip, ip_str, sizeof(ip_str)),
                     net_ntohs(ip_port.port));
    }

    if (ip_is_lan(assoc->ip_port.ip) != 0 && ip_is_lan(ip_port.ip) == 0) {
        return;
    }

    assoc->ip_port = ip_port;
    assoc->timestamp = unix_time();
}

/* Check if client with public_key is already in list of length length.
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 * TODO(irungentoo): Maybe optimize this.
 *
 *  return True(1) or False(0)
 */
static int client_or_ip_port_in_list(Logger *log, Client_data *list, uint16_t length, const uint8_t *public_key,
                                     IP_Port ip_port)
{
    const uint64_t temp_time = unix_time();
    uint32_t index = index_of_client_pk(list, length, public_key);

    /* if public_key is in list, find it and maybe overwrite ip_port */
    if (index != UINT32_MAX) {
        update_client(log, index, &list[index], ip_port);
        return 1;
    }

    /* public_key not in list yet: see if we can find an identical ip_port, in
     * that case we kill the old public_key by overwriting it with the new one
     * TODO(irungentoo): maybe we SHOULDN'T do that if that public_key is in a friend_list
     * and the one who is the actual friend's public_key/address set?
     * MAYBE: check the other address, if valid, don't nuke? */
    index = index_of_client_ip_port(list, length, &ip_port);

    if (index == UINT32_MAX) {
        return 0;
    }

    IPPTsPng *assoc;
    int ip_version;

    if (ip_port.ip.family == TOX_AF_INET) {
        assoc = &list[index].assoc4;
        ip_version = 4;
    } else {
        assoc = &list[index].assoc6;
        ip_version = 6;
    }

    /* Initialize client timestamp. */
    assoc->timestamp = temp_time;
    memcpy(list[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    LOGGER_DEBUG(log, "coipil[%u]: switching public_key (ipv%d)", index, ip_version);

    /* kill the other address, if it was set */
    memset(assoc, 0, sizeof(IPPTsPng));
    return 1;
}

/* Add node to the node list making sure only the nodes closest to cmp_pk are in the list.
 */
bool add_to_list(Node_format *nodes_list, unsigned int length, const uint8_t *pk, IP_Port ip_port,
                 const uint8_t *cmp_pk)
{
    uint8_t pk_bak[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port ip_port_bak;

    for (size_t i = 0; i < length; ++i) {
        if (id_closest(cmp_pk, nodes_list[i].public_key, pk) == 2) {
            memcpy(pk_bak, nodes_list[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
            ip_port_bak = nodes_list[i].ip_port;
            memcpy(nodes_list[i].public_key, pk, CRYPTO_PUBLIC_KEY_SIZE);
            nodes_list[i].ip_port = ip_port;

            if (i != (length - 1)) {
                add_to_list(nodes_list, length, pk_bak, ip_port_bak, cmp_pk);
            }

            return 1;
        }
    }

    return 0;
}

/* TODO(irungentoo): change this to 7 when done*/
#define HARDENING_ALL_OK 2
/* return 0 if not.
 * return 1 if route request are ok
 * return 2 if it responds to send node packets correctly
 * return 4 if it can test other nodes correctly
 * return HARDENING_ALL_OK if all ok.
 */
static uint8_t hardening_correct(const Hardening *h)
{
    return h->routes_requests_ok + (h->send_nodes_ok << 1) + (h->testing_requests << 2);
}
/*
 * helper for get_close_nodes(). argument list is a monster :D
 */
static void get_close_nodes_inner(const uint8_t *public_key, Node_format *nodes_list,
                                  Family sa_family, const Client_data *client_list, uint32_t client_list_length,
                                  uint32_t *num_nodes_ptr, uint8_t is_LAN, uint8_t want_good)
{
    if ((sa_family != TOX_AF_INET) && (sa_family != TOX_AF_INET6) && (sa_family != 0)) {
        return;
    }

    uint32_t num_nodes = *num_nodes_ptr;

    for (uint32_t i = 0; i < client_list_length; i++) {
        const Client_data *const client = &client_list[i];

        /* node already in list? */
        if (index_of_node_pk(nodes_list, MAX_SENT_NODES, client->public_key) != UINT32_MAX) {
            continue;
        }

        const IPPTsPng *ipptp = nullptr;

        if (sa_family == TOX_AF_INET) {
            ipptp = &client->assoc4;
        } else if (sa_family == TOX_AF_INET6) {
            ipptp = &client->assoc6;
        } else if (client->assoc4.timestamp >= client->assoc6.timestamp) {
            ipptp = &client->assoc4;
        } else {
            ipptp = &client->assoc6;
        }

        /* node not in a good condition? */
        if (is_timeout(ipptp->timestamp, BAD_NODE_TIMEOUT)) {
            continue;
        }

        /* don't send LAN ips to non LAN peers */
        if (ip_is_lan(ipptp->ip_port.ip) == 0 && !is_LAN) {
            continue;
        }

        if (ip_is_lan(ipptp->ip_port.ip) != 0 && want_good && hardening_correct(&ipptp->hardening) != HARDENING_ALL_OK
                && !id_equal(public_key, client->public_key)) {
            continue;
        }

        if (num_nodes < MAX_SENT_NODES) {
            memcpy(nodes_list[num_nodes].public_key, client->public_key, CRYPTO_PUBLIC_KEY_SIZE);
            nodes_list[num_nodes].ip_port = ipptp->ip_port;
            num_nodes++;
        } else {
            add_to_list(nodes_list, MAX_SENT_NODES, client->public_key, ipptp->ip_port, public_key);
        }
    }

    *num_nodes_ptr = num_nodes;
}

/* Find MAX_SENT_NODES nodes closest to the public_key for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * TODO(irungentoo): For the love of based <your favorite deity, in doubt use
 * "love"> make this function cleaner and much more efficient.
 *
 * want_good : do we want only good nodes as checked with the hardening returned or not?
 */
static int get_somewhat_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list,
                                    Family sa_family, uint8_t is_LAN, uint8_t want_good)
{
    uint32_t num_nodes = 0;
    get_close_nodes_inner(public_key, nodes_list, sa_family,
                          dht->close_clientlist, LCLIENT_LIST, &num_nodes, is_LAN, 0);

    /* TODO(irungentoo): uncomment this when hardening is added to close friend clients */
#if 0

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        get_close_nodes_inner(dht, public_key, nodes_list, sa_family,
                              dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                              &num_nodes, is_LAN, want_good);
    }

#endif

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        get_close_nodes_inner(public_key, nodes_list, sa_family,
                              dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                              &num_nodes, is_LAN, 0);
    }

    return num_nodes;
}

int get_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list, Family sa_family,
                    uint8_t is_LAN, uint8_t want_good)
{
    memset(nodes_list, 0, MAX_SENT_NODES * sizeof(Node_format));
    return get_somewhat_close_nodes(dht, public_key, nodes_list, sa_family, is_LAN, want_good);
}

typedef struct {
    const uint8_t *base_public_key;
    Client_data entry;
} DHT_Cmp_data;

static int cmp_dht_entry(const void *a, const void *b)
{
    DHT_Cmp_data cmp1, cmp2;
    memcpy(&cmp1, a, sizeof(DHT_Cmp_data));
    memcpy(&cmp2, b, sizeof(DHT_Cmp_data));
    const Client_data entry1 = cmp1.entry;
    const Client_data entry2 = cmp2.entry;
    const uint8_t *cmp_public_key = cmp1.base_public_key;

#define ASSOC_TIMEOUT(assoc) is_timeout((assoc).timestamp, BAD_NODE_TIMEOUT)

    bool t1 = ASSOC_TIMEOUT(entry1.assoc4) && ASSOC_TIMEOUT(entry1.assoc6);
    bool t2 = ASSOC_TIMEOUT(entry2.assoc4) && ASSOC_TIMEOUT(entry2.assoc6);

    if (t1 && t2) {
        return 0;
    }

    if (t1) {
        return -1;
    }

    if (t2) {
        return 1;
    }

#define INCORRECT_HARDENING(assoc) hardening_correct(&(assoc).hardening) != HARDENING_ALL_OK

    t1 = INCORRECT_HARDENING(entry1.assoc4) && INCORRECT_HARDENING(entry1.assoc6);
    t2 = INCORRECT_HARDENING(entry2.assoc4) && INCORRECT_HARDENING(entry2.assoc6);

    if (t1 && !t2) {
        return -1;
    }

    if (!t1 && t2) {
        return 1;
    }

    const int close = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (close == 1) {
        return 1;
    }

    if (close == 2) {
        return -1;
    }

    return 0;
}

/* Is it ok to store node with public_key in client.
 *
 * return 0 if node can't be stored.
 * return 1 if it can.
 */
static unsigned int store_node_ok(const Client_data *client, const uint8_t *public_key, const uint8_t *comp_public_key)
{
    return (is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT)
            && is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT))
           || id_closest(comp_public_key, client->public_key, public_key) == 2;
}

static void sort_client_list(Client_data *list, unsigned int length, const uint8_t *comp_public_key)
{
    // Pass comp_public_key to qsort with each Client_data entry, so the
    // comparison function can use it as the base of comparison.
    VLA(DHT_Cmp_data, cmp_list, length);

    for (uint32_t i = 0; i < length; i++) {
        cmp_list[i].base_public_key = comp_public_key;
        cmp_list[i].entry = list[i];
    }

    qsort(cmp_list, length, sizeof(DHT_Cmp_data), cmp_dht_entry);

    for (uint32_t i = 0; i < length; i++) {
        list[i] = cmp_list[i].entry;
    }
}

static void update_client_with_reset(Client_data *client, const IP_Port *ip_port)
{
    IPPTsPng *ipptp_write = nullptr;
    IPPTsPng *ipptp_clear = nullptr;

    if (ip_port->ip.family == TOX_AF_INET) {
        ipptp_write = &client->assoc4;
        ipptp_clear = &client->assoc6;
    } else {
        ipptp_write = &client->assoc6;
        ipptp_clear = &client->assoc4;
    }

    ipptp_write->ip_port = *ip_port;
    ipptp_write->timestamp = unix_time();

    ip_reset(&ipptp_write->ret_ip_port.ip);
    ipptp_write->ret_ip_port.port = 0;
    ipptp_write->ret_timestamp = 0;

    /* zero out other address */
    memset(ipptp_clear, 0, sizeof(*ipptp_clear));
}

/* Replace a first bad (or empty) node with this one
 *  or replace a possibly bad node (tests failed or not done yet)
 *  that is further than any other in the list
 *  from the comp_public_key
 *  or replace a good node that is further
 *  than any other in the list from the comp_public_key
 *  and further than public_key.
 *
 * Do not replace any node if the list has no bad or possibly bad nodes
 *  and all nodes in the list are closer to comp_public_key
 *  than public_key.
 *
 *  returns true when the item was stored, false otherwise */
static bool replace_all(Client_data    *list,
                        uint16_t        length,
                        const uint8_t  *public_key,
                        IP_Port         ip_port,
                        const uint8_t  *comp_public_key)
{
    if ((ip_port.ip.family != TOX_AF_INET) && (ip_port.ip.family != TOX_AF_INET6)) {
        return false;
    }

    if (!store_node_ok(&list[1], public_key, comp_public_key) &&
            !store_node_ok(&list[0], public_key, comp_public_key)) {
        return false;
    }

    sort_client_list(list, length, comp_public_key);

    Client_data *const client = &list[0];
    id_copy(client->public_key, public_key);

    update_client_with_reset(client, &ip_port);
    return true;
}

/* Add node to close list.
 *
 * simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_to_close(DHT *dht, const uint8_t *public_key, IP_Port ip_port, bool simulate)
{
    unsigned int index = bit_by_bit_cmp(public_key, dht->self_public_key);

    if (index >= LCLIENT_LENGTH) {
        index = LCLIENT_LENGTH - 1;
    }

    for (uint32_t i = 0; i < LCLIENT_NODES; ++i) {
        /* TODO(iphydf): write bounds checking test to catch the case that
         * index is left as >= LCLIENT_LENGTH */
        Client_data *const client = &dht->close_clientlist[(index * LCLIENT_NODES) + i];

        if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) ||
                !is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT)) {
            continue;
        }

        if (simulate) {
            return 0;
        }

        id_copy(client->public_key, public_key);
        update_client_with_reset(client, &ip_port);
        return 0;
    }

    return -1;
}

/* Return 1 if node can be added to close list, 0 if it can't.
 */
bool node_addable_to_close_list(DHT *dht, const uint8_t *public_key, IP_Port ip_port)
{
    return add_to_close(dht, public_key, ip_port, 1) == 0;
}

static bool is_pk_in_client_list(const Client_data *list, unsigned int client_list_length, const uint8_t *public_key,
                                 IP_Port ip_port)
{
    const uint32_t index = index_of_client_pk(list, client_list_length, public_key);

    if (index == UINT32_MAX) {
        return 0;
    }

    const IPPTsPng *assoc = ip_port.ip.family == TOX_AF_INET
                            ? &list[index].assoc4
                            : &list[index].assoc6;

    return !is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT);
}

static bool is_pk_in_close_list(DHT *dht, const uint8_t *public_key, IP_Port ip_port)
{
    unsigned int index = bit_by_bit_cmp(public_key, dht->self_public_key);

    if (index >= LCLIENT_LENGTH) {
        index = LCLIENT_LENGTH - 1;
    }

    return is_pk_in_client_list(dht->close_clientlist + index * LCLIENT_NODES, LCLIENT_NODES, public_key, ip_port);
}

/* Check if the node obtained with a get_nodes with public_key should be pinged.
 * NOTE: for best results call it after addto_lists;
 *
 * return false if the node should not be pinged.
 * return true if it should.
 */
static bool ping_node_from_getnodes_ok(DHT *dht, const uint8_t *public_key, IP_Port ip_port)
{
    bool ret = false;

    if (add_to_close(dht, public_key, ip_port, 1) == 0) {
        ret = true;
    }

    unsigned int *const num = &dht->num_to_bootstrap;
    const uint32_t index = index_of_node_pk(dht->to_bootstrap, *num, public_key);
    const bool in_close_list = is_pk_in_close_list(dht, public_key, ip_port);

    if (ret && index == UINT32_MAX && !in_close_list) {
        if (*num < MAX_CLOSE_TO_BOOTSTRAP_NODES) {
            memcpy(dht->to_bootstrap[*num].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
            dht->to_bootstrap[*num].ip_port = ip_port;
            ++*num;
        } else {
            // TODO(irungentoo): ipv6 vs v4
            add_to_list(dht->to_bootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES, public_key, ip_port, dht->self_public_key);
        }
    }

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        DHT_Friend *dht_friend = &dht->friends_list[i];

        bool store_ok = false;

        if (store_node_ok(&dht_friend->client_list[1], public_key, dht_friend->public_key)) {
            store_ok = true;
        }

        if (store_node_ok(&dht_friend->client_list[0], public_key, dht_friend->public_key)) {
            store_ok = true;
        }

        unsigned int *const friend_num = &dht_friend->num_to_bootstrap;
        const uint32_t index = index_of_node_pk(dht_friend->to_bootstrap, *friend_num, public_key);
        const bool pk_in_list = is_pk_in_client_list(dht_friend->client_list, MAX_FRIEND_CLIENTS, public_key, ip_port);

        if (store_ok && index == UINT32_MAX && !pk_in_list) {
            if (*friend_num < MAX_SENT_NODES) {
                Node_format *const format = &dht_friend->to_bootstrap[*friend_num];
                memcpy(format->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
                format->ip_port = ip_port;
                ++*friend_num;
            } else {
                add_to_list(dht_friend->to_bootstrap, MAX_SENT_NODES, public_key, ip_port, dht_friend->public_key);
            }

            ret = true;
        }
    }

    return ret;
}

/* Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.
 *
 *  returns 1+ if the item is used in any list, 0 else
 */
uint32_t addto_lists(DHT *dht, IP_Port ip_port, const uint8_t *public_key)
{
    uint32_t used = 0;

    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == TOX_AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip.v6)) {
        ip_port.ip.family = TOX_AF_INET;
        ip_port.ip.ip.v4.uint32 = ip_port.ip.ip.v6.uint32[3];
    }

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */
    const bool in_close_list = client_or_ip_port_in_list(dht->log, dht->close_clientlist,
                               LCLIENT_LIST, public_key, ip_port);

    /* add_to_close should be called only if !in_list (don't extract to variable) */
    if (in_close_list || add_to_close(dht, public_key, ip_port, 0)) {
        used++;
    }

    DHT_Friend *friend_foundip = nullptr;

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        const bool in_list = client_or_ip_port_in_list(dht->log, dht->friends_list[i].client_list,
                             MAX_FRIEND_CLIENTS, public_key, ip_port);

        /* replace_all should be called only if !in_list (don't extract to variable) */
        if (in_list || replace_all(dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, public_key,
                                   ip_port, dht->friends_list[i].public_key)) {
            DHT_Friend *dht_friend = &dht->friends_list[i];

            if (id_equal(public_key, dht_friend->public_key)) {
                friend_foundip = dht_friend;
            }

            used++;
        }
    }

    if (!friend_foundip) {
        return used;
    }

    for (uint32_t i = 0; i < friend_foundip->lock_count; ++i) {
        if (friend_foundip->callbacks[i].ip_callback) {
            friend_foundip->callbacks[i].ip_callback(friend_foundip->callbacks[i].data,
                    friend_foundip->callbacks[i].number, ip_port);
        }
    }

    return used;
}

static bool update_client_data(Client_data *array, size_t size, IP_Port ip_port, const uint8_t *pk)
{
    const uint64_t temp_time = unix_time();
    const uint32_t index = index_of_client_pk(array, size, pk);

    if (index == UINT32_MAX) {
        return false;
    }

    Client_data *const data = &array[index];
    IPPTsPng *assoc;

    if (ip_port.ip.family == TOX_AF_INET) {
        assoc = &data->assoc4;
    } else if (ip_port.ip.family == TOX_AF_INET6) {
        assoc = &data->assoc6;
    } else {
        return true;
    }

    assoc->ret_ip_port = ip_port;
    assoc->ret_timestamp = temp_time;
    return true;
}

/* If public_key is a friend or us, update ret_ip_port
 * nodepublic_key is the id of the node that sent us this info.
 */
static void returnedip_ports(DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *nodepublic_key)
{
    /* convert IPv4-in-IPv6 to IPv4 */
    if ((ip_port.ip.family == TOX_AF_INET6) && IPV6_IPV4_IN_V6(ip_port.ip.ip.v6)) {
        ip_port.ip.family = TOX_AF_INET;
        ip_port.ip.ip.v4.uint32 = ip_port.ip.ip.v6.uint32[3];
    }

    if (id_equal(public_key, dht->self_public_key)) {
        update_client_data(dht->close_clientlist, LCLIENT_LIST, ip_port, nodepublic_key);
        return;
    }

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        if (id_equal(public_key, dht->friends_list[i].public_key)) {
            Client_data *const client_list = dht->friends_list[i].client_list;

            if (update_client_data(client_list, MAX_FRIEND_CLIENTS, ip_port, nodepublic_key)) {
                return;
            }
        }
    }
}

/* Send a getnodes request.
   sendback_node is the node that it will send back the response to (set to NULL to disable this) */
static int getnodes(DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                    const Node_format *sendback_node)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->self_public_key)) {
        return -1;
    }

    uint8_t plain_message[sizeof(Node_format) * 2] = {0};

    Node_format receiver;
    memcpy(receiver.public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    receiver.ip_port = ip_port;
    memcpy(plain_message, &receiver, sizeof(receiver));

    uint64_t ping_id = 0;

    if (sendback_node != nullptr) {
        memcpy(plain_message + sizeof(receiver), sendback_node, sizeof(Node_format));
        ping_id = ping_array_add(dht->dht_harden_ping_array, plain_message, sizeof(plain_message));
    } else {
        ping_id = ping_array_add(dht->dht_ping_array, plain_message, sizeof(receiver));
    }

    if (ping_id == 0) {
        return -1;
    }

    uint8_t plain[CRYPTO_PUBLIC_KEY_SIZE + sizeof(ping_id)];
    uint8_t data[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE];

    memcpy(plain, client_id, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, &ping_id, sizeof(ping_id));

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    DHT_get_shared_key_sent(dht, shared_key, public_key);

    const int len = DHT_create_packet(dht->self_public_key, shared_key, NET_PACKET_GET_NODES,
                                      plain, sizeof(plain), data);

    if (len != sizeof(data)) {
        return -1;
    }

    return sendpacket(dht->net, ip_port, data, len);
}

/* Send a send nodes response: message for IPv6 nodes */
static int sendnodes_ipv6(const DHT *dht, IP_Port ip_port, const uint8_t *public_key, const uint8_t *client_id,
                          const uint8_t *sendback_data, uint16_t length, const uint8_t *shared_encryption_key)
{
    /* Check if packet is going to be sent to ourself. */
    if (id_equal(public_key, dht->self_public_key)) {
        return -1;
    }

    if (length != sizeof(uint64_t)) {
        return -1;
    }

    const size_t node_format_size = sizeof(Node_format);

    Node_format nodes_list[MAX_SENT_NODES];
    const uint32_t num_nodes = get_close_nodes(dht, client_id, nodes_list, 0, ip_is_lan(ip_port.ip) == 0, 1);

    VLA(uint8_t, plain, 1 + node_format_size * MAX_SENT_NODES + length);

    int nodes_length = 0;

    if (num_nodes) {
        nodes_length = pack_nodes(plain + 1, node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);

        if (nodes_length <= 0) {
            return -1;
        }
    }

    plain[0] = num_nodes;
    memcpy(plain + 1 + nodes_length, sendback_data, length);

    const uint32_t crypto_size = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE;
    VLA(uint8_t, data, 1 + nodes_length + length + crypto_size);

    const int len = DHT_create_packet(dht->self_public_key, shared_encryption_key, NET_PACKET_SEND_NODES_IPV6,
                                      plain, 1 + nodes_length + length, data);

    if (len != SIZEOF_VLA(data)) {
        return -1;
    }

    return sendpacket(dht->net, ip_port, data, len);
}

#define CRYPTO_NODE_SIZE (CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t))

static int handle_getnodes(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length != (CRYPTO_SIZE + CRYPTO_MAC_SIZE + sizeof(uint64_t))) {
        return true;
    }

    DHT *const dht = (DHT *)object;

    /* Check if packet is from ourself. */
    if (id_equal(packet + 1, dht->self_public_key)) {
        return true;
    }

    uint8_t plain[CRYPTO_NODE_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    DHT_get_shared_key_recv(dht, shared_key, packet + 1);
    const int len = decrypt_data_symmetric(
                        shared_key,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                        CRYPTO_NODE_SIZE + CRYPTO_MAC_SIZE,
                        plain);

    if (len != CRYPTO_NODE_SIZE) {
        return true;
    }

    sendnodes_ipv6(dht, source, packet + 1, plain, plain + CRYPTO_PUBLIC_KEY_SIZE, sizeof(uint64_t), shared_key);

    ping_add(dht->ping, packet + 1, source);

    return false;
}

/* return false if no
   return true if yes */
static bool sent_getnode_to_node(DHT *dht, const uint8_t *public_key, IP_Port node_ip_port, uint64_t ping_id,
                                 Node_format *sendback_node)
{
    uint8_t data[sizeof(Node_format) * 2];

    if (ping_array_check(dht->dht_ping_array, data, sizeof(data), ping_id) == sizeof(Node_format)) {
        memset(sendback_node, 0, sizeof(Node_format));
    } else if (ping_array_check(dht->dht_harden_ping_array, data, sizeof(data), ping_id) == sizeof(data)) {
        memcpy(sendback_node, data + sizeof(Node_format), sizeof(Node_format));
    } else {
        return false;
    }

    Node_format test;
    memcpy(&test, data, sizeof(Node_format));

    if (!ipport_equal(&test.ip_port, &node_ip_port) || !id_equal(test.public_key, public_key)) {
        return false;
    }

    return true;
}

/* Function is needed in following functions. */
static int send_hardening_getnode_res(const DHT *dht, const Node_format *sendto, const uint8_t *queried_client_id,
                                      const uint8_t *nodes_data, uint16_t nodes_data_length);

static int handle_sendnodes_core(void *object, IP_Port source, const uint8_t *packet, uint16_t length,
                                 Node_format *plain_nodes, uint16_t size_plain_nodes, uint32_t *num_nodes_out)
{
    DHT *const dht = (DHT *)object;
    const uint32_t cid_size = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + 1 + sizeof(uint64_t) + CRYPTO_MAC_SIZE;

    if (length < cid_size) { /* too short */
        return 1;
    }

    const uint32_t data_size = length - cid_size;

    if (data_size == 0) {
        return 1;
    }

    if (data_size > sizeof(Node_format) * MAX_SENT_NODES) { /* invalid length */
        return 1;
    }

    VLA(uint8_t, plain, 1 + data_size + sizeof(uint64_t));
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    DHT_get_shared_key_sent(dht, shared_key, packet + 1);
    const int len = decrypt_data_symmetric(
                        shared_key,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                        1 + data_size + sizeof(uint64_t) + CRYPTO_MAC_SIZE,
                        plain);

    if ((unsigned int)len != SIZEOF_VLA(plain)) {
        return 1;
    }

    if (plain[0] > size_plain_nodes) {
        return 1;
    }

    Node_format sendback_node;

    uint64_t ping_id;
    memcpy(&ping_id, plain + 1 + data_size, sizeof(ping_id));

    if (!sent_getnode_to_node(dht, packet + 1, source, ping_id, &sendback_node)) {
        return 1;
    }

    uint16_t length_nodes = 0;
    const int num_nodes = unpack_nodes(plain_nodes, plain[0], &length_nodes, plain + 1, data_size, 0);

    if (length_nodes != data_size) {
        return 1;
    }

    if (num_nodes != plain[0]) {
        return 1;
    }

    if (num_nodes < 0) {
        return 1;
    }

    /* store the address the *request* was sent to */
    addto_lists(dht, source, packet + 1);

    *num_nodes_out = num_nodes;

    send_hardening_getnode_res(dht, &sendback_node, packet + 1, plain + 1, data_size);
    return 0;
}

static int handle_sendnodes_ipv6(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    DHT *const dht = (DHT *)object;
    Node_format plain_nodes[MAX_SENT_NODES];
    uint32_t num_nodes;

    if (handle_sendnodes_core(object, source, packet, length, plain_nodes, MAX_SENT_NODES, &num_nodes)) {
        return 1;
    }

    if (num_nodes == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < num_nodes; i++) {
        if (ipport_isset(&plain_nodes[i].ip_port)) {
            ping_node_from_getnodes_ok(dht, plain_nodes[i].public_key, plain_nodes[i].ip_port);
            returnedip_ports(dht, plain_nodes[i].ip_port, plain_nodes[i].public_key, packet + 1);
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

int DHT_addfriend(DHT *dht, const uint8_t *public_key, void (*ip_callback)(void *data, int32_t number, IP_Port),
                  void *data, int32_t number, uint16_t *lock_count)
{
    const uint32_t friend_num = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    uint16_t lock_num;

    if (friend_num != UINT32_MAX) { /* Is friend already in DHT? */
        DHT_Friend *const dht_friend = &dht->friends_list[friend_num];

        if (dht_friend->lock_count == DHT_FRIEND_MAX_LOCKS) {
            return -1;
        }

        lock_num = dht_friend->lock_count;
        ++dht_friend->lock_count;
        dht_friend->callbacks[lock_num].ip_callback = ip_callback;
        dht_friend->callbacks[lock_num].data = data;
        dht_friend->callbacks[lock_num].number = number;

        if (lock_count) {
            *lock_count = lock_num + 1;
        }

        return 0;
    }

    DHT_Friend *const temp = (DHT_Friend *)realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends + 1));

    if (temp == nullptr) {
        return -1;
    }

    dht->friends_list = temp;
    DHT_Friend *const dht_friend = &dht->friends_list[dht->num_friends];
    memset(dht_friend, 0, sizeof(DHT_Friend));
    memcpy(dht_friend->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    dht_friend->nat.NATping_id = random_u64();
    ++dht->num_friends;

    lock_num = dht_friend->lock_count;
    ++dht_friend->lock_count;
    dht_friend->callbacks[lock_num].ip_callback = ip_callback;
    dht_friend->callbacks[lock_num].data = data;
    dht_friend->callbacks[lock_num].number = number;

    if (lock_count) {
        *lock_count = lock_num + 1;
    }

    dht_friend->num_to_bootstrap = get_close_nodes(dht, dht_friend->public_key, dht_friend->to_bootstrap, 0, 1, 0);

    return 0;
}

int DHT_delfriend(DHT *dht, const uint8_t *public_key, uint16_t lock_count)
{
    const uint32_t friend_num = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    if (friend_num == UINT32_MAX) {
        return -1;
    }

    DHT_Friend *const dht_friend = &dht->friends_list[friend_num];
    --dht_friend->lock_count;

    if (dht_friend->lock_count && lock_count) { /* DHT friend is still in use.*/
        --lock_count;
        dht_friend->callbacks[lock_count].ip_callback = nullptr;
        dht_friend->callbacks[lock_count].data = nullptr;
        dht_friend->callbacks[lock_count].number = 0;
        return 0;
    }

    --dht->num_friends;

    if (dht->num_friends != friend_num) {
        memcpy(&dht->friends_list[friend_num],
               &dht->friends_list[dht->num_friends],
               sizeof(DHT_Friend));
    }

    if (dht->num_friends == 0) {
        free(dht->friends_list);
        dht->friends_list = nullptr;
        return 0;
    }

    DHT_Friend *const temp = (DHT_Friend *)realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends));

    if (temp == nullptr) {
        return -1;
    }

    dht->friends_list = temp;
    return 0;
}

/* TODO(irungentoo): Optimize this. */
int DHT_getfriendip(const DHT *dht, const uint8_t *public_key, IP_Port *ip_port)
{
    ip_reset(&ip_port->ip);
    ip_port->port = 0;

    const uint32_t friend_index = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    if (friend_index == UINT32_MAX) {
        return -1;
    }

    DHT_Friend *const frnd = &dht->friends_list[friend_index];
    const uint32_t client_index = index_of_client_pk(frnd->client_list, MAX_FRIEND_CLIENTS, public_key);

    if (client_index == -1) {
        return 0;
    }

    const Client_data *const client = &frnd->client_list[client_index];
    const IPPTsPng *const assocs[ASSOC_COUNT] = { &client->assoc6, &client->assoc4 };

    for (size_t i = 0; i < ASSOC_COUNT; i++) {
        const IPPTsPng *const assoc = assocs[i];

        if (!is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT)) {
            *ip_port = assoc->ip_port;
            return 1;
        }
    }

    return -1;
}

/* returns number of nodes not in kill-timeout */
static uint8_t do_ping_and_sendnode_requests(DHT *dht, uint64_t *lastgetnode, const uint8_t *public_key,
        Client_data *list, uint32_t list_count, uint32_t *bootstrap_times, bool sortable)
{
    uint8_t not_kill = 0;
    const uint64_t temp_time = unix_time();

    uint32_t num_nodes = 0;
    VLA(Client_data *, client_list, list_count * 2);
    VLA(IPPTsPng *, assoc_list, list_count * 2);
    unsigned int sort = 0;
    bool sort_ok = false;

    for (uint32_t i = 0; i < list_count; i++) {
        /* If node is not dead. */
        Client_data *client = &list[i];

        IPPTsPng *assocs[ASSOC_COUNT] = { &client->assoc6, &client->assoc4 };

        for (size_t i = 0; i < ASSOC_COUNT; i++) {
            IPPTsPng *assoc = assocs[i];

            if (!is_timeout(assoc->timestamp, KILL_NODE_TIMEOUT)) {
                sort = 0;
                not_kill++;

                if (is_timeout(assoc->last_pinged, PING_INTERVAL)) {
                    getnodes(dht, assoc->ip_port, client->public_key, public_key, nullptr);
                    assoc->last_pinged = temp_time;
                }

                /* If node is good. */
                if (!is_timeout(assoc->timestamp, BAD_NODE_TIMEOUT)) {
                    client_list[num_nodes] = client;
                    assoc_list[num_nodes] = assoc;
                    ++num_nodes;
                }
            } else {
                ++sort;

                /* Timed out should be at beginning, if they are not, sort the list. */
                if (sort > 1 && sort < (((i + 1) * 2) - 1)) {
                    sort_ok = true;
                }
            }
        }
    }

    if (sortable && sort_ok) {
        sort_client_list(list, list_count, public_key);
    }

    if ((num_nodes != 0) && (is_timeout(*lastgetnode, GET_NODE_INTERVAL) || *bootstrap_times < MAX_BOOTSTRAP_TIMES)) {
        uint32_t rand_node = rand() % num_nodes;

        if ((num_nodes - 1) != rand_node) {
            rand_node += rand() % (num_nodes - (rand_node + 1));
        }

        getnodes(dht, assoc_list[rand_node]->ip_port, client_list[rand_node]->public_key, public_key, nullptr);

        *lastgetnode = temp_time;
        ++*bootstrap_times;
    }

    return not_kill;
}

/* Ping each client in the "friends" list every PING_INTERVAL seconds. Send a get nodes request
 * every GET_NODE_INTERVAL seconds to a random good node for each "friend" in our "friends" list.
 */
static void do_DHT_friends(DHT *dht)
{
    for (size_t i = 0; i < dht->num_friends; ++i) {
        DHT_Friend *const dht_friend = &dht->friends_list[i];

        for (size_t j = 0; j < dht_friend->num_to_bootstrap; ++j) {
            getnodes(dht, dht_friend->to_bootstrap[j].ip_port, dht_friend->to_bootstrap[j].public_key, dht_friend->public_key,
                     nullptr);
        }

        dht_friend->num_to_bootstrap = 0;

        do_ping_and_sendnode_requests(dht, &dht_friend->lastgetnode, dht_friend->public_key, dht_friend->client_list,
                                      MAX_FRIEND_CLIENTS,
                                      &dht_friend->bootstrap_times, 1);
    }
}

/* Ping each client in the close nodes list every PING_INTERVAL seconds.
 * Send a get nodes request every GET_NODE_INTERVAL seconds to a random good node in the list.
 */
static void do_Close(DHT *dht)
{
    for (size_t i = 0; i < dht->num_to_bootstrap; ++i) {
        getnodes(dht, dht->to_bootstrap[i].ip_port, dht->to_bootstrap[i].public_key, dht->self_public_key, nullptr);
    }

    dht->num_to_bootstrap = 0;

    uint8_t not_killed = do_ping_and_sendnode_requests(
                             dht, &dht->close_lastgetnodes, dht->self_public_key, dht->close_clientlist, LCLIENT_LIST, &dht->close_bootstrap_times,
                             0);

    if (not_killed != 0) {
        return;
    }

    /* all existing nodes are at least KILL_NODE_TIMEOUT,
     * which means we are mute, as we only send packets to
     * nodes NOT in KILL_NODE_TIMEOUT
     *
     * so: reset all nodes to be BAD_NODE_TIMEOUT, but not
     * KILL_NODE_TIMEOUT, so we at least keep trying pings */
    const uint64_t badonly = unix_time() - BAD_NODE_TIMEOUT;

    for (size_t i = 0; i < LCLIENT_LIST; i++) {
        Client_data *const client = &dht->close_clientlist[i];

        IPPTsPng *const assocs[ASSOC_COUNT] = { &client->assoc6, &client->assoc4 };

        for (size_t j = 0; j < ASSOC_COUNT; j++) {
            IPPTsPng *const assoc = assocs[j];

            if (assoc->timestamp) {
                assoc->timestamp = badonly;
            }
        }
    }
}

void DHT_getnodes(DHT *dht, const IP_Port *from_ipp, const uint8_t *from_id, const uint8_t *which_id)
{
    getnodes(dht, *from_ipp, from_id, which_id, nullptr);
}

void DHT_bootstrap(DHT *dht, IP_Port ip_port, const uint8_t *public_key)
{
    getnodes(dht, ip_port, public_key, dht->self_public_key, nullptr);
}
int DHT_bootstrap_from_address(DHT *dht, const char *address, uint8_t ipv6enabled,
                               uint16_t port, const uint8_t *public_key)
{
    IP_Port ip_port_v64;
    IP *ip_extra = nullptr;
    IP_Port ip_port_v4;
    ip_init(&ip_port_v64.ip, ipv6enabled);

    if (ipv6enabled) {
        /* setup for getting BOTH: an IPv6 AND an IPv4 address */
        ip_port_v64.ip.family = TOX_AF_UNSPEC;
        ip_reset(&ip_port_v4.ip);
        ip_extra = &ip_port_v4.ip;
    }

    if (addr_resolve_or_parse_ip(address, &ip_port_v64.ip, ip_extra)) {
        ip_port_v64.port = port;
        DHT_bootstrap(dht, ip_port_v64, public_key);

        if ((ip_extra != nullptr) && ip_isset(ip_extra)) {
            ip_port_v4.port = port;
            DHT_bootstrap(dht, ip_port_v4, public_key);
        }

        return 1;
    }

    return 0;
}

/* Send the given packet to node with public_key
 *
 *  return -1 if failure.
 */
int route_packet(const DHT *dht, const uint8_t *public_key, const uint8_t *packet, uint16_t length)
{
    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        if (id_equal(public_key, dht->close_clientlist[i].public_key)) {
            const Client_data *const client = &dht->close_clientlist[i];
            const IPPTsPng *const assocs[ASSOC_COUNT] = { &client->assoc6, &client->assoc4 };

            for (size_t j = 0; j < ASSOC_COUNT; j++) {
                const IPPTsPng *const assoc = assocs[j];

                if (ip_isset(&assoc->ip_port.ip)) {
                    return sendpacket(dht->net, assoc->ip_port, packet, length);
                }
            }

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
static int friend_iplist(const DHT *dht, IP_Port *ip_portlist, uint16_t friend_num)
{
    if (friend_num >= dht->num_friends) {
        return -1;
    }

    const DHT_Friend *const dht_friend = &dht->friends_list[friend_num];
    IP_Port ipv4s[MAX_FRIEND_CLIENTS];
    int num_ipv4s = 0;
    IP_Port ipv6s[MAX_FRIEND_CLIENTS];
    int num_ipv6s = 0;

    for (size_t i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        const Client_data *const client = &dht_friend->client_list[i];

        /* If ip is not zero and node is good. */
        if (ip_isset(&client->assoc4.ret_ip_port.ip) && !is_timeout(client->assoc4.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv4s[num_ipv4s] = client->assoc4.ret_ip_port;
            ++num_ipv4s;
        }

        if (ip_isset(&client->assoc6.ret_ip_port.ip) && !is_timeout(client->assoc6.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv6s[num_ipv6s] = client->assoc6.ret_ip_port;
            ++num_ipv6s;
        }

        if (id_equal(client->public_key, dht_friend->public_key)) {
            if (!is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT)
                    || !is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT)) {
                return 0; /* direct connectivity */
            }
        }
    }

#ifdef FRIEND_IPLIST_PAD
    memcpy(ip_portlist, ipv6s, num_ipv6s * sizeof(IP_Port));

    if (num_ipv6s == MAX_FRIEND_CLIENTS) {
        return MAX_FRIEND_CLIENTS;
    }

    int num_ipv4s_used = MAX_FRIEND_CLIENTS - num_ipv6s;

    if (num_ipv4s_used > num_ipv4s) {
        num_ipv4s_used = num_ipv4s;
    }

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
 *  return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 4).
 */
int route_tofriend(const DHT *dht, const uint8_t *friend_id, const uint8_t *packet, uint16_t length)
{
    const uint32_t num = index_of_friend_pk(dht->friends_list, dht->num_friends, friend_id);

    if (num == UINT32_MAX) {
        return 0;
    }

    uint32_t sent = 0;
    uint8_t friend_sent[MAX_FRIEND_CLIENTS] = {0};

    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    const int ip_num = friend_iplist(dht, ip_list, num);

    if (ip_num < (MAX_FRIEND_CLIENTS / 4)) {
        return 0; /* Reason for that? */
    }

    const DHT_Friend *const dht_friend = &dht->friends_list[num];

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */

    for (uint32_t i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        if (friend_sent[i]) {/* Send one packet per client.*/
            continue;
        }

        const Client_data *const client = &dht_friend->client_list[i];
        const IPPTsPng *const assocs[ASSOC_COUNT] = { &client->assoc4, &client->assoc6 };

        for (size_t j = 0; j < ASSOC_COUNT; j++) {
            const IPPTsPng *const assoc = assocs[j];

            /* If ip is not zero and node is good. */
            if (ip_isset(&assoc->ret_ip_port.ip) && !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                const int retval = sendpacket(dht->net, assoc->ip_port, packet, length);

                if ((unsigned int)retval == length) {
                    ++sent;
                    friend_sent[i] = 1;
                }
            }
        }
    }

    return sent;
}

/* Send the following packet to one random person who tells us they are connected to friend_id.
 *
 *  return number of nodes the packet was sent to.
 */
static int routeone_tofriend(DHT *dht, const uint8_t *friend_id, const uint8_t *packet, uint16_t length)
{
    const uint32_t num = index_of_friend_pk(dht->friends_list, dht->num_friends, friend_id);

    if (num == UINT32_MAX) {
        return 0;
    }

    const DHT_Friend *const dht_friend = &dht->friends_list[num];

    IP_Port ip_list[MAX_FRIEND_CLIENTS * 2];
    int n = 0;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */

    for (uint32_t i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        const Client_data *const client = &dht_friend->client_list[i];
        const IPPTsPng *const assocs[ASSOC_COUNT] = { &client->assoc4, &client->assoc6 };

        for (size_t j = 0; j < ASSOC_COUNT; j++) {
            const IPPTsPng *assoc = assocs[j];

            /* If ip is not zero and node is good. */
            if (ip_isset(&assoc->ret_ip_port.ip) && !is_timeout(assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                ip_list[n] = assoc->ip_port;
                ++n;
            }
        }
    }

    if (n < 1) {
        return 0;
    }

    const int retval = sendpacket(dht->net, ip_list[rand() % n], packet, length);

    if ((unsigned int)retval == length) {
        return 1;
    }

    return 0;
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
    const int len = create_request(
                        dht->self_public_key, dht->self_secret_key, packet, public_key, data,
                        sizeof(uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

    if (len == -1) {
        return -1;
    }

    if (type == 0) { /* If packet is request use many people to route it. */
        num = route_tofriend(dht, public_key, packet, len);
    } else if (type == 1) { /* If packet is response use only one person to route it */
        num = routeone_tofriend(dht, public_key, packet, len);
    }

    if (num == 0) {
        return -1;
    }

    return num;
}

/* Handle a received ping request for. */
static int handle_NATping(void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                          uint16_t length, void *userdata)
{
    if (length != sizeof(uint64_t) + 1) {
        return 1;
    }

    DHT *const dht = (DHT *)object;
    uint64_t ping_id;
    memcpy(&ping_id, packet + 1, sizeof(uint64_t));

    uint32_t friendnumber = index_of_friend_pk(dht->friends_list, dht->num_friends, source_pubkey);

    if (friendnumber == UINT32_MAX) {
        return 1;
    }

    DHT_Friend *const dht_friend = &dht->friends_list[friendnumber];

    if (packet[0] == NAT_PING_REQUEST) {
        /* 1 is reply */
        send_NATping(dht, source_pubkey, ping_id, NAT_PING_RESPONSE);
        dht_friend->nat.recvNATping_timestamp = unix_time();
        return 0;
    }

    if (packet[0] == NAT_PING_RESPONSE) {
        if (dht_friend->nat.NATping_id == ping_id) {
            dht_friend->nat.NATping_id = random_u64();
            dht_friend->nat.hole_punching = 1;
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

    if (len > MAX_FRIEND_CLIENTS) {
        return zero;
    }

    uint16_t numbers[MAX_FRIEND_CLIENTS] = {0};

    for (uint32_t i = 0; i < len; ++i) {
        for (uint32_t j = 0; j < len; ++j) {
            if (ip_equal(&ip_portlist[i].ip, &ip_portlist[j].ip)) {
                ++numbers[i];
            }
        }

        if (numbers[i] >= min_num) {
            return ip_portlist[i].ip;
        }
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
    uint16_t num = 0;

    for (uint32_t i = 0; i < len; ++i) {
        if (ip_equal(&ip_portlist[i].ip, &ip)) {
            portlist[num] = net_ntohs(ip_portlist[i].port);
            ++num;
        }
    }

    return num;
}

static void punch_holes(DHT *dht, IP ip, uint16_t *port_list, uint16_t numports, uint16_t friend_num)
{
    if (!dht->hole_punching_enabled) {
        return;
    }

    if (numports > MAX_FRIEND_CLIENTS || numports == 0) {
        return;
    }

    const uint16_t first_port = port_list[0];
    uint32_t i;

    for (i = 0; i < numports; ++i) {
        if (first_port != port_list[i]) {
            break;
        }
    }

    if (i == numports) { /* If all ports are the same, only try that one port. */
        IP_Port pinging;
        ip_copy(&pinging.ip, &ip);
        pinging.port = net_htons(first_port);
        ping_send_request(dht->ping, pinging, dht->friends_list[friend_num].public_key);
    } else {
        for (i = 0; i < MAX_PUNCHING_PORTS; ++i) {
            /* TODO(irungentoo): Improve port guessing algorithm. */
            const uint32_t it = i + dht->friends_list[friend_num].nat.punching_index;
            const int8_t sign = (it % 2) ? -1 : 1;
            const uint32_t delta = sign * (it / (2 * numports));
            const uint32_t index = (it / 2) % numports;
            const uint16_t port = port_list[index] + delta;
            IP_Port pinging;
            ip_copy(&pinging.ip, &ip);
            pinging.port = net_htons(port);
            ping_send_request(dht->ping, pinging, dht->friends_list[friend_num].public_key);
        }

        dht->friends_list[friend_num].nat.punching_index += i;
    }

    if (dht->friends_list[friend_num].nat.tries > MAX_NORMAL_PUNCHING_TRIES) {
        const uint16_t port = 1024;
        IP_Port pinging;
        ip_copy(&pinging.ip, &ip);

        for (i = 0; i < MAX_PUNCHING_PORTS; ++i) {
            uint32_t it = i + dht->friends_list[friend_num].nat.punching_index2;
            pinging.port = net_htons(port + it);
            ping_send_request(dht->ping, pinging, dht->friends_list[friend_num].public_key);
        }

        dht->friends_list[friend_num].nat.punching_index2 += i - (MAX_PUNCHING_PORTS / 2);
    }

    ++dht->friends_list[friend_num].nat.tries;
}

static void do_NAT(DHT *dht)
{
    const uint64_t temp_time = unix_time();

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        IP_Port ip_list[MAX_FRIEND_CLIENTS];
        const int num = friend_iplist(dht, ip_list, i);

        /* If already connected or friend is not online don't try to hole punch. */
        if (num < MAX_FRIEND_CLIENTS / 2) {
            continue;
        }

        if (dht->friends_list[i].nat.NATping_timestamp + PUNCH_INTERVAL < temp_time) {
            send_NATping(dht, dht->friends_list[i].public_key, dht->friends_list[i].nat.NATping_id, NAT_PING_REQUEST);
            dht->friends_list[i].nat.NATping_timestamp = temp_time;
        }

        if (dht->friends_list[i].nat.hole_punching == 1 &&
                dht->friends_list[i].nat.punching_timestamp + PUNCH_INTERVAL < temp_time &&
                dht->friends_list[i].nat.recvNATping_timestamp + PUNCH_INTERVAL * 2 >= temp_time) {

            const IP ip = NAT_commonip(ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (!ip_isset(&ip)) {
                continue;
            }

            if (dht->friends_list[i].nat.punching_timestamp + PUNCH_RESET_TIME < temp_time) {
                dht->friends_list[i].nat.tries = 0;
                dht->friends_list[i].nat.punching_index = 0;
                dht->friends_list[i].nat.punching_index2 = 0;
            }

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            const uint16_t numports = NAT_getports(port_list, ip_list, num, ip);
            punch_holes(dht, ip, port_list, numports, i);

            dht->friends_list[i].nat.punching_timestamp = temp_time;
            dht->friends_list[i].nat.hole_punching = 0;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/

#define HARDREQ_DATA_SIZE 384 /* Attempt to prevent amplification/other attacks*/

#define CHECK_TYPE_ROUTE_REQ 0
#define CHECK_TYPE_ROUTE_RES 1
#define CHECK_TYPE_GETNODE_REQ 2
#define CHECK_TYPE_GETNODE_RES 3
#define CHECK_TYPE_TEST_REQ 4
#define CHECK_TYPE_TEST_RES 5

#if DHT_HARDENING
static int send_hardening_req(DHT *dht, Node_format *sendto, uint8_t type, uint8_t *contents, uint16_t length)
{
    if (length > HARDREQ_DATA_SIZE - 1) {
        return -1;
    }

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t data[HARDREQ_DATA_SIZE] = {0};
    data[0] = type;
    memcpy(data + 1, contents, length);
    const int len = create_request(
                        dht->self_public_key, dht->self_secret_key, packet, sendto->public_key,
                        data, sizeof(data), CRYPTO_PACKET_HARDENING);

    if (len == -1) {
        return -1;
    }

    return sendpacket(dht->net, sendto->ip_port, packet, len);
}

/* Send a get node hardening request */
static int send_hardening_getnode_req(DHT *dht, Node_format *dest, Node_format *node_totest, uint8_t *search_id)
{
    uint8_t data[sizeof(Node_format) + CRYPTO_PUBLIC_KEY_SIZE];
    memcpy(data, node_totest, sizeof(Node_format));
    memcpy(data + sizeof(Node_format), search_id, CRYPTO_PUBLIC_KEY_SIZE);
    return send_hardening_req(dht, dest, CHECK_TYPE_GETNODE_REQ, data, sizeof(Node_format) + CRYPTO_PUBLIC_KEY_SIZE);
}
#endif

/* Send a get node hardening response */
static int send_hardening_getnode_res(const DHT *dht, const Node_format *sendto, const uint8_t *queried_client_id,
                                      const uint8_t *nodes_data, uint16_t nodes_data_length)
{
    if (!ip_isset(&sendto->ip_port.ip)) {
        return -1;
    }

    uint8_t packet[MAX_CRYPTO_REQUEST_SIZE];
    VLA(uint8_t, data, 1 + CRYPTO_PUBLIC_KEY_SIZE + nodes_data_length);
    data[0] = CHECK_TYPE_GETNODE_RES;
    memcpy(data + 1, queried_client_id, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(data + 1 + CRYPTO_PUBLIC_KEY_SIZE, nodes_data, nodes_data_length);
    const int len = create_request(
                        dht->self_public_key, dht->self_secret_key, packet, sendto->public_key,
                        data, SIZEOF_VLA(data), CRYPTO_PACKET_HARDENING);

    if (len == -1) {
        return -1;
    }

    return sendpacket(dht->net, sendto->ip_port, packet, len);
}

/* TODO(irungentoo): improve */
static IPPTsPng *get_closelist_IPPTsPng(DHT *dht, const uint8_t *public_key, Family sa_family)
{
    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        if (!id_equal(dht->close_clientlist[i].public_key, public_key)) {
            continue;
        }

        if (sa_family == TOX_AF_INET) {
            return &dht->close_clientlist[i].assoc4;
        }

        if (sa_family == TOX_AF_INET6) {
            return &dht->close_clientlist[i].assoc6;
        }
    }

    return nullptr;
}

/*
 * check how many nodes in nodes are also present in the closelist.
 * TODO(irungentoo): make this function better.
 */
static uint32_t have_nodes_closelist(DHT *dht, Node_format *nodes, uint16_t num)
{
    uint32_t counter = 0;

    for (uint32_t i = 0; i < num; ++i) {
        if (id_equal(nodes[i].public_key, dht->self_public_key)) {
            ++counter;
            continue;
        }

        const IPPTsPng *const temp = get_closelist_IPPTsPng(dht, nodes[i].public_key, nodes[i].ip_port.ip.family);

        if (temp) {
            if (!is_timeout(temp->timestamp, BAD_NODE_TIMEOUT)) {
                ++counter;
            }
        }
    }

    return counter;
}

/* Interval in seconds between hardening checks */
#define HARDENING_INTERVAL 120
#define HARDEN_TIMEOUT 1200

/* Handle a received hardening packet */
static int handle_hardening(void *object, IP_Port source, const uint8_t *source_pubkey, const uint8_t *packet,
                            uint16_t length, void *userdata)
{
    DHT *const dht = (DHT *)object;

    if (length < 2) {
        return 1;
    }

    switch (packet[0]) {
        case CHECK_TYPE_GETNODE_REQ: {
            if (length != HARDREQ_DATA_SIZE) {
                return 1;
            }

            Node_format node, tocheck_node;
            node.ip_port = source;
            memcpy(node.public_key, source_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
            memcpy(&tocheck_node, packet + 1, sizeof(Node_format));

            if (getnodes(dht, tocheck_node.ip_port, tocheck_node.public_key, packet + 1 + sizeof(Node_format), &node) == -1) {
                return 1;
            }

            return 0;
        }

        case CHECK_TYPE_GETNODE_RES: {
            if (length <= CRYPTO_PUBLIC_KEY_SIZE + 1) {
                return 1;
            }

            if (length > 1 + CRYPTO_PUBLIC_KEY_SIZE + sizeof(Node_format) * MAX_SENT_NODES) {
                return 1;
            }

            uint16_t length_nodes = length - 1 - CRYPTO_PUBLIC_KEY_SIZE;
            Node_format nodes[MAX_SENT_NODES];
            const int num_nodes = unpack_nodes(nodes, MAX_SENT_NODES, nullptr, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                               length_nodes, 0);

            /* TODO(irungentoo): MAX_SENT_NODES nodes should be returned at all times
             (right now we have a small network size so it could cause problems for testing and etc..) */
            if (num_nodes <= 0) {
                return 1;
            }

            /* NOTE: This should work for now but should be changed to something better. */
            if (have_nodes_closelist(dht, nodes, num_nodes) < (uint32_t)((num_nodes + 2) / 2)) {
                return 1;
            }

            IPPTsPng *const temp = get_closelist_IPPTsPng(dht, packet + 1, nodes[0].ip_port.ip.family);

            if (temp == nullptr) {
                return 1;
            }

            if (is_timeout(temp->hardening.send_nodes_timestamp, HARDENING_INTERVAL)) {
                return 1;
            }

            if (!id_equal(temp->hardening.send_nodes_pingedid, source_pubkey)) {
                return 1;
            }

            /* If Nodes look good and the request checks out */
            temp->hardening.send_nodes_ok = 1;
            return 0;/* success*/
        }
    }

    return 1;
}

#if DHT_HARDENING
/* Return a random node from all the nodes we are connected to.
 * TODO(irungentoo): improve this function.
 */
static Node_format random_node(DHT *dht, Family sa_family)
{
    uint8_t id[CRYPTO_PUBLIC_KEY_SIZE];

    for (uint32_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE / 4; ++i) { /* populate the id with pseudorandom bytes.*/
        const uint32_t t = rand();
        memcpy(id + i * sizeof(t), &t, sizeof(t));
    }

    Node_format nodes_list[MAX_SENT_NODES];
    memset(nodes_list, 0, sizeof(nodes_list));
    const uint32_t num_nodes = get_close_nodes(dht, id, nodes_list, sa_family, 1, 0);

    if (num_nodes == 0) {
        return nodes_list[0];
    }

    return nodes_list[rand() % num_nodes];
}
#endif

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
static uint16_t list_nodes(Client_data *list, size_t length, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0) {
        return 0;
    }

    uint16_t count = 0;

    for (size_t i = length; i != 0; --i) {
        const IPPTsPng *assoc = nullptr;

        if (!is_timeout(list[i - 1].assoc4.timestamp, BAD_NODE_TIMEOUT)) {
            assoc = &list[i - 1].assoc4;
        }

        if (!is_timeout(list[i - 1].assoc6.timestamp, BAD_NODE_TIMEOUT)) {
            if (assoc == nullptr) {
                assoc = &list[i - 1].assoc6;
            } else if (rand() % 2) {
                assoc = &list[i - 1].assoc6;
            }
        }

        if (assoc != nullptr) {
            memcpy(nodes[count].public_key, list[i - 1].public_key, CRYPTO_PUBLIC_KEY_SIZE);
            nodes[count].ip_port = assoc->ip_port;
            ++count;

            if (count >= max_num) {
                return count;
            }
        }
    }

    return count;
}

/* Put up to max_num nodes in nodes from the random friends.
 *
 * return the number of nodes.
 */
uint16_t randfriends_nodes(DHT *dht, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0) {
        return 0;
    }

    uint16_t count = 0;
    const unsigned int r = rand();

    for (size_t i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        count += list_nodes(dht->friends_list[(i + r) % DHT_FAKE_FRIEND_NUMBER].client_list, MAX_FRIEND_CLIENTS, nodes + count,
                            max_num - count);

        if (count >= max_num) {
            break;
        }
    }

    return count;
}

/* Put up to max_num nodes in nodes from the closelist.
 *
 * return the number of nodes.
 */
uint16_t closelist_nodes(DHT *dht, Node_format *nodes, uint16_t max_num)
{
    return list_nodes(dht->close_clientlist, LCLIENT_LIST, nodes, max_num);
}

#if DHT_HARDENING
static void do_hardening(DHT *dht)
{
    for (uint32_t i = 0; i < LCLIENT_LIST * 2; ++i) {
        IPPTsPng *cur_iptspng;
        Family sa_family;
        const uint8_t *const public_key = dht->close_clientlist[i / 2].public_key;

        if (i % 2 == 0) {
            cur_iptspng = &dht->close_clientlist[i / 2].assoc4;
            sa_family = TOX_AF_INET;
        } else {
            cur_iptspng = &dht->close_clientlist[i / 2].assoc6;
            sa_family = TOX_AF_INET6;
        }

        if (is_timeout(cur_iptspng->timestamp, BAD_NODE_TIMEOUT)) {
            continue;
        }

        if (cur_iptspng->hardening.send_nodes_ok == 0) {
            if (is_timeout(cur_iptspng->hardening.send_nodes_timestamp, HARDENING_INTERVAL)) {
                Node_format rand_node = random_node(dht, sa_family);

                if (!ipport_isset(&rand_node.ip_port)) {
                    continue;
                }

                if (id_equal(public_key, rand_node.public_key)) {
                    continue;
                }

                Node_format to_test;
                to_test.ip_port = cur_iptspng->ip_port;
                memcpy(to_test.public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);

                // TODO(irungentoo): The search id should maybe not be ours?
                if (send_hardening_getnode_req(dht, &rand_node, &to_test, dht->self_public_key) > 0) {
                    memcpy(cur_iptspng->hardening.send_nodes_pingedid, rand_node.public_key, CRYPTO_PUBLIC_KEY_SIZE);
                    cur_iptspng->hardening.send_nodes_timestamp = unix_time();
                }
            }
        } else {
            if (is_timeout(cur_iptspng->hardening.send_nodes_timestamp, HARDEN_TIMEOUT)) {
                cur_iptspng->hardening.send_nodes_ok = 0;
            }
        }

        // TODO(irungentoo): add the 2 other testers.
    }
}
#endif

/*----------------------------------------------------------------------------------*/

void cryptopacket_registerhandler(DHT *dht, uint8_t byte, cryptopacket_handler_callback cb, void *object)
{
    dht->cryptopackethandlers[byte].function = cb;
    dht->cryptopackethandlers[byte].object = object;
}

static int cryptopacket_handle(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    DHT *const dht = (DHT *)object;

    assert(packet[0] == NET_PACKET_CRYPTO);

    if (length <= CRYPTO_PUBLIC_KEY_SIZE * 2 + CRYPTO_NONCE_SIZE + 1 + CRYPTO_MAC_SIZE ||
            length > MAX_CRYPTO_REQUEST_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    // Check if request is for us.
    if (id_equal(packet + 1, dht->self_public_key)) {
        uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
        uint8_t number;
        const int len = handle_request(dht->self_public_key, dht->self_secret_key, public_key,
                                       data, &number, packet, length);

        if (len == -1 || len == 0) {
            return 1;
        }

        if (!dht->cryptopackethandlers[number].function) {
            return 1;
        }

        return dht->cryptopackethandlers[number].function(
                   dht->cryptopackethandlers[number].object, source, public_key,
                   data, len, userdata);
    }

    /* If request is not for us, try routing it. */
    const int retval = route_packet(dht, packet + 1, packet, length);

    if ((unsigned int)retval == length) {
        return 0;
    }

    return 1;
}

/*----------------------------------------------------------------------------------*/

DHT *new_DHT(Logger *log, Networking_Core *net, bool holepunching_enabled)
{
    /* init time */
    unix_time_update();

    if (net == nullptr) {
        return nullptr;
    }

    DHT *const dht = (DHT *)calloc(1, sizeof(DHT));

    if (dht == nullptr) {
        return nullptr;
    }

    dht->log = log;
    dht->net = net;

    dht->hole_punching_enabled = holepunching_enabled;

    dht->ping = ping_new(dht);

    if (dht->ping == nullptr) {
        kill_DHT(dht);
        return nullptr;
    }

    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, &handle_getnodes, dht);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, dht);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO, &cryptopacket_handle, dht);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, &handle_NATping, dht);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_HARDENING, &handle_hardening, dht);

    crypto_new_keypair(dht->self_public_key, dht->self_secret_key);

    dht->dht_ping_array = ping_array_new(DHT_PING_ARRAY_SIZE, PING_TIMEOUT);
    dht->dht_harden_ping_array = ping_array_new(DHT_PING_ARRAY_SIZE, PING_TIMEOUT);

    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        uint8_t random_key_bytes[CRYPTO_PUBLIC_KEY_SIZE];
        random_bytes(random_key_bytes, sizeof(random_key_bytes));

        if (DHT_addfriend(dht, random_key_bytes, nullptr, nullptr, 0, nullptr) != 0) {
            kill_DHT(dht);
            return nullptr;
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

    do_Close(dht);
    do_DHT_friends(dht);
    do_NAT(dht);
    ping_iterate(dht->ping);
#if DHT_HARDENING
    do_hardening(dht);
#endif
    dht->last_run = unix_time();
}

void kill_DHT(DHT *dht)
{
    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, nullptr, nullptr);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, nullptr, nullptr);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, nullptr, nullptr);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_HARDENING, nullptr, nullptr);
    ping_array_kill(dht->dht_ping_array);
    ping_array_kill(dht->dht_harden_ping_array);
    ping_kill(dht->ping);
    free(dht->friends_list);
    free(dht->loaded_nodes_list);
    free(dht);
}

/* new DHT format for load/save, more robust and forward compatible */
// TODO(irungentoo): Move this closer to Messenger.
#define DHT_STATE_COOKIE_GLOBAL 0x159000d

#define DHT_STATE_COOKIE_TYPE      0x11ce
#define DHT_STATE_TYPE_NODES       4

#define MAX_SAVED_DHT_NODES (((DHT_FAKE_FRIEND_NUMBER * MAX_FRIEND_CLIENTS) + LCLIENT_LIST) * 2)

/* Get the size of the DHT (for saving). */
uint32_t DHT_size(const DHT *dht)
{
    uint32_t numv4 = 0;
    uint32_t numv6 = 0;

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        numv4 += (dht->close_clientlist[i].assoc4.timestamp != 0);
        numv6 += (dht->close_clientlist[i].assoc6.timestamp != 0);
    }

    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER && i < dht->num_friends; ++i) {
        const DHT_Friend *const fr = &dht->friends_list[i];

        for (uint32_t j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
            numv4 += (fr->client_list[j].assoc4.timestamp != 0);
            numv6 += (fr->client_list[j].assoc6.timestamp != 0);
        }
    }

    const uint32_t size32 = sizeof(uint32_t);
    const uint32_t sizesubhead = size32 * 2;

    return size32 + sizesubhead + (packed_node_size(TOX_AF_INET) * numv4) + (packed_node_size(TOX_AF_INET6) * numv6);
}

static uint8_t *DHT_save_subheader(uint8_t *data, uint32_t len, uint16_t type)
{
    host_to_lendian32(data, len);
    data += sizeof(uint32_t);
    host_to_lendian32(data, (host_tolendian16(DHT_STATE_COOKIE_TYPE) << 16) | host_tolendian16(type));
    data += sizeof(uint32_t);
    return data;
}


/* Save the DHT in data where data is an array of size DHT_size(). */
void DHT_save(const DHT *dht, uint8_t *data)
{
    host_to_lendian32(data,  DHT_STATE_COOKIE_GLOBAL);
    data += sizeof(uint32_t);

    uint8_t *const old_data = data;

    /* get right offset. we write the actual header later. */
    data = DHT_save_subheader(data, 0, 0);

    Node_format clients[MAX_SAVED_DHT_NODES];

    uint32_t num = 0;

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        if (dht->close_clientlist[i].assoc4.timestamp != 0) {
            memcpy(clients[num].public_key, dht->close_clientlist[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
            clients[num].ip_port = dht->close_clientlist[i].assoc4.ip_port;
            ++num;
        }

        if (dht->close_clientlist[i].assoc6.timestamp != 0) {
            memcpy(clients[num].public_key, dht->close_clientlist[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
            clients[num].ip_port = dht->close_clientlist[i].assoc6.ip_port;
            ++num;
        }
    }

    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER && i < dht->num_friends; ++i) {
        const DHT_Friend *const fr = &dht->friends_list[i];

        for (uint32_t j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
            if (fr->client_list[j].assoc4.timestamp != 0) {
                memcpy(clients[num].public_key, fr->client_list[j].public_key, CRYPTO_PUBLIC_KEY_SIZE);
                clients[num].ip_port = fr->client_list[j].assoc4.ip_port;
                ++num;
            }

            if (fr->client_list[j].assoc6.timestamp != 0) {
                memcpy(clients[num].public_key, fr->client_list[j].public_key, CRYPTO_PUBLIC_KEY_SIZE);
                clients[num].ip_port = fr->client_list[j].assoc6.ip_port;
                ++num;
            }
        }
    }

    DHT_save_subheader(old_data, pack_nodes(data, sizeof(Node_format) * num, clients, num), DHT_STATE_TYPE_NODES);
}

/* Bootstrap from this number of nodes every time DHT_connect_after_load() is called */
#define SAVE_BOOTSTAP_FREQUENCY 8

/* Start sending packets after DHT loaded_friends_list and loaded_clients_list are set */
int DHT_connect_after_load(DHT *dht)
{
    if (dht == nullptr) {
        return -1;
    }

    if (!dht->loaded_nodes_list) {
        return -1;
    }

    /* DHT is connected, stop. */
    if (DHT_non_lan_connected(dht)) {
        free(dht->loaded_nodes_list);
        dht->loaded_nodes_list = nullptr;
        dht->loaded_num_nodes = 0;
        return 0;
    }

    for (uint32_t i = 0; i < dht->loaded_num_nodes && i < SAVE_BOOTSTAP_FREQUENCY; ++i) {
        const unsigned int index = dht->loaded_nodes_index % dht->loaded_num_nodes;
        DHT_bootstrap(dht, dht->loaded_nodes_list[index].ip_port, dht->loaded_nodes_list[index].public_key);
        ++dht->loaded_nodes_index;
    }

    return 0;
}

static int dht_load_state_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
{
    DHT *dht = (DHT *)outer;

    switch (type) {
        case DHT_STATE_TYPE_NODES: {
            if (length == 0) {
                break;
            }

            free(dht->loaded_nodes_list);
            // Copy to loaded_clients_list
            dht->loaded_nodes_list = (Node_format *)calloc(MAX_SAVED_DHT_NODES, sizeof(Node_format));

            const int num = unpack_nodes(dht->loaded_nodes_list, MAX_SAVED_DHT_NODES, nullptr, data, length, 0);

            if (num > 0) {
                dht->loaded_num_nodes = num;
            } else {
                dht->loaded_num_nodes = 0;
            }

            break;
        }

        default:
            LOGGER_ERROR(dht->log, "Load state (DHT): contains unrecognized part (len %u, type %u)\n",
                         length, type);
            break;
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
    const uint32_t cookie_len = sizeof(uint32_t);

    if (length > cookie_len) {
        uint32_t data32;
        lendian_to_host32(&data32, data);

        if (data32 == DHT_STATE_COOKIE_GLOBAL) {
            return load_state(dht_load_state_callback, dht->log, dht, data + cookie_len,
                              length - cookie_len, DHT_STATE_COOKIE_TYPE);
        }
    }

    return -1;
}

/*  return false if we are not connected to the DHT.
 *  return true if we are.
 */
bool DHT_isconnected(const DHT *dht)
{
    unix_time_update();

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *const client = &dht->close_clientlist[i];

        if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) ||
                !is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT)) {
            return true;
        }
    }

    return false;
}

/*  return false if we are not connected or only connected to lan peers with the DHT.
 *  return true if we are.
 */
bool DHT_non_lan_connected(const DHT *dht)
{
    unix_time_update();

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *const client = &dht->close_clientlist[i];

        if (!is_timeout(client->assoc4.timestamp, BAD_NODE_TIMEOUT) && ip_is_lan(client->assoc4.ip_port.ip) == -1) {
            return true;
        }

        if (!is_timeout(client->assoc6.timestamp, BAD_NODE_TIMEOUT) && ip_is_lan(client->assoc6.ip_port.ip) == -1) {
            return true;
        }
    }

    return false;
}
