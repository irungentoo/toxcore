/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * An implementation of the DHT as seen in docs/updates/DHT.md
 */
#include "DHT.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "LAN_discovery.h"
#include "ccompat.h"
#include "logger.h"
#include "mono_time.h"
#include "network.h"
#include "ping.h"
#include "state.h"
#include "util.h"

/** The timeout after which a node is discarded completely. */
#define KILL_NODE_TIMEOUT (BAD_NODE_TIMEOUT + PING_INTERVAL)

/** Ping interval in seconds for each random sending of a get nodes request. */
#define GET_NODE_INTERVAL 20

#define MAX_PUNCHING_PORTS 48

/** Interval in seconds between punching attempts*/
#define PUNCH_INTERVAL 3

/** Time in seconds after which punching parameters will be reset */
#define PUNCH_RESET_TIME 40

#define MAX_NORMAL_PUNCHING_TRIES 5

#define NAT_PING_REQUEST    0
#define NAT_PING_RESPONSE   1

/** Number of get node requests to send to quickly find close nodes. */
#define MAX_BOOTSTRAP_TIMES 5

typedef struct DHT_Friend_Callback {
    dht_ip_cb *ip_callback;
    void *data;
    int32_t number;
} DHT_Friend_Callback;

struct DHT_Friend {
    uint8_t     public_key[CRYPTO_PUBLIC_KEY_SIZE];
    Client_data client_list[MAX_FRIEND_CLIENTS];

    /* Time at which the last get_nodes request was sent. */
    uint64_t    lastgetnode;
    /* number of times get_node packets were sent. */
    uint32_t    bootstrap_times;

    /* Symmetric NAT hole punching stuff. */
    NAT         nat;

    uint16_t lock_count;
    DHT_Friend_Callback callbacks[DHT_FRIEND_MAX_LOCKS];

    Node_format to_bootstrap[MAX_SENT_NODES];
    unsigned int num_to_bootstrap;
};

static const DHT_Friend empty_dht_friend = {{0}};
const Node_format empty_node_format = {{0}};

typedef struct Cryptopacket_Handler {
    cryptopacket_handler_cb *function;
    void *object;
} Cryptopacket_Handler;

struct DHT {
    const Logger *log;
    const Network *ns;
    Mono_Time *mono_time;
    const Random *rng;
    Networking_Core *net;

    bool hole_punching_enabled;
    bool lan_discovery_enabled;

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
    uint64_t       cur_time;

    Cryptopacket_Handler cryptopackethandlers[256];

    Node_format to_bootstrap[MAX_CLOSE_TO_BOOTSTRAP_NODES];
    unsigned int num_to_bootstrap;

    dht_get_nodes_response_cb *get_nodes_response;
};

const uint8_t *dht_friend_public_key(const DHT_Friend *dht_friend)
{
    return dht_friend->public_key;
}

const Client_data *dht_friend_client(const DHT_Friend *dht_friend, size_t index)
{
    return &dht_friend->client_list[index];
}

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

non_null()
static bool assoc_timeout(uint64_t cur_time, const IPPTsPng *assoc)
{
    return (assoc->timestamp + BAD_NODE_TIMEOUT) <= cur_time;
}

/** @brief Converts an IPv4-in-IPv6 to IPv4 and returns the new IP_Port.
 *
 * If the ip_port is already IPv4 this function returns a copy of the original ip_port.
 */
non_null()
static IP_Port ip_port_normalize(const IP_Port *ip_port)
{
    IP_Port res = *ip_port;

    if (net_family_is_ipv6(res.ip.family) && ipv6_ipv4_in_v6(&res.ip.ip.v6)) {
        res.ip.family = net_family_ipv4();
        res.ip.ip.v4.uint32 = res.ip.ip.v6.uint32[3];
    }

    return res;
}

/** @brief Compares pk1 and pk2 with pk.
 *
 * @retval 0 if both are same distance.
 * @retval 1 if pk1 is closer.
 * @retval 2 if pk2 is closer.
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

/** Return index of first unequal bit number between public keys pk1 and pk2. */
unsigned int bit_by_bit_cmp(const uint8_t *pk1, const uint8_t *pk2)
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

/**
 * Shared key generations are costly, it is therefore smart to store commonly used
 * ones so that they can be re-used later without being computed again.
 *
 * If a shared key is already in shared_keys, copy it to shared_key.
 * Otherwise generate it into shared_key and copy it to shared_keys
 */
void get_shared_key(const Mono_Time *mono_time, Shared_Keys *shared_keys, uint8_t *shared_key,
                    const uint8_t *secret_key, const uint8_t *public_key)
{
    uint32_t num = -1;
    uint32_t curr = 0;

    for (uint32_t i = 0; i < MAX_KEYS_PER_SLOT; ++i) {
        const int index = public_key[30] * MAX_KEYS_PER_SLOT + i;
        Shared_Key *const key = &shared_keys->keys[index];

        if (key->stored) {
            if (pk_equal(public_key, key->public_key)) {
                memcpy(shared_key, key->shared_key, CRYPTO_SHARED_KEY_SIZE);
                ++key->times_requested;
                key->time_last_requested = mono_time_get(mono_time);
                return;
            }

            if (num != 0) {
                if (mono_time_is_timeout(mono_time, key->time_last_requested, KEYS_TIMEOUT)) {
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
        key->stored = true;
        key->times_requested = 1;
        memcpy(key->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(key->shared_key, shared_key, CRYPTO_SHARED_KEY_SIZE);
        key->time_last_requested = mono_time_get(mono_time);
    }
}

/**
 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we receive.
 */
void dht_get_shared_key_recv(DHT *dht, uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key(dht->mono_time, &dht->shared_keys_recv, shared_key, dht->self_secret_key, public_key);
}

/**
 * Copy shared_key to encrypt/decrypt DHT packet from public_key into shared_key
 * for packets that we send.
 */
void dht_get_shared_key_sent(DHT *dht, uint8_t *shared_key, const uint8_t *public_key)
{
    get_shared_key(dht->mono_time, &dht->shared_keys_sent, shared_key, dht->self_secret_key, public_key);
}

#define CRYPTO_SIZE (1 + CRYPTO_PUBLIC_KEY_SIZE * 2 + CRYPTO_NONCE_SIZE)

/**
 * @brief Create a request to peer.
 *
 * Packs the data and sender public key and encrypts the packet.
 *
 * @param[in] send_public_key public key of the sender.
 * @param[in] send_secret_key secret key of the sender.
 * @param[out] packet an array of @ref MAX_CRYPTO_REQUEST_SIZE big.
 * @param[in] recv_public_key public key of the receiver.
 * @param[in] data represents the data we send with the request.
 * @param[in] data_length the length of the data.
 * @param[in] request_id the id of the request (32 = friend request, 254 = ping request).
 *
 * @attention Constraints:
 * @code
 * sizeof(packet) >= MAX_CRYPTO_REQUEST_SIZE
 * @endcode
 *
 * @retval -1 on failure.
 * @return the length of the created packet on success.
 */
int create_request(const Random *rng, const uint8_t *send_public_key, const uint8_t *send_secret_key,
                   uint8_t *packet, const uint8_t *recv_public_key,
                   const uint8_t *data, uint32_t data_length, uint8_t request_id)
{
    if (send_public_key == nullptr || packet == nullptr || recv_public_key == nullptr || data == nullptr) {
        return -1;
    }

    if (MAX_CRYPTO_REQUEST_SIZE < data_length + CRYPTO_SIZE + 1 + CRYPTO_MAC_SIZE) {
        return -1;
    }

    uint8_t *const nonce = packet + 1 + CRYPTO_PUBLIC_KEY_SIZE * 2;
    random_nonce(rng, nonce);
    uint8_t temp[MAX_CRYPTO_REQUEST_SIZE] = {0};
    temp[0] = request_id;
    memcpy(temp + 1, data, data_length);
    const int len = encrypt_data(recv_public_key, send_secret_key, nonce, temp, data_length + 1,
                                 packet + CRYPTO_SIZE);

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

/**
 * @brief Decrypts and unpacks a DHT request packet.
 *
 * Puts the senders public key in the request in @p public_key, the data from
 * the request in @p data.
 *
 * @param[in] self_public_key public key of the receiver (us).
 * @param[in] self_secret_key secret key of the receiver (us).
 * @param[out] public_key public key of the sender, copied from the input packet.
 * @param[out] data decrypted request data, copied from the input packet, must
 *   have room for @ref MAX_CRYPTO_REQUEST_SIZE bytes.
 * @param[in] packet is the request packet.
 * @param[in] packet_length length of the packet.
 *
 * @attention Constraints:
 * @code
 * sizeof(data) >= MAX_CRYPTO_REQUEST_SIZE
 * @endcode
 *
 * @retval -1 if not valid request.
 * @return the length of the unpacked data.
 */
int handle_request(const uint8_t *self_public_key, const uint8_t *self_secret_key, uint8_t *public_key, uint8_t *data,
                   uint8_t *request_id, const uint8_t *packet, uint16_t packet_length)
{
    if (self_public_key == nullptr || public_key == nullptr || data == nullptr || request_id == nullptr
            || packet == nullptr) {
        return -1;
    }

    if (packet_length <= CRYPTO_SIZE + CRYPTO_MAC_SIZE || packet_length > MAX_CRYPTO_REQUEST_SIZE) {
        return -1;
    }

    if (!pk_equal(packet + 1, self_public_key)) {
        return -1;
    }

    memcpy(public_key, packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_PUBLIC_KEY_SIZE);
    const uint8_t *const nonce = packet + 1 + CRYPTO_PUBLIC_KEY_SIZE * 2;
    uint8_t temp[MAX_CRYPTO_REQUEST_SIZE];
    int32_t len1 = decrypt_data(public_key, self_secret_key, nonce,
                                packet + CRYPTO_SIZE, packet_length - CRYPTO_SIZE, temp);

    if (len1 == -1 || len1 == 0) {
        crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
        return -1;
    }

    assert(len1 == packet_length - CRYPTO_SIZE - CRYPTO_MAC_SIZE);
    // Because coverity can't figure out this equation:
    assert(len1 <= MAX_CRYPTO_REQUEST_SIZE - CRYPTO_SIZE - CRYPTO_MAC_SIZE);

    request_id[0] = temp[0];
    --len1;
    memcpy(data, temp + 1, len1);
    crypto_memzero(temp, MAX_CRYPTO_REQUEST_SIZE);
    return len1;
}

/** @return packet size of packed node with ip_family on success.
 * @retval -1 on failure.
 */
int packed_node_size(Family ip_family)
{
    if (net_family_is_ipv4(ip_family) || net_family_is_tcp_ipv4(ip_family)) {
        return PACKED_NODE_SIZE_IP4;
    }

    if (net_family_is_ipv6(ip_family) || net_family_is_tcp_ipv6(ip_family)) {
        return PACKED_NODE_SIZE_IP6;
    }

    return -1;
}


/** @brief Pack an IP_Port structure into data of max size length.
 *
 * Packed_length is the offset of data currently packed.
 *
 * @return size of packed IP_Port data on success.
 * @retval -1 on failure.
 */
int pack_ip_port(const Logger *logger, uint8_t *data, uint16_t length, const IP_Port *ip_port)
{
    if (data == nullptr) {
        return -1;
    }

    bool is_ipv4;
    uint8_t family;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        // TODO(irungentoo): use functions to convert endianness
        is_ipv4 = true;
        family = TOX_AF_INET;
    } else if (net_family_is_tcp_ipv4(ip_port->ip.family)) {
        is_ipv4 = true;
        family = TOX_TCP_INET;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        is_ipv4 = false;
        family = TOX_AF_INET6;
    } else if (net_family_is_tcp_ipv6(ip_port->ip.family)) {
        is_ipv4 = false;
        family = TOX_TCP_INET6;
    } else {
        Ip_Ntoa ip_str;
        // TODO(iphydf): Find out why we're trying to pack invalid IPs, stop
        // doing that, and turn this into an error.
        LOGGER_TRACE(logger, "cannot pack invalid IP: %s", net_ip_ntoa(&ip_port->ip, &ip_str));
        return -1;
    }

    if (is_ipv4) {
        const uint32_t size = 1 + SIZE_IP4 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        data[0] = family;
        memcpy(data + 1, &ip_port->ip.ip.v4, SIZE_IP4);
        memcpy(data + 1 + SIZE_IP4, &ip_port->port, sizeof(uint16_t));
        return size;
    } else {
        const uint32_t size = 1 + SIZE_IP6 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        data[0] = family;
        memcpy(data + 1, &ip_port->ip.ip.v6, SIZE_IP6);
        memcpy(data + 1 + SIZE_IP6, &ip_port->port, sizeof(uint16_t));
        return size;
    }
}

/** @brief Encrypt plain and write resulting DHT packet into packet with max size length.
 *
 * @return size of packet on success.
 * @retval -1 on failure.
 */
int dht_create_packet(const Random *rng, const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                      const uint8_t *shared_key, const uint8_t type,
                      const uint8_t *plain, size_t plain_length,
                      uint8_t *packet, size_t length)
{
    uint8_t *encrypted = (uint8_t *)malloc(plain_length + CRYPTO_MAC_SIZE);
    uint8_t nonce[CRYPTO_NONCE_SIZE];

    if (encrypted == nullptr) {
        return -1;
    }

    random_nonce(rng, nonce);

    const int encrypted_length = encrypt_data_symmetric(shared_key, nonce, plain, plain_length, encrypted);

    if (encrypted_length == -1) {
        free(encrypted);
        return -1;
    }

    if (length < 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encrypted_length) {
        free(encrypted);
        return -1;
    }

    packet[0] = type;
    memcpy(packet + 1, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypted, encrypted_length);

    free(encrypted);
    return 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + encrypted_length;
}

/** @brief Unpack IP_Port structure from data of max size length into ip_port.
 *
 * len_processed is the offset of data currently unpacked.
 *
 * @return size of unpacked ip_port on success.
 * @retval -1 on failure.
 */
int unpack_ip_port(IP_Port *ip_port, const uint8_t *data, uint16_t length, bool tcp_enabled)
{
    if (data == nullptr) {
        return -1;
    }

    bool is_ipv4;
    Family host_family;

    if (data[0] == TOX_AF_INET) {
        is_ipv4 = true;
        host_family = net_family_ipv4();
    } else if (data[0] == TOX_TCP_INET) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = true;
        host_family = net_family_tcp_ipv4();
    } else if (data[0] == TOX_AF_INET6) {
        is_ipv4 = false;
        host_family = net_family_ipv6();
    } else if (data[0] == TOX_TCP_INET6) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = false;
        host_family = net_family_tcp_ipv6();
    } else {
        return -1;
    }

    *ip_port = empty_ip_port;

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

/** @brief Pack number of nodes into data of maxlength length.
 *
 * @return length of packed nodes on success.
 * @retval -1 on failure.
 */
int pack_nodes(const Logger *logger, uint8_t *data, uint16_t length, const Node_format *nodes, uint16_t number)
{
    uint32_t packed_length = 0;

    for (uint32_t i = 0; i < number && packed_length < length; ++i) {
        const int ipp_size = pack_ip_port(logger, data + packed_length, length - packed_length, &nodes[i].ip_port);

        if (ipp_size == -1) {
            return -1;
        }

        packed_length += ipp_size;

        if (packed_length + CRYPTO_PUBLIC_KEY_SIZE > length) {
            return -1;
        }

        memcpy(data + packed_length, nodes[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
        packed_length += CRYPTO_PUBLIC_KEY_SIZE;

#ifndef NDEBUG
        const uint32_t increment = ipp_size + CRYPTO_PUBLIC_KEY_SIZE;
#endif
        assert(increment == PACKED_NODE_SIZE_IP4 || increment == PACKED_NODE_SIZE_IP6);
    }

    return packed_length;
}

/** @brief Unpack data of length into nodes of size max_num_nodes.
 * Put the length of the data processed in processed_data_len.
 * tcp_enabled sets if TCP nodes are expected (true) or not (false).
 *
 * @return number of unpacked nodes on success.
 * @retval -1 on failure.
 */
int unpack_nodes(Node_format *nodes, uint16_t max_num_nodes, uint16_t *processed_data_len, const uint8_t *data,
                 uint16_t length, bool tcp_enabled)
{
    uint32_t num = 0;
    uint32_t len_processed = 0;

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

#ifndef NDEBUG
        const uint32_t increment = ipp_size + CRYPTO_PUBLIC_KEY_SIZE;
#endif
        assert(increment == PACKED_NODE_SIZE_IP4 || increment == PACKED_NODE_SIZE_IP6);
    }

    if (processed_data_len != nullptr) {
        *processed_data_len = len_processed;
    }

    return num;
}

/** @brief Find index in an array with public_key equal to pk.
 *
 * @return index or UINT32_MAX if not found.
 */
non_null(3) nullable(1)
static uint32_t index_of_client_pk(const Client_data *array, uint32_t size, const uint8_t *pk)
{
    assert(size == 0 || array != nullptr);

    for (uint32_t i = 0; i < size; ++i) {
        if (pk_equal(array[i].public_key, pk)) {
            return i;
        }
    }

    return UINT32_MAX;
}

non_null(3) nullable(1)
static uint32_t index_of_friend_pk(const DHT_Friend *array, uint32_t size, const uint8_t *pk)
{
    assert(size == 0 || array != nullptr);

    for (uint32_t i = 0; i < size; ++i) {
        if (pk_equal(array[i].public_key, pk)) {
            return i;
        }
    }

    return UINT32_MAX;
}

non_null(3) nullable(1)
static uint32_t index_of_node_pk(const Node_format *array, uint32_t size, const uint8_t *pk)
{
    assert(size == 0 || array != nullptr);

    for (uint32_t i = 0; i < size; ++i) {
        if (pk_equal(array[i].public_key, pk)) {
            return i;
        }
    }

    return UINT32_MAX;
}

/** @brief Find index of Client_data with ip_port equal to param ip_port.
 *
 * @return index or UINT32_MAX if not found.
 */
non_null(3) nullable(1)
static uint32_t index_of_client_ip_port(const Client_data *array, uint32_t size, const IP_Port *ip_port)
{
    assert(size == 0 || array != nullptr);

    for (uint32_t i = 0; i < size; ++i) {
        if ((net_family_is_ipv4(ip_port->ip.family) && ipport_equal(&array[i].assoc4.ip_port, ip_port)) ||
                (net_family_is_ipv6(ip_port->ip.family) && ipport_equal(&array[i].assoc6.ip_port, ip_port))) {
            return i;
        }
    }

    return UINT32_MAX;
}

/** Update ip_port of client if it's needed. */
non_null()
static void update_client(const Logger *log, const Mono_Time *mono_time, int index, Client_data *client,
                          const IP_Port *ip_port)
{
    IPPTsPng *assoc;
    int ip_version;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        assoc = &client->assoc4;
        ip_version = 4;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        assoc = &client->assoc6;
        ip_version = 6;
    } else {
        return;
    }

    if (!ipport_equal(&assoc->ip_port, ip_port)) {
        Ip_Ntoa ip_str_from;
        Ip_Ntoa ip_str_to;
        LOGGER_TRACE(log, "coipil[%u]: switching ipv%d from %s:%u to %s:%u",
                     index, ip_version,
                     net_ip_ntoa(&assoc->ip_port.ip, &ip_str_from),
                     net_ntohs(assoc->ip_port.port),
                     net_ip_ntoa(&ip_port->ip, &ip_str_to),
                     net_ntohs(ip_port->port));
    }

    if (!ip_is_lan(&assoc->ip_port.ip) && ip_is_lan(&ip_port->ip)) {
        return;
    }

    assoc->ip_port = *ip_port;
    assoc->timestamp = mono_time_get(mono_time);
}

/** @brief Check if client with public_key is already in list of length length.
 *
 * If it is then set its corresponding timestamp to current time.
 * If the id is already in the list with a different ip_port, update it.
 * TODO(irungentoo): Maybe optimize this.
 */
non_null()
static bool client_or_ip_port_in_list(const Logger *log, const Mono_Time *mono_time, Client_data *list, uint16_t length,
                                      const uint8_t *public_key, const IP_Port *ip_port)
{
    const uint64_t temp_time = mono_time_get(mono_time);
    uint32_t index = index_of_client_pk(list, length, public_key);

    /* if public_key is in list, find it and maybe overwrite ip_port */
    if (index != UINT32_MAX) {
        update_client(log, mono_time, index, &list[index], ip_port);
        return true;
    }

    /* public_key not in list yet: see if we can find an identical ip_port, in
     * that case we kill the old public_key by overwriting it with the new one
     * TODO(irungentoo): maybe we SHOULDN'T do that if that public_key is in a friend_list
     * and the one who is the actual friend's public_key/address set?
     * MAYBE: check the other address, if valid, don't nuke? */
    index = index_of_client_ip_port(list, length, ip_port);

    if (index == UINT32_MAX) {
        return false;
    }

    IPPTsPng *assoc;
    int ip_version;

    if (net_family_is_ipv4(ip_port->ip.family)) {
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
    const IPPTsPng empty_ipptspng = {{{{0}}}};
    *assoc = empty_ipptspng;
    return true;
}

bool add_to_list(Node_format *nodes_list, uint32_t length, const uint8_t *pk, const IP_Port *ip_port,
                 const uint8_t *cmp_pk)
{
    for (uint32_t i = 0; i < length; ++i) {
        if (id_closest(cmp_pk, nodes_list[i].public_key, pk) == 2) {
            uint8_t pk_bak[CRYPTO_PUBLIC_KEY_SIZE];
            memcpy(pk_bak, nodes_list[i].public_key, CRYPTO_PUBLIC_KEY_SIZE);
            const IP_Port ip_port_bak = nodes_list[i].ip_port;
            memcpy(nodes_list[i].public_key, pk, CRYPTO_PUBLIC_KEY_SIZE);
            nodes_list[i].ip_port = *ip_port;

            if (i != length - 1) {
                add_to_list(nodes_list, length, pk_bak, &ip_port_bak, cmp_pk);
            }

            return true;
        }
    }

    return false;
}

/**
 * helper for `get_close_nodes()`. argument list is a monster :D
 */
non_null()
static void get_close_nodes_inner(uint64_t cur_time, const uint8_t *public_key, Node_format *nodes_list,
                                  Family sa_family, const Client_data *client_list, uint32_t client_list_length,
                                  uint32_t *num_nodes_ptr, bool is_LAN,
                                  bool want_announce)
{
    if (!net_family_is_ipv4(sa_family) && !net_family_is_ipv6(sa_family) && !net_family_is_unspec(sa_family)) {
        return;
    }

    uint32_t num_nodes = *num_nodes_ptr;

    for (uint32_t i = 0; i < client_list_length; ++i) {
        const Client_data *const client = &client_list[i];

        /* node already in list? */
        if (index_of_node_pk(nodes_list, MAX_SENT_NODES, client->public_key) != UINT32_MAX) {
            continue;
        }

        const IPPTsPng *ipptp;

        if (net_family_is_ipv4(sa_family)) {
            ipptp = &client->assoc4;
        } else if (net_family_is_ipv6(sa_family)) {
            ipptp = &client->assoc6;
        } else if (client->assoc4.timestamp >= client->assoc6.timestamp) {
            ipptp = &client->assoc4;
        } else {
            ipptp = &client->assoc6;
        }

        /* node not in a good condition? */
        if (assoc_timeout(cur_time, ipptp)) {
            continue;
        }

        /* don't send LAN ips to non LAN peers */
        if (ip_is_lan(&ipptp->ip_port.ip) && !is_LAN) {
            continue;
        }

#ifdef CHECK_ANNOUNCE_NODE

        if (want_announce && !client->announce_node) {
            continue;
        }

#endif

        if (num_nodes < MAX_SENT_NODES) {
            memcpy(nodes_list[num_nodes].public_key, client->public_key, CRYPTO_PUBLIC_KEY_SIZE);
            nodes_list[num_nodes].ip_port = ipptp->ip_port;
            ++num_nodes;
        } else {
            // TODO(zugz): this could be made significantly more efficient by
            // using a version of add_to_list which works with a sorted list.
            add_to_list(nodes_list, MAX_SENT_NODES, client->public_key, &ipptp->ip_port, public_key);
        }
    }

    *num_nodes_ptr = num_nodes;
}

/**
 * Find MAX_SENT_NODES nodes closest to the public_key for the send nodes request:
 * put them in the nodes_list and return how many were found.
 *
 * want_announce: return only nodes which implement the dht announcements protocol.
 */
non_null()
static int get_somewhat_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list,
                                    Family sa_family, bool is_LAN, bool want_announce)
{
    uint32_t num_nodes = 0;
    get_close_nodes_inner(dht->cur_time, public_key, nodes_list, sa_family,
                          dht->close_clientlist, LCLIENT_LIST, &num_nodes, is_LAN, want_announce);

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        get_close_nodes_inner(dht->cur_time, public_key, nodes_list, sa_family,
                              dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS,
                              &num_nodes, is_LAN, want_announce);
    }

    return num_nodes;
}

int get_close_nodes(const DHT *dht, const uint8_t *public_key, Node_format *nodes_list, Family sa_family,
                    bool is_LAN, bool want_announce)
{
    memset(nodes_list, 0, MAX_SENT_NODES * sizeof(Node_format));
    return get_somewhat_close_nodes(dht, public_key, nodes_list, sa_family,
                                    is_LAN, want_announce);
}

typedef struct DHT_Cmp_Data {
    uint64_t cur_time;
    const uint8_t *base_public_key;
    Client_data entry;
} DHT_Cmp_Data;

non_null()
static int dht_cmp_entry(const void *a, const void *b)
{
    const DHT_Cmp_Data *cmp1 = (const DHT_Cmp_Data *)a;
    const DHT_Cmp_Data *cmp2 = (const DHT_Cmp_Data *)b;
    const Client_data entry1 = cmp1->entry;
    const Client_data entry2 = cmp2->entry;
    const uint8_t *cmp_public_key = cmp1->base_public_key;

    const bool t1 = assoc_timeout(cmp1->cur_time, &entry1.assoc4) && assoc_timeout(cmp1->cur_time, &entry1.assoc6);
    const bool t2 = assoc_timeout(cmp2->cur_time, &entry2.assoc4) && assoc_timeout(cmp2->cur_time, &entry2.assoc6);

    if (t1 && t2) {
        return 0;
    }

    if (t1) {
        return -1;
    }

    if (t2) {
        return 1;
    }

    const int closest = id_closest(cmp_public_key, entry1.public_key, entry2.public_key);

    if (closest == 1) {
        return 1;
    }

    if (closest == 2) {
        return -1;
    }

    return 0;
}

#ifdef CHECK_ANNOUNCE_NODE
non_null()
static void set_announce_node_in_list(Client_data *list, uint32_t list_len, const uint8_t *public_key)
{
    const uint32_t index = index_of_client_pk(list, list_len, public_key);

    if (index != UINT32_MAX) {
        list[index].announce_node = true;
    }
}

void set_announce_node(DHT *dht, const uint8_t *public_key)
{
    unsigned int index = bit_by_bit_cmp(public_key, dht->self_public_key);

    if (index >= LCLIENT_LENGTH) {
        index = LCLIENT_LENGTH - 1;
    }

    set_announce_node_in_list(dht->close_clientlist + index * LCLIENT_NODES, LCLIENT_NODES, public_key);

    for (int32_t i = 0; i < dht->num_friends; ++i) {
        set_announce_node_in_list(dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, public_key);
    }
}

/** @brief Send data search request, searching for a random key. */
non_null()
static bool send_announce_ping(DHT *dht, const uint8_t *public_key, const IP_Port *ip_port)
{
    uint8_t plain[CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t)];

    uint8_t unused_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(dht->rng, plain, unused_secret_key);

    const uint64_t ping_id = ping_array_add(dht->dht_ping_array,
                                            dht->mono_time,
                                            dht->rng,
                                            public_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, &ping_id, sizeof(ping_id));

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_sent(dht, shared_key, public_key);

    uint8_t request[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE];

    if (dht_create_packet(dht->rng, dht->self_public_key, shared_key, NET_PACKET_DATA_SEARCH_REQUEST,
                          plain, sizeof(plain), request, sizeof(request)) != sizeof(request)) {
        return false;
    }

    return sendpacket(dht->net, ip_port, request, sizeof(request)) == sizeof(request);
}

/** @brief If the response is valid, set the sender as an announce node. */
non_null(1, 2, 3) nullable(5)
static int handle_data_search_response(void *object, const IP_Port *source,
                                       const uint8_t *packet, uint16_t length,
                                       void *userdata)
{
    DHT *dht = (DHT *) object;

    const int32_t plain_len = (int32_t)length - (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (plain_len < (int32_t)(CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t))) {
        return 1;
    }

    VLA(uint8_t, plain, plain_len);
    const uint8_t *public_key = packet + 1;
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_recv(dht, shared_key, public_key);

    if (decrypt_data_symmetric(shared_key,
                               packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                               packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                               plain_len + CRYPTO_MAC_SIZE,
                               plain) != plain_len) {
        return 1;
    }

    uint64_t ping_id;
    memcpy(&ping_id, plain + (plain_len - sizeof(uint64_t)), sizeof(ping_id));

    uint8_t ping_data[CRYPTO_PUBLIC_KEY_SIZE];

    if (ping_array_check(dht->dht_ping_array,
                         dht->mono_time, ping_data,
                         sizeof(ping_data), ping_id) != sizeof(ping_data)) {
        return 1;
    }

    if (!pk_equal(ping_data, public_key)) {
        return 1;
    }

    set_announce_node(dht, public_key);

    return 0;

}
#endif

/** @brief Is it ok to store node with public_key in client.
 *
 * return false if node can't be stored.
 * return true if it can.
 */
non_null()
static bool store_node_ok(const Client_data *client, uint64_t cur_time, const uint8_t *public_key,
                          const uint8_t *comp_public_key)
{
    return (assoc_timeout(cur_time, &client->assoc4)
            && assoc_timeout(cur_time, &client->assoc6))
           || id_closest(comp_public_key, client->public_key, public_key) == 2;
}

non_null()
static void sort_client_list(Client_data *list, uint64_t cur_time, unsigned int length,
                             const uint8_t *comp_public_key)
{
    // Pass comp_public_key to qsort with each Client_data entry, so the
    // comparison function can use it as the base of comparison.
    DHT_Cmp_Data *cmp_list = (DHT_Cmp_Data *)calloc(length, sizeof(DHT_Cmp_Data));

    if (cmp_list == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < length; ++i) {
        cmp_list[i].cur_time = cur_time;
        cmp_list[i].base_public_key = comp_public_key;
        cmp_list[i].entry = list[i];
    }

    qsort(cmp_list, length, sizeof(DHT_Cmp_Data), dht_cmp_entry);

    for (uint32_t i = 0; i < length; ++i) {
        list[i] = cmp_list[i].entry;
    }

    free(cmp_list);
}

non_null()
static void update_client_with_reset(const Mono_Time *mono_time, Client_data *client, const IP_Port *ip_port)
{
    IPPTsPng *ipptp_write = nullptr;
    IPPTsPng *ipptp_clear = nullptr;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        ipptp_write = &client->assoc4;
        ipptp_clear = &client->assoc6;
    } else {
        ipptp_write = &client->assoc6;
        ipptp_clear = &client->assoc4;
    }

    ipptp_write->ip_port = *ip_port;
    ipptp_write->timestamp = mono_time_get(mono_time);

    ip_reset(&ipptp_write->ret_ip_port.ip);
    ipptp_write->ret_ip_port.port = 0;
    ipptp_write->ret_timestamp = 0;
    ipptp_write->ret_ip_self = false;

    /* zero out other address */
    memset(ipptp_clear, 0, sizeof(*ipptp_clear));
}

/**
 * Replace a first bad (or empty) node with this one
 * or replace a possibly bad node (tests failed or not done yet)
 * that is further than any other in the list
 * from the comp_public_key
 * or replace a good node that is further
 * than any other in the list from the comp_public_key
 * and further than public_key.
 *
 * Do not replace any node if the list has no bad or possibly bad nodes
 * and all nodes in the list are closer to comp_public_key
 * than public_key.
 *
 * @return true when the item was stored, false otherwise
 */
non_null()
static bool replace_all(const DHT *dht,
                        Client_data    *list,
                        uint16_t        length,
                        const uint8_t  *public_key,
                        const IP_Port  *ip_port,
                        const uint8_t  *comp_public_key)
{
    if (!net_family_is_ipv4(ip_port->ip.family) && !net_family_is_ipv6(ip_port->ip.family)) {
        return false;
    }

    if (!store_node_ok(&list[1], dht->cur_time, public_key, comp_public_key) &&
            !store_node_ok(&list[0], dht->cur_time, public_key, comp_public_key)) {
        return false;
    }

    sort_client_list(list, dht->cur_time, length, comp_public_key);

    Client_data *const client = &list[0];
    pk_copy(client->public_key, public_key);

    update_client_with_reset(dht->mono_time, client, ip_port);
    return true;
}

/** @brief Add node to close list.
 *
 * simulate is set to 1 if we want to check if a node can be added to the list without adding it.
 *
 * return false on failure.
 * return true on success.
 */
non_null()
static bool add_to_close(DHT *dht, const uint8_t *public_key, const IP_Port *ip_port, bool simulate)
{
    unsigned int index = bit_by_bit_cmp(public_key, dht->self_public_key);

    if (index >= LCLIENT_LENGTH) {
        index = LCLIENT_LENGTH - 1;
    }

    for (uint32_t i = 0; i < LCLIENT_NODES; ++i) {
        /* TODO(iphydf): write bounds checking test to catch the case that
         * index is left as >= LCLIENT_LENGTH */
        Client_data *const client = &dht->close_clientlist[(index * LCLIENT_NODES) + i];

        if (!assoc_timeout(dht->cur_time, &client->assoc4) ||
                !assoc_timeout(dht->cur_time, &client->assoc6)) {
            continue;
        }

        if (simulate) {
            return true;
        }

        pk_copy(client->public_key, public_key);
        update_client_with_reset(dht->mono_time, client, ip_port);
#ifdef CHECK_ANNOUNCE_NODE
        client->announce_node = false;
        send_announce_ping(dht, public_key, ip_port);
#endif
        return true;
    }

    return false;
}

/** Return 1 if node can be added to close list, 0 if it can't. */
bool node_addable_to_close_list(DHT *dht, const uint8_t *public_key, const IP_Port *ip_port)
{
    return add_to_close(dht, public_key, ip_port, true);
}

non_null()
static bool is_pk_in_client_list(const Client_data *list, unsigned int client_list_length, uint64_t cur_time,
                                 const uint8_t *public_key, const IP_Port *ip_port)
{
    const uint32_t index = index_of_client_pk(list, client_list_length, public_key);

    if (index == UINT32_MAX) {
        return false;
    }

    const IPPTsPng *assoc = net_family_is_ipv4(ip_port->ip.family)
                            ? &list[index].assoc4
                            : &list[index].assoc6;

    return !assoc_timeout(cur_time, assoc);
}

non_null()
static bool is_pk_in_close_list(const DHT *dht, const uint8_t *public_key, const IP_Port *ip_port)
{
    unsigned int index = bit_by_bit_cmp(public_key, dht->self_public_key);

    if (index >= LCLIENT_LENGTH) {
        index = LCLIENT_LENGTH - 1;
    }

    return is_pk_in_client_list(dht->close_clientlist + index * LCLIENT_NODES, LCLIENT_NODES, dht->cur_time, public_key,
                                ip_port);
}

/** @brief Check if the node obtained with a get_nodes with public_key should be pinged.
 *
 * NOTE: for best results call it after addto_lists.
 *
 * return false if the node should not be pinged.
 * return true if it should.
 */
non_null()
static bool ping_node_from_getnodes_ok(DHT *dht, const uint8_t *public_key, const IP_Port *ip_port)
{
    bool ret = false;

    if (add_to_close(dht, public_key, ip_port, true)) {
        ret = true;
    }

    {
        unsigned int *const num = &dht->num_to_bootstrap;
        const uint32_t index = index_of_node_pk(dht->to_bootstrap, *num, public_key);
        const bool in_close_list = is_pk_in_close_list(dht, public_key, ip_port);

        if (ret && index == UINT32_MAX && !in_close_list) {
            if (*num < MAX_CLOSE_TO_BOOTSTRAP_NODES) {
                memcpy(dht->to_bootstrap[*num].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
                dht->to_bootstrap[*num].ip_port = *ip_port;
                ++*num;
            } else {
                // TODO(irungentoo): ipv6 vs v4
                add_to_list(dht->to_bootstrap, MAX_CLOSE_TO_BOOTSTRAP_NODES, public_key, ip_port, dht->self_public_key);
            }
        }
    }

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        DHT_Friend *dht_friend = &dht->friends_list[i];

        bool store_ok = false;

        if (store_node_ok(&dht_friend->client_list[1], dht->cur_time, public_key, dht_friend->public_key)) {
            store_ok = true;
        }

        if (store_node_ok(&dht_friend->client_list[0], dht->cur_time, public_key, dht_friend->public_key)) {
            store_ok = true;
        }

        unsigned int *const friend_num = &dht_friend->num_to_bootstrap;
        const uint32_t index = index_of_node_pk(dht_friend->to_bootstrap, *friend_num, public_key);
        const bool pk_in_list = is_pk_in_client_list(dht_friend->client_list, MAX_FRIEND_CLIENTS, dht->cur_time, public_key,
                                ip_port);

        if (store_ok && index == UINT32_MAX && !pk_in_list) {
            if (*friend_num < MAX_SENT_NODES) {
                Node_format *const format = &dht_friend->to_bootstrap[*friend_num];
                memcpy(format->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
                format->ip_port = *ip_port;
                ++*friend_num;
            } else {
                add_to_list(dht_friend->to_bootstrap, MAX_SENT_NODES, public_key, ip_port, dht_friend->public_key);
            }

            ret = true;
        }
    }

    return ret;
}

/** @brief Attempt to add client with ip_port and public_key to the friends client list
 * and close_clientlist.
 *
 * @return 1+ if the item is used in any list, 0 else
 */
uint32_t addto_lists(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key)
{
    IP_Port ipp_copy = ip_port_normalize(ip_port);

    uint32_t used = 0;

    /* NOTE: Current behavior if there are two clients with the same id is
     * to replace the first ip by the second.
     */
    const bool in_close_list = client_or_ip_port_in_list(dht->log, dht->mono_time, dht->close_clientlist, LCLIENT_LIST,
                               public_key, &ipp_copy);

    /* add_to_close should be called only if !in_list (don't extract to variable) */
    if (in_close_list || !add_to_close(dht, public_key, &ipp_copy, false)) {
        ++used;
    }

    const DHT_Friend *friend_foundip = nullptr;

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        const bool in_list = client_or_ip_port_in_list(dht->log, dht->mono_time, dht->friends_list[i].client_list,
                             MAX_FRIEND_CLIENTS, public_key, &ipp_copy);

        /* replace_all should be called only if !in_list (don't extract to variable) */
        if (in_list
                || replace_all(dht, dht->friends_list[i].client_list, MAX_FRIEND_CLIENTS, public_key, &ipp_copy,
                               dht->friends_list[i].public_key)) {
            const DHT_Friend *dht_friend = &dht->friends_list[i];

            if (pk_equal(public_key, dht_friend->public_key)) {
                friend_foundip = dht_friend;
            }

            ++used;
        }
    }

    if (friend_foundip == nullptr) {
        return used;
    }

    for (uint32_t i = 0; i < friend_foundip->lock_count; ++i) {
        if (friend_foundip->callbacks[i].ip_callback != nullptr) {
            friend_foundip->callbacks[i].ip_callback(friend_foundip->callbacks[i].data,
                    friend_foundip->callbacks[i].number, &ipp_copy);
        }
    }

    return used;
}

non_null()
static bool update_client_data(const Mono_Time *mono_time, Client_data *array, size_t size, const IP_Port *ip_port,
                               const uint8_t *pk, bool node_is_self)
{
    const uint64_t temp_time = mono_time_get(mono_time);
    const uint32_t index = index_of_client_pk(array, size, pk);

    if (index == UINT32_MAX) {
        return false;
    }

    Client_data *const data = &array[index];
    IPPTsPng *assoc;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        assoc = &data->assoc4;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        assoc = &data->assoc6;
    } else {
        return true;
    }

    assoc->ret_ip_port = *ip_port;
    assoc->ret_timestamp = temp_time;
    assoc->ret_ip_self = node_is_self;

    return true;
}

/**
 * If public_key is a friend or us, update ret_ip_port
 * nodepublic_key is the id of the node that sent us this info.
 */
non_null()
static void returnedip_ports(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key, const uint8_t *nodepublic_key)
{
    IP_Port ipp_copy = ip_port_normalize(ip_port);

    if (pk_equal(public_key, dht->self_public_key)) {
        update_client_data(dht->mono_time, dht->close_clientlist, LCLIENT_LIST, &ipp_copy, nodepublic_key, true);
        return;
    }

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        if (pk_equal(public_key, dht->friends_list[i].public_key)) {
            Client_data *const client_list = dht->friends_list[i].client_list;

            if (update_client_data(dht->mono_time, client_list, MAX_FRIEND_CLIENTS, &ipp_copy, nodepublic_key, false)) {
                return;
            }
        }
    }
}

bool dht_getnodes(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key, const uint8_t *client_id)
{
    /* Check if packet is going to be sent to ourself. */
    if (pk_equal(public_key, dht->self_public_key)) {
        return false;
    }

    uint8_t plain_message[sizeof(Node_format) * 2] = {0};

    Node_format receiver;
    memcpy(receiver.public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    receiver.ip_port = *ip_port;

    if (pack_nodes(dht->log, plain_message, sizeof(plain_message), &receiver, 1) == -1) {
        return false;
    }

    uint64_t ping_id = 0;

    ping_id = ping_array_add(dht->dht_ping_array, dht->mono_time, dht->rng, plain_message, sizeof(receiver));

    if (ping_id == 0) {
        LOGGER_ERROR(dht->log, "adding ping id failed");
        return false;
    }

    uint8_t plain[CRYPTO_PUBLIC_KEY_SIZE + sizeof(ping_id)];
    uint8_t data[1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + sizeof(plain) + CRYPTO_MAC_SIZE];

    memcpy(plain, client_id, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(plain + CRYPTO_PUBLIC_KEY_SIZE, &ping_id, sizeof(ping_id));

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_sent(dht, shared_key, public_key);

    const int len = dht_create_packet(dht->rng,
                                      dht->self_public_key, shared_key, NET_PACKET_GET_NODES,
                                      plain, sizeof(plain), data, sizeof(data));

    crypto_memzero(shared_key, sizeof(shared_key));

    if (len != sizeof(data)) {
        LOGGER_ERROR(dht->log, "getnodes packet encryption failed");
        return false;
    }

    return sendpacket(dht->net, ip_port, data, len) > 0;
}

/** Send a send nodes response: message for IPv6 nodes */
non_null()
static int sendnodes_ipv6(const DHT *dht, const IP_Port *ip_port, const uint8_t *public_key, const uint8_t *client_id,
                          const uint8_t *sendback_data, uint16_t length, const uint8_t *shared_encryption_key)
{
    /* Check if packet is going to be sent to ourself. */
    if (pk_equal(public_key, dht->self_public_key)) {
        return -1;
    }

    if (length != sizeof(uint64_t)) {
        return -1;
    }

    const size_t node_format_size = sizeof(Node_format);

    Node_format nodes_list[MAX_SENT_NODES];
    const uint32_t num_nodes =
        get_close_nodes(dht, client_id, nodes_list, net_family_unspec(), ip_is_lan(&ip_port->ip), false);

    VLA(uint8_t, plain, 1 + node_format_size * MAX_SENT_NODES + length);

    int nodes_length = 0;

    if (num_nodes > 0) {
        nodes_length = pack_nodes(dht->log, plain + 1, node_format_size * MAX_SENT_NODES, nodes_list, num_nodes);

        if (nodes_length <= 0) {
            return -1;
        }
    }

    plain[0] = num_nodes;
    memcpy(plain + 1 + nodes_length, sendback_data, length);

    const uint32_t crypto_size = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE;
    VLA(uint8_t, data, 1 + nodes_length + length + crypto_size);

    const int len = dht_create_packet(dht->rng,
                                      dht->self_public_key, shared_encryption_key, NET_PACKET_SEND_NODES_IPV6,
                                      plain, 1 + nodes_length + length, data, SIZEOF_VLA(data));

    if (len != SIZEOF_VLA(data)) {
        return -1;
    }

    return sendpacket(dht->net, ip_port, data, len);
}

#define CRYPTO_NODE_SIZE (CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t))

non_null()
static int handle_getnodes(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length != (CRYPTO_SIZE + CRYPTO_MAC_SIZE + sizeof(uint64_t))) {
        return 1;
    }

    DHT *const dht = (DHT *)object;

    /* Check if packet is from ourself. */
    if (pk_equal(packet + 1, dht->self_public_key)) {
        return 1;
    }

    uint8_t plain[CRYPTO_NODE_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    dht_get_shared_key_recv(dht, shared_key, packet + 1);
    const int len = decrypt_data_symmetric(
                        shared_key,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                        CRYPTO_NODE_SIZE + CRYPTO_MAC_SIZE,
                        plain);

    if (len != CRYPTO_NODE_SIZE) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return 1;
    }

    sendnodes_ipv6(dht, source, packet + 1, plain, plain + CRYPTO_PUBLIC_KEY_SIZE, sizeof(uint64_t), shared_key);

    ping_add(dht->ping, packet + 1, source);

    crypto_memzero(shared_key, sizeof(shared_key));

    return 0;
}

/** Return true if we sent a getnode packet to the peer associated with the supplied info. */
non_null()
static bool sent_getnode_to_node(DHT *dht, const uint8_t *public_key, const IP_Port *node_ip_port, uint64_t ping_id)
{
    uint8_t data[sizeof(Node_format) * 2];

    if (ping_array_check(dht->dht_ping_array, dht->mono_time, data, sizeof(data), ping_id) != sizeof(Node_format)) {
        return false;
    }

    Node_format test;

    if (unpack_nodes(&test, 1, nullptr, data, sizeof(data), false) != 1) {
        return false;
    }

    return ipport_equal(&test.ip_port, node_ip_port) && pk_equal(test.public_key, public_key);
}

non_null()
static bool handle_sendnodes_core(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                  Node_format *plain_nodes, uint16_t size_plain_nodes, uint32_t *num_nodes_out)
{
    DHT *const dht = (DHT *)object;
    const uint32_t cid_size = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + 1 + sizeof(uint64_t) + CRYPTO_MAC_SIZE;

    if (length < cid_size) { /* too short */
        return false;
    }

    const uint32_t data_size = length - cid_size;

    if (data_size == 0) {
        return false;
    }

    if (data_size > sizeof(Node_format) * MAX_SENT_NODES) { /* invalid length */
        return false;
    }

    VLA(uint8_t, plain, 1 + data_size + sizeof(uint64_t));
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_sent(dht, shared_key, packet + 1);
    const int len = decrypt_data_symmetric(
                        shared_key,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                        packet + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                        1 + data_size + sizeof(uint64_t) + CRYPTO_MAC_SIZE,
                        plain);

    crypto_memzero(shared_key, sizeof(shared_key));

    if ((unsigned int)len != SIZEOF_VLA(plain)) {
        return false;
    }

    if (plain[0] > size_plain_nodes) {
        return false;
    }

    uint64_t ping_id;
    memcpy(&ping_id, plain + 1 + data_size, sizeof(ping_id));

    if (!sent_getnode_to_node(dht, packet + 1, source, ping_id)) {
        return false;
    }

    uint16_t length_nodes = 0;
    const int num_nodes = unpack_nodes(plain_nodes, plain[0], &length_nodes, plain + 1, data_size, false);

    if (length_nodes != data_size) {
        return false;
    }

    if (num_nodes != plain[0]) {
        return false;
    }

    if (num_nodes < 0) {
        return false;
    }

    /* store the address the *request* was sent to */
    addto_lists(dht, source, packet + 1);

    *num_nodes_out = num_nodes;

    return true;
}

non_null()
static int handle_sendnodes_ipv6(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                                 void *userdata)
{
    DHT *const dht = (DHT *)object;
    Node_format plain_nodes[MAX_SENT_NODES];
    uint32_t num_nodes;

    if (!handle_sendnodes_core(object, source, packet, length, plain_nodes, MAX_SENT_NODES, &num_nodes)) {
        return 1;
    }

    if (num_nodes == 0) {
        return 0;
    }

    for (uint32_t i = 0; i < num_nodes; ++i) {
        if (ipport_isset(&plain_nodes[i].ip_port)) {
            ping_node_from_getnodes_ok(dht, plain_nodes[i].public_key, &plain_nodes[i].ip_port);
            returnedip_ports(dht, &plain_nodes[i].ip_port, plain_nodes[i].public_key, packet + 1);

            if (dht->get_nodes_response != nullptr) {
                dht->get_nodes_response(dht, &plain_nodes[i], userdata);
            }
        }
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*------------------------END of packet handling functions--------------------------*/

non_null(1) nullable(2, 3, 5)
static void dht_friend_lock(DHT_Friend *const dht_friend, dht_ip_cb *ip_callback,
                            void *data, int32_t number, uint16_t *lock_count)
{
    const uint16_t lock_num = dht_friend->lock_count;
    ++dht_friend->lock_count;
    dht_friend->callbacks[lock_num].ip_callback = ip_callback;
    dht_friend->callbacks[lock_num].data = data;
    dht_friend->callbacks[lock_num].number = number;

    if (lock_count != nullptr) {
        *lock_count = lock_num + 1;
    }
}

int dht_addfriend(DHT *dht, const uint8_t *public_key, dht_ip_cb *ip_callback,
                  void *data, int32_t number, uint16_t *lock_count)
{
    const uint32_t friend_num = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    if (friend_num != UINT32_MAX) { /* Is friend already in DHT? */
        DHT_Friend *const dht_friend = &dht->friends_list[friend_num];

        if (dht_friend->lock_count == DHT_FRIEND_MAX_LOCKS) {
            return -1;
        }

        dht_friend_lock(dht_friend, ip_callback, data, number, lock_count);

        return 0;
    }

    DHT_Friend *const temp = (DHT_Friend *)realloc(dht->friends_list, sizeof(DHT_Friend) * (dht->num_friends + 1));

    if (temp == nullptr) {
        return -1;
    }

    dht->friends_list = temp;
    DHT_Friend *const dht_friend = &dht->friends_list[dht->num_friends];
    *dht_friend = empty_dht_friend;
    memcpy(dht_friend->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    dht_friend->nat.nat_ping_id = random_u64(dht->rng);
    ++dht->num_friends;

    dht_friend_lock(dht_friend, ip_callback, data, number, lock_count);

    dht_friend->num_to_bootstrap = get_close_nodes(dht, dht_friend->public_key, dht_friend->to_bootstrap, net_family_unspec(),
                                   true, false);

    return 0;
}

int dht_delfriend(DHT *dht, const uint8_t *public_key, uint16_t lock_count)
{
    const uint32_t friend_num = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    if (friend_num == UINT32_MAX) {
        return -1;
    }

    DHT_Friend *const dht_friend = &dht->friends_list[friend_num];
    --dht_friend->lock_count;

    if (dht_friend->lock_count > 0 && lock_count > 0) { /* DHT friend is still in use.*/
        --lock_count;
        dht_friend->callbacks[lock_count].ip_callback = nullptr;
        dht_friend->callbacks[lock_count].data = nullptr;
        dht_friend->callbacks[lock_count].number = 0;
        return 0;
    }

    --dht->num_friends;

    if (dht->num_friends != friend_num) {
        dht->friends_list[friend_num] = dht->friends_list[dht->num_friends];
    }

    if (dht->num_friends == 0) {
        free(dht->friends_list);
        dht->friends_list = nullptr;
        return 0;
    }

    DHT_Friend *const temp = (DHT_Friend *)realloc(dht->friends_list, sizeof(DHT_Friend) * dht->num_friends);

    if (temp == nullptr) {
        return -1;
    }

    dht->friends_list = temp;
    return 0;
}

/* TODO(irungentoo): Optimize this. */
int dht_getfriendip(const DHT *dht, const uint8_t *public_key, IP_Port *ip_port)
{
    ip_reset(&ip_port->ip);
    ip_port->port = 0;

    const uint32_t friend_index = index_of_friend_pk(dht->friends_list, dht->num_friends, public_key);

    if (friend_index == UINT32_MAX) {
        return -1;
    }

    const DHT_Friend *const frnd = &dht->friends_list[friend_index];
    const uint32_t client_index = index_of_client_pk(frnd->client_list, MAX_FRIEND_CLIENTS, public_key);

    if (client_index == -1) {
        return 0;
    }

    const Client_data *const client = &frnd->client_list[client_index];
    const IPPTsPng *const assocs[] = { &client->assoc6, &client->assoc4, nullptr };

    for (const IPPTsPng * const *it = assocs; *it != nullptr; ++it) {
        const IPPTsPng *const assoc = *it;

        if (!assoc_timeout(dht->cur_time, assoc)) {
            *ip_port = assoc->ip_port;
            return 1;
        }
    }

    return -1;
}

/** returns number of nodes not in kill-timeout */
non_null()
static uint8_t do_ping_and_sendnode_requests(DHT *dht, uint64_t *lastgetnode, const uint8_t *public_key,
        Client_data *list, uint32_t list_count, uint32_t *bootstrap_times, bool sortable)
{
    uint8_t not_kill = 0;
    const uint64_t temp_time = mono_time_get(dht->mono_time);

    uint32_t num_nodes = 0;
    Client_data **client_list = (Client_data **)calloc(list_count * 2, sizeof(Client_data *));
    IPPTsPng **assoc_list = (IPPTsPng **)calloc(list_count * 2, sizeof(IPPTsPng *));
    unsigned int sort = 0;
    bool sort_ok = false;

    if (client_list == nullptr || assoc_list == nullptr) {
        free(assoc_list);
        free(client_list);
        return 0;
    }

    for (uint32_t i = 0; i < list_count; ++i) {
        /* If node is not dead. */
        Client_data *client = &list[i];

        IPPTsPng *const assocs[] = { &client->assoc6, &client->assoc4 };

        for (uint32_t j = 0; j < sizeof(assocs) / sizeof(assocs[0]); ++j) {
            IPPTsPng *const assoc = assocs[j];

            if (!mono_time_is_timeout(dht->mono_time, assoc->timestamp, KILL_NODE_TIMEOUT)) {
                sort = 0;
                ++not_kill;

                if (mono_time_is_timeout(dht->mono_time, assoc->last_pinged, PING_INTERVAL)) {
                    dht_getnodes(dht, &assoc->ip_port, client->public_key, public_key);
                    assoc->last_pinged = temp_time;
                }

                /* If node is good. */
                if (!assoc_timeout(dht->cur_time, assoc)) {
                    client_list[num_nodes] = client;
                    assoc_list[num_nodes] = assoc;
                    ++num_nodes;
                }
            } else {
                ++sort;

                /* Timed out should be at beginning, if they are not, sort the list. */
                if (sort > 1 && sort < (((j + 1) * 2) - 1)) {
                    sort_ok = true;
                }
            }
        }
    }

    if (sortable && sort_ok) {
        sort_client_list(list, dht->cur_time, list_count, public_key);
    }

    if (num_nodes > 0 && (mono_time_is_timeout(dht->mono_time, *lastgetnode, GET_NODE_INTERVAL)
                          || *bootstrap_times < MAX_BOOTSTRAP_TIMES)) {
        uint32_t rand_node = random_range_u32(dht->rng, num_nodes);

        if ((num_nodes - 1) != rand_node) {
            rand_node += random_range_u32(dht->rng, num_nodes - (rand_node + 1));
        }

        dht_getnodes(dht, &assoc_list[rand_node]->ip_port, client_list[rand_node]->public_key, public_key);

        *lastgetnode = temp_time;
        ++*bootstrap_times;
    }

    free(assoc_list);
    free(client_list);
    return not_kill;
}

/** @brief Ping each client in the "friends" list every PING_INTERVAL seconds.
 *
 * Send a get nodes request  every GET_NODE_INTERVAL seconds to a random good
 * node for each "friend" in our "friends" list.
 */
non_null()
static void do_dht_friends(DHT *dht)
{
    for (size_t i = 0; i < dht->num_friends; ++i) {
        DHT_Friend *const dht_friend = &dht->friends_list[i];

        for (size_t j = 0; j < dht_friend->num_to_bootstrap; ++j) {
            dht_getnodes(dht, &dht_friend->to_bootstrap[j].ip_port, dht_friend->to_bootstrap[j].public_key, dht_friend->public_key);
        }

        dht_friend->num_to_bootstrap = 0;

        do_ping_and_sendnode_requests(dht, &dht_friend->lastgetnode, dht_friend->public_key, dht_friend->client_list,
                                      MAX_FRIEND_CLIENTS,
                                      &dht_friend->bootstrap_times, true);
    }
}

/** @brief Ping each client in the close nodes list every PING_INTERVAL seconds.
 *
 * Send a get nodes request every GET_NODE_INTERVAL seconds to a random good node in the list.
 */
non_null()
static void do_Close(DHT *dht)
{
    for (size_t i = 0; i < dht->num_to_bootstrap; ++i) {
        dht_getnodes(dht, &dht->to_bootstrap[i].ip_port, dht->to_bootstrap[i].public_key, dht->self_public_key);
    }

    dht->num_to_bootstrap = 0;

    const uint8_t not_killed = do_ping_and_sendnode_requests(
                                   dht, &dht->close_lastgetnodes, dht->self_public_key, dht->close_clientlist, LCLIENT_LIST, &dht->close_bootstrap_times,
                                   false);

    if (not_killed != 0) {
        return;
    }

    /* all existing nodes are at least KILL_NODE_TIMEOUT,
     * which means we are mute, as we only send packets to
     * nodes NOT in KILL_NODE_TIMEOUT
     *
     * so: reset all nodes to be BAD_NODE_TIMEOUT, but not
     * KILL_NODE_TIMEOUT, so we at least keep trying pings */
    const uint64_t badonly = mono_time_get(dht->mono_time) - BAD_NODE_TIMEOUT;

    for (size_t i = 0; i < LCLIENT_LIST; ++i) {
        Client_data *const client = &dht->close_clientlist[i];

        IPPTsPng *const assocs[] = { &client->assoc6, &client->assoc4, nullptr };

        for (IPPTsPng * const *it = assocs; *it != nullptr; ++it) {
            IPPTsPng *const assoc = *it;

            if (assoc->timestamp != 0) {
                assoc->timestamp = badonly;
            }
        }
    }
}

bool dht_bootstrap(DHT *dht, const IP_Port *ip_port, const uint8_t *public_key)
{
    if (pk_equal(public_key, dht->self_public_key)) {
        // Bootstrapping off ourselves is ok (onion paths are still set up).
        return true;
    }

    return dht_getnodes(dht, ip_port, public_key, dht->self_public_key);
}

int dht_bootstrap_from_address(DHT *dht, const char *address, bool ipv6enabled,
                               uint16_t port, const uint8_t *public_key)
{
    IP_Port ip_port_v64;
    IP *ip_extra = nullptr;
    IP_Port ip_port_v4;
    ip_init(&ip_port_v64.ip, ipv6enabled);

    if (ipv6enabled) {
        /* setup for getting BOTH: an IPv6 AND an IPv4 address */
        ip_port_v64.ip.family = net_family_unspec();
        ip_reset(&ip_port_v4.ip);
        ip_extra = &ip_port_v4.ip;
    }

    if (addr_resolve_or_parse_ip(dht->ns, address, &ip_port_v64.ip, ip_extra)) {
        ip_port_v64.port = port;
        dht_bootstrap(dht, &ip_port_v64, public_key);

        if ((ip_extra != nullptr) && ip_isset(ip_extra)) {
            ip_port_v4.port = port;
            dht_bootstrap(dht, &ip_port_v4, public_key);
        }

        return 1;
    }

    return 0;
}

/** @brief Send the given packet to node with public_key.
 *
 * @return number of bytes sent.
 * @retval -1 if failure.
 */
int route_packet(const DHT *dht, const uint8_t *public_key, const uint8_t *packet, uint16_t length)
{
    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        if (pk_equal(public_key, dht->close_clientlist[i].public_key)) {
            const Client_data *const client = &dht->close_clientlist[i];
            const IPPTsPng *const assocs[] = { &client->assoc6, &client->assoc4, nullptr };

            for (const IPPTsPng * const *it = assocs; *it != nullptr; ++it) {
                const IPPTsPng *const assoc = *it;

                if (ip_isset(&assoc->ip_port.ip)) {
                    return sendpacket(dht->net, &assoc->ip_port, packet, length);
                }
            }

            break;
        }
    }

    return -1;
}

/** @brief Puts all the different ips returned by the nodes for a friend_num into array ip_portlist.
 *
 * ip_portlist must be at least MAX_FRIEND_CLIENTS big.
 *
 * @return the number of ips returned.
 * @retval 0 if we are connected to friend or if no ips were found.
 * @retval -1 if no such friend.
 */
non_null()
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
        if (ip_isset(&client->assoc4.ret_ip_port.ip)
                && !mono_time_is_timeout(dht->mono_time, client->assoc4.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv4s[num_ipv4s] = client->assoc4.ret_ip_port;
            ++num_ipv4s;
        }

        if (ip_isset(&client->assoc6.ret_ip_port.ip)
                && !mono_time_is_timeout(dht->mono_time, client->assoc6.ret_timestamp, BAD_NODE_TIMEOUT)) {
            ipv6s[num_ipv6s] = client->assoc6.ret_ip_port;
            ++num_ipv6s;
        }

        if (pk_equal(client->public_key, dht_friend->public_key)) {
            if (!assoc_timeout(dht->cur_time, &client->assoc6)
                    || !assoc_timeout(dht->cur_time, &client->assoc4)) {
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


/**
 * Callback invoked for each IP/port of each client of a friend.
 *
 * For each client, the callback is invoked twice: once for IPv4 and once for
 * IPv6. If the callback returns `false` after the IPv4 invocation, it will not
 * be invoked for IPv6.
 *
 * @param dht The main DHT instance.
 * @param ip_port The currently processed IP/port.
 * @param n A pointer to the number that will be returned from `foreach_ip_port`.
 * @param userdata The `userdata` pointer passed to `foreach_ip_port`.
 */
typedef bool foreach_ip_port_cb(const DHT *dht, const IP_Port *ip_port, uint32_t *n, void *userdata);

/**
 * Runs a callback on every active connection for a given DHT friend.
 *
 * This iterates over the client list of a DHT friend and invokes a callback for
 * every non-zero IP/port (IPv4 and IPv6) that's not timed out.
 *
 * @param dht The main DHT instance, passed to the callback.
 * @param dht_friend The friend over whose connections we should iterate.
 * @param callback The callback to invoke for each IP/port.
 * @param userdata Extra pointer passed to the callback.
 */
non_null()
static uint32_t foreach_ip_port(const DHT *dht, const DHT_Friend *dht_friend,
                                foreach_ip_port_cb *callback, void *userdata)
{
    uint32_t n = 0;

    /* extra legwork, because having the outside allocating the space for us
     * is *usually* good(tm) (bites us in the behind in this case though) */
    for (uint32_t i = 0; i < MAX_FRIEND_CLIENTS; ++i) {
        const Client_data *const client = &dht_friend->client_list[i];
        const IPPTsPng *const assocs[] = { &client->assoc4, &client->assoc6, nullptr };

        for (const IPPTsPng * const *it = assocs; *it != nullptr; ++it) {
            const IPPTsPng *const assoc = *it;

            /* If ip is not zero and node is good. */
            if (!ip_isset(&assoc->ret_ip_port.ip)
                    && !mono_time_is_timeout(dht->mono_time, assoc->ret_timestamp, BAD_NODE_TIMEOUT)) {
                continue;
            }

            if (!callback(dht, &assoc->ip_port, &n, userdata)) {
                /* If the callback is happy with just one of the assocs, we
                 * don't give it the second one. */
                break;
            }
        }
    }

    return n;
}

non_null()
static bool send_packet_to_friend(const DHT *dht, const IP_Port *ip_port, uint32_t *n, void *userdata)
{
    const Packet *packet = (const Packet *)userdata;
    const int retval = send_packet(dht->net, ip_port, *packet);

    if ((uint32_t)retval == packet->length) {
        ++*n;
        /* Send one packet per friend: stop the foreach on the first success. */
        return false;
    }

    return true;
}

/**
 * Send the following packet to everyone who tells us they are connected to friend_id.
 *
 * @return ip for friend.
 * @return number of nodes the packet was sent to. (Only works if more than (MAX_FRIEND_CLIENTS / 4).
 */
uint32_t route_to_friend(const DHT *dht, const uint8_t *friend_id, const Packet *packet)
{
    const uint32_t num = index_of_friend_pk(dht->friends_list, dht->num_friends, friend_id);

    if (num == UINT32_MAX) {
        return 0;
    }


    IP_Port ip_list[MAX_FRIEND_CLIENTS];
    const int ip_num = friend_iplist(dht, ip_list, num);

    if (ip_num < MAX_FRIEND_CLIENTS / 4) {
        return 0; /* Reason for that? */
    }

    const DHT_Friend *const dht_friend = &dht->friends_list[num];
    Packet packet_userdata = *packet;  // Copy because it needs to be non-const.

    return foreach_ip_port(dht, dht_friend, send_packet_to_friend, &packet_userdata);
}

non_null()
static bool get_ip_port(const DHT *dht, const IP_Port *ip_port, uint32_t *n, void *userdata)
{
    IP_Port *ip_list = (IP_Port *)userdata;
    ip_list[*n] = *ip_port;
    ++*n;
    return true;
}

/** @brief Send the following packet to one random person who tells us they are connected to friend_id.
 *
 * @return number of nodes the packet was sent to.
 */
non_null()
static uint32_t routeone_to_friend(const DHT *dht, const uint8_t *friend_id, const Packet *packet)
{
    const uint32_t num = index_of_friend_pk(dht->friends_list, dht->num_friends, friend_id);

    if (num == UINT32_MAX) {
        return 0;
    }

    const DHT_Friend *const dht_friend = &dht->friends_list[num];

    IP_Port ip_list[MAX_FRIEND_CLIENTS * 2];

    const int n = foreach_ip_port(dht, dht_friend, get_ip_port, ip_list);

    if (n < 1) {
        return 0;
    }

    const uint32_t rand_idx = random_range_u32(dht->rng, n);
    const int retval = send_packet(dht->net, &ip_list[rand_idx], *packet);

    if ((unsigned int)retval == packet->length) {
        return 1;
    }

    return 0;
}

/*----------------------------------------------------------------------------------*/
/*---------------------BEGINNING OF NAT PUNCHING FUNCTIONS--------------------------*/

non_null()
static int send_NATping(const DHT *dht, const uint8_t *public_key, uint64_t ping_id, uint8_t type)
{
    uint8_t data[sizeof(uint64_t) + 1];
    uint8_t packet_data[MAX_CRYPTO_REQUEST_SIZE];

    data[0] = type;
    memcpy(data + 1, &ping_id, sizeof(uint64_t));
    /* 254 is NAT ping request packet id */
    const int len = create_request(
                        dht->rng, dht->self_public_key, dht->self_secret_key, packet_data, public_key,
                        data, sizeof(uint64_t) + 1, CRYPTO_PACKET_NAT_PING);

    if (len == -1) {
        return -1;
    }

    assert(len <= UINT16_MAX);
    uint32_t num = 0;
    const Packet packet = {packet_data, (uint16_t)len};

    if (type == 0) { /* If packet is request use many people to route it. */
        num = route_to_friend(dht, public_key, &packet);
    } else if (type == 1) { /* If packet is response use only one person to route it */
        num = routeone_to_friend(dht, public_key, &packet);
    }

    if (num == 0) {
        return -1;
    }

    return num;
}

/** Handle a received ping request for. */
non_null()
static int handle_NATping(void *object, const IP_Port *source, const uint8_t *source_pubkey, const uint8_t *packet,
                          uint16_t length, void *userdata)
{
    if (length != sizeof(uint64_t) + 1) {
        return 1;
    }

    DHT *const dht = (DHT *)object;
    uint64_t ping_id;
    memcpy(&ping_id, packet + 1, sizeof(uint64_t));

    const uint32_t friendnumber = index_of_friend_pk(dht->friends_list, dht->num_friends, source_pubkey);

    if (friendnumber == UINT32_MAX) {
        return 1;
    }

    DHT_Friend *const dht_friend = &dht->friends_list[friendnumber];

    if (packet[0] == NAT_PING_REQUEST) {
        /* 1 is reply */
        send_NATping(dht, source_pubkey, ping_id, NAT_PING_RESPONSE);
        dht_friend->nat.recv_nat_ping_timestamp = mono_time_get(dht->mono_time);
        return 0;
    }

    if (packet[0] == NAT_PING_RESPONSE) {
        if (dht_friend->nat.nat_ping_id == ping_id) {
            dht_friend->nat.nat_ping_id = random_u64(dht->rng);
            dht_friend->nat.hole_punching = true;
            return 0;
        }
    }

    return 1;
}

/** @brief Get the most common ip in the ip_portlist.
 * Only return ip if it appears in list min_num or more.
 * len must not be bigger than MAX_FRIEND_CLIENTS.
 *
 * @return ip of 0 if failure.
 */
non_null()
static IP nat_commonip(const IP_Port *ip_portlist, uint16_t len, uint16_t min_num)
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

/** @brief Return all the ports for one ip in a list.
 * portlist must be at least len long,
 * where len is the length of ip_portlist.
 *
 * @return number of ports and puts the list of ports in portlist.
 */
non_null()
static uint16_t nat_getports(uint16_t *portlist, const IP_Port *ip_portlist, uint16_t len, const IP *ip)
{
    uint16_t num = 0;

    for (uint32_t i = 0; i < len; ++i) {
        if (ip_equal(&ip_portlist[i].ip, ip)) {
            portlist[num] = net_ntohs(ip_portlist[i].port);
            ++num;
        }
    }

    return num;
}

non_null()
static void punch_holes(DHT *dht, const IP *ip, const uint16_t *port_list, uint16_t numports, uint16_t friend_num)
{
    if (!dht->hole_punching_enabled) {
        return;
    }

    if (numports > MAX_FRIEND_CLIENTS || numports == 0) {
        return;
    }

    const uint16_t first_port = port_list[0];
    uint16_t port_candidate;

    for (port_candidate = 0; port_candidate < numports; ++port_candidate) {
        if (first_port != port_list[port_candidate]) {
            break;
        }
    }

    if (port_candidate == numports) { /* If all ports are the same, only try that one port. */
        IP_Port pinging;
        ip_copy(&pinging.ip, ip);
        pinging.port = net_htons(first_port);
        ping_send_request(dht->ping, &pinging, dht->friends_list[friend_num].public_key);
    } else {
        uint16_t i;
        for (i = 0; i < MAX_PUNCHING_PORTS; ++i) {
            /* TODO(irungentoo): Improve port guessing algorithm. */
            const uint32_t it = i + dht->friends_list[friend_num].nat.punching_index;
            const int8_t sign = (it % 2 != 0) ? -1 : 1;
            const uint32_t delta = sign * (it / (2 * numports));
            const uint32_t index = (it / 2) % numports;
            const uint16_t port = port_list[index] + delta;
            IP_Port pinging;
            ip_copy(&pinging.ip, ip);
            pinging.port = net_htons(port);
            ping_send_request(dht->ping, &pinging, dht->friends_list[friend_num].public_key);
        }

        dht->friends_list[friend_num].nat.punching_index += i;
    }

    if (dht->friends_list[friend_num].nat.tries > MAX_NORMAL_PUNCHING_TRIES) {
        IP_Port pinging;
        ip_copy(&pinging.ip, ip);

        uint16_t i;
        for (i = 0; i < MAX_PUNCHING_PORTS; ++i) {
            uint32_t it = i + dht->friends_list[friend_num].nat.punching_index2;
            const uint16_t port = 1024;
            pinging.port = net_htons(port + it);
            ping_send_request(dht->ping, &pinging, dht->friends_list[friend_num].public_key);
        }

        dht->friends_list[friend_num].nat.punching_index2 += i - (MAX_PUNCHING_PORTS / 2);
    }

    ++dht->friends_list[friend_num].nat.tries;
}

non_null()
static void do_NAT(DHT *dht)
{
    const uint64_t temp_time = mono_time_get(dht->mono_time);

    for (uint32_t i = 0; i < dht->num_friends; ++i) {
        IP_Port ip_list[MAX_FRIEND_CLIENTS];
        const int num = friend_iplist(dht, ip_list, i);

        /* If already connected or friend is not online don't try to hole punch. */
        if (num < MAX_FRIEND_CLIENTS / 2) {
            continue;
        }

        if (dht->friends_list[i].nat.nat_ping_timestamp + PUNCH_INTERVAL < temp_time) {
            send_NATping(dht, dht->friends_list[i].public_key, dht->friends_list[i].nat.nat_ping_id, NAT_PING_REQUEST);
            dht->friends_list[i].nat.nat_ping_timestamp = temp_time;
        }

        if (dht->friends_list[i].nat.hole_punching &&
                dht->friends_list[i].nat.punching_timestamp + PUNCH_INTERVAL < temp_time &&
                dht->friends_list[i].nat.recv_nat_ping_timestamp + PUNCH_INTERVAL * 2 >= temp_time) {

            const IP ip = nat_commonip(ip_list, num, MAX_FRIEND_CLIENTS / 2);

            if (!ip_isset(&ip)) {
                continue;
            }

            if (dht->friends_list[i].nat.punching_timestamp + PUNCH_RESET_TIME < temp_time) {
                dht->friends_list[i].nat.tries = 0;
                dht->friends_list[i].nat.punching_index = 0;
                dht->friends_list[i].nat.punching_index2 = 0;
            }

            uint16_t port_list[MAX_FRIEND_CLIENTS];
            const uint16_t numports = nat_getports(port_list, ip_list, num, &ip);
            punch_holes(dht, &ip, port_list, numports, i);

            dht->friends_list[i].nat.punching_timestamp = temp_time;
            dht->friends_list[i].nat.hole_punching = false;
        }
    }
}

/*----------------------------------------------------------------------------------*/
/*-----------------------END OF NAT PUNCHING FUNCTIONS------------------------------*/

/** @brief Put up to max_num nodes in nodes from the closelist.
 *
 * @return the number of nodes.
 */
non_null()
static uint16_t list_nodes(const Random *rng, const Client_data *list, size_t length,
                           uint64_t cur_time, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0) {
        return 0;
    }

    uint16_t count = 0;

    for (size_t i = length; i != 0; --i) {
        const IPPTsPng *assoc = nullptr;

        if (!assoc_timeout(cur_time, &list[i - 1].assoc4)) {
            assoc = &list[i - 1].assoc4;
        }

        if (!assoc_timeout(cur_time, &list[i - 1].assoc6)) {
            if (assoc == nullptr) {
                assoc = &list[i - 1].assoc6;
            } else if ((random_u08(rng) % 2) != 0) {
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

/** @brief Put up to max_num nodes in nodes from the random friends.
 *
 * Important: this function relies on the first two DHT friends *not* being real
 * friends to avoid leaking information about real friends into the onion paths.
 *
 * @return the number of nodes.
 */
uint16_t randfriends_nodes(const DHT *dht, Node_format *nodes, uint16_t max_num)
{
    if (max_num == 0) {
        return 0;
    }

    uint16_t count = 0;
    const uint32_t r = random_u32(dht->rng);

    assert(DHT_FAKE_FRIEND_NUMBER <= dht->num_friends);

    // Only gather nodes from the initial 2 fake friends.
    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        count += list_nodes(dht->rng, dht->friends_list[(i + r) % DHT_FAKE_FRIEND_NUMBER].client_list,
                            MAX_FRIEND_CLIENTS, dht->cur_time,
                            nodes + count, max_num - count);

        if (count >= max_num) {
            break;
        }
    }

    return count;
}

/** @brief Put up to max_num nodes in nodes from the closelist.
 *
 * @return the number of nodes.
 */
uint16_t closelist_nodes(const DHT *dht, Node_format *nodes, uint16_t max_num)
{
    return list_nodes(dht->rng, dht->close_clientlist, LCLIENT_LIST, dht->cur_time, nodes, max_num);
}

/*----------------------------------------------------------------------------------*/

void cryptopacket_registerhandler(DHT *dht, uint8_t byte, cryptopacket_handler_cb *cb, void *object)
{
    dht->cryptopackethandlers[byte].function = cb;
    dht->cryptopackethandlers[byte].object = object;
}

non_null()
static int cryptopacket_handle(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    DHT *const dht = (DHT *)object;

    assert(packet[0] == NET_PACKET_CRYPTO);

    if (length <= CRYPTO_PUBLIC_KEY_SIZE * 2 + CRYPTO_NONCE_SIZE + 1 + CRYPTO_MAC_SIZE ||
            length > MAX_CRYPTO_REQUEST_SIZE + CRYPTO_MAC_SIZE) {
        return 1;
    }

    // Check if request is for us.
    if (pk_equal(packet + 1, dht->self_public_key)) {
        uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t data[MAX_CRYPTO_REQUEST_SIZE];
        uint8_t number;
        const int len = handle_request(dht->self_public_key, dht->self_secret_key, public_key,
                                       data, &number, packet, length);

        if (len == -1 || len == 0) {
            return 1;
        }

        if (dht->cryptopackethandlers[number].function == nullptr) {
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

void dht_callback_get_nodes_response(DHT *dht, dht_get_nodes_response_cb *function)
{
    dht->get_nodes_response = function;
}

non_null(1, 2, 3) nullable(5)
static int handle_LANdiscovery(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    DHT *dht = (DHT *)object;

    if (!dht->lan_discovery_enabled) {
        return 1;
    }

    if (!ip_is_lan(&source->ip)) {
        return 1;
    }

    if (length != CRYPTO_PUBLIC_KEY_SIZE + 1) {
        return 1;
    }

    dht_bootstrap(dht, source, packet + 1);
    return 0;
}

/*----------------------------------------------------------------------------------*/

DHT *new_dht(const Logger *log, const Random *rng, const Network *ns, Mono_Time *mono_time, Networking_Core *net,
             bool hole_punching_enabled, bool lan_discovery_enabled)
{
    if (net == nullptr) {
        return nullptr;
    }

    DHT *const dht = (DHT *)calloc(1, sizeof(DHT));

    if (dht == nullptr) {
        return nullptr;
    }

    dht->ns = ns;
    dht->mono_time = mono_time;
    dht->cur_time = mono_time_get(mono_time);
    dht->log = log;
    dht->net = net;
    dht->rng = rng;

    dht->hole_punching_enabled = hole_punching_enabled;
    dht->lan_discovery_enabled = lan_discovery_enabled;

    dht->ping = ping_new(mono_time, rng, dht);

    if (dht->ping == nullptr) {
        kill_dht(dht);
        return nullptr;
    }

    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, &handle_getnodes, dht);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, &handle_sendnodes_ipv6, dht);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO, &cryptopacket_handle, dht);
    networking_registerhandler(dht->net, NET_PACKET_LAN_DISCOVERY, &handle_LANdiscovery, dht);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, &handle_NATping, dht);

#ifdef CHECK_ANNOUNCE_NODE
    networking_registerhandler(dht->net, NET_PACKET_DATA_SEARCH_RESPONSE, &handle_data_search_response, dht);
#endif

    crypto_new_keypair(rng, dht->self_public_key, dht->self_secret_key);

    dht->dht_ping_array = ping_array_new(DHT_PING_ARRAY_SIZE, PING_TIMEOUT);

    if (dht->dht_ping_array == nullptr) {
        kill_dht(dht);
        return nullptr;
    }

    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER; ++i) {
        uint8_t random_public_key_bytes[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t random_secret_key_bytes[CRYPTO_SECRET_KEY_SIZE];

        crypto_new_keypair(rng, random_public_key_bytes, random_secret_key_bytes);

        if (dht_addfriend(dht, random_public_key_bytes, nullptr, nullptr, 0, nullptr) != 0) {
            kill_dht(dht);
            return nullptr;
        }
    }

    if (dht->num_friends != DHT_FAKE_FRIEND_NUMBER) {
        LOGGER_ERROR(log, "the RNG provided seems to be broken: it generated the same keypair twice");
        kill_dht(dht);
        return nullptr;
    }

    return dht;
}

void do_dht(DHT *dht)
{
    const uint64_t cur_time = mono_time_get(dht->mono_time);

    if (dht->cur_time == cur_time) {
        return;
    }

    dht->cur_time = cur_time;

    // Load friends/clients if first call to do_dht
    if (dht->loaded_num_nodes > 0) {
        dht_connect_after_load(dht);
    }

    do_Close(dht);
    do_dht_friends(dht);
    do_NAT(dht);
    ping_iterate(dht->ping);
}

void kill_dht(DHT *dht)
{
    if (dht == nullptr) {
        return;
    }

    networking_registerhandler(dht->net, NET_PACKET_GET_NODES, nullptr, nullptr);
    networking_registerhandler(dht->net, NET_PACKET_SEND_NODES_IPV6, nullptr, nullptr);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO, nullptr, nullptr);
    networking_registerhandler(dht->net, NET_PACKET_LAN_DISCOVERY, nullptr, nullptr);
    cryptopacket_registerhandler(dht, CRYPTO_PACKET_NAT_PING, nullptr, nullptr);

    ping_array_kill(dht->dht_ping_array);
    ping_kill(dht->ping);
    free(dht->friends_list);
    free(dht->loaded_nodes_list);
    crypto_memzero(&dht->shared_keys_recv, sizeof(dht->shared_keys_recv));
    crypto_memzero(&dht->shared_keys_sent, sizeof(dht->shared_keys_sent));
    crypto_memzero(dht->self_secret_key, sizeof(dht->self_secret_key));
    free(dht);
}

/* new DHT format for load/save, more robust and forward compatible */
// TODO(irungentoo): Move this closer to Messenger.
#define DHT_STATE_COOKIE_GLOBAL 0x159000d

#define DHT_STATE_COOKIE_TYPE      0x11ce
#define DHT_STATE_TYPE_NODES       4

#define MAX_SAVED_DHT_NODES (((DHT_FAKE_FRIEND_NUMBER * MAX_FRIEND_CLIENTS) + LCLIENT_LIST) * 2)

/** Get the size of the DHT (for saving). */
uint32_t dht_size(const DHT *dht)
{
    uint32_t numv4 = 0;
    uint32_t numv6 = 0;

    for (uint32_t i = 0; i < dht->loaded_num_nodes; ++i) {
        numv4 += net_family_is_ipv4(dht->loaded_nodes_list[i].ip_port.ip.family);
        numv6 += net_family_is_ipv6(dht->loaded_nodes_list[i].ip_port.ip.family);
    }

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        numv4 += dht->close_clientlist[i].assoc4.timestamp != 0;
        numv6 += dht->close_clientlist[i].assoc6.timestamp != 0;
    }

    for (uint32_t i = 0; i < DHT_FAKE_FRIEND_NUMBER && i < dht->num_friends; ++i) {
        const DHT_Friend *const fr = &dht->friends_list[i];

        for (uint32_t j = 0; j < MAX_FRIEND_CLIENTS; ++j) {
            numv4 += fr->client_list[j].assoc4.timestamp != 0;
            numv6 += fr->client_list[j].assoc6.timestamp != 0;
        }
    }

    const uint32_t size32 = sizeof(uint32_t);
    const uint32_t sizesubhead = size32 * 2;

    return size32 + sizesubhead + packed_node_size(net_family_ipv4()) * numv4 + packed_node_size(net_family_ipv6()) * numv6;
}

/** Save the DHT in data where data is an array of size `dht_size()`. */
void dht_save(const DHT *dht, uint8_t *data)
{
    host_to_lendian_bytes32(data, DHT_STATE_COOKIE_GLOBAL);
    data += sizeof(uint32_t);

    uint8_t *const old_data = data;

    /* get right offset. we write the actual header later. */
    data = state_write_section_header(data, DHT_STATE_COOKIE_TYPE, 0, 0);

    Node_format *clients = (Node_format *)calloc(MAX_SAVED_DHT_NODES, sizeof(Node_format));

    if (clients == nullptr) {
        LOGGER_ERROR(dht->log, "could not allocate %u nodes", MAX_SAVED_DHT_NODES);
        return;
    }

    uint32_t num = 0;

    if (dht->loaded_num_nodes > 0) {
        memcpy(clients, dht->loaded_nodes_list, sizeof(Node_format) * dht->loaded_num_nodes);
        num += dht->loaded_num_nodes;
    }

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

    state_write_section_header(old_data, DHT_STATE_COOKIE_TYPE, pack_nodes(dht->log, data, sizeof(Node_format) * num,
                               clients, num), DHT_STATE_TYPE_NODES);

    free(clients);
}

/** Bootstrap from this number of nodes every time `dht_connect_after_load()` is called */
#define SAVE_BOOTSTAP_FREQUENCY 8

/** @brief Start sending packets after DHT loaded_friends_list and loaded_clients_list are set.
 *
 * @retval 0 if successful
 * @retval -1 otherwise
 */
int dht_connect_after_load(DHT *dht)
{
    if (dht == nullptr) {
        return -1;
    }

    if (dht->loaded_nodes_list == nullptr) {
        return -1;
    }

    /* DHT is connected, stop. */
    if (dht_non_lan_connected(dht)) {
        free(dht->loaded_nodes_list);
        dht->loaded_nodes_list = nullptr;
        dht->loaded_num_nodes = 0;
        return 0;
    }

    for (uint32_t i = 0; i < dht->loaded_num_nodes && i < SAVE_BOOTSTAP_FREQUENCY; ++i) {
        const unsigned int index = dht->loaded_nodes_index % dht->loaded_num_nodes;
        dht_bootstrap(dht, &dht->loaded_nodes_list[index].ip_port, dht->loaded_nodes_list[index].public_key);
        ++dht->loaded_nodes_index;
    }

    return 0;
}

non_null()
static State_Load_Status dht_load_state_callback(void *outer, const uint8_t *data, uint32_t length, uint16_t type)
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

            if (dht->loaded_nodes_list == nullptr) {
                LOGGER_ERROR(dht->log, "could not allocate %u nodes", MAX_SAVED_DHT_NODES);
                dht->loaded_num_nodes = 0;
                break;
            }

            const int num = unpack_nodes(dht->loaded_nodes_list, MAX_SAVED_DHT_NODES, nullptr, data, length, false);

            if (num > 0) {
                dht->loaded_num_nodes = num;
            } else {
                dht->loaded_num_nodes = 0;
            }

            break;
        }

        default: {
            LOGGER_ERROR(dht->log, "Load state (DHT): contains unrecognized part (len %u, type %u)",
                         length, type);
            break;
        }
    }

    return STATE_LOAD_STATUS_CONTINUE;
}

/** @brief Load the DHT from data of size size.
 *
 * @retval -1 if failure.
 * @retval 0 if success.
 */
int dht_load(DHT *dht, const uint8_t *data, uint32_t length)
{
    const uint32_t cookie_len = sizeof(uint32_t);

    if (length > cookie_len) {
        uint32_t data32;
        lendian_bytes_to_host32(&data32, data);

        if (data32 == DHT_STATE_COOKIE_GLOBAL) {
            return state_load(dht->log, dht_load_state_callback, dht, data + cookie_len,
                              length - cookie_len, DHT_STATE_COOKIE_TYPE);
        }
    }

    return -1;
}

/**
 * @retval false if we are not connected to the DHT.
 * @retval true if we are.
 */
bool dht_isconnected(const DHT *dht)
{
    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *const client = &dht->close_clientlist[i];

        if (!assoc_timeout(dht->cur_time, &client->assoc4) ||
                !assoc_timeout(dht->cur_time, &client->assoc6)) {
            return true;
        }
    }

    return false;
}

/**
 * @retval false if we are not connected or only connected to lan peers with the DHT.
 * @retval true if we are.
 */
bool dht_non_lan_connected(const DHT *dht)
{
    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *const client = &dht->close_clientlist[i];

        if (!assoc_timeout(dht->cur_time, &client->assoc4)
                && !ip_is_lan(&client->assoc4.ip_port.ip)) {
            return true;
        }

        if (!assoc_timeout(dht->cur_time, &client->assoc6)
                && !ip_is_lan(&client->assoc6.ip_port.ip)) {
            return true;
        }
    }

    return false;
}

/** @brief Copies our own ip_port structure to `dest`.
 *
 * WAN addresses take priority over LAN addresses.
 *
 * This function will zero the `dest` buffer before use.
 *
 * @retval 0 if our ip port can't be found (this usually means we're not connected to the DHT).
 * @retval 1 if IP is a WAN address.
 * @retval 2 if IP is a LAN address.
 */
unsigned int ipport_self_copy(const DHT *dht, IP_Port *dest)
{
    ipport_reset(dest);

    bool is_lan = false;

    for (uint32_t i = 0; i < LCLIENT_LIST; ++i) {
        const Client_data *client = dht_get_close_client(dht, i);
        const IP_Port *ip_port4 = &client->assoc4.ret_ip_port;

        if (client->assoc4.ret_ip_self && ipport_isset(ip_port4)) {
            ipport_copy(dest, ip_port4);
            is_lan = ip_is_lan(&dest->ip);

            if (!is_lan) {
                break;
            }
        }

        const IP_Port *ip_port6 = &client->assoc6.ret_ip_port;

        if (client->assoc6.ret_ip_self && ipport_isset(ip_port6)) {
            ipport_copy(dest, ip_port6);
            is_lan = ip_is_lan(&dest->ip);

            if (!is_lan) {
                break;
            }
        }
    }

    if (!ipport_isset(dest)) {
        return 0;
    }

    if (is_lan) {
        return 2;
    }

    return 1;
}
