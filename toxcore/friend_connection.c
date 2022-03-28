/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Connection to friends.
 */
#include "friend_connection.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

#define PORTS_PER_DISCOVERY 10

typedef struct Friend_Conn_Callbacks {
    fc_status_cb *status_callback;
    fc_data_cb *data_callback;
    fc_lossy_data_cb *lossy_data_callback;

    void *callback_object;
    int callback_id;
} Friend_Conn_Callbacks;

struct Friend_Conn {
    uint8_t status;

    uint8_t real_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t dht_temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t dht_lock;
    IP_Port dht_ip_port;
    uint64_t dht_pk_lastrecv;
    uint64_t dht_ip_port_lastrecv;

    int onion_friendnum;
    int crypt_connection_id;

    uint64_t ping_lastrecv;
    uint64_t ping_lastsent;
    uint64_t share_relays_lastsent;

    Friend_Conn_Callbacks callbacks[MAX_FRIEND_CONNECTION_CALLBACKS];

    uint16_t lock_count;

    Node_format tcp_relays[FRIEND_MAX_STORED_TCP_RELAYS];
    uint16_t tcp_relay_counter;
    uint32_t tcp_relay_share_index;

    bool hosting_tcp_relay;
};

static const Friend_Conn empty_friend_conn = {0};


struct Friend_Connections {
    const Mono_Time *mono_time;
    const Logger *logger;
    Net_Crypto *net_crypto;
    DHT *dht;
    Broadcast_Info *broadcast;
    Onion_Client *onion_c;

    Friend_Conn *conns;
    uint32_t num_cons;

    fr_request_cb *fr_request_callback;
    void *fr_request_object;

    global_status_cb *global_status_callback;
    void *global_status_callback_object;

    uint64_t last_lan_discovery;
    uint16_t next_lan_port;

    bool local_discovery_enabled;
};

int friend_conn_get_onion_friendnum(const Friend_Conn *fc)
{
    return fc->onion_friendnum;
}

Net_Crypto *friendconn_net_crypto(const Friend_Connections *fr_c)
{
    return fr_c->net_crypto;
}

const IP_Port *friend_conn_get_dht_ip_port(const Friend_Conn *fc)
{
    return &fc->dht_ip_port;
}


/**
 * @retval true if the friendcon_id is valid.
 * @retval false if the friendcon_id is not valid.
 */
non_null()
static bool friendconn_id_valid(const Friend_Connections *fr_c, int friendcon_id)
{
    return (unsigned int)friendcon_id < fr_c->num_cons &&
           fr_c->conns != nullptr &&
           fr_c->conns[friendcon_id].status != FRIENDCONN_STATUS_NONE;
}


/** @brief Set the size of the friend connections list to num.
 *
 * @retval false if realloc fails.
 * @retval true if it succeeds.
 */
non_null()
static bool realloc_friendconns(Friend_Connections *fr_c, uint32_t num)
{
    if (num == 0) {
        free(fr_c->conns);
        fr_c->conns = nullptr;
        return true;
    }

    Friend_Conn *newgroup_cons = (Friend_Conn *)realloc(fr_c->conns, num * sizeof(Friend_Conn));

    if (newgroup_cons == nullptr) {
        return false;
    }

    fr_c->conns = newgroup_cons;
    return true;
}

/** @brief Create a new empty friend connection.
 *
 * @retval -1 on failure.
 * @return friendcon_id on success.
 */
non_null()
static int create_friend_conn(Friend_Connections *fr_c)
{
    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        if (fr_c->conns[i].status == FRIENDCONN_STATUS_NONE) {
            return i;
        }
    }

    if (!realloc_friendconns(fr_c, fr_c->num_cons + 1)) {
        return -1;
    }

    const int id = fr_c->num_cons;
    ++fr_c->num_cons;
    fr_c->conns[id] = empty_friend_conn;

    return id;
}

/** @brief Wipe a friend connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int wipe_friend_conn(Friend_Connections *fr_c, int friendcon_id)
{
    if (!friendconn_id_valid(fr_c, friendcon_id)) {
        return -1;
    }

    fr_c->conns[friendcon_id] = empty_friend_conn;

    uint32_t i;

    for (i = fr_c->num_cons; i != 0; --i) {
        if (fr_c->conns[i - 1].status != FRIENDCONN_STATUS_NONE) {
            break;
        }
    }

    if (fr_c->num_cons != i) {
        fr_c->num_cons = i;
        realloc_friendconns(fr_c, fr_c->num_cons);
    }

    return 0;
}

Friend_Conn *get_conn(const Friend_Connections *fr_c, int friendcon_id)
{
    if (!friendconn_id_valid(fr_c, friendcon_id)) {
        return nullptr;
    }

    return &fr_c->conns[friendcon_id];
}

/** 
 * @return friendcon_id corresponding to the real public key on success.
 * @retval -1 on failure.
 */
int getfriend_conn_id_pk(const Friend_Connections *fr_c, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        const Friend_Conn *friend_con = get_conn(fr_c, i);

        if (friend_con != nullptr) {
            if (pk_equal(friend_con->real_public_key, real_pk)) {
                return i;
            }
        }
    }

    return -1;
}

/** @brief Add a TCP relay associated to the friend.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
non_null()
static int friend_add_tcp_relay(Friend_Connections *fr_c, int friendcon_id, const IP_Port *ip_port,
                                const uint8_t *public_key)
{
    IP_Port ipp_copy = *ip_port;

    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    /* Local ip and same pk means that they are hosting a TCP relay. */
    if (ip_is_local(&ipp_copy.ip) && pk_equal(friend_con->dht_temp_pk, public_key)) {
        if (!net_family_is_unspec(friend_con->dht_ip_port.ip.family)) {
            ipp_copy.ip = friend_con->dht_ip_port.ip;
        } else {
            friend_con->hosting_tcp_relay = 0;
        }
    }

    const uint16_t index = friend_con->tcp_relay_counter % FRIEND_MAX_STORED_TCP_RELAYS;

    for (unsigned i = 0; i < FRIEND_MAX_STORED_TCP_RELAYS; ++i) {
        if (!net_family_is_unspec(friend_con->tcp_relays[i].ip_port.ip.family)
                && pk_equal(friend_con->tcp_relays[i].public_key, public_key)) {
            friend_con->tcp_relays[i] = empty_node_format;
        }
    }

    friend_con->tcp_relays[index].ip_port = ipp_copy;
    memcpy(friend_con->tcp_relays[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    ++friend_con->tcp_relay_counter;

    return add_tcp_relay_peer(fr_c->net_crypto, friend_con->crypt_connection_id, &ipp_copy, public_key);
}

/** Connect to number saved relays for friend. */
non_null()
static void connect_to_saved_tcp_relays(Friend_Connections *fr_c, int friendcon_id, unsigned int number)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return;
    }

    for (unsigned i = 0; (i < FRIEND_MAX_STORED_TCP_RELAYS) && (number != 0); ++i) {
        const uint16_t index = (friend_con->tcp_relay_counter - (i + 1)) % FRIEND_MAX_STORED_TCP_RELAYS;

        if (!net_family_is_unspec(friend_con->tcp_relays[index].ip_port.ip.family)) {
            if (add_tcp_relay_peer(fr_c->net_crypto, friend_con->crypt_connection_id, &friend_con->tcp_relays[index].ip_port,
                                   friend_con->tcp_relays[index].public_key) == 0) {
                --number;
            }
        }
    }
}

non_null()
static unsigned int send_relays(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return 0;
    }

    Node_format nodes[MAX_SHARED_RELAYS] = {{{0}}};
    uint8_t data[1024];

    const uint32_t n = copy_connected_tcp_relays_index(fr_c->net_crypto, nodes, MAX_SHARED_RELAYS,
                       friend_con->tcp_relay_share_index);

    friend_con->tcp_relay_share_index += MAX_SHARED_RELAYS;

    for (uint32_t i = 0; i < n; ++i) {
        /* Associated the relays being sent with this connection.
         * On receiving the peer will do the same which will establish the connection. */
        friend_add_tcp_relay(fr_c, friendcon_id, &nodes[i].ip_port, nodes[i].public_key);
    }

    int length = pack_nodes(fr_c->logger, data + 1, sizeof(data) - 1, nodes, n);

    if (length <= 0) {
        return 0;
    }

    data[0] = PACKET_ID_SHARE_RELAYS;
    ++length;

    if (write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, data, length, false) != -1) {
        friend_con->share_relays_lastsent = mono_time_get(fr_c->mono_time);
        return 1;
    }

    return 0;
}

/** callback for recv TCP relay nodes. */
non_null()
static int tcp_relay_node_callback(void *object, uint32_t number, const IP_Port *ip_port, const uint8_t *public_key)
{
    Friend_Connections *fr_c = (Friend_Connections *)object;
    const Friend_Conn *friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return -1;
    }

    if (friend_con->crypt_connection_id != -1) {
        return friend_add_tcp_relay(fr_c, number, ip_port, public_key);
    }

    return add_tcp_relay(fr_c->net_crypto, ip_port, public_key);
}

non_null()
static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id);

/** Callback for DHT ip_port changes. */
non_null()
static void dht_ip_callback(void *object, int32_t number, const IP_Port *ip_port)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return;
    }

    if (friend_con->crypt_connection_id == -1) {
        friend_new_connection(fr_c, number);
    }

    set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, ip_port, true);
    friend_con->dht_ip_port = *ip_port;
    friend_con->dht_ip_port_lastrecv = mono_time_get(fr_c->mono_time);

    if (friend_con->hosting_tcp_relay) {
        friend_add_tcp_relay(fr_c, number, ip_port, friend_con->dht_temp_pk);
        friend_con->hosting_tcp_relay = 0;
    }
}

non_null()
static void change_dht_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_public_key)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return;
    }

    friend_con->dht_pk_lastrecv = mono_time_get(fr_c->mono_time);

    if (friend_con->dht_lock > 0) {
        if (dht_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock) != 0) {
            LOGGER_ERROR(fr_c->logger, "a. Could not delete dht peer. Please report this.");
            return;
        }

        friend_con->dht_lock = 0;
    }

    dht_addfriend(fr_c->dht, dht_public_key, dht_ip_callback, fr_c, friendcon_id, &friend_con->dht_lock);
    memcpy(friend_con->dht_temp_pk, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
}

non_null()
static int handle_status(void *object, int number, bool status, void *userdata)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return -1;
    }

    bool status_changed = false;

    if (status) {  /* Went online. */
        status_changed = true;
        friend_con->status = FRIENDCONN_STATUS_CONNECTED;
        friend_con->ping_lastrecv = mono_time_get(fr_c->mono_time);
        friend_con->share_relays_lastsent = 0;
        onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
    } else {  /* Went offline. */
        if (friend_con->status != FRIENDCONN_STATUS_CONNECTING) {
            status_changed = true;
            friend_con->dht_pk_lastrecv = mono_time_get(fr_c->mono_time);
            onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
        }

        friend_con->status = FRIENDCONN_STATUS_CONNECTING;
        friend_con->crypt_connection_id = -1;
        friend_con->hosting_tcp_relay = 0;
    }

    if (status_changed) {
        if (fr_c->global_status_callback != nullptr) {
            fr_c->global_status_callback(fr_c->global_status_callback_object, number, status, userdata);
        }

        for (unsigned i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
            if (friend_con->callbacks[i].status_callback != nullptr) {
                friend_con->callbacks[i].status_callback(
                    friend_con->callbacks[i].callback_object,
                    friend_con->callbacks[i].callback_id, status, userdata);
            }
        }
    }

    return 0;
}

/** Callback for dht public key changes. */
non_null()
static void dht_pk_callback(void *object, int32_t number, const uint8_t *dht_public_key, void *userdata)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return;
    }

    if (pk_equal(friend_con->dht_temp_pk, dht_public_key)) {
        return;
    }

    change_dht_pk(fr_c, number, dht_public_key);

    /* if pk changed, create a new connection.*/
    if (friend_con->crypt_connection_id != -1) {
        crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);
        friend_con->crypt_connection_id = -1;
        handle_status(object, number, false, userdata); /* Going offline. */
    }

    friend_new_connection(fr_c, number);
    onion_set_friend_DHT_pubkey(fr_c->onion_c, friend_con->onion_friendnum, dht_public_key);
}

non_null()
static int handle_packet(void *object, int number, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return -1;
    }

    if (data[0] == PACKET_ID_FRIEND_REQUESTS) {
        if (fr_c->fr_request_callback != nullptr) {
            fr_c->fr_request_callback(fr_c->fr_request_object, friend_con->real_public_key, data, length, userdata);
        }

        return 0;
    }

    if (data[0] == PACKET_ID_ALIVE) {
        friend_con->ping_lastrecv = mono_time_get(fr_c->mono_time);
        return 0;
    }

    if (data[0] == PACKET_ID_SHARE_RELAYS) {
        Node_format nodes[MAX_SHARED_RELAYS];
        const int n = unpack_nodes(nodes, MAX_SHARED_RELAYS, nullptr, data + 1, length - 1, true);

        if (n == -1) {
            return -1;
        }

        for (int j = 0; j < n; ++j) {
            friend_add_tcp_relay(fr_c, number, &nodes[j].ip_port, nodes[j].public_key);
        }

        return 0;
    }

    for (unsigned i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].data_callback != nullptr) {
            friend_con->callbacks[i].data_callback(
                friend_con->callbacks[i].callback_object,
                friend_con->callbacks[i].callback_id, data, length, userdata);
        }

        friend_con = get_conn(fr_c, number);

        if (friend_con == nullptr) {
            return -1;
        }
    }

    return 0;
}

non_null()
static int handle_lossy_packet(void *object, int number, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    const Friend_Connections *const fr_c = (const Friend_Connections *)object;
    const Friend_Conn *friend_con = get_conn(fr_c, number);

    if (friend_con == nullptr) {
        return -1;
    }

    for (unsigned i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].lossy_data_callback != nullptr) {
            friend_con->callbacks[i].lossy_data_callback(
                friend_con->callbacks[i].callback_object,
                friend_con->callbacks[i].callback_id, data, length, userdata);
        }

        friend_con = get_conn(fr_c, number);

        if (friend_con == nullptr) {
            return -1;
        }
    }

    return 0;
}

non_null()
static int handle_new_connections(void *object, const New_Connection *n_c)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    const int friendcon_id = getfriend_conn_id_pk(fr_c, n_c->public_key);
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    if (friend_con->crypt_connection_id != -1) {
        return -1;
    }

    const int id = accept_crypto_connection(fr_c->net_crypto, n_c);

    if (id == -1) {
        return -1;
    }

    connection_status_handler(fr_c->net_crypto, id, &handle_status, fr_c, friendcon_id);
    connection_data_handler(fr_c->net_crypto, id, &handle_packet, fr_c, friendcon_id);
    connection_lossy_data_handler(fr_c->net_crypto, id, &handle_lossy_packet, fr_c, friendcon_id);
    friend_con->crypt_connection_id = id;

    if (!net_family_is_ipv4(n_c->source.ip.family) && !net_family_is_ipv6(n_c->source.ip.family)) {
        set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, &friend_con->dht_ip_port, false);
    } else {
        friend_con->dht_ip_port = n_c->source;
        friend_con->dht_ip_port_lastrecv = mono_time_get(fr_c->mono_time);
    }

    if (!pk_equal(friend_con->dht_temp_pk, n_c->dht_public_key)) {
        change_dht_pk(fr_c, friendcon_id, n_c->dht_public_key);
    }

    nc_dht_pk_callback(fr_c->net_crypto, id, &dht_pk_callback, fr_c, friendcon_id);
    return 0;
}

static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    if (friend_con->crypt_connection_id != -1) {
        return -1;
    }

    /* If dht_temp_pk does not contains a pk. */
    if (friend_con->dht_lock == 0) {
        return -1;
    }

    const int id = new_crypto_connection(fr_c->net_crypto, friend_con->real_public_key, friend_con->dht_temp_pk);

    if (id == -1) {
        return -1;
    }

    friend_con->crypt_connection_id = id;
    connection_status_handler(fr_c->net_crypto, id, &handle_status, fr_c, friendcon_id);
    connection_data_handler(fr_c->net_crypto, id, &handle_packet, fr_c, friendcon_id);
    connection_lossy_data_handler(fr_c->net_crypto, id, &handle_lossy_packet, fr_c, friendcon_id);
    nc_dht_pk_callback(fr_c->net_crypto, id, &dht_pk_callback, fr_c, friendcon_id);

    return 0;
}

non_null()
static int send_ping(const Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    const uint8_t ping = PACKET_ID_ALIVE;
    const int64_t ret = write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, &ping, sizeof(ping), false);

    if (ret != -1) {
        friend_con->ping_lastsent = mono_time_get(fr_c->mono_time);
        return 0;
    }

    return -1;
}

/** @brief Increases lock_count for the connection with friendcon_id by 1.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int friend_connection_lock(const Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    ++friend_con->lock_count;
    return 0;
}

/**
 * @retval FRIENDCONN_STATUS_CONNECTED if the friend is connected.
 * @retval FRIENDCONN_STATUS_CONNECTING if the friend isn't connected.
 * @retval FRIENDCONN_STATUS_NONE on failure.
 */
unsigned int friend_con_connected(const Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return 0;
    }

    return friend_con->status;
}

/** @brief Copy public keys associated to friendcon_id.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int get_friendcon_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, const Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    if (real_pk != nullptr) {
        memcpy(real_pk, friend_con->real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }

    if (dht_temp_pk != nullptr) {
        memcpy(dht_temp_pk, friend_con->dht_temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
    }

    return 0;
}

/** Set temp dht key for connection. */
void set_dht_temp_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_temp_pk, void *userdata)
{
    dht_pk_callback(fr_c, friendcon_id, dht_temp_pk, userdata);
}

/** @brief Set the callbacks for the friend connection.
 * @param index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we
 *   want the callback to set in the array.
 *
 * @retval 0 on success.
 * @retval -1 on failure
 */
int friend_connection_callbacks(const Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                fc_status_cb *status_callback,
                                fc_data_cb *data_callback,
                                fc_lossy_data_cb *lossy_data_callback,
                                void *object, int number)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    if (index >= MAX_FRIEND_CONNECTION_CALLBACKS) {
        return -1;
    }

    if (object != nullptr && (status_callback == nullptr || data_callback == nullptr || lossy_data_callback == nullptr)) {
        LOGGER_ERROR(fr_c->logger, "non-null user data object but null callbacks");
        return -1;
    }

    friend_con->callbacks[index].status_callback = status_callback;
    friend_con->callbacks[index].data_callback = data_callback;
    friend_con->callbacks[index].lossy_data_callback = lossy_data_callback;

    friend_con->callbacks[index].callback_object = object;
    friend_con->callbacks[index].callback_id = number;

    return 0;
}

/** Set global status callback for friend connections. */
void set_global_status_callback(Friend_Connections *fr_c, global_status_cb *global_status_callback, void *object)
{
    if (object != nullptr && global_status_callback == nullptr) {
        LOGGER_ERROR(fr_c->logger, "non-null user data object but null callback");
        object = nullptr;
    }

    fr_c->global_status_callback = global_status_callback;
    fr_c->global_status_callback_object = object;
}

/** @brief return the crypt_connection_id for the connection.
 *
 * @return crypt_connection_id on success.
 * @retval -1 on failure.
 */
int friend_connection_crypt_connection_id(const Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    return friend_con->crypt_connection_id;
}

/** @brief Create a new friend connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * @retval -1 on failure.
 * @return connection id on success.
 */
int new_friend_connection(Friend_Connections *fr_c, const uint8_t *real_public_key)
{
    int friendcon_id = getfriend_conn_id_pk(fr_c, real_public_key);

    if (friendcon_id != -1) {
        ++fr_c->conns[friendcon_id].lock_count;
        return friendcon_id;
    }

    friendcon_id = create_friend_conn(fr_c);

    if (friendcon_id == -1) {
        return -1;
    }

    const int32_t onion_friendnum = onion_addfriend(fr_c->onion_c, real_public_key);

    if (onion_friendnum == -1) {
        return -1;
    }

    Friend_Conn *const friend_con = &fr_c->conns[friendcon_id];

    friend_con->crypt_connection_id = -1;
    friend_con->status = FRIENDCONN_STATUS_CONNECTING;
    memcpy(friend_con->real_public_key, real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    friend_con->onion_friendnum = onion_friendnum;

    recv_tcp_relay_handler(fr_c->onion_c, onion_friendnum, &tcp_relay_node_callback, fr_c, friendcon_id);
    onion_dht_pk_callback(fr_c->onion_c, onion_friendnum, &dht_pk_callback, fr_c, friendcon_id);

    return friendcon_id;
}

/** @brief Kill a friend connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
int kill_friend_connection(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    if (friend_con->lock_count > 0) {
        --friend_con->lock_count;
        return 0;
    }

    onion_delfriend(fr_c->onion_c, friend_con->onion_friendnum);
    crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);

    if (friend_con->dht_lock > 0) {
        dht_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock);
    }

    return wipe_friend_conn(fr_c, friendcon_id);
}


/** @brief Set friend request callback.
 *
 * This function will be called every time a friend request packet is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, fr_request_cb *fr_request_callback, void *object)
{
    fr_c->fr_request_callback = fr_request_callback;
    fr_c->fr_request_object = object;
    oniondata_registerhandler(fr_c->onion_c, CRYPTO_PACKET_FRIEND_REQ, fr_request_callback, object);
}

/** @brief Send a Friend request packet.
 *
 * @retval -1 if failure.
 * @retval  0 if it sent the friend request directly to the friend.
 * @return the number of peers it was routed through if it did not send it directly.
 */
int send_friend_request_packet(Friend_Connections *fr_c, int friendcon_id, uint32_t nospam_num, const uint8_t *data,
                               uint16_t length)
{
    if (1 + sizeof(nospam_num) + length > ONION_CLIENT_MAX_DATA_SIZE || length == 0) {
        return -1;
    }

    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con == nullptr) {
        return -1;
    }

    VLA(uint8_t, packet, 1 + sizeof(nospam_num) + length);
    memcpy(packet + 1, &nospam_num, sizeof(nospam_num));
    memcpy(packet + 1 + sizeof(nospam_num), data, length);

    if (friend_con->status == FRIENDCONN_STATUS_CONNECTED) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, packet, SIZEOF_VLA(packet), false) != -1 ? 1 : 0;
    }

    packet[0] = CRYPTO_PACKET_FRIEND_REQ;
    const int num = send_onion_data(fr_c->onion_c, friend_con->onion_friendnum, packet, SIZEOF_VLA(packet));

    if (num <= 0) {
        return -1;
    }

    return num;
}

/** Create new friend_connections instance. */
Friend_Connections *new_friend_connections(
        const Logger *logger, const Mono_Time *mono_time, const Network *ns,
        Onion_Client *onion_c, bool local_discovery_enabled)
{
    if (onion_c == nullptr) {
        return nullptr;
    }

    Friend_Connections *const temp = (Friend_Connections *)calloc(1, sizeof(Friend_Connections));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->mono_time = mono_time;
    temp->logger = logger;
    temp->dht = onion_get_dht(onion_c);
    temp->net_crypto = onion_get_net_crypto(onion_c);
    temp->onion_c = onion_c;
    temp->local_discovery_enabled = local_discovery_enabled;
    // Don't include default port in port range
    temp->next_lan_port = TOX_PORTRANGE_FROM + 1;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);

    if (temp->local_discovery_enabled) {
        temp->broadcast = lan_discovery_init(ns);

        if (temp->broadcast == nullptr) {
            LOGGER_ERROR(logger, "could not initialise LAN discovery");
        }
    }

    return temp;
}

/** Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
non_null()
static void lan_discovery(Friend_Connections *fr_c)
{
    if (fr_c->last_lan_discovery + LAN_DISCOVERY_INTERVAL < mono_time_get(fr_c->mono_time)) {
        const uint16_t first = fr_c->next_lan_port;
        uint16_t last = first + PORTS_PER_DISCOVERY;
        last = last > TOX_PORTRANGE_TO ? TOX_PORTRANGE_TO : last;

        // Always send to default port
        lan_discovery_send(dht_get_net(fr_c->dht), fr_c->broadcast, dht_get_self_public_key(fr_c->dht),
                           net_htons(TOX_PORT_DEFAULT));

        // And check some extra ports
        for (uint16_t port = first; port < last; ++port) {
            lan_discovery_send(dht_get_net(fr_c->dht), fr_c->broadcast, dht_get_self_public_key(fr_c->dht), net_htons(port));
        }

        // Don't include default port in port range
        fr_c->next_lan_port = last != TOX_PORTRANGE_TO ? last : TOX_PORTRANGE_FROM + 1;
        fr_c->last_lan_discovery = mono_time_get(fr_c->mono_time);
    }
}

/** main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c, void *userdata)
{
    const uint64_t temp_time = mono_time_get(fr_c->mono_time);

    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        Friend_Conn *const friend_con = get_conn(fr_c, i);

        if (friend_con != nullptr) {
            if (friend_con->status == FRIENDCONN_STATUS_CONNECTING) {
                if (friend_con->dht_pk_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    if (friend_con->dht_lock > 0) {
                        dht_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock);
                        friend_con->dht_lock = 0;
                        memset(friend_con->dht_temp_pk, 0, CRYPTO_PUBLIC_KEY_SIZE);
                    }
                }

                if (friend_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_ip_port.ip.family = net_family_unspec();
                }

                if (friend_con->dht_lock > 0) {
                    if (friend_new_connection(fr_c, i) == 0) {
                        set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, &friend_con->dht_ip_port, false);
                        connect_to_saved_tcp_relays(fr_c, i, MAX_FRIEND_TCP_CONNECTIONS / 2); /* Only fill it half up. */
                    }
                }
            } else if (friend_con->status == FRIENDCONN_STATUS_CONNECTED) {
                if (friend_con->ping_lastsent + FRIEND_PING_INTERVAL < temp_time) {
                    send_ping(fr_c, i);
                }

                if (friend_con->share_relays_lastsent + SHARE_RELAYS_INTERVAL < temp_time) {
                    send_relays(fr_c, i);
                }

                if (friend_con->ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                    /* If we stopped receiving ping packets, kill it. */
                    crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);
                    friend_con->crypt_connection_id = -1;
                    handle_status(fr_c, i, false, userdata); /* Going offline. */
                }
            }
        }
    }

    if (fr_c->local_discovery_enabled) {
        lan_discovery(fr_c);
    }
}

/** Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c)
{
    if (fr_c == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        kill_friend_connection(fr_c, i);
    }

    lan_discovery_kill(fr_c->broadcast);
    free(fr_c);
}
