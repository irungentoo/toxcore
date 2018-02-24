/*
 * Connection to friends.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2014 Tox project.
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

#include "friend_connection.h"

#include "util.h"

#define PORTS_PER_DISCOVERY 10

typedef struct {
    uint8_t status;

    uint8_t real_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t dht_temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t dht_lock;
    IP_Port dht_ip_port;
    uint64_t dht_pk_lastrecv, dht_ip_port_lastrecv;

    int onion_friendnum;
    int crypt_connection_id;

    uint64_t ping_lastrecv, ping_lastsent;
    uint64_t share_relays_lastsent;

    struct {
        int (*status_callback)(void *object, int id, uint8_t status, void *userdata);
        int (*data_callback)(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);
        int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length, void *userdata);

        void *callback_object;
        int callback_id;
    } callbacks[MAX_FRIEND_CONNECTION_CALLBACKS];

    uint16_t lock_count;

    Node_format tcp_relays[FRIEND_MAX_STORED_TCP_RELAYS];
    uint16_t tcp_relay_counter;

    bool hosting_tcp_relay;
} Friend_Conn;


struct Friend_Connections {
    Net_Crypto *net_crypto;
    DHT *dht;
    Onion_Client *onion_c;

    Friend_Conn *conns;
    uint32_t num_cons;

    int (*fr_request_callback)(void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t len,
                               void *userdata);
    void *fr_request_object;

    uint64_t last_LANdiscovery;
    uint16_t next_LANport;

    bool local_discovery_enabled;
};

Net_Crypto *friendconn_net_crypto(const Friend_Connections *fr_c)
{
    return fr_c->net_crypto;
}


/* return true if the friendcon_id is valid.
 * return false if the friendcon_id is not valid.
 */
static bool friendconn_id_valid(const Friend_Connections *fr_c, int friendcon_id)
{
    return (unsigned int)friendcon_id < fr_c->num_cons &&
           fr_c->conns != nullptr &&
           fr_c->conns[friendcon_id].status != FRIENDCONN_STATUS_NONE;
}


/* Set the size of the friend connections list to num.
 *
 *  return false if realloc fails.
 *  return true if it succeeds.
 */
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

/* Create a new empty friend connection.
 *
 * return -1 on failure.
 * return friendcon_id on success.
 */
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
    memset(&fr_c->conns[id], 0, sizeof(Friend_Conn));

    return id;
}

/* Wipe a friend connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_friend_conn(Friend_Connections *fr_c, int friendcon_id)
{
    if (!friendconn_id_valid(fr_c, friendcon_id)) {
        return -1;
    }

    memset(&fr_c->conns[friendcon_id], 0, sizeof(Friend_Conn));

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

static Friend_Conn *get_conn(const Friend_Connections *fr_c, int friendcon_id)
{
    if (!friendconn_id_valid(fr_c, friendcon_id)) {
        return nullptr;
    }

    return &fr_c->conns[friendcon_id];
}

/* return friendcon_id corresponding to the real public key on success.
 * return -1 on failure.
 */
int getfriend_conn_id_pk(Friend_Connections *fr_c, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        Friend_Conn *friend_con = get_conn(fr_c, i);

        if (friend_con) {
            if (public_key_cmp(friend_con->real_public_key, real_pk) == 0) {
                return i;
            }
        }
    }

    return -1;
}

/* Add a TCP relay associated to the friend.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int friend_add_tcp_relay(Friend_Connections *fr_c, int friendcon_id, IP_Port ip_port, const uint8_t *public_key)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    /* Local ip and same pk means that they are hosting a TCP relay. */
    if (ip_is_local(ip_port.ip) && public_key_cmp(friend_con->dht_temp_pk, public_key) == 0) {
        if (friend_con->dht_ip_port.ip.family != 0) {
            ip_port.ip = friend_con->dht_ip_port.ip;
        } else {
            friend_con->hosting_tcp_relay = 0;
        }
    }

    const uint16_t index = friend_con->tcp_relay_counter % FRIEND_MAX_STORED_TCP_RELAYS;

    for (unsigned i = 0; i < FRIEND_MAX_STORED_TCP_RELAYS; ++i) {
        if (friend_con->tcp_relays[i].ip_port.ip.family != 0
                && public_key_cmp(friend_con->tcp_relays[i].public_key, public_key) == 0) {
            memset(&friend_con->tcp_relays[i], 0, sizeof(Node_format));
        }
    }

    friend_con->tcp_relays[index].ip_port = ip_port;
    memcpy(friend_con->tcp_relays[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    ++friend_con->tcp_relay_counter;

    return add_tcp_relay_peer(fr_c->net_crypto, friend_con->crypt_connection_id, ip_port, public_key);
}

/* Connect to number saved relays for friend. */
static void connect_to_saved_tcp_relays(Friend_Connections *fr_c, int friendcon_id, unsigned int number)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return;
    }

    for (unsigned i = 0; (i < FRIEND_MAX_STORED_TCP_RELAYS) && (number != 0); ++i) {
        const uint16_t index = (friend_con->tcp_relay_counter - (i + 1)) % FRIEND_MAX_STORED_TCP_RELAYS;

        if (friend_con->tcp_relays[index].ip_port.ip.family) {
            if (add_tcp_relay_peer(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->tcp_relays[index].ip_port,
                                   friend_con->tcp_relays[index].public_key) == 0) {
                --number;
            }
        }
    }
}

static unsigned int send_relays(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return 0;
    }

    Node_format nodes[MAX_SHARED_RELAYS];
    uint8_t data[1024];

    const int n = copy_connected_tcp_relays(fr_c->net_crypto, nodes, MAX_SHARED_RELAYS);

    for (int i = 0; i < n; ++i) {
        /* Associated the relays being sent with this connection.
           On receiving the peer will do the same which will establish the connection. */
        friend_add_tcp_relay(fr_c, friendcon_id, nodes[i].ip_port, nodes[i].public_key);
    }

    int length = pack_nodes(data + 1, sizeof(data) - 1, nodes, n);

    if (length <= 0) {
        return 0;
    }

    data[0] = PACKET_ID_SHARE_RELAYS;
    ++length;

    if (write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, data, length, 0) != -1) {
        friend_con->share_relays_lastsent = unix_time();
        return 1;
    }

    return 0;
}

/* callback for recv TCP relay nodes. */
static int tcp_relay_node_callback(void *object, uint32_t number, IP_Port ip_port, const uint8_t *public_key)
{
    Friend_Connections *fr_c = (Friend_Connections *)object;
    const Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return -1;
    }

    if (friend_con->crypt_connection_id != -1) {
        return friend_add_tcp_relay(fr_c, number, ip_port, public_key);
    }

    return add_tcp_relay(fr_c->net_crypto, ip_port, public_key);
}

static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id);
/* Callback for DHT ip_port changes. */
static void dht_ip_callback(void *object, int32_t number, IP_Port ip_port)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return;
    }

    if (friend_con->crypt_connection_id == -1) {
        friend_new_connection(fr_c, number);
    }

    set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, ip_port, 1);
    friend_con->dht_ip_port = ip_port;
    friend_con->dht_ip_port_lastrecv = unix_time();

    if (friend_con->hosting_tcp_relay) {
        friend_add_tcp_relay(fr_c, number, ip_port, friend_con->dht_temp_pk);
        friend_con->hosting_tcp_relay = 0;
    }
}

static void change_dht_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_public_key)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return;
    }

    friend_con->dht_pk_lastrecv = unix_time();

    if (friend_con->dht_lock) {
        if (DHT_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock) != 0) {
            printf("a. Could not delete dht peer. Please report this.\n");
            return;
        }

        friend_con->dht_lock = 0;
    }

    DHT_addfriend(fr_c->dht, dht_public_key, dht_ip_callback, fr_c, friendcon_id, &friend_con->dht_lock);
    memcpy(friend_con->dht_temp_pk, dht_public_key, CRYPTO_PUBLIC_KEY_SIZE);
}

static int handle_status(void *object, int number, uint8_t status, void *userdata)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return -1;
    }

    bool call_cb = 0;

    if (status) {  /* Went online. */
        call_cb = 1;
        friend_con->status = FRIENDCONN_STATUS_CONNECTED;
        friend_con->ping_lastrecv = unix_time();
        friend_con->share_relays_lastsent = 0;
        onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
    } else {  /* Went offline. */
        if (friend_con->status != FRIENDCONN_STATUS_CONNECTING) {
            call_cb = 1;
            friend_con->dht_pk_lastrecv = unix_time();
            onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
        }

        friend_con->status = FRIENDCONN_STATUS_CONNECTING;
        friend_con->crypt_connection_id = -1;
        friend_con->hosting_tcp_relay = 0;
    }

    if (call_cb) {
        unsigned int i;

        for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
            if (friend_con->callbacks[i].status_callback) {
                friend_con->callbacks[i].status_callback(
                    friend_con->callbacks[i].callback_object,
                    friend_con->callbacks[i].callback_id, status, userdata);
            }
        }
    }

    return 0;
}

/* Callback for dht public key changes. */
static void dht_pk_callback(void *object, int32_t number, const uint8_t *dht_public_key, void *userdata)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *const friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return;
    }

    if (public_key_cmp(friend_con->dht_temp_pk, dht_public_key) == 0) {
        return;
    }

    change_dht_pk(fr_c, number, dht_public_key);

    /* if pk changed, create a new connection.*/
    if (friend_con->crypt_connection_id != -1) {
        crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);
        friend_con->crypt_connection_id = -1;
        handle_status(object, number, 0, userdata); /* Going offline. */
    }

    friend_new_connection(fr_c, number);
    onion_set_friend_DHT_pubkey(fr_c->onion_c, friend_con->onion_friendnum, dht_public_key);
}

static int handle_packet(void *object, int number, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    Friend_Connections *const fr_c = (Friend_Connections *)object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return -1;
    }

    if (data[0] == PACKET_ID_FRIEND_REQUESTS) {
        if (fr_c->fr_request_callback) {
            fr_c->fr_request_callback(fr_c->fr_request_object, friend_con->real_public_key, data, length, userdata);
        }

        return 0;
    }

    if (data[0] == PACKET_ID_ALIVE) {
        friend_con->ping_lastrecv = unix_time();
        return 0;
    }

    if (data[0] == PACKET_ID_SHARE_RELAYS) {
        Node_format nodes[MAX_SHARED_RELAYS];
        const int n = unpack_nodes(nodes, MAX_SHARED_RELAYS, nullptr, data + 1, length - 1, 1);

        if (n == -1) {
            return -1;
        }

        for (int j = 0; j < n; j++) {
            friend_add_tcp_relay(fr_c, number, nodes[j].ip_port, nodes[j].public_key);
        }

        return 0;
    }

    for (unsigned i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].data_callback) {
            friend_con->callbacks[i].data_callback(
                friend_con->callbacks[i].callback_object,
                friend_con->callbacks[i].callback_id, data, length, userdata);
        }

        friend_con = get_conn(fr_c, number);

        if (!friend_con) {
            return -1;
        }
    }

    return 0;
}

static int handle_lossy_packet(void *object, int number, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 0) {
        return -1;
    }

    Friend_Connections *const fr_c = (Friend_Connections *)object;
    const Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con) {
        return -1;
    }

    for (unsigned i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].lossy_data_callback) {
            friend_con->callbacks[i].lossy_data_callback(
                friend_con->callbacks[i].callback_object,
                friend_con->callbacks[i].callback_id, data, length, userdata);
        }

        friend_con = get_conn(fr_c, number);

        if (!friend_con) {
            return -1;
        }
    }

    return 0;
}

static int handle_new_connections(void *object, New_Connection *n_c)
{
    Friend_Connections *const fr_c = (Friend_Connections *)object;
    const int friendcon_id = getfriend_conn_id_pk(fr_c, n_c->public_key);
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
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

    if (n_c->source.ip.family != TOX_AF_INET && n_c->source.ip.family != TOX_AF_INET6) {
        set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->dht_ip_port, 0);
    } else {
        friend_con->dht_ip_port = n_c->source;
        friend_con->dht_ip_port_lastrecv = unix_time();
    }

    if (public_key_cmp(friend_con->dht_temp_pk, n_c->dht_public_key) != 0) {
        change_dht_pk(fr_c, friendcon_id, n_c->dht_public_key);
    }

    nc_dht_pk_callback(fr_c->net_crypto, id, &dht_pk_callback, fr_c, friendcon_id);
    return 0;
}

static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    if (friend_con->crypt_connection_id != -1) {
        return -1;
    }

    /* If dht_temp_pk does not contains a pk. */
    if (!friend_con->dht_lock) {
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

static int send_ping(const Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    const uint8_t ping = PACKET_ID_ALIVE;
    const int64_t ret = write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, &ping, sizeof(ping), 0);

    if (ret != -1) {
        friend_con->ping_lastsent = unix_time();
        return 0;
    }

    return -1;
}

/* Increases lock_count for the connection with friendcon_id by 1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int friend_connection_lock(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    ++friend_con->lock_count;
    return 0;
}

/* return FRIENDCONN_STATUS_CONNECTED if the friend is connected.
 * return FRIENDCONN_STATUS_CONNECTING if the friend isn't connected.
 * return FRIENDCONN_STATUS_NONE on failure.
 */
unsigned int friend_con_connected(Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return 0;
    }

    return friend_con->status;
}

/* Copy public keys associated to friendcon_id.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int get_friendcon_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    if (real_pk) {
        memcpy(real_pk, friend_con->real_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }

    if (dht_temp_pk) {
        memcpy(dht_temp_pk, friend_con->dht_temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
    }

    return 0;
}

/* Set temp dht key for connection.
 */
void set_dht_temp_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_temp_pk, void *userdata)
{
    dht_pk_callback(fr_c, friendcon_id, dht_temp_pk, userdata);
}

/* Set the callbacks for the friend connection.
 * index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int friend_connection_callbacks(Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                int (*status_callback)(void *object, int id, uint8_t status, void *userdata),
                                int (*data_callback)(void *object, int id, const uint8_t *data, uint16_t len, void *userdata),
                                int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length, void *userdata),
                                void *object, int number)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    if (index >= MAX_FRIEND_CONNECTION_CALLBACKS) {
        return -1;
    }

    friend_con->callbacks[index].status_callback = status_callback;
    friend_con->callbacks[index].data_callback = data_callback;
    friend_con->callbacks[index].lossy_data_callback = lossy_data_callback;

    friend_con->callbacks[index].callback_object = object;
    friend_con->callbacks[index].callback_id = number;

    return 0;
}

/* return the crypt_connection_id for the connection.
 *
 * return crypt_connection_id on success.
 * return -1 on failure.
 */
int friend_connection_crypt_connection_id(Friend_Connections *fr_c, int friendcon_id)
{
    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    return friend_con->crypt_connection_id;
}

/* Create a new friend connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * return -1 on failure.
 * return connection id on success.
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

/* Kill a friend connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int kill_friend_connection(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    if (friend_con->lock_count) {
        --friend_con->lock_count;
        return 0;
    }

    onion_delfriend(fr_c->onion_c, friend_con->onion_friendnum);
    crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);

    if (friend_con->dht_lock) {
        DHT_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock);
    }

    return wipe_friend_conn(fr_c, friendcon_id);
}


/* Set friend request callback.
 *
 * This function will be called every time a friend request packet is received.
 */
void set_friend_request_callback(Friend_Connections *fr_c, int (*fr_request_callback)(void *, const uint8_t *,
                                 const uint8_t *, uint16_t, void *), void *object)
{
    fr_c->fr_request_callback = fr_request_callback;
    fr_c->fr_request_object = object;
    oniondata_registerhandler(fr_c->onion_c, CRYPTO_PACKET_FRIEND_REQ, fr_request_callback, object);
}

/* Send a Friend request packet.
 *
 *  return -1 if failure.
 *  return  0 if it sent the friend request directly to the friend.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int send_friend_request_packet(Friend_Connections *fr_c, int friendcon_id, uint32_t nospam_num, const uint8_t *data,
                               uint16_t length)
{
    if (1 + sizeof(nospam_num) + length > ONION_CLIENT_MAX_DATA_SIZE || length == 0) {
        return -1;
    }

    const Friend_Conn *const friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con) {
        return -1;
    }

    VLA(uint8_t, packet, 1 + sizeof(nospam_num) + length);
    memcpy(packet + 1, &nospam_num, sizeof(nospam_num));
    memcpy(packet + 1 + sizeof(nospam_num), data, length);

    if (friend_con->status == FRIENDCONN_STATUS_CONNECTED) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, packet, SIZEOF_VLA(packet), 0) != -1;
    }

    packet[0] = CRYPTO_PACKET_FRIEND_REQ;
    const int num = send_onion_data(fr_c->onion_c, friend_con->onion_friendnum, packet, SIZEOF_VLA(packet));

    if (num <= 0) {
        return -1;
    }

    return num;
}

/* Create new friend_connections instance. */
Friend_Connections *new_friend_connections(Onion_Client *onion_c, bool local_discovery_enabled)
{
    if (onion_c == nullptr) {
        return nullptr;
    }

    Friend_Connections *const temp = (Friend_Connections *)calloc(1, sizeof(Friend_Connections));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->dht = onion_get_dht(onion_c);
    temp->net_crypto = onion_get_net_crypto(onion_c);
    temp->onion_c = onion_c;
    temp->local_discovery_enabled = local_discovery_enabled;
    // Don't include default port in port range
    temp->next_LANport = TOX_PORTRANGE_FROM + 1;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);

    if (temp->local_discovery_enabled) {
        lan_discovery_init(temp->dht);
    }

    return temp;
}

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
static void LANdiscovery(Friend_Connections *fr_c)
{
    if (fr_c->last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        const uint16_t first = fr_c->next_LANport;
        uint16_t last = first + PORTS_PER_DISCOVERY;
        last = last > TOX_PORTRANGE_TO ? TOX_PORTRANGE_TO : last;

        // Always send to default port
        lan_discovery_send(net_htons(TOX_PORT_DEFAULT), fr_c->dht);

        // And check some extra ports
        for (uint16_t port = first; port < last; port++) {
            lan_discovery_send(net_htons(port), fr_c->dht);
        }

        // Don't include default port in port range
        fr_c->next_LANport = last != TOX_PORTRANGE_TO ? last : TOX_PORTRANGE_FROM + 1;
        fr_c->last_LANdiscovery = unix_time();
    }
}

/* main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c, void *userdata)
{
    const uint64_t temp_time = unix_time();

    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        Friend_Conn *const friend_con = get_conn(fr_c, i);

        if (friend_con) {
            if (friend_con->status == FRIENDCONN_STATUS_CONNECTING) {
                if (friend_con->dht_pk_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    if (friend_con->dht_lock) {
                        DHT_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock);
                        friend_con->dht_lock = 0;
                        memset(friend_con->dht_temp_pk, 0, CRYPTO_PUBLIC_KEY_SIZE);
                    }
                }

                if (friend_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_ip_port.ip.family = 0;
                }

                if (friend_con->dht_lock) {
                    if (friend_new_connection(fr_c, i) == 0) {
                        set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->dht_ip_port, 0);
                        connect_to_saved_tcp_relays(fr_c, i, (MAX_FRIEND_TCP_CONNECTIONS / 2)); /* Only fill it half up. */
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
                    handle_status(fr_c, i, 0, userdata); /* Going offline. */
                }
            }
        }
    }

    if (fr_c->local_discovery_enabled) {
        LANdiscovery(fr_c);
    }
}

/* Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c)
{
    if (!fr_c) {
        return;
    }

    for (uint32_t i = 0; i < fr_c->num_cons; ++i) {
        kill_friend_connection(fr_c, i);
    }

    if (fr_c->local_discovery_enabled) {
        lan_discovery_kill(fr_c->dht);
    }

    free(fr_c);
}
