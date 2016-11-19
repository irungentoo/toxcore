/* tox_connection.c
 *
 * Connection to tox instances.
 *
 *  Copyright (C) 2016 Tox project All Rights Reserved.
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

#include "tox_connection.h"
#include "util.h"

/* return 1 if the toxconn_id is not valid.
 * return 0 if the toxconn_id is valid.
 */
static uint8_t toxconn_id_not_valid(const Tox_Connections *tox_conns, int toxconn_id)
{
    if ((unsigned int)toxconn_id >= tox_conns->num_cons)
        return 1;

    if (tox_conns->conns == NULL)
        return 1;

    if (tox_conns->conns[toxconn_id].status == TOXCONN_STATUS_NONE)
        return 1;

    return 0;
}


/* Set the size of the tox connections list to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_toxconns(Tox_Connections *tox_conns, uint32_t num)
{
    if (num == 0) {
        free(tox_conns->conns);
        tox_conns->conns = NULL;
        return 0;
    }

    Tox_Conn *newgroup_cons = realloc(tox_conns->conns, num * sizeof(Tox_Conn));

    if (newgroup_cons == NULL)
        return -1;

    tox_conns->conns = newgroup_cons;
    return 0;
}

/* Create a new empty tox connection.
 *
 * return -1 on failure.
 * return toxconn_id on success.
 */
static int create_toxconn(Tox_Connections *tox_conns)
{
    uint32_t i;

    for (i = 0; i < tox_conns->num_cons; ++i) {
        if (tox_conns->conns[i].status == TOXCONN_STATUS_NONE)
            return i;
    }

    int id = -1;

    if (realloc_toxconns(tox_conns, tox_conns->num_cons + 1) == 0) {
        id = tox_conns->num_cons;
        ++tox_conns->num_cons;
        memset(&(tox_conns->conns[id]), 0, sizeof(Tox_Conn));
    }

    return id;
}

/* Wipe a single tox connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_tox_conn(Tox_Connections *tox_conns, int toxconn_id)
{
    if (toxconn_id_not_valid(tox_conns, toxconn_id))
        return -1;

    uint32_t i;
    memset(&(tox_conns->conns[toxconn_id]), 0 , sizeof(Tox_Conn));

    for (i = tox_conns->num_cons; i != 0; --i) {
        if (tox_conns->conns[i - 1].status != TOXCONN_STATUS_NONE)
            break;
    }

    if (tox_conns->num_cons != i) {
        tox_conns->num_cons = i;
        realloc_toxconns(tox_conns, tox_conns->num_cons);
    }

    return 0;
}

static Tox_Conn *get_conn(const Tox_Connections *tox_conns, int toxconn_id)
{
    if (toxconn_id_not_valid(tox_conns, toxconn_id))
        return 0;

    return &tox_conns->conns[toxconn_id];
}

/* return toxconn_id corresponding to the real public key on success.
 * return -1 on failure.
 */
int toxconn_get_id_from_pk(Tox_Connections *tox_conns, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < tox_conns->num_cons; ++i) {
        Tox_Conn *tox_con = get_conn(tox_conns, i);

        if (tox_con) {
            if (public_key_cmp(tox_con->real_public_key, real_pk) == 0)
                return i;
        }
    }

    return -1;
}

/* Add a TCP relay associated to the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int toxconn_add_tcp_relay(Tox_Connections *tox_conns, int toxconn_id, IP_Port ip_port, const uint8_t *public_key)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    /* Local ip and same pk means that they are hosting a TCP relay. */
    if (Local_ip(ip_port.ip) && public_key_cmp(tox_con->dht_temp_pk, public_key) == 0) {
        if (tox_con->dht_ip_port.ip.family != 0) {
            ip_port.ip = tox_con->dht_ip_port.ip;
        } else {
            tox_con->hosting_tcp_relay = 0;
        }
    }

    unsigned int i;

    uint16_t index = tox_con->tcp_relay_counter % TOXCONN_MAX_STORED_TCP_RELAYS;

    for (i = 0; i < TOXCONN_MAX_STORED_TCP_RELAYS; ++i) {
        if (tox_con->tcp_relays[i].ip_port.ip.family != 0
                && public_key_cmp(tox_con->tcp_relays[i].public_key, public_key) == 0) {
            memset(&tox_con->tcp_relays[i], 0, sizeof(Node_format));
        }
    }

    tox_con->tcp_relays[index].ip_port = ip_port;
    memcpy(tox_con->tcp_relays[index].public_key, public_key, crypto_box_PUBLICKEYBYTES);
    ++tox_con->tcp_relay_counter;

    return add_tcp_relay_peer(tox_conns->net_crypto, tox_con->crypt_connection_id, ip_port, public_key);
}

/* Connect to number saved relays for connection. */
static void connect_to_saved_tcp_relays(Tox_Connections *tox_conns, int toxconn_id, unsigned int number)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return;

    unsigned int i;

    for (i = 0; (i < TOXCONN_MAX_STORED_TCP_RELAYS) && (number != 0); ++i) {
        uint16_t index = (tox_con->tcp_relay_counter - (i + 1)) % TOXCONN_MAX_STORED_TCP_RELAYS;

        if (tox_con->tcp_relays[index].ip_port.ip.family) {
            if (add_tcp_relay_peer(tox_conns->net_crypto, tox_con->crypt_connection_id, tox_con->tcp_relays[index].ip_port,
                                   tox_con->tcp_relays[index].public_key) == 0) {
                --number;
            }
        }
    }
}

static unsigned int send_relays(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return 0;

    Node_format nodes[MAX_SHARED_RELAYS];
    uint8_t data[1024];
    int n, length;

    n = copy_connected_tcp_relays(tox_conns->net_crypto, nodes, MAX_SHARED_RELAYS);

    int i;

    for (i = 0; i < n; ++i) {
        /* Associated the relays being sent with this connection.
           On receiving the peer will do the same which will establish the connection. */
        toxconn_add_tcp_relay(tox_conns, toxconn_id, nodes[i].ip_port, nodes[i].public_key);
    }

    length = pack_nodes(data + 1, sizeof(data) - 1, nodes, n);

    if (length <= 0)
        return 0;

    data[0] = PACKET_ID_SHARE_RELAYS;
    ++length;

    if (write_cryptpacket(tox_conns->net_crypto, tox_con->crypt_connection_id, data, length, 0) != -1) {
        tox_con->share_relays_lastsent = unix_time();
        return 1;
    }

    return 0;
}

/* callback for recv TCP relay nodes. */
static int tcp_relay_node_callback(void *object, uint32_t number, IP_Port ip_port, const uint8_t *public_key)
{
    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return -1;

    if (tox_con->crypt_connection_id != -1) {
        return toxconn_add_tcp_relay(tox_conns, number, ip_port, public_key);
    } else {
        return add_tcp_relay(tox_conns->net_crypto, ip_port, public_key);
    }
}

static int toxconn_new_connection(Tox_Connections *tox_conns, int toxconn_id);
/* Callback for DHT ip_port changes. */
static void dht_ip_callback(void *object, int32_t number, IP_Port ip_port)
{
    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return;

    if (tox_con->crypt_connection_id == -1) {
        toxconn_new_connection(tox_conns, number);
    }

    set_direct_ip_port(tox_conns->net_crypto, tox_con->crypt_connection_id, ip_port, 1);
    tox_con->dht_ip_port = ip_port;
    tox_con->dht_ip_port_lastrecv = unix_time();

    if (tox_con->hosting_tcp_relay) {
        toxconn_add_tcp_relay(tox_conns, number, ip_port, tox_con->dht_temp_pk);
        tox_con->hosting_tcp_relay = 0;
    }
}

static void change_dht_pk(Tox_Connections *tox_conns, int toxconn_id, const uint8_t *dht_public_key)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return;

    tox_con->dht_pk_lastrecv = unix_time();

    if (tox_con->dht_lock) {
        if (DHT_delfriend(tox_conns->dht, tox_con->dht_temp_pk, tox_con->dht_lock) != 0) {
            printf("a. Could not delete dht peer. Please report this.\n");
            return;
        }

        tox_con->dht_lock = 0;
    }

    DHT_addfriend(tox_conns->dht, dht_public_key, dht_ip_callback, tox_conns, toxconn_id, &tox_con->dht_lock);
    memcpy(tox_con->dht_temp_pk, dht_public_key, crypto_box_PUBLICKEYBYTES);
}

static int handle_status(void *object, int number, uint8_t status)
{
    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return -1;

    _Bool call_cb = 0;

    if (status) {  /* Went online. */
        call_cb = 1;
        tox_con->status = TOXCONN_STATUS_CONNECTED;
        tox_con->ping_lastrecv = unix_time();
        tox_con->share_relays_lastsent = 0;
        onion_set_friend_online(tox_conns->onion_c, tox_con->onion_friendnum, status);
    } else {  /* Went offline. */
        if (tox_con->status != TOXCONN_STATUS_CONNECTING) {
            call_cb = 1;
            tox_con->dht_pk_lastrecv = unix_time();
            onion_set_friend_online(tox_conns->onion_c, tox_con->onion_friendnum, status);
        }

        tox_con->status = TOXCONN_STATUS_CONNECTING;
        tox_con->crypt_connection_id = -1;
        tox_con->hosting_tcp_relay = 0;
    }

    if (call_cb) {
        unsigned int i;

        for (i = 0; i < MAX_TOX_CONNECTION_CALLBACKS; ++i) {
            if (tox_con->callbacks[i].status_callback)
                tox_con->callbacks[i].status_callback(tox_con->callbacks[i].status_callback_object,
                        tox_con->callbacks[i].status_callback_id, status);
        }
    }

    return 0;
}

/* Callback for dht public key changes. */
static void dht_pk_callback(void *object, int32_t number, const uint8_t *dht_public_key)
{
    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return;

    if (public_key_cmp(tox_con->dht_temp_pk, dht_public_key) == 0)
        return;

    change_dht_pk(tox_conns, number, dht_public_key);

    /* if pk changed, create a new connection.*/
    if (tox_con->crypt_connection_id != -1) {
        crypto_kill(tox_conns->net_crypto, tox_con->crypt_connection_id);
        tox_con->crypt_connection_id = -1;
        handle_status(object, number, 0); /* Going offline. */
    }

    toxconn_new_connection(tox_conns, number);
    onion_set_friend_DHT_pubkey(tox_conns->onion_c, tox_con->onion_friendnum, dht_public_key);
}

static int handle_packet(void *object, int number, uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return -1;

    if (data[0] == PACKET_ID_FRIEND_REQUESTS) {
        if (tox_conns->toxconn_request_callback)
            tox_conns->toxconn_request_callback(tox_conns->toxconn_request_object, tox_con->real_public_key, data, length);

        return 0;
    } else if (data[0] == PACKET_ID_ALIVE) {
        tox_con->ping_lastrecv = unix_time();
        return 0;
    } else if (data[0] == PACKET_ID_SHARE_RELAYS) {
        Node_format nodes[MAX_SHARED_RELAYS];
        int n;

        if ((n = unpack_nodes(nodes, MAX_SHARED_RELAYS, NULL, data + 1, length - 1, 1)) == -1)
            return -1;

        int j;

        for (j = 0; j < n; j++) {
            toxconn_add_tcp_relay(tox_conns, number, nodes[j].ip_port, nodes[j].public_key);
        }

        return 0;
    }

    unsigned int i;

    for (i = 0; i < MAX_TOX_CONNECTION_CALLBACKS; ++i) {
        if (tox_con->callbacks[i].data_callback)
            tox_con->callbacks[i].data_callback(tox_con->callbacks[i].data_callback_object,
                                                   tox_con->callbacks[i].data_callback_id, data, length);

        tox_con = get_conn(tox_conns, number);

        if (!tox_con)
            return -1;
    }

    return 0;
}

static int handle_lossy_packet(void *object, int number, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    Tox_Connections *tox_conns = object;
    Tox_Conn *tox_con = get_conn(tox_conns, number);

    if (!tox_con)
        return -1;

    unsigned int i;

    for (i = 0; i < MAX_TOX_CONNECTION_CALLBACKS; ++i) {
        if (tox_con->callbacks[i].lossy_data_callback)
            tox_con->callbacks[i].lossy_data_callback(tox_con->callbacks[i].lossy_data_callback_object,
                    tox_con->callbacks[i].lossy_data_callback_id, data, length);

        tox_con = get_conn(tox_conns, number);

        if (!tox_con)
            return -1;
    }

    return 0;
}

static int handle_new_connections(void *object, New_Connection *n_c)
{
    Tox_Connections *tox_conns = object;
    int toxconn_id = toxconn_get_id_from_pk(tox_conns, n_c->public_key);
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (tox_con) {

        if (tox_con->crypt_connection_id != -1)
            return -1;

        int id = accept_crypto_connection(tox_conns->net_crypto, n_c);

        if (id == -1) {
            return -1;
        }

        connection_status_handler(tox_conns->net_crypto, id, &handle_status, tox_conns, toxconn_id);
        connection_data_handler(tox_conns->net_crypto, id, &handle_packet, tox_conns, toxconn_id);
        connection_lossy_data_handler(tox_conns->net_crypto, id, &handle_lossy_packet, tox_conns, toxconn_id);
        tox_con->crypt_connection_id = id;

        if (n_c->source.ip.family != AF_INET && n_c->source.ip.family != AF_INET6) {
            set_direct_ip_port(tox_conns->net_crypto, tox_con->crypt_connection_id, tox_con->dht_ip_port, 0);
        } else {
            tox_con->dht_ip_port = n_c->source;
            tox_con->dht_ip_port_lastrecv = unix_time();
        }

        if (public_key_cmp(tox_con->dht_temp_pk, n_c->dht_public_key) != 0) {
            change_dht_pk(tox_conns, toxconn_id, n_c->dht_public_key);
        }

        nc_dht_pk_callback(tox_conns->net_crypto, id, &dht_pk_callback, tox_conns, toxconn_id);
        return 0;
    }

    return -1;
}

static int toxconn_new_connection(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    if (tox_con->crypt_connection_id != -1) {
        return -1;
    }

    /* If dht_temp_pk does not contains a pk. */
    if (!tox_con->dht_lock) {
        return -1;
    }

    int id = new_crypto_connection(tox_conns->net_crypto, tox_con->real_public_key, tox_con->dht_temp_pk);

    if (id == -1)
        return -1;

    tox_con->crypt_connection_id = id;
    connection_status_handler(tox_conns->net_crypto, id, &handle_status, tox_conns, toxconn_id);
    connection_data_handler(tox_conns->net_crypto, id, &handle_packet, tox_conns, toxconn_id);
    connection_lossy_data_handler(tox_conns->net_crypto, id, &handle_lossy_packet, tox_conns, toxconn_id);
    nc_dht_pk_callback(tox_conns->net_crypto, id, &dht_pk_callback, tox_conns, toxconn_id);

    return 0;
}

static int send_ping(const Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    uint8_t ping = PACKET_ID_ALIVE;
    int64_t ret = write_cryptpacket(tox_conns->net_crypto, tox_con->crypt_connection_id, &ping, sizeof(ping), 0);

    if (ret != -1) {
        tox_con->ping_lastsent = unix_time();
        return 0;
    }

    return -1;
}

/* Increases lock_count for the connection with toxconn_id by 1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int toxconns_inc_conn_lock(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    ++tox_con->lock_count;
    return 0;
}

/* return TOXCONN_STATUS_CONNECTED if the peer is connected.
 * return TOXCONN_STATUS_CONNECTING if the peer isn't connected.
 * return TOXCONN_STATUS_NONE on failure.
 */
unsigned int toxconn_is_connected(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return 0;

    return tox_con->status;
}

/* Copy public keys associated to toxconn_id.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int toxconn_get_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    if (real_pk)
        memcpy(real_pk, tox_con->real_public_key, crypto_box_PUBLICKEYBYTES);

    if (dht_temp_pk)
        memcpy(dht_temp_pk, tox_con->dht_temp_pk, crypto_box_PUBLICKEYBYTES);

    return 0;
}

/* Set temp dht key for connection. */
void set_dht_temp_pk(Tox_Connections *tox_conns, int toxconn_id, const uint8_t *dht_temp_pk)
{
    dht_pk_callback(tox_conns, toxconn_id, dht_temp_pk);
}

/* Set the callbacks for the given connection.
 * index is the index (0 to (MAX_TOX_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int toxconn_set_callbacks(Tox_Connections *tox_conns, int toxconn_id, unsigned int index,
                          int (*status_callback)(void *object, int id, uint8_t status),
                          int (*data_callback)(void *object, int id, uint8_t *data, uint16_t length),
                          int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length),
                          void *object, int number)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    if (index >= MAX_TOX_CONNECTION_CALLBACKS)
        return -1;

    tox_con->callbacks[index].status_callback = status_callback;
    tox_con->callbacks[index].data_callback = data_callback;
    tox_con->callbacks[index].lossy_data_callback = lossy_data_callback;

    tox_con->callbacks[index].status_callback_object =
        tox_con->callbacks[index].data_callback_object =
            tox_con->callbacks[index].lossy_data_callback_object = object;

    tox_con->callbacks[index].status_callback_id =
        tox_con->callbacks[index].data_callback_id =
            tox_con->callbacks[index].lossy_data_callback_id = number;
    return 0;
}

/* return the crypt_connection_id for the connection.
 *
 * return crypt_connection_id on success.
 * return -1 on failure.
 */
int toxconn_crypt_connection_id(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    return tox_con->crypt_connection_id;
}

/* Create a new connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_tox_conn(Tox_Connections *tox_conns, const uint8_t *real_public_key)
{
    int toxconn_id = toxconn_get_id_from_pk(tox_conns, real_public_key);

    if (toxconn_id != -1) {
        ++tox_conns->conns[toxconn_id].lock_count;
        return toxconn_id;
    }

    toxconn_id = create_toxconn(tox_conns);

    if (toxconn_id == -1)
        return -1;

    int32_t onion_friendnum = onion_addfriend(tox_conns->onion_c, real_public_key);

    if (onion_friendnum == -1)
        return -1;

    Tox_Conn *tox_con = &tox_conns->conns[toxconn_id];

    tox_con->crypt_connection_id = -1;
    tox_con->status = TOXCONN_STATUS_CONNECTING;
    memcpy(tox_con->real_public_key, real_public_key, crypto_box_PUBLICKEYBYTES);
    tox_con->onion_friendnum = onion_friendnum;

    recv_tcp_relay_handler(tox_conns->onion_c, onion_friendnum, &tcp_relay_node_callback, tox_conns, toxconn_id);
    onion_dht_pk_callback(tox_conns->onion_c, onion_friendnum, &dht_pk_callback, tox_conns, toxconn_id);

    return toxconn_id;
}

/* Kill a connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int kill_tox_conn(Tox_Connections *tox_conns, int toxconn_id)
{
    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    if (tox_con->lock_count) {
        --tox_con->lock_count;
        return 0;
    }

    onion_delfriend(tox_conns->onion_c, tox_con->onion_friendnum);
    crypto_kill(tox_conns->net_crypto, tox_con->crypt_connection_id);

    if (tox_con->dht_lock) {
        DHT_delfriend(tox_conns->dht, tox_con->dht_temp_pk, tox_con->dht_lock);
    }

    return wipe_tox_conn(tox_conns, toxconn_id);
}


/* Set connection request callback.
 *
 * This function will be called every time any connection request packet is received.
 */
void set_tox_conn_request_callback(Tox_Connections *tox_conns,
                                   int (*toxconn_request_callback)(void *, const uint8_t *, const uint8_t *, uint16_t),
                                   void *object)
{
    tox_conns->toxconn_request_callback = toxconn_request_callback;
    tox_conns->toxconn_request_object = object;
    oniondata_registerhandler(tox_conns->onion_c, CRYPTO_PACKET_FRIEND_REQ, toxconn_request_callback, object);
}

/* Send a connection request packet.
 *
 *  return -1 if failure.
 *  return  0 if it sent the friend request directly to the friend.
 *  return the number of peers it was routed through if it did not send it directly.
 */
int send_tox_conn_request_pkt(Tox_Connections *tox_conns, int toxconn_id, uint32_t nospam_num, const uint8_t *data,
                               uint16_t length)
{
    if (1 + sizeof(nospam_num) + length > ONION_CLIENT_MAX_DATA_SIZE || length == 0)
        return -1;

    Tox_Conn *tox_con = get_conn(tox_conns, toxconn_id);

    if (!tox_con)
        return -1;

    uint8_t packet[1 + sizeof(nospam_num) + length];
    memcpy(packet + 1, &nospam_num, sizeof(nospam_num));
    memcpy(packet + 1 + sizeof(nospam_num), data, length);

    if (tox_con->status == TOXCONN_STATUS_CONNECTED) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return write_cryptpacket(tox_conns->net_crypto, tox_con->crypt_connection_id, packet, sizeof(packet), 0) != -1;
    } else {
        packet[0] = CRYPTO_PACKET_FRIEND_REQ;
        int num = send_onion_data(tox_conns->onion_c, tox_con->onion_friendnum, packet, sizeof(packet));

        if (num <= 0)
            return -1;

        return num;
    }
}

/* Create new Tox_Connections instance. */
Tox_Connections *new_tox_conns(Onion_Client *onion_c)
{
    if (!onion_c)
        return NULL;

    Tox_Connections *temp = calloc(1, sizeof(Tox_Connections));

    if (temp == NULL)
        return NULL;

    temp->dht = onion_c->dht;
    temp->net_crypto = onion_c->c;
    temp->onion_c = onion_c;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);
    LANdiscovery_init(temp->dht);

    return temp;
}

/* Send a LAN discovery packet every LAN_DISCOVERY_INTERVAL seconds. */
static void LANdiscovery(Tox_Connections *tox_conns)
{
    if (tox_conns->last_LANdiscovery + LAN_DISCOVERY_INTERVAL < unix_time()) {
        send_LANdiscovery(htons(TOX_PORT_DEFAULT), tox_conns->dht);
        tox_conns->last_LANdiscovery = unix_time();
    }
}

/* main Tox_Connections loop. */
void do_tox_connections(Tox_Connections *tox_conns)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < tox_conns->num_cons; ++i) {
        Tox_Conn *tox_con = get_conn(tox_conns, i);

        if (tox_con) {
            if (tox_con->status == TOXCONN_STATUS_CONNECTING) {
                if (tox_con->dht_pk_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    if (tox_con->dht_lock) {
                        DHT_delfriend(tox_conns->dht, tox_con->dht_temp_pk, tox_con->dht_lock);
                        tox_con->dht_lock = 0;
                    }
                }

                if (tox_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    tox_con->dht_ip_port.ip.family = 0;
                }

                if (tox_con->dht_lock) {
                    if (toxconn_new_connection(tox_conns, i) == 0) {
                        set_direct_ip_port(tox_conns->net_crypto, tox_con->crypt_connection_id, tox_con->dht_ip_port, 0);
                        connect_to_saved_tcp_relays(tox_conns, i, (MAX_TCP_CONNECTIONS / 2)); /* Only fill it half up. */
                    }
                }

            } else if (tox_con->status == TOXCONN_STATUS_CONNECTED) {
                if (tox_con->ping_lastsent + TOXCONN_PING_INTERVAL < temp_time) {
                    send_ping(tox_conns, i);
                }

                if (tox_con->share_relays_lastsent + SHARE_RELAYS_INTERVAL < temp_time) {
                    send_relays(tox_conns, i);
                }

                if (tox_con->ping_lastrecv + TOXCONN_TIMEOUT < temp_time) {
                    /* If we stopped receiving ping packets, kill it. */
                    crypto_kill(tox_conns->net_crypto, tox_con->crypt_connection_id);
                    tox_con->crypt_connection_id = -1;
                    handle_status(tox_conns, i, 0); /* Going offline. */
                }
            }
        }
    }

    LANdiscovery(tox_conns);
}

/* Free everything related with given Tox_Connections. */
void kill_tox_conns(Tox_Connections *tox_conns)
{
    if (!tox_conns)
        return;

    uint32_t i;

    for (i = 0; i < tox_conns->num_cons; ++i) {
        kill_tox_conn(tox_conns, i);
    }

    LANdiscovery_kill(tox_conns->dht);
    free(tox_conns);
}
