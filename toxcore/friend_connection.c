/* friend_connection.c
 *
 * Connection to friends.
 *
 *  Copyright (C) 2014 Tox project All Rights Reserved.
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

#include "friend_connection.h"
#include "util.h"

/* return 1 if the friendcon_id is not valid.
 * return 0 if the friendcon_id is valid.
 */
static uint8_t friendconn_id_not_valid(const Friend_Connections *fr_c, int friendcon_id)
{
    if ((unsigned int)friendcon_id >= fr_c->num_cons)
        return 1;

    if (fr_c->conns == NULL)
        return 1;

    if (fr_c->conns[friendcon_id].status == FRIENDCONN_STATUS_NONE)
        return 1;

    return 0;
}


/* Set the size of the friend connections list to num.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_friendconns(Friend_Connections *fr_c, uint32_t num)
{
    if (num == 0) {
        free(fr_c->conns);
        fr_c->conns = NULL;
        return 0;
    }

    Friend_Conn *newgroup_cons = realloc(fr_c->conns, num * sizeof(Friend_Conn));

    if (newgroup_cons == NULL)
        return -1;

    fr_c->conns = newgroup_cons;
    return 0;
}

/* Create a new empty friend connection.
 *
 * return -1 on failure.
 * return friendcon_id on success.
 */
static int create_friend_conn(Friend_Connections *fr_c)
{
    uint32_t i;

    for (i = 0; i < fr_c->num_cons; ++i) {
        if (fr_c->conns[i].status == FRIENDCONN_STATUS_NONE)
            return i;
    }

    int id = -1;

    if (realloc_friendconns(fr_c, fr_c->num_cons + 1) == 0) {
        id = fr_c->num_cons;
        ++fr_c->num_cons;
        memset(&(fr_c->conns[id]), 0, sizeof(Friend_Conn));
    }

    return id;
}

/* Wipe a friend connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_friend_conn(Friend_Connections *fr_c, int friendcon_id)
{
    if (friendconn_id_not_valid(fr_c, friendcon_id))
        return -1;

    uint32_t i;
    memset(&(fr_c->conns[friendcon_id]), 0 , sizeof(Friend_Conn));

    for (i = fr_c->num_cons; i != 0; --i) {
        if (fr_c->conns[i - 1].status != FRIENDCONN_STATUS_NONE)
            break;
    }

    if (fr_c->num_cons != i) {
        fr_c->num_cons = i;
        realloc_friendconns(fr_c, fr_c->num_cons);
    }

    return 0;
}

static Friend_Conn *get_conn(const Friend_Connections *fr_c, int friendcon_id)
{
    if (friendconn_id_not_valid(fr_c, friendcon_id))
        return 0;

    return &fr_c->conns[friendcon_id];
}

/* return friendcon_id corresponding to the real public key on success.
 * return -1 on failure.
 */
int getfriend_conn_id_pk(Friend_Connections *fr_c, const uint8_t *real_pk)
{
    uint32_t i;

    for (i = 0; i < fr_c->num_cons; ++i) {
        Friend_Conn *friend_con = get_conn(fr_c, i);

        if (friend_con) {
            if (memcmp(friend_con->real_public_key, real_pk, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
        }
    }

    return -1;
}

/* callback for recv TCP relay nodes. */
static int tcp_relay_node_callback(void *object, uint32_t number, IP_Port ip_port, const uint8_t *public_key)
{
    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return -1;

    if (friend_con->crypt_connection_id != -1) {
        return add_tcp_relay_peer(fr_c->net_crypto, friend_con->crypt_connection_id, ip_port, public_key);
    } else {
        return add_tcp_relay(fr_c->net_crypto, ip_port, public_key);
    }
}

static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id);
/* Callback for DHT ip_port changes. */
static void dht_ip_callback(void *object, int32_t number, IP_Port ip_port)
{
    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return;

    if (friend_con->crypt_connection_id == -1) {
        friend_new_connection(fr_c, number);
    }

    set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, ip_port);
    friend_con->dht_ip_port = ip_port;
    friend_con->dht_ip_port_lastrecv = unix_time();
}

/* Callback for dht public key changes. */
static void dht_pk_callback(void *object, int32_t number, const uint8_t *dht_public_key)
{
    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return;

    friend_con->dht_ping_lastrecv = unix_time();

    if (memcmp(friend_con->dht_temp_pk, dht_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return;

    if (friend_con->dht_lock) {
        if (DHT_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock) != 0) {
            printf("a. Could not delete dht peer. Please report this.\n");
            return;
        }

        friend_con->dht_lock = 0;
    }

    DHT_addfriend(fr_c->dht, dht_public_key, dht_ip_callback, object, number, &friend_con->dht_lock);

    if (friend_con->crypt_connection_id == -1) {
        friend_new_connection(fr_c, number);
    }

    set_connection_dht_public_key(fr_c->net_crypto, friend_con->crypt_connection_id, dht_public_key);
    onion_set_friend_DHT_pubkey(fr_c->onion_c, friend_con->onion_friendnum, dht_public_key);

    memcpy(friend_con->dht_temp_pk, dht_public_key, crypto_box_PUBLICKEYBYTES);
}

static int handle_status(void *object, int number, uint8_t status)
{
    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return -1;

    _Bool call_cb = 0;

    if (status) {  /* Went online. */
        call_cb = 1;
        friend_con->status = FRIENDCONN_STATUS_CONNECTED;
        friend_con->ping_lastrecv = unix_time();
        onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
    } else {  /* Went offline. */
        if (friend_con->status != FRIENDCONN_STATUS_CONNECTING) {
            call_cb = 1;
            friend_con->dht_ping_lastrecv = unix_time();
            onion_set_friend_online(fr_c->onion_c, friend_con->onion_friendnum, status);
        }

        friend_con->status = FRIENDCONN_STATUS_CONNECTING;
        friend_con->crypt_connection_id = -1;
    }

    if (call_cb) {
        unsigned int i;

        for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
            if (friend_con->callbacks[i].status_callback)
                friend_con->callbacks[i].status_callback(friend_con->callbacks[i].status_callback_object,
                        friend_con->callbacks[i].status_callback_id, status);
        }
    }

    return 0;
}

static int handle_packet(void *object, int number, uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (data[0] == PACKET_ID_FRIEND_REQUESTS) {
        if (fr_c->fr_request_callback)
            fr_c->fr_request_callback(fr_c->fr_request_object, friend_con->real_public_key, data, length);

        return 0;
    }

    if (!friend_con)
        return -1;

    if (data[0] == PACKET_ID_ALIVE) {
        friend_con->ping_lastrecv = unix_time();
        return 0;
    }

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].data_callback)
            friend_con->callbacks[i].data_callback(friend_con->callbacks[i].data_callback_object,
                                                   friend_con->callbacks[i].data_callback_id, data, length);

        friend_con = get_conn(fr_c, number);

        if (!friend_con)
            return -1;
    }

    return 0;
}

static int handle_lossy_packet(void *object, int number, const uint8_t *data, uint16_t length)
{
    if (length == 0)
        return -1;

    Friend_Connections *fr_c = object;
    Friend_Conn *friend_con = get_conn(fr_c, number);

    if (!friend_con)
        return -1;

    unsigned int i;

    for (i = 0; i < MAX_FRIEND_CONNECTION_CALLBACKS; ++i) {
        if (friend_con->callbacks[i].lossy_data_callback)
            friend_con->callbacks[i].lossy_data_callback(friend_con->callbacks[i].lossy_data_callback_object,
                    friend_con->callbacks[i].lossy_data_callback_id, data, length);

        friend_con = get_conn(fr_c, number);

        if (!friend_con)
            return -1;
    }

    return 0;
}

static int handle_new_connections(void *object, New_Connection *n_c)
{
    Friend_Connections *fr_c = object;
    int friendcon_id = getfriend_conn_id_pk(fr_c, n_c->public_key);
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (friend_con) {

        if (friend_con->crypt_connection_id != -1)
            return -1;

        int id = accept_crypto_connection(fr_c->net_crypto, n_c);
        connection_status_handler(fr_c->net_crypto, id, &handle_status, fr_c, friendcon_id);
        connection_data_handler(fr_c->net_crypto, id, &handle_packet, fr_c, friendcon_id);
        connection_lossy_data_handler(fr_c->net_crypto, id, &handle_lossy_packet, fr_c, friendcon_id);
        friend_con->crypt_connection_id = id;

        if (n_c->source.ip.family != AF_INET && n_c->source.ip.family != AF_INET6) {
            set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->dht_ip_port);
        } else {
            friend_con->dht_ip_port = n_c->source;
            friend_con->dht_ip_port_lastrecv = unix_time();
        }

        dht_pk_callback(fr_c, friendcon_id, n_c->dht_public_key);

        nc_dht_pk_callback(fr_c->net_crypto, id, &dht_pk_callback, fr_c, friendcon_id);
        return 0;
    }

    return -1;
}

static int friend_new_connection(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    if (friend_con->crypt_connection_id != -1) {
        return -1;
    }

    int id = new_crypto_connection(fr_c->net_crypto, friend_con->real_public_key);

    if (id == -1)
        return -1;

    friend_con->crypt_connection_id = id;
    connection_status_handler(fr_c->net_crypto, id, &handle_status, fr_c, friendcon_id);
    connection_data_handler(fr_c->net_crypto, id, &handle_packet, fr_c, friendcon_id);
    connection_lossy_data_handler(fr_c->net_crypto, id, &handle_lossy_packet, fr_c, friendcon_id);
    nc_dht_pk_callback(fr_c->net_crypto, id, &dht_pk_callback, fr_c, friendcon_id);

    return 0;
}

static int send_ping(const Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    uint8_t ping = PACKET_ID_ALIVE;
    int64_t ret = write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, &ping, sizeof(ping), 0);

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
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    ++friend_con->lock_count;
    return 0;
}

/* return FRIENDCONN_STATUS_CONNECTED if the friend is connected.
 * return FRIENDCONN_STATUS_CONNECTING if the friend isn't connected.
 * return FRIENDCONN_STATUS_NONE on failure.
 */
unsigned int friend_con_connected(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return 0;

    return friend_con->status;
}

/* Copy public keys associated to friendcon_id.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int get_friendcon_public_keys(uint8_t *real_pk, uint8_t *dht_temp_pk, Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    if (real_pk)
        memcpy(real_pk, friend_con->real_public_key, crypto_box_PUBLICKEYBYTES);

    if (dht_temp_pk)
        memcpy(dht_temp_pk, friend_con->dht_temp_pk, crypto_box_PUBLICKEYBYTES);

    return 0;
}

/* Set temp dht key for connection.
 */
void set_dht_temp_pk(Friend_Connections *fr_c, int friendcon_id, const uint8_t *dht_temp_pk)
{
    dht_pk_callback(fr_c, friendcon_id, dht_temp_pk);
}

/* Set the callbacks for the friend connection.
 * index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we want the callback to set in the array.
 *
 * return 0 on success.
 * return -1 on failure
 */
int friend_connection_callbacks(Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                int (*status_callback)(void *object, int id, uint8_t status), int (*data_callback)(void *object, int id, uint8_t *data,
                                        uint16_t length), int (*lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length), void *object,
                                int number)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    if (index >= MAX_FRIEND_CONNECTION_CALLBACKS)
        return -1;

    friend_con->callbacks[index].status_callback = status_callback;
    friend_con->callbacks[index].data_callback = data_callback;
    friend_con->callbacks[index].lossy_data_callback = lossy_data_callback;

    friend_con->callbacks[index].status_callback_object =
        friend_con->callbacks[index].data_callback_object =
            friend_con->callbacks[index].lossy_data_callback_object = object;

    friend_con->callbacks[index].status_callback_id =
        friend_con->callbacks[index].data_callback_id =
            friend_con->callbacks[index].lossy_data_callback_id = number;
    return 0;
}

/* return the crypt_connection_id for the connection.
 *
 * return crypt_connection_id on success.
 * return -1 on failure.
 */
int friend_connection_crypt_connection_id(Friend_Connections *fr_c, int friendcon_id)
{
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

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

    if (friendcon_id == -1)
        return -1;

    int32_t onion_friendnum = onion_addfriend(fr_c->onion_c, real_public_key);

    if (onion_friendnum == -1)
        return -1;

    Friend_Conn *friend_con = &fr_c->conns[friendcon_id];

    friend_con->crypt_connection_id = -1;
    friend_con->status = FRIENDCONN_STATUS_CONNECTING;
    memcpy(friend_con->real_public_key, real_public_key, crypto_box_PUBLICKEYBYTES);
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
    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

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
                                 const uint8_t *, uint16_t), void *object)
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
    if (1 + sizeof(nospam_num) + length > ONION_CLIENT_MAX_DATA_SIZE || length == 0)
        return -1;

    Friend_Conn *friend_con = get_conn(fr_c, friendcon_id);

    if (!friend_con)
        return -1;

    uint8_t packet[1 + sizeof(nospam_num) + length];
    memcpy(packet + 1, &nospam_num, sizeof(nospam_num));
    memcpy(packet + 1 + sizeof(nospam_num), data, length);

    if (friend_con->status == FRIENDCONN_STATUS_CONNECTED) {
        packet[0] = PACKET_ID_FRIEND_REQUESTS;
        return write_cryptpacket(fr_c->net_crypto, friend_con->crypt_connection_id, packet, sizeof(packet), 0) != -1;
    } else {
        packet[0] = CRYPTO_PACKET_FRIEND_REQ;
        int num = send_onion_data(fr_c->onion_c, friend_con->onion_friendnum, packet, sizeof(packet));

        if (num <= 0)
            return -1;

        return num;
    }
}

/* Create new friend_connections instance. */
Friend_Connections *new_friend_connections(Onion_Client *onion_c)
{
    if (!onion_c)
        return NULL;

    Friend_Connections *temp = calloc(1, sizeof(Friend_Connections));

    if (temp == NULL)
        return NULL;

    temp->dht = onion_c->dht;
    temp->net_crypto = onion_c->c;
    temp->onion_c = onion_c;

    new_connection_handler(temp->net_crypto, &handle_new_connections, temp);

    return temp;
}

/* main friend_connections loop. */
void do_friend_connections(Friend_Connections *fr_c)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < fr_c->num_cons; ++i) {
        Friend_Conn *friend_con = get_conn(fr_c, i);

        if (friend_con) {
            if (friend_con->status == FRIENDCONN_STATUS_CONNECTING) {
                if (friend_con->dht_ping_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    if (friend_con->dht_lock) {
                        DHT_delfriend(fr_c->dht, friend_con->dht_temp_pk, friend_con->dht_lock);
                        friend_con->dht_lock = 0;
                    }
                }

                if (friend_con->dht_ip_port_lastrecv + FRIEND_DHT_TIMEOUT < temp_time) {
                    friend_con->dht_ip_port.ip.family = 0;
                }

                if (friend_con->dht_lock) {
                    if (friend_new_connection(fr_c, i) == 0) {
                        set_connection_dht_public_key(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->dht_temp_pk);
                        set_direct_ip_port(fr_c->net_crypto, friend_con->crypt_connection_id, friend_con->dht_ip_port);
                    }
                }

            } else if (friend_con->status == FRIENDCONN_STATUS_CONNECTED) {
                if (friend_con->ping_lastsent + FRIEND_PING_INTERVAL < temp_time) {
                    send_ping(fr_c, i);
                }

                if (friend_con->ping_lastrecv + FRIEND_CONNECTION_TIMEOUT < temp_time) {
                    /* If we stopped receiving ping packets, kill it. */
                    crypto_kill(fr_c->net_crypto, friend_con->crypt_connection_id);
                    friend_con->crypt_connection_id = -1;
                    handle_status(fr_c, i, 0); /* Going offline. */
                }
            }
        }
    }
}

/* Free everything related with friend_connections. */
void kill_friend_connections(Friend_Connections *fr_c)
{
    if (!fr_c)
        return;

    uint32_t i;

    for (i = 0; i < fr_c->num_cons; ++i) {
        kill_friend_connection(fr_c, i);
    }

    free(fr_c);
}
