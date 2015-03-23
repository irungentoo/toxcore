/* net_crypto.c
 *
 * Functions for the core network crypto.
 * See also: http://wiki.tox.im/index.php/DHT
 *
 * NOTE: This code has to be perfect. We don't mess around with encryption.
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

#include "net_crypto.h"
#include "util.h"
#include "math.h"
#include "logger.h"

static uint8_t crypt_connection_id_not_valid(const Net_Crypto *c, int crypt_connection_id)
{
    return (uint32_t)crypt_connection_id >= c->crypto_connections_length;
}

/* cookie timeout in seconds */
#define COOKIE_TIMEOUT 10
#define COOKIE_DATA_LENGTH (crypto_box_PUBLICKEYBYTES * 2)
#define COOKIE_CONTENTS_LENGTH (sizeof(uint64_t) + COOKIE_DATA_LENGTH)
#define COOKIE_LENGTH (crypto_box_NONCEBYTES + COOKIE_CONTENTS_LENGTH + crypto_box_MACBYTES)

#define COOKIE_REQUEST_PLAIN_LENGTH (COOKIE_DATA_LENGTH + sizeof(uint64_t))
#define COOKIE_REQUEST_LENGTH (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES)
#define COOKIE_RESPONSE_LENGTH (1 + crypto_box_NONCEBYTES + COOKIE_LENGTH + sizeof(uint64_t) + crypto_box_MACBYTES)

/* Create a cookie request packet and put it in packet.
 * dht_public_key is the dht public key of the other
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_REQUEST_LENGTH on success.
 */
static int create_cookie_request(const Net_Crypto *c, uint8_t *packet, uint8_t *dht_public_key, uint64_t number,
                                 uint8_t *shared_key)
{
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t padding[crypto_box_PUBLICKEYBYTES] = {0};

    memcpy(plain, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + crypto_box_PUBLICKEYBYTES, padding, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + (crypto_box_PUBLICKEYBYTES * 2), &number, sizeof(uint64_t));

    DHT_get_shared_key_sent(c->dht, shared_key, dht_public_key);
    uint8_t nonce[crypto_box_NONCEBYTES];
    new_nonce(nonce);
    packet[0] = NET_PACKET_COOKIE_REQUEST;
    memcpy(packet + 1, c->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(packet + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    int len = encrypt_data_symmetric(shared_key, nonce, plain, sizeof(plain),
                                     packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES)
        return -1;

    return (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + len);
}

/* Create cookie of length COOKIE_LENGTH from bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_cookie(uint8_t *cookie, const uint8_t *bytes, const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    uint64_t temp_time = unix_time();
    memcpy(contents, &temp_time, sizeof(temp_time));
    memcpy(contents + sizeof(temp_time), bytes, COOKIE_DATA_LENGTH);
    new_nonce(cookie);
    int len = encrypt_data_symmetric(encryption_key, cookie, contents, sizeof(contents), cookie + crypto_box_NONCEBYTES);

    if (len != COOKIE_LENGTH - crypto_box_NONCEBYTES)
        return -1;

    return 0;
}

/* Open cookie of length COOKIE_LENGTH to bytes of length COOKIE_DATA_LENGTH using encryption_key
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int open_cookie(uint8_t *bytes, const uint8_t *cookie, const uint8_t *encryption_key)
{
    uint8_t contents[COOKIE_CONTENTS_LENGTH];
    int len = decrypt_data_symmetric(encryption_key, cookie, cookie + crypto_box_NONCEBYTES,
                                     COOKIE_LENGTH - crypto_box_NONCEBYTES, contents);

    if (len != sizeof(contents))
        return -1;

    uint64_t cookie_time;
    memcpy(&cookie_time, contents, sizeof(cookie_time));
    uint64_t temp_time = unix_time();

    if (cookie_time + COOKIE_TIMEOUT < temp_time || temp_time < cookie_time)
        return -1;

    memcpy(bytes, contents + sizeof(cookie_time), COOKIE_DATA_LENGTH);
    return 0;
}


/* Create a cookie response packet and put it in packet.
 * request_plain must be COOKIE_REQUEST_PLAIN_LENGTH bytes.
 * packet must be of size COOKIE_RESPONSE_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_RESPONSE_LENGTH on success.
 */
static int create_cookie_response(const Net_Crypto *c, uint8_t *packet, const uint8_t *request_plain,
                                  const uint8_t *shared_key, const uint8_t *dht_public_key)
{
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, request_plain, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, dht_public_key, crypto_box_PUBLICKEYBYTES);
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

    if (create_cookie(plain, cookie_plain, c->secret_symmetric_key) != 0)
        return -1;

    memcpy(plain + COOKIE_LENGTH, request_plain + COOKIE_DATA_LENGTH, sizeof(uint64_t));
    packet[0] = NET_PACKET_COOKIE_RESPONSE;
    new_nonce(packet + 1);
    int len = encrypt_data_symmetric(shared_key, packet + 1, plain, sizeof(plain), packet + 1 + crypto_box_NONCEBYTES);

    if (len != COOKIE_RESPONSE_LENGTH - (1 + crypto_box_NONCEBYTES))
        return -1;

    return COOKIE_RESPONSE_LENGTH;
}

/* Handle the cookie request packet of length length.
 * Put what was in the request in request_plain (must be of size COOKIE_REQUEST_PLAIN_LENGTH)
 * Put the key used to decrypt the request into shared_key (of size crypto_box_BEFORENMBYTES) for use in the response.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_cookie_request(const Net_Crypto *c, uint8_t *request_plain, uint8_t *shared_key,
                                 uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    if (length != COOKIE_REQUEST_LENGTH)
        return -1;

    memcpy(dht_public_key, packet + 1, crypto_box_PUBLICKEYBYTES);
    DHT_get_shared_key_sent(c->dht, shared_key, dht_public_key);
    int len = decrypt_data_symmetric(shared_key, packet + 1 + crypto_box_PUBLICKEYBYTES,
                                     packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES,
                                     request_plain);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH)
        return -1;

    return 0;
}

/* Handle the cookie request packet (for raw UDP)
 */
static int udp_handle_cookie_request(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    Net_Crypto *c = object;
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0)
        return 1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return 1;

    if ((uint32_t)sendpacket(c->dht->net, source, data, sizeof(data)) != sizeof(data))
        return 1;

    return 0;
}

/* Handle the cookie request packet (for TCP)
 */
static int tcp_handle_cookie_request(const Net_Crypto *c, TCP_Client_Connection *TCP_con, uint8_t conn_id,
                                     const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key, packet, length) != 0)
        return -1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return -1;

    if (send_data(TCP_con, conn_id, data, sizeof(data)) != 1)
        return -1;

    return 0;
}

/* Handle the cookie request packet (for TCP oob packets)
 */
static int tcp_oob_handle_cookie_request(const Net_Crypto *c, TCP_Client_Connection *TCP_con,
        const uint8_t *dht_public_key, const uint8_t *packet, uint16_t length)
{
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
    uint8_t dht_public_key_temp[crypto_box_PUBLICKEYBYTES];

    if (handle_cookie_request(c, request_plain, shared_key, dht_public_key_temp, packet, length) != 0)
        return -1;

    if (memcmp(dht_public_key, dht_public_key_temp, crypto_box_PUBLICKEYBYTES) != 0)
        return -1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key, dht_public_key) != sizeof(data))
        return -1;

    if (send_oob_packet(TCP_con, dht_public_key, data, sizeof(data)) != 1)
        return -1;

    return 0;
}

/* Handle a cookie response packet of length encrypted with shared_key.
 * put the cookie in the response in cookie
 *
 * cookie must be of length COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return COOKIE_LENGTH on success.
 */
static int handle_cookie_response(uint8_t *cookie, uint64_t *number, const uint8_t *packet, uint16_t length,
                                  const uint8_t *shared_key)
{
    if (length != COOKIE_RESPONSE_LENGTH)
        return -1;

    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];
    int len = decrypt_data_symmetric(shared_key, packet + 1, packet + 1 + crypto_box_NONCEBYTES,
                                     length - (1 + crypto_box_NONCEBYTES), plain);

    if (len != sizeof(plain))
        return -1;

    memcpy(cookie, plain, COOKIE_LENGTH);
    memcpy(number, plain + COOKIE_LENGTH, sizeof(uint64_t));
    return COOKIE_LENGTH;
}

#define HANDSHAKE_PACKET_LENGTH (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH + crypto_box_MACBYTES)

/* Create a handshake packet and put it in packet.
 * cookie must be COOKIE_LENGTH bytes.
 * packet must be of size HANDSHAKE_PACKET_LENGTH or bigger.
 *
 * return -1 on failure.
 * return HANDSHAKE_PACKET_LENGTH on success.
 */
static int create_crypto_handshake(const Net_Crypto *c, uint8_t *packet, const uint8_t *cookie, const uint8_t *nonce,
                                   const uint8_t *session_pk, const uint8_t *peer_real_pk, const uint8_t *peer_dht_pubkey)
{
    uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
    memcpy(plain, nonce, crypto_box_NONCEBYTES);
    memcpy(plain + crypto_box_NONCEBYTES, session_pk, crypto_box_PUBLICKEYBYTES);
    crypto_hash_sha512(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, cookie, COOKIE_LENGTH);
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, peer_real_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, peer_dht_pubkey, crypto_box_PUBLICKEYBYTES);

    if (create_cookie(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, cookie_plain,
                      c->secret_symmetric_key) != 0)
        return -1;

    new_nonce(packet + 1 + COOKIE_LENGTH);
    int len = encrypt_data(peer_real_pk, c->self_secret_key, packet + 1 + COOKIE_LENGTH, plain, sizeof(plain),
                           packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES);

    if (len != HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES))
        return -1;

    packet[0] = NET_PACKET_CRYPTO_HS;
    memcpy(packet + 1, cookie, COOKIE_LENGTH);

    return HANDSHAKE_PACKET_LENGTH;
}

/* Handle a crypto handshake packet of length.
 * put the nonce contained in the packet in nonce,
 * the session public key in session_pk
 * the real public key of the peer in peer_real_pk
 * the dht public key of the peer in dht_public_key and
 * the cookie inside the encrypted part of the packet in cookie.
 *
 * if expected_real_pk isn't NULL it denotes the real public key
 * the packet should be from.
 *
 * nonce must be at least crypto_box_NONCEBYTES
 * session_pk must be at least crypto_box_PUBLICKEYBYTES
 * peer_real_pk must be at least crypto_box_PUBLICKEYBYTES
 * cookie must be at least COOKIE_LENGTH
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_crypto_handshake(const Net_Crypto *c, uint8_t *nonce, uint8_t *session_pk, uint8_t *peer_real_pk,
                                   uint8_t *dht_public_key, uint8_t *cookie, const uint8_t *packet, uint16_t length, const uint8_t *expected_real_pk)
{
    if (length != HANDSHAKE_PACKET_LENGTH)
        return -1;

    uint8_t cookie_plain[COOKIE_DATA_LENGTH];

    if (open_cookie(cookie_plain, packet + 1, c->secret_symmetric_key) != 0)
        return -1;

    if (expected_real_pk)
        if (crypto_cmp(cookie_plain, expected_real_pk, crypto_box_PUBLICKEYBYTES) != 0)
            return -1;

    uint8_t cookie_hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(cookie_hash, packet + 1, COOKIE_LENGTH);

    uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
    int len = decrypt_data(cookie_plain, c->self_secret_key, packet + 1 + COOKIE_LENGTH,
                           packet + 1 + COOKIE_LENGTH + crypto_box_NONCEBYTES,
                           HANDSHAKE_PACKET_LENGTH - (1 + COOKIE_LENGTH + crypto_box_NONCEBYTES), plain);

    if (len != sizeof(plain))
        return -1;

    if (memcmp(cookie_hash, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, crypto_hash_sha512_BYTES) != 0)
        return -1;

    memcpy(nonce, plain, crypto_box_NONCEBYTES);
    memcpy(session_pk, plain + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie, plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES, COOKIE_LENGTH);
    memcpy(peer_real_pk, cookie_plain, crypto_box_PUBLICKEYBYTES);
    memcpy(dht_public_key, cookie_plain + crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
    return 0;
}


static Crypto_Connection *get_crypto_connection(const Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    return &c->crypto_connections[crypt_connection_id];
}


/* Sends a packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_packet_to(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
//TODO TCP, etc...
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    int direct_send_attempt = 0;

    pthread_mutex_lock(&conn->mutex);

    //TODO: on bad networks, direct connections might not last indefinitely.
    if (conn->ip_port.ip.family != 0) {
        uint8_t direct_connected = 0;
        crypto_connection_status(c, crypt_connection_id, &direct_connected);

        if (direct_connected && (uint32_t)sendpacket(c->dht->net, conn->ip_port, data, length) == length) {
            pthread_mutex_unlock(&conn->mutex);
            return 0;
        }

        //TODO: a better way of sending packets directly to confirm the others ip.
        if (length < 96 || data[0] == NET_PACKET_COOKIE_REQUEST || data[0] == NET_PACKET_CRYPTO_HS) {
            if ((uint32_t)sendpacket(c->dht->net, conn->ip_port, data, length) == length)
                direct_send_attempt = 1;
        }

    }

    pthread_mutex_unlock(&conn->mutex);

    //TODO: detect and kill bad relays.
    uint32_t i;

    unsigned int r;

    if (!conn->last_relay_sentto) {
        r = rand();
    } else {
        r = conn->last_relay_sentto - 1;
    }

    if (conn->num_tcp_online) {
        for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
            pthread_mutex_lock(&c->tcp_mutex);

            unsigned int tcp_index = (i + r) % MAX_TCP_CONNECTIONS;
            int ret = 0;

            if (conn->status_tcp[tcp_index] == STATUS_TCP_ONLINE) {/* friend is connected to this relay. */
                ret = send_data(c->tcp_connections[tcp_index], conn->con_number_tcp[tcp_index], data, length);
            }

            pthread_mutex_unlock(&c->tcp_mutex);

            if (ret == 1) {
                conn->last_relay_sentto = tcp_index + 1;
                return 0;
            }
        }
    }

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        pthread_mutex_lock(&c->tcp_mutex);

        unsigned int tcp_index = (i + r) % MAX_TCP_CONNECTIONS;
        int ret = 0;

        if (conn->status_tcp[tcp_index] == STATUS_TCP_INVISIBLE) {
            ret = send_oob_packet(c->tcp_connections[tcp_index], conn->dht_public_key, data, length);
        }

        pthread_mutex_unlock(&c->tcp_mutex);

        if (ret == 1) {
            conn->last_relay_sentto = tcp_index + 1;
            return 0;
        }
    }

    if (direct_send_attempt) {
        return 0;
    }

    return -1;
}

/** START: Array Related functions **/


/* Return number of packets in array
 * Note that holes are counted too.
 */
static uint32_t num_packets_array(const Packets_Array *array)
{
    return array->buffer_end - array->buffer_start;
}

/* Add data with packet number to array.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_data_to_buffer(Packets_Array *array, uint32_t number, const Packet_Data *data)
{
    if (number - array->buffer_start > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (array->buffer[num])
        return -1;

    Packet_Data *new_d = malloc(sizeof(Packet_Data));

    if (new_d == NULL)
        return -1;

    memcpy(new_d, data, sizeof(Packet_Data));
    array->buffer[num] = new_d;

    if ((number - array->buffer_start) >= (array->buffer_end - array->buffer_start))
        array->buffer_end = number + 1;

    return 0;
}

/* Get pointer of data with packet number.
 *
 * return -1 on failure.
 * return 0 if data at number is empty.
 * return 1 if data pointer was put in data.
 */
static int get_data_pointer(const Packets_Array *array, Packet_Data **data, uint32_t number)
{
    uint32_t num_spots = array->buffer_end - array->buffer_start;

    if (array->buffer_end - number > num_spots || number - array->buffer_start >= num_spots)
        return -1;

    uint32_t num = number % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num])
        return 0;

    *data = array->buffer[num];
    return 1;
}

/* Add data to end of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t add_data_end_of_buffer(Packets_Array *array, const Packet_Data *data)
{
    if (num_packets_array(array) >= CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    Packet_Data *new_d = malloc(sizeof(Packet_Data));

    if (new_d == NULL)
        return -1;

    memcpy(new_d, data, sizeof(Packet_Data));
    uint32_t id = array->buffer_end;
    array->buffer[id % CRYPTO_PACKET_BUFFER_SIZE] = new_d;
    ++array->buffer_end;
    return id;
}

/* Read data from begginning of array.
 *
 * return -1 on failure.
 * return packet number on success.
 */
static int64_t read_data_beg_buffer(Packets_Array *array, Packet_Data *data)
{
    if (array->buffer_end == array->buffer_start)
        return -1;

    uint32_t num = array->buffer_start % CRYPTO_PACKET_BUFFER_SIZE;

    if (!array->buffer[num])
        return -1;

    memcpy(data, array->buffer[num], sizeof(Packet_Data));
    uint32_t id = array->buffer_start;
    ++array->buffer_start;
    free(array->buffer[num]);
    array->buffer[num] = NULL;
    return id;
}

/* Delete all packets in array before number (but not number)
 *
 * return -1 on failure.
 * return 0 on success
 */
static int clear_buffer_until(Packets_Array *array, uint32_t number)
{
    uint32_t num_spots = array->buffer_end - array->buffer_start;

    if (array->buffer_end - number >= num_spots || number - array->buffer_start > num_spots)
        return -1;

    uint32_t i;

    for (i = array->buffer_start; i != number; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = NULL;
        }
    }

    array->buffer_start = i;
    return 0;
}

static int clear_buffer(Packets_Array *array)
{
    uint32_t i;

    for (i = array->buffer_start; i != array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (array->buffer[num]) {
            free(array->buffer[num]);
            array->buffer[num] = NULL;
        }
    }

    array->buffer_start = i;
    return 0;
}

/* Set array buffer end to number.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int set_buffer_end(Packets_Array *array, uint32_t number)
{
    if ((number - array->buffer_start) > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    if ((number - array->buffer_end) > CRYPTO_PACKET_BUFFER_SIZE)
        return -1;

    array->buffer_end = number;
    return 0;
}

/* Create a packet request packet from recv_array and send_buffer_end into
 * data of length.
 *
 * return -1 on failure.
 * return length of packet on success.
 */
static int generate_request_packet(uint8_t *data, uint16_t length, const Packets_Array *recv_array)
{
    if (length == 0)
        return -1;

    data[0] = PACKET_ID_REQUEST;

    uint16_t cur_len = 1;

    if (recv_array->buffer_start == recv_array->buffer_end)
        return cur_len;

    if (length <= cur_len)
        return cur_len;

    uint32_t i, n = 1;

    for (i = recv_array->buffer_start; i != recv_array->buffer_end; ++i) {
        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (!recv_array->buffer[num]) {
            data[cur_len] = n;
            n = 0;
            ++cur_len;

            if (length <= cur_len)
                return cur_len;

        } else if (n == 255) {
            data[cur_len] = 0;
            n = 0;
            ++cur_len;

            if (length <= cur_len)
                return cur_len;
        }

        ++n;
    }

    return cur_len;
}

/* Handle a request data packet.
 * Remove all the packets the other received from the array.
 *
 * return -1 on failure.
 * return number of requested packets on success.
 */
static int handle_request_packet(Packets_Array *send_array, const uint8_t *data, uint16_t length)
{
    if (length < 1)
        return -1;

    if (data[0] != PACKET_ID_REQUEST)
        return -1;

    if (length == 1)
        return 0;

    ++data;
    --length;

    uint32_t i, n = 1;
    uint32_t requested = 0;

    for (i = send_array->buffer_start; i != send_array->buffer_end; ++i) {
        if (length == 0)
            break;

        uint32_t num = i % CRYPTO_PACKET_BUFFER_SIZE;

        if (n == data[0]) {
            if (send_array->buffer[num]) {
                send_array->buffer[num]->sent = 0;
            }

            ++data;
            --length;
            n = 0;
            ++requested;
        } else {
            free(send_array->buffer[num]);
            send_array->buffer[num] = NULL;
        }

        if (n == 255) {
            n = 1;

            if (data[0] != 0)
                return -1;

            ++data;
            --length;
        } else {
            ++n;
        }
    }

    return requested;
}

/** END: Array Related functions **/

#define MAX_DATA_DATA_PACKET_SIZE (MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))

/* Creates and sends a data packet to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length + (1 + sizeof(uint16_t) + crypto_box_MACBYTES) > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    pthread_mutex_lock(&conn->mutex);
    uint8_t packet[1 + sizeof(uint16_t) + length + crypto_box_MACBYTES];
    packet[0] = NET_PACKET_CRYPTO_DATA;
    memcpy(packet + 1, conn->sent_nonce + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
    int len = encrypt_data_symmetric(conn->shared_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t));

    if (len + 1 + sizeof(uint16_t) != sizeof(packet)) {
        pthread_mutex_unlock(&conn->mutex);
        return -1;
    }

    increment_nonce(conn->sent_nonce);
    pthread_mutex_unlock(&conn->mutex);

    return send_packet_to(c, crypt_connection_id, packet, sizeof(packet));
}

/* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet_helper(Net_Crypto *c, int crypt_connection_id, uint32_t buffer_start, uint32_t num,
                                   const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    num = htonl(num);
    buffer_start = htonl(buffer_start);
    uint16_t padding_length = (MAX_CRYPTO_DATA_SIZE - length) % CRYPTO_MAX_PADDING;
    uint8_t packet[sizeof(uint32_t) + sizeof(uint32_t) + padding_length + length];
    memcpy(packet, &buffer_start, sizeof(uint32_t));
    memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
    memset(packet + (sizeof(uint32_t) * 2), 0, padding_length);
    memcpy(packet + (sizeof(uint32_t) * 2) + padding_length, data, length);

    return send_data_packet(c, crypt_connection_id, packet, sizeof(packet));
}

static int reset_max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    /* If last packet send failed, try to send packet again.
       If sending it fails we won't be able to send the new packet. */
    if (conn->maximum_speed_reached) {
        Packet_Data *dt = NULL;
        uint32_t packet_num = conn->send_array.buffer_end - 1;
        int ret = get_data_pointer(&conn->send_array, &dt, packet_num);

        uint8_t send_failed = 0;

        if (ret == 1) {
            if (!dt->sent) {
                if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, dt->data,
                                            dt->length) != 0) {
                    send_failed = 1;
                } else {
                    dt->sent = 1;
                }
            }
        }

        if (!send_failed) {
            conn->maximum_speed_reached = 0;
        } else {
            return -1;
        }
    }

    return 0;
}

/*  return -1 if data could not be put in packet queue.
 *  return positive packet number if data was put into the queue.
 */
static int64_t send_lossless_packet(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                                    uint8_t congestion_control)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    /* If last packet send failed, try to send packet again.
       If sending it fails we won't be able to send the new packet. */
    reset_max_speed_reached(c, crypt_connection_id);

    if (conn->maximum_speed_reached && congestion_control) {
        return -1;
    }

    Packet_Data dt;
    dt.sent = 0;
    dt.length = length;
    memcpy(dt.data, data, length);
    pthread_mutex_lock(&conn->mutex);
    int64_t packet_num = add_data_end_of_buffer(&conn->send_array, &dt);
    pthread_mutex_unlock(&conn->mutex);

    if (packet_num == -1)
        return -1;

    if (!congestion_control && conn->maximum_speed_reached) {
        return packet_num;
    }

    if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, data, length) == 0) {
        Packet_Data *dt1 = NULL;

        if (get_data_pointer(&conn->send_array, &dt1, packet_num) == 1)
            dt1->sent = 1;
    } else {
        conn->maximum_speed_reached = 1;
        LOGGER_ERROR("send_data_packet failed\n");
    }

    return packet_num;
}

/* Get the lowest 2 bytes from the nonce and convert
 * them to host byte format before returning them.
 */
static uint16_t get_nonce_uint16(const uint8_t *nonce)
{
    uint16_t num;
    memcpy(&num, nonce + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
    return ntohs(num);
}

#define DATA_NUM_THRESHOLD 21845

/* Handle a data packet.
 * Decrypt packet of length and put it into data.
 * data must be at least MAX_DATA_DATA_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of data on success.
 */
static int handle_data_packet(const Net_Crypto *c, int crypt_connection_id, uint8_t *data, const uint8_t *packet,
                              uint16_t length)
{
    if (length <= (1 + sizeof(uint16_t) + crypto_box_MACBYTES) || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t nonce[crypto_box_NONCEBYTES];
    memcpy(nonce, conn->recv_nonce, crypto_box_NONCEBYTES);
    uint16_t num_cur_nonce = get_nonce_uint16(nonce);
    uint16_t num;
    memcpy(&num, packet + 1, sizeof(uint16_t));
    num = ntohs(num);
    uint16_t diff = num - num_cur_nonce;
    increment_nonce_number(nonce, diff);
    int len = decrypt_data_symmetric(conn->shared_key, nonce, packet + 1 + sizeof(uint16_t),
                                     length - (1 + sizeof(uint16_t)), data);

    if ((unsigned int)len != length - (1 + sizeof(uint16_t) + crypto_box_MACBYTES))
        return -1;

    if (diff > DATA_NUM_THRESHOLD * 2) {
        increment_nonce_number(conn->recv_nonce, DATA_NUM_THRESHOLD);
    }

    return len;
}

/* Send a request packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_request_packet(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t data[MAX_CRYPTO_DATA_SIZE];
    int len = generate_request_packet(data, sizeof(data), &conn->recv_array);

    if (len == -1)
        return -1;

    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end, data,
                                   len);
}

/* Send up to max num previously requested data packets.
 *
 * return -1 on failure.
 * return number of packets sent on success.
 */
static int send_requested_packets(Net_Crypto *c, int crypt_connection_id, uint16_t max_num)
{
    if (max_num == 0)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint32_t i, num_sent = 0, array_size = num_packets_array(&conn->send_array);

    for (i = 0; i < array_size; ++i) {
        Packet_Data *dt;
        uint32_t packet_num = (i + conn->send_array.buffer_start);
        int ret = get_data_pointer(&conn->send_array, &dt, packet_num);

        if (ret == -1) {
            return -1;
        } else if (ret == 0) {
            continue;
        }

        if (dt->sent) {
            continue;
        }

        if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, dt->data,
                                    dt->length) == 0) {
            dt->sent = 1;
            ++num_sent;
        }

        if (num_sent >= max_num)
            break;
    }

    return num_sent;
}


/* Add a new temp packet to send repeatedly.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int new_temp_packet(const Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t *temp_packet = malloc(length);

    if (temp_packet == 0)
        return -1;

    if (conn->temp_packet)
        free(conn->temp_packet);

    memcpy(temp_packet, packet, length);
    conn->temp_packet = temp_packet;
    conn->temp_packet_length = length;
    conn->temp_packet_sent_time = 0;
    conn->temp_packet_num_sent = 0;
    return 0;
}

/* Clear the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int clear_temp_packet(const Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (conn->temp_packet)
        free(conn->temp_packet);

    conn->temp_packet = 0;
    conn->temp_packet_length = 0;
    conn->temp_packet_sent_time = 0;
    conn->temp_packet_num_sent = 0;
    return 0;
}


/* Send the temp packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_temp_packet(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (!conn->temp_packet)
        return -1;

    if (send_packet_to(c, crypt_connection_id, conn->temp_packet, conn->temp_packet_length) != 0)
        return -1;

    conn->temp_packet_sent_time = current_time_monotonic();
    ++conn->temp_packet_num_sent;
    return 0;
}

/* Create a handshake packet and set it as a temp packet.
 * cookie must be COOKIE_LENGTH.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int create_send_handshake(Net_Crypto *c, int crypt_connection_id, const uint8_t *cookie,
                                 const uint8_t *dht_public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

    if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionpublic_key,
                                conn->public_key, dht_public_key) != sizeof(handshake_packet))
        return -1;

    if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0)
        return -1;

    send_temp_packet(c, crypt_connection_id);
    return 0;
}

/* Send a kill packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_kill_packet(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t kill_packet = PACKET_ID_KILL;
    return send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, conn->send_array.buffer_end,
                                   &kill_packet, sizeof(kill_packet));
}

/* Handle a received data packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_data_packet_helper(const Net_Crypto *c, int crypt_connection_id, const uint8_t *packet,
                                     uint16_t length)
{
    if (length > MAX_CRYPTO_PACKET_SIZE || length <= CRYPTO_DATA_PACKET_MIN_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t data[MAX_DATA_DATA_PACKET_SIZE];
    int len = handle_data_packet(c, crypt_connection_id, data, packet, length);

    if (len <= (int)(sizeof(uint32_t) * 2))
        return -1;

    uint32_t buffer_start, num;
    memcpy(&buffer_start, data, sizeof(uint32_t));
    memcpy(&num, data + sizeof(uint32_t), sizeof(uint32_t));
    buffer_start = ntohl(buffer_start);
    num = ntohl(num);

    if (buffer_start != conn->send_array.buffer_start && clear_buffer_until(&conn->send_array, buffer_start) != 0)
        return -1;

    uint8_t *real_data = data + (sizeof(uint32_t) * 2);
    uint16_t real_length = len - (sizeof(uint32_t) * 2);

    while (real_data[0] == 0) { /* Remove Padding */
        ++real_data;
        --real_length;

        if (real_length == 0)
            return -1;
    }

    if (real_data[0] == PACKET_ID_KILL) {
        conn->killed = 1;
        return 0;
    }

    if (conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
        clear_temp_packet(c, crypt_connection_id);
        conn->status = CRYPTO_CONN_ESTABLISHED;

        if (conn->connection_status_callback)
            conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 1);
    }

    if (real_data[0] == PACKET_ID_REQUEST) {
        int requested = handle_request_packet(&conn->send_array, real_data, real_length);

        if (requested == -1) {
            return -1;
        } else {
            //TODO?
        }

        set_buffer_end(&conn->recv_array, num);
    } else if (real_data[0] >= CRYPTO_RESERVED_PACKETS && real_data[0] < PACKET_ID_LOSSY_RANGE_START) {
        Packet_Data dt;
        dt.length = real_length;
        memcpy(dt.data, real_data, real_length);

        if (add_data_to_buffer(&conn->recv_array, num, &dt) != 0)
            return -1;


        while (1) {
            pthread_mutex_lock(&conn->mutex);
            int ret = read_data_beg_buffer(&conn->recv_array, &dt);
            pthread_mutex_unlock(&conn->mutex);

            if (ret == -1)
                break;

            if (conn->connection_data_callback)
                conn->connection_data_callback(conn->connection_data_callback_object, conn->connection_data_callback_id, dt.data,
                                               dt.length);

            /* conn might get killed in callback. */
            conn = get_crypto_connection(c, crypt_connection_id);

            if (conn == 0)
                return -1;
        }

        /* Packet counter. */
        ++conn->packet_counter;
    } else if (real_data[0] >= PACKET_ID_LOSSY_RANGE_START &&
               real_data[0] < (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE)) {

        set_buffer_end(&conn->recv_array, num);

        if (conn->connection_lossy_data_callback)
            conn->connection_lossy_data_callback(conn->connection_lossy_data_callback_object,
                                                 conn->connection_lossy_data_callback_id, real_data, real_length);

    } else {
        return -1;
    }

    return 0;
}

/* Handle a packet that was received for the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_packet_connection(Net_Crypto *c, int crypt_connection_id, const uint8_t *packet, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    switch (packet[0]) {
        case NET_PACKET_COOKIE_RESPONSE: {
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTING)
                return -1;

            uint8_t cookie[COOKIE_LENGTH];
            uint64_t number;

            if (handle_cookie_response(cookie, &number, packet, length, conn->shared_key) != sizeof(cookie))
                return -1;

            if (number != conn->cookie_request_number)
                return -1;

            if (create_send_handshake(c, crypt_connection_id, cookie, conn->dht_public_key) != 0)
                return -1;

            conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            return 0;
        }

        case NET_PACKET_CRYPTO_HS: {
            if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT
                    || conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
                uint8_t peer_real_pk[crypto_box_PUBLICKEYBYTES];
                uint8_t dht_public_key[crypto_box_PUBLICKEYBYTES];
                uint8_t cookie[COOKIE_LENGTH];

                if (handle_crypto_handshake(c, conn->recv_nonce, conn->peersessionpublic_key, peer_real_pk, dht_public_key, cookie,
                                            packet, length, conn->public_key) != 0)
                    return -1;

                encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

                if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
                    if (create_send_handshake(c, crypt_connection_id, cookie, dht_public_key) != 0)
                        return -1;
                }

                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
                /* Status needs to be CRYPTO_CONN_NOT_CONFIRMED for this to work. */
                set_connection_dht_public_key(c, crypt_connection_id, dht_public_key);

                if (conn->dht_pk_callback)
                    conn->dht_pk_callback(conn->dht_pk_callback_object, conn->dht_pk_callback_number, dht_public_key);

            } else {
                return -1;
            }

            return 0;
        }

        case NET_PACKET_CRYPTO_DATA: {
            if (conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED) {
                return handle_data_packet_helper(c, crypt_connection_id, packet, length);
            } else {
                return -1;
            }

            return 0;
        }

        default: {
            return -1;
        }
    }

    return 0;
}

/* Set the size of the friend list to numfriends.
 *
 *  return -1 if realloc fails.
 *  return 0 if it succeeds.
 */
static int realloc_cryptoconnection(Net_Crypto *c, uint32_t num)
{
    if (num == 0) {
        free(c->crypto_connections);
        c->crypto_connections = NULL;
        return 0;
    }

    Crypto_Connection *newcrypto_connections = realloc(c->crypto_connections, num * sizeof(Crypto_Connection));

    if (newcrypto_connections == NULL)
        return -1;

    c->crypto_connections = newcrypto_connections;
    return 0;
}


/* Create a new empty crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int create_crypto_connection(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION)
            return i;
    }

    while (1) { /* TODO: is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (!c->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    int id = -1;

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == 0) {
        id = c->crypto_connections_length;
        ++c->crypto_connections_length;
        memset(&(c->crypto_connections[id]), 0, sizeof(Crypto_Connection));

        if (pthread_mutex_init(&c->crypto_connections[id].mutex, NULL) != 0) {
            pthread_mutex_unlock(&c->connections_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&c->connections_mutex);
    return id;
}

/* Wipe a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int wipe_crypto_connection(Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return -1;

    uint32_t i;

    /* Keep mutex, only destroy it when connection is realloced out. */
    pthread_mutex_t mutex = c->crypto_connections[crypt_connection_id].mutex;
    memset(&(c->crypto_connections[crypt_connection_id]), 0 , sizeof(Crypto_Connection));
    c->crypto_connections[crypt_connection_id].mutex = mutex;

    for (i = c->crypto_connections_length; i != 0; --i) {
        if (c->crypto_connections[i - 1].status == CRYPTO_CONN_NO_CONNECTION) {
            pthread_mutex_destroy(&c->crypto_connections[i - 1].mutex);
        } else {
            break;
        }
    }

    if (c->crypto_connections_length != i) {
        c->crypto_connections_length = i;
        realloc_cryptoconnection(c, c->crypto_connections_length);
    }

    return 0;
}

/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
static int getcryptconnection_id(const Net_Crypto *c, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION)
            if (memcmp(public_key, c->crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* Get crypto connection id from public key of peer.
 *
 *  return -1 if there are no connections like we are looking for.
 *  return id if it found it.
 */
static int getcryptconnection_id_dht_pubkey(const Net_Crypto *c, const uint8_t *dht_public_key)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION && c->crypto_connections[i].dht_public_key_set)
            if (memcmp(dht_public_key, c->crypto_connections[i].dht_public_key, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* Add a source to the crypto connection.
 * This is to be used only when we have received a packet from that source.
 *
 *  return -1 on failure.
 *  return positive number on success.
 *  0 if source was a direct UDP connection.
 *  TODO
 */
static int crypto_connection_add_source(Net_Crypto *c, int crypt_connection_id, IP_Port source)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (source.ip.family == AF_INET || source.ip.family == AF_INET6) {
        if (!ipport_equal(&source, &conn->ip_port)) {
            if (!bs_list_add(&c->ip_port_list, &source, crypt_connection_id))
                return -1;

            bs_list_remove(&c->ip_port_list, &conn->ip_port, crypt_connection_id);
            conn->ip_port = source;
        }

        conn->direct_lastrecv_time = current_time_monotonic();
        return 0;
    }

    return -1;
}


/* Set function to be called when someone requests a new connection to us.
 *
 * The set function should return -1 on failure and 0 on success.
 *
 * n_c is only valid for the duration of the function call.
 */
void new_connection_handler(Net_Crypto *c, int (*new_connection_callback)(void *object, New_Connection *n_c),
                            void *object)
{
    c->new_connection_callback = new_connection_callback;
    c->new_connection_callback_object = object;
}

/* Handle a handshake packet by someone who wants to initiate a new connection with us.
 * This calls the callback set by new_connection_handler() if the handshake is ok.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_new_connection_handshake(Net_Crypto *c, IP_Port source, const uint8_t *data, uint16_t length)
{
    New_Connection n_c;
    n_c.cookie = malloc(COOKIE_LENGTH);

    if (n_c.cookie == NULL)
        return -1;

    n_c.source = source;
    n_c.cookie_length = COOKIE_LENGTH;

    if (handle_crypto_handshake(c, n_c.recv_nonce, n_c.peersessionpublic_key, n_c.public_key, n_c.dht_public_key,
                                n_c.cookie, data, length, 0) != 0) {
        free(n_c.cookie);
        return -1;
    }

    int crypt_connection_id = getcryptconnection_id(c, n_c.public_key);

    if (crypt_connection_id != -1) {
        int ret = -1;
        Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

        if (conn != 0 && (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT)) {
            memcpy(conn->recv_nonce, n_c.recv_nonce, crypto_box_NONCEBYTES);
            memcpy(conn->peersessionpublic_key, n_c.peersessionpublic_key, crypto_box_PUBLICKEYBYTES);
            encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

            crypto_connection_add_source(c, crypt_connection_id, source);

            if (create_send_handshake(c, crypt_connection_id, n_c.cookie, n_c.dht_public_key) == 0) {
                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
                /* Status needs to be CRYPTO_CONN_NOT_CONFIRMED for this to work. */
                set_connection_dht_public_key(c, crypt_connection_id, n_c.dht_public_key);

                if (conn->dht_pk_callback)
                    conn->dht_pk_callback(conn->dht_pk_callback_object, conn->dht_pk_callback_number, n_c.dht_public_key);

                ret = 0;
            }
        }

        free(n_c.cookie);
        return ret;
    }

    int ret = c->new_connection_callback(c->new_connection_callback_object, &n_c);
    free(n_c.cookie);
    return ret;
}

/* Accept a crypto connection.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int accept_crypto_connection(Net_Crypto *c, New_Connection *n_c)
{
    if (getcryptconnection_id(c, n_c->public_key) != -1)
        return -1;

    int crypt_connection_id = create_crypto_connection(c);

    if (crypt_connection_id == -1)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    memcpy(conn->public_key, n_c->public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(conn->recv_nonce, n_c->recv_nonce, crypto_box_NONCEBYTES);
    memcpy(conn->peersessionpublic_key, n_c->peersessionpublic_key, crypto_box_PUBLICKEYBYTES);
    random_nonce(conn->sent_nonce);
    crypto_box_keypair(conn->sessionpublic_key, conn->sessionsecret_key);
    encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

    if (n_c->cookie_length != COOKIE_LENGTH)
        return -1;

    if (create_send_handshake(c, crypt_connection_id, n_c->cookie, n_c->dht_public_key) != 0)
        return -1;

    conn->status = CRYPTO_CONN_NOT_CONFIRMED;
    /* Status needs to be CRYPTO_CONN_NOT_CONFIRMED for this to work. */
    set_connection_dht_public_key(c, crypt_connection_id, n_c->dht_public_key);
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    crypto_connection_add_source(c, crypt_connection_id, n_c->source);
    return crypt_connection_id;
}

/* Create a crypto connection.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *c, const uint8_t *real_public_key)
{
    int crypt_connection_id = getcryptconnection_id(c, real_public_key);

    if (crypt_connection_id != -1)
        return crypt_connection_id;

    crypt_connection_id = create_crypto_connection(c);

    if (crypt_connection_id == -1)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    memcpy(conn->public_key, real_public_key, crypto_box_PUBLICKEYBYTES);
    random_nonce(conn->sent_nonce);
    crypto_box_keypair(conn->sessionpublic_key, conn->sessionsecret_key);
    conn->status = CRYPTO_CONN_COOKIE_REQUESTING;
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
    return crypt_connection_id;
}

/* Set the status for the TCP connection for conn in location to status.
 */
static void set_conn_tcp_status(Crypto_Connection *conn, unsigned int location, unsigned int status)
{
    if (conn->status_tcp[location] == status) {
        return;
    }

    if (conn->status_tcp[location] == STATUS_TCP_ONLINE) {
        --conn->num_tcp_online;
    }

    if (status == STATUS_TCP_ONLINE) {
        ++conn->num_tcp_online;
    }

    conn->status_tcp[location] = status;
}

/* Disconnect peer from all associated TCP connections.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int disconnect_peer_tcp(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (conn->status_tcp[i] != STATUS_TCP_NULL) {
            pthread_mutex_lock(&c->tcp_mutex);
            send_disconnect_request(c->tcp_connections[i], conn->con_number_tcp[i]);
            set_conn_tcp_status(conn, i, STATUS_TCP_NULL);
            conn->con_number_tcp[i] = 0;
            pthread_mutex_unlock(&c->tcp_mutex);
        }
    }

    return 0;
}

/* Connect peer to all associated TCP connections.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int connect_peer_tcp(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            continue;

        pthread_mutex_lock(&c->tcp_mutex);
        //TODO check function return?
        send_routing_request(c->tcp_connections[i], conn->dht_public_key);
        pthread_mutex_unlock(&c->tcp_mutex);
    }

    return 0;
}

/* Copy friends DHT public key into dht_key.
 *
 * return 0 on failure (no key copied).
 * return 1 on success (key copied).
 */
unsigned int get_connection_dht_key(const Net_Crypto *c, int crypt_connection_id, uint8_t *dht_public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return 0;

    if (conn->dht_public_key_set == 0)
        return 0;

    memcpy(dht_public_key, conn->dht_public_key, crypto_box_PUBLICKEYBYTES);
    return 1;
}


/* Set the DHT public key of the crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_connection_dht_public_key(Net_Crypto *c, int crypt_connection_id, const uint8_t *dht_public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (conn->dht_public_key_set == 1 && memcmp(conn->dht_public_key, dht_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    if (conn->dht_public_key_set == 1) {
        disconnect_peer_tcp(c, crypt_connection_id);
    }

    memcpy(conn->dht_public_key, dht_public_key, crypto_box_PUBLICKEYBYTES);
    conn->dht_public_key_set = 1;

    if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
        conn->cookie_request_number = random_64b();
        uint8_t cookie_request[COOKIE_REQUEST_LENGTH];

        if (create_cookie_request(c, cookie_request, conn->dht_public_key, conn->cookie_request_number,
                                  conn->shared_key) != sizeof(cookie_request))
            return -1;

        if (new_temp_packet(c, crypt_connection_id, cookie_request, sizeof(cookie_request)) != 0)
            return -1;
    }//TODO

    connect_peer_tcp(c, crypt_connection_id);
    return 0;
}

/* Set the direct ip of the crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_direct_ip_port(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (ip_port.ip.family != AF_INET && ip_port.ip.family != AF_INET6)
        return -1;

    if (!ipport_equal(&ip_port, &conn->ip_port)) {
        if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_time) > current_time_monotonic()) {
            if (LAN_ip(ip_port.ip) == 0 && LAN_ip(conn->ip_port.ip) == 0 && conn->ip_port.port == ip_port.port)
                return -1;
        }

        if (bs_list_add(&c->ip_port_list, &ip_port, crypt_connection_id)) {
            bs_list_remove(&c->ip_port_list, &conn->ip_port, crypt_connection_id);
            conn->ip_port = ip_port;
            conn->direct_lastrecv_time = 0;
            return 0;
        }
    }

    return -1;
}

static int tcp_response_callback(void *object, uint8_t connection_id, const uint8_t *public_key)
{
    TCP_Client_Connection *TCP_con = object;
    Net_Crypto *c = TCP_con->net_crypto_pointer;

    int crypt_connection_id = getcryptconnection_id_dht_pubkey(c, public_key);

    if (crypt_connection_id == -1)
        return -1;

    set_tcp_connection_number(TCP_con, connection_id, crypt_connection_id);

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint32_t location = TCP_con->net_crypto_location;

    if (location >= MAX_TCP_CONNECTIONS)
        return -1;

    if (c->tcp_connections[location] != TCP_con)
        return -1;

    conn->con_number_tcp[location] = connection_id;
    uint32_t i;

    for (i = 0; i < conn->num_tcp_relays; ++i) {
        if (memcmp(TCP_con->public_key, conn->tcp_relays[i].public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            set_conn_tcp_status(conn, location, STATUS_TCP_INVISIBLE);
            return 0;
        }
    }

    set_conn_tcp_status(conn, location, STATUS_TCP_OFFLINE);
    return 0;
}

static int tcp_status_callback(void *object, uint32_t number, uint8_t connection_id, uint8_t status)
{
    TCP_Client_Connection *TCP_con = object;
    Net_Crypto *c = TCP_con->net_crypto_pointer;

    Crypto_Connection *conn = get_crypto_connection(c, number);

    if (conn == 0)
        return -1;

    uint32_t location = TCP_con->net_crypto_location;

    if (location >= MAX_TCP_CONNECTIONS)
        return -1;

    if (c->tcp_connections[location] != TCP_con)
        return -1;

    if (status == 1) {
        set_conn_tcp_status(conn, location, STATUS_TCP_OFFLINE);
    } else if (status == 2) {
        set_conn_tcp_status(conn, location, STATUS_TCP_ONLINE);
    }

    conn->con_number_tcp[location] = connection_id;
    return 0;
}

static int tcp_data_callback(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length)
{

    if (length == 0)
        return -1;

    TCP_Client_Connection *TCP_con = object;
    Net_Crypto *c = TCP_con->net_crypto_pointer;

    if (data[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_handle_cookie_request(c, TCP_con, connection_id, data, length);
    }

    Crypto_Connection *conn = get_crypto_connection(c, number);

    if (conn == 0)
        return -1;

    pthread_mutex_unlock(&c->tcp_mutex);
    int ret = handle_packet_connection(c, number, data, length);
    pthread_mutex_lock(&c->tcp_mutex);

    if (ret != 0)
        return -1;

    //TODO detect and kill bad TCP connections.
    return 0;
}

static int tcp_oob_callback(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    TCP_Client_Connection *TCP_con = object;
    Net_Crypto *c = TCP_con->net_crypto_pointer;
    uint32_t location = TCP_con->net_crypto_location;

    if (data[0] == NET_PACKET_COOKIE_REQUEST) {
        return tcp_oob_handle_cookie_request(c, TCP_con, public_key, data, length);
    }

    int crypt_connection_id = getcryptconnection_id_dht_pubkey(c, public_key);

    if (crypt_connection_id == -1) {
        IP_Port source;
        source.port = 0;
        source.ip.family = TCP_FAMILY;
        source.ip.ip6.uint32[0] = location;

        if (data[0] != NET_PACKET_CRYPTO_HS) {
            LOGGER_DEBUG("tcp snhappen %u\n", data[0]);
            return -1;
        }

        if (handle_new_connection_handshake(c, source, data, length) != 0)
            return -1;

        return 0;
    }

    pthread_mutex_unlock(&c->tcp_mutex);
    int ret = handle_packet_connection(c, crypt_connection_id, data, length);
    pthread_mutex_lock(&c->tcp_mutex);

    if (ret != 0)
        return -1;

    return 0;
}

static int tcp_onion_callback(void *object, const uint8_t *data, uint16_t length)
{
    Net_Crypto *c = object;

    if (c->tcp_onion_callback)
        return c->tcp_onion_callback(c->tcp_onion_callback_object, data, length);

    return 1;
}


/* Check if tcp connection to public key can be created.
 *
 * return -1 if it can't.
 * return 0 if it can.
 */
static int tcp_connection_check(const Net_Crypto *c, const uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections_new[i] == NULL)
            continue;

        if (memcmp(c->tcp_connections_new[i]->public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
            return -1;
    }

    uint32_t num = 0;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            continue;

        if (memcmp(c->tcp_connections[i]->public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0)
            return -1;

        ++num;
    }

    if (num == MAX_TCP_CONNECTIONS)
        return -1;

    return 0;
}

/* Add a tcp relay, associating it to a crypt_connection_id.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay_peer(Net_Crypto *c, int crypt_connection_id, IP_Port ip_port, const uint8_t *public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (ip_port.ip.family == TCP_INET) {
        ip_port.ip.family = AF_INET;
    } else if (ip_port.ip.family == TCP_INET6) {
        ip_port.ip.family = AF_INET6;
    }

    if (ip_port.ip.family != AF_INET && ip_port.ip.family != AF_INET6)
        return -1;

    uint32_t i;

    for (i = 0; i < conn->num_tcp_relays; ++i) {
        if (memcmp(conn->tcp_relays[i].public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            conn->tcp_relays[i].ip_port = ip_port;
            return 0;
        }
    }

    if (conn->num_tcp_relays == MAX_TCP_RELAYS_PEER) {
        uint16_t index = rand() % MAX_TCP_RELAYS_PEER;
        conn->tcp_relays[index].ip_port = ip_port;
        memcpy(conn->tcp_relays[index].public_key, public_key, crypto_box_PUBLICKEYBYTES);
    } else {
        conn->tcp_relays[conn->num_tcp_relays].ip_port = ip_port;
        memcpy(conn->tcp_relays[conn->num_tcp_relays].public_key, public_key, crypto_box_PUBLICKEYBYTES);
        ++conn->num_tcp_relays;
    }

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            continue;

        if (memcmp(c->tcp_connections[i]->public_key, public_key, crypto_box_PUBLICKEYBYTES) == 0) {
            if (conn->status_tcp[i] == STATUS_TCP_OFFLINE)
                set_conn_tcp_status(conn, i, STATUS_TCP_INVISIBLE);
        }
    }

    return add_tcp_relay(c, ip_port, public_key);
}

/* Add a tcp relay to the array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
int add_tcp_relay(Net_Crypto *c, IP_Port ip_port, const uint8_t *public_key)
{
    if (ip_port.ip.family == TCP_INET) {
        ip_port.ip.family = AF_INET;
    } else if (ip_port.ip.family == TCP_INET6) {
        ip_port.ip.family = AF_INET6;
    }

    if (ip_port.ip.family != AF_INET && ip_port.ip.family != AF_INET6)
        return -1;

    if (tcp_connection_check(c, public_key) != 0)
        return -1;

    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections_new[i] == NULL) {
            c->tcp_connections_new[i] = new_TCP_connection(ip_port, public_key, c->dht->self_public_key, c->dht->self_secret_key,
                                        &c->proxy_info);

            return 0;
        }
    }

    return -1;
}

/* Return a random TCP connection number for use in send_tcp_onion_request.
 *
 * TODO: This number is just the index of an array that the elements can
 * change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_con_number(Net_Crypto *c)
{
    unsigned int i, r = rand();

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[(i + r) % MAX_TCP_CONNECTIONS]) {
            return (i + r) % MAX_TCP_CONNECTIONS;
        }
    }

    return -1;
}

/* Send an onion packet via the TCP relay corresponding to TCP_conn_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int send_tcp_onion_request(Net_Crypto *c, unsigned int TCP_conn_number, const uint8_t *data, uint16_t length)
{
    if (TCP_conn_number > MAX_TCP_CONNECTIONS) {
        return -1;
    }

    if (c->tcp_connections[TCP_conn_number]) {
        pthread_mutex_lock(&c->tcp_mutex);
        int ret = send_onion_request(c->tcp_connections[TCP_conn_number], data, length);
        pthread_mutex_unlock(&c->tcp_mutex);

        if (ret == 1)
            return 0;
    }

    return -1;
}

/* Set the function to be called when an onion response packet is received by one of the TCP connections.
 */
void tcp_onion_response_handler(Net_Crypto *c, int (*tcp_onion_callback)(void *object, const uint8_t *data,
                                uint16_t length), void *object)
{
    c->tcp_onion_callback = tcp_onion_callback;
    c->tcp_onion_callback_object = object;
}

/* Copy a maximum of num TCP relays we are connected to to tcp_relays.
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
unsigned int copy_connected_tcp_relays(const Net_Crypto *c, Node_format *tcp_relays, uint16_t num)
{
    if (num == 0)
        return 0;

    uint32_t i;
    uint16_t copied = 0;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] != NULL) {
            memcpy(tcp_relays[copied].public_key, c->tcp_connections[i]->public_key, crypto_box_PUBLICKEYBYTES);
            tcp_relays[copied].ip_port = c->tcp_connections[i]->ip_port;

            if (tcp_relays[copied].ip_port.ip.family == AF_INET) {
                tcp_relays[copied].ip_port.ip.family = TCP_INET;
            } else if (tcp_relays[copied].ip_port.ip.family == AF_INET6) {
                tcp_relays[copied].ip_port.ip.family = TCP_INET6;
            }

            ++copied;

            if (copied == num)
                return copied;
        }
    }

    return copied;
}

/* Add a connected tcp connection to the tcp_connections array.
 *
 * return 0 if it was added.
 * return -1 if it wasn't.
 */
static int add_tcp_connected(Net_Crypto *c, TCP_Client_Connection *tcp_con)
{
    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            break;
    }

    if (i == MAX_TCP_CONNECTIONS)
        return -1;

    uint32_t tcp_num = i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == 0)
            return -1;

        if (conn->status == CRYPTO_CONN_NO_CONNECTION)
            continue;

        if (conn->status == CRYPTO_CONN_TIMED_OUT)
            continue;

        if (conn->dht_public_key_set)
            if (send_routing_request(tcp_con, conn->dht_public_key) != 1)
                return -1;

    }

    tcp_con->net_crypto_pointer = c;
    tcp_con->net_crypto_location = tcp_num;
    routing_response_handler(tcp_con, tcp_response_callback, tcp_con);
    routing_status_handler(tcp_con, tcp_status_callback, tcp_con);
    routing_data_handler(tcp_con, tcp_data_callback, tcp_con);
    oob_data_handler(tcp_con, tcp_oob_callback, tcp_con);
    onion_response_handler(tcp_con, tcp_onion_callback, c);
    c->tcp_connections[tcp_num] = tcp_con;
    return 0;
}

static void do_tcp(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections_new[i] == NULL)
            continue;

        pthread_mutex_lock(&c->tcp_mutex);
        do_TCP_connection(c->tcp_connections_new[i]);
        pthread_mutex_unlock(&c->tcp_mutex);

        if (c->tcp_connections_new[i]->status == TCP_CLIENT_CONFIRMED) {
            pthread_mutex_lock(&c->tcp_mutex);
            int ret = add_tcp_connected(c, c->tcp_connections_new[i]);
            pthread_mutex_unlock(&c->tcp_mutex);

            if (ret == 0) {
                c->tcp_connections_new[i] = NULL;
            } else {
                kill_TCP_connection(c->tcp_connections_new[i]);
                c->tcp_connections_new[i] = NULL;
            }
        }
    }

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            continue;

        pthread_mutex_lock(&c->tcp_mutex);
        do_TCP_connection(c->tcp_connections[i]);
        pthread_mutex_unlock(&c->tcp_mutex);
    }
}

static void clear_disconnected_tcp_peer(Crypto_Connection *conn, uint32_t number)
{
    if (conn->status == CRYPTO_CONN_NO_CONNECTION)
        return;

    if (number >= MAX_TCP_CONNECTIONS)
        return;

    set_conn_tcp_status(conn, number, STATUS_TCP_NULL);
    conn->con_number_tcp[number] = 0;
}

static void clear_disconnected_tcp(Net_Crypto *c)
{
    uint32_t i, j;

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections_new[i] == NULL)
            continue;

        if (c->tcp_connections_new[i]->status != TCP_CLIENT_DISCONNECTED)
            continue;

        kill_TCP_connection(c->tcp_connections_new[i]);
        c->tcp_connections_new[i] = NULL;
    }

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        if (c->tcp_connections[i] == NULL)
            continue;

        TCP_Client_Connection *tcp_con = c->tcp_connections[i];

        if (tcp_con->status != TCP_CLIENT_DISCONNECTED)
            continue;

        /* Try reconnecting to relay on disconnect. */
        add_tcp_relay(c, tcp_con->ip_port, tcp_con->public_key);

        pthread_mutex_lock(&c->tcp_mutex);
        c->tcp_connections[i] = NULL;
        kill_TCP_connection(tcp_con);

        for (j = 0; j < c->crypto_connections_length; ++j) {
            Crypto_Connection *conn = get_crypto_connection(c, j);

            if (conn == 0)
                continue;

            clear_disconnected_tcp_peer(conn, i);
        }

        pthread_mutex_unlock(&c->tcp_mutex);
    }
}

/* Set function to be called when connection with crypt_connection_id goes connects/disconnects.
 *
 * The set function should return -1 on failure and 0 on success.
 * Note that if this function is set, the connection will clear itself on disconnect.
 * Object and id will be passed to this function untouched.
 * status is 1 if the connection is going online, 0 if it is going offline.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_status_handler(const Net_Crypto *c, int crypt_connection_id,
                              int (*connection_status_callback)(void *object, int id, uint8_t status), void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    conn->connection_status_callback = connection_status_callback;
    conn->connection_status_callback_object = object;
    conn->connection_status_callback_id = id;
    return 0;
}

/* Set function to be called when connection with crypt_connection_id receives a data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_data_handler(const Net_Crypto *c, int crypt_connection_id, int (*connection_data_callback)(void *object,
                            int id, uint8_t *data, uint16_t length), void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    conn->connection_data_callback = connection_data_callback;
    conn->connection_data_callback_object = object;
    conn->connection_data_callback_id = id;
    return 0;
}

/* Set function to be called when connection with crypt_connection_id receives a lossy data packet of length.
 *
 * The set function should return -1 on failure and 0 on success.
 * Object and id will be passed to this function untouched.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int connection_lossy_data_handler(Net_Crypto *c, int crypt_connection_id,
                                  int (*connection_lossy_data_callback)(void *object, int id, const uint8_t *data, uint16_t length), void *object, int id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    conn->connection_lossy_data_callback = connection_lossy_data_callback;
    conn->connection_lossy_data_callback_object = object;
    conn->connection_lossy_data_callback_id = id;
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
int nc_dht_pk_callback(Net_Crypto *c, int crypt_connection_id, void (*function)(void *data, int32_t number,
                       const uint8_t *dht_public_key), void *object, uint32_t number)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    conn->dht_pk_callback = function;
    conn->dht_pk_callback_object = object;
    conn->dht_pk_callback_number = number;
    return 0;
}

/* Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int crypto_id_ip_port(const Net_Crypto *c, IP_Port ip_port)
{
    return bs_list_find(&c->ip_port_list, &ip_port);
}

#define CRYPTO_MIN_PACKET_SIZE (1 + sizeof(uint16_t) + crypto_box_MACBYTES)

/* Handle raw UDP packets coming directly from the socket.
 *
 * Handles:
 * Cookie response packets.
 * Crypto handshake packets.
 * Crypto data packets.
 *
 */
static int udp_handle_packet(void *object, IP_Port source, const uint8_t *packet, uint16_t length)
{
    if (length <= CRYPTO_MIN_PACKET_SIZE || length > MAX_CRYPTO_PACKET_SIZE)
        return 1;

    Net_Crypto *c = object;
    int crypt_connection_id = crypto_id_ip_port(c, source);

    if (crypt_connection_id == -1) {
        if (packet[0] != NET_PACKET_CRYPTO_HS)
            return 1;

        if (handle_new_connection_handshake(c, source, packet, length) != 0)
            return 1;

        return 0;
    }

    if (handle_packet_connection(c, crypt_connection_id, packet, length) != 0)
        return 1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    pthread_mutex_lock(&conn->mutex);
    conn->direct_lastrecv_time = current_time_monotonic();
    pthread_mutex_unlock(&conn->mutex);
    return 0;
}

/* The dT for the average packet receiving rate calculations.
   Also used as the */
#define PACKET_COUNTER_AVERAGE_INTERVAL 50

/* Ratio of recv queue size / recv packet rate (in seconds) times
 * the number of ms between request packets to send at that ratio
 */
#define REQUEST_PACKETS_COMPARE_CONSTANT (0.5 * 100.0)
static void send_crypto_packets(Net_Crypto *c)
{
    uint32_t i;
    uint64_t temp_time = current_time_monotonic();
    double total_send_rate = 0;
    uint32_t peak_request_packet_interval = ~0;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == 0)
            return;

        if (CRYPTO_SEND_PACKET_INTERVAL + conn->temp_packet_sent_time < temp_time) {
            send_temp_packet(c, i);
        }

        if ((conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED)
                && (CRYPTO_SEND_PACKET_INTERVAL + conn->last_request_packet_sent) < temp_time) {
            if (send_request_packet(c, i) == 0) {
                conn->last_request_packet_sent = temp_time;
            }

        }

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            if (conn->packet_recv_rate > CRYPTO_PACKET_MIN_RATE) {
                double request_packet_interval = (REQUEST_PACKETS_COMPARE_CONSTANT / (((double)num_packets_array(
                                                      &conn->recv_array) + 1.0) / (conn->packet_recv_rate + 1.0)));

                if (temp_time - conn->last_request_packet_sent > (uint64_t)request_packet_interval) {
                    if (send_request_packet(c, i) == 0) {
                        conn->last_request_packet_sent = temp_time;
                    }
                }

                if (request_packet_interval < peak_request_packet_interval) {
                    peak_request_packet_interval = request_packet_interval;
                }
            }

            if ((PACKET_COUNTER_AVERAGE_INTERVAL + conn->packet_counter_set) < temp_time) {

                double dt = temp_time - conn->packet_counter_set;

                conn->packet_recv_rate = (double)conn->packet_counter / (dt / 1000.0);
                conn->packet_counter = 0;
                conn->packet_counter_set = temp_time;

                uint32_t packets_sent = conn->packets_sent;
                conn->packets_sent = 0;

                /* conjestion control
                    calculate a new value of conn->packet_send_rate based on some data
                 */

                unsigned int pos = conn->last_sendqueue_counter % CONGESTION_QUEUE_ARRAY_SIZE;
                conn->last_sendqueue_size[pos] = num_packets_array(&conn->send_array);
                ++conn->last_sendqueue_counter;

                unsigned int j;
                long signed int sum = 0;
                sum = (long signed int)conn->last_sendqueue_size[(pos) % CONGESTION_QUEUE_ARRAY_SIZE] -
                      (long signed int)conn->last_sendqueue_size[(pos - (CONGESTION_QUEUE_ARRAY_SIZE - 1)) % CONGESTION_QUEUE_ARRAY_SIZE];

                conn->last_num_packets_sent[pos] = packets_sent;
                long signed int total_sent = 0;

                for (j = 0; j < CONGESTION_QUEUE_ARRAY_SIZE; ++j) {
                    total_sent += conn->last_num_packets_sent[j];
                }

                total_sent -= sum;

                double min_speed = 1000.0 * (((double)(total_sent)) / ((double)(CONGESTION_QUEUE_ARRAY_SIZE) *
                                             PACKET_COUNTER_AVERAGE_INTERVAL));

                conn->packet_send_rate = min_speed * 1.2;

                if (conn->packet_send_rate < CRYPTO_PACKET_MIN_RATE) {
                    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
                }

            }

            if (conn->last_packets_left_set == 0) {
                conn->last_packets_left_set = temp_time;
                conn->packets_left = CRYPTO_MIN_QUEUE_LENGTH;
            } else if (((uint64_t)((1000.0 / conn->packet_send_rate) + 0.5) + conn->last_packets_left_set) < temp_time) {
                uint32_t num_packets = conn->packet_send_rate * ((double)(temp_time - conn->last_packets_left_set) / 1000.0) + 0.5;

                if (conn->packets_left > num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH) {
                    conn->packets_left = num_packets * 4 + CRYPTO_MIN_QUEUE_LENGTH;
                } else {
                    conn->packets_left += num_packets;
                }

                conn->last_packets_left_set = temp_time;
            }

            int ret = send_requested_packets(c, i, conn->packets_left);

            if (ret != -1) {
                conn->packets_left -= ret;
            }

            if (conn->packet_send_rate > CRYPTO_PACKET_MIN_RATE * 1.5) {
                total_send_rate += conn->packet_send_rate;
            }
        }
    }

    c->current_sleep_time = ~0;
    uint32_t sleep_time = peak_request_packet_interval;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }

    if (total_send_rate > CRYPTO_PACKET_MIN_RATE) {
        sleep_time = (1000.0 / total_send_rate);

        if (c->current_sleep_time > sleep_time) {
            c->current_sleep_time = sleep_time + 1;
        }
    }

    sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    if (c->current_sleep_time > sleep_time) {
        c->current_sleep_time = sleep_time;
    }
}

/* Return 1 if max speed was reached for this connection (no more data can be physically through the pipe).
 * Return 0 if it wasn't reached.
 */
_Bool max_speed_reached(Net_Crypto *c, int crypt_connection_id)
{
    return reset_max_speed_reached(c, crypt_connection_id) != 0;
}

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(const Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return 0;

    uint32_t max_packets = CRYPTO_PACKET_BUFFER_SIZE - num_packets_array(&conn->send_array);

    if (conn->packets_left < max_packets) {
        return conn->packets_left;
    } else {
        return max_packets;
    }
}

/* Sends a lossless cryptopacket.
 *
 * return -1 if data could not be put in packet queue.
 * return positive packet number if data was put into the queue.
 *
 * congestion_control: should congestion control apply to this packet?
 */
int64_t write_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length,
                          uint8_t congestion_control)
{
    if (length == 0)
        return -1;

    if (data[0] < CRYPTO_RESERVED_PACKETS)
        return -1;

    if (data[0] >= PACKET_ID_LOSSY_RANGE_START)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (conn->status != CRYPTO_CONN_ESTABLISHED)
        return -1;

    if (congestion_control && conn->packets_left == 0)
        return -1;

    int64_t ret = send_lossless_packet(c, crypt_connection_id, data, length, congestion_control);

    if (ret == -1)
        return -1;

    if (congestion_control) {
        --conn->packets_left;
        conn->packets_sent++;
    }

    return ret;
}

/* Check if packet_number was received by the other side.
 *
 * packet_number must be a valid packet number of a packet sent on this connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int cryptpacket_received(Net_Crypto *c, int crypt_connection_id, uint32_t packet_number)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint32_t num = conn->send_array.buffer_end - conn->send_array.buffer_start;
    uint32_t num1 = packet_number - conn->send_array.buffer_start;

    if (num < num1) {
        return 0;
    } else {
        return -1;
    }
}

/* return -1 on failure.
 * return 0 on success.
 *
 * Sends a lossy cryptopacket. (first byte must in the PACKET_ID_LOSSY_RANGE_*)
 */
int send_lossy_cryptpacket(Net_Crypto *c, int crypt_connection_id, const uint8_t *data, uint16_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    if (data[0] < PACKET_ID_LOSSY_RANGE_START)
        return -1;

    if (data[0] >= (PACKET_ID_LOSSY_RANGE_START + PACKET_ID_LOSSY_RANGE_SIZE))
        return -1;

    pthread_mutex_lock(&c->connections_mutex);
    ++c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    int ret = -1;

    if (conn) {
        pthread_mutex_lock(&conn->mutex);
        uint32_t buffer_start = conn->recv_array.buffer_start;
        uint32_t buffer_end = conn->send_array.buffer_end;
        pthread_mutex_unlock(&conn->mutex);
        ret = send_data_packet_helper(c, crypt_connection_id, buffer_start, buffer_end, data, length);
    }

    pthread_mutex_lock(&c->connections_mutex);
    --c->connection_use_counter;
    pthread_mutex_unlock(&c->connections_mutex);

    return ret;
}

/* Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    while (1) { /* TODO: is this really the best way to do this? */
        pthread_mutex_lock(&c->connections_mutex);

        if (!c->connection_use_counter) {
            break;
        }

        pthread_mutex_unlock(&c->connections_mutex);
    }

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    int ret = -1;

    if (conn) {
        if (conn->status == CRYPTO_CONN_ESTABLISHED)
            send_kill_packet(c, crypt_connection_id);

        disconnect_peer_tcp(c, crypt_connection_id);
        bs_list_remove(&c->ip_port_list, &conn->ip_port, crypt_connection_id);
        clear_temp_packet(c, crypt_connection_id);
        clear_buffer(&conn->send_array);
        clear_buffer(&conn->recv_array);
        ret = wipe_crypto_connection(c, crypt_connection_id);
    }

    pthread_mutex_unlock(&c->connections_mutex);

    return ret;
}

/* return one of CRYPTO_CONN_* values indicating the state of the connection.
 *
 * sets direct_connected to 1 if connection connects directly to other, 0 if it isn't.
 */
unsigned int crypto_connection_status(const Net_Crypto *c, int crypt_connection_id, uint8_t *direct_connected)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return CRYPTO_CONN_NO_CONNECTION;

    *direct_connected = 0;

    if ((UDP_DIRECT_TIMEOUT + conn->direct_lastrecv_time) > current_time_monotonic())
        *direct_connected = 1;

    return conn->status;
}

void new_keys(Net_Crypto *c)
{
    crypto_box_keypair(c->self_public_key, c->self_secret_key);
}

/* Save the public and private keys to the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void save_keys(const Net_Crypto *c, uint8_t *keys)
{
    memcpy(keys, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(keys + crypto_box_PUBLICKEYBYTES, c->self_secret_key, crypto_box_SECRETKEYBYTES);
}

/* Load the public and private keys from the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void load_keys(Net_Crypto *c, const uint8_t *keys)
{
    memcpy(c->self_public_key, keys, crypto_box_PUBLICKEYBYTES);
    memcpy(c->self_secret_key, keys + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);
}

/* Run this to (re)initialize net_crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(DHT *dht, TCP_Proxy_Info *proxy_info)
{
    unix_time_update();

    if (dht == NULL)
        return NULL;

    Net_Crypto *temp = calloc(1, sizeof(Net_Crypto));

    if (temp == NULL)
        return NULL;

    if (create_recursive_mutex(&temp->tcp_mutex) != 0 ||
            pthread_mutex_init(&temp->connections_mutex, NULL) != 0) {
        free(temp);
        return NULL;
    }

    temp->dht = dht;

    new_keys(temp);
    new_symmetric_key(temp->secret_symmetric_key);

    temp->current_sleep_time = CRYPTO_SEND_PACKET_INTERVAL;

    networking_registerhandler(dht->net, NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    networking_registerhandler(dht->net, NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, temp);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO_HS, &udp_handle_packet, temp);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO_DATA, &udp_handle_packet, temp);

    bs_list_init(&temp->ip_port_list, sizeof(IP_Port), 8);

    temp->proxy_info = *proxy_info;

    return temp;
}

static void kill_timedout(Net_Crypto *c)
{
    uint32_t i;
    //uint64_t temp_time = current_time_monotonic();

    for (i = 0; i < c->crypto_connections_length; ++i) {
        Crypto_Connection *conn = get_crypto_connection(c, i);

        if (conn == 0)
            return;

        if (conn->status == CRYPTO_CONN_NO_CONNECTION || conn->status == CRYPTO_CONN_TIMED_OUT)
            continue;

        if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT
                || conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
            if (conn->temp_packet_num_sent < MAX_NUM_SENDPACKET_TRIES)
                continue;

            conn->killed = 1;

        }

        if (conn->killed) {
            if (conn->connection_status_callback) {
                conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 0);
                crypto_kill(c, i);
                continue;
            }

            conn->status = CRYPTO_CONN_TIMED_OUT;
            continue;
        }

        if (conn->status == CRYPTO_CONN_ESTABLISHED) {
            //TODO: add a timeout here?
        }
    }
}

/* return the optimal interval in ms for running do_net_crypto.
 */
uint32_t crypto_run_interval(const Net_Crypto *c)
{
    return c->current_sleep_time;
}

/* Main loop. */
void do_net_crypto(Net_Crypto *c)
{
    unix_time_update();
    kill_timedout(c);
    do_tcp(c);
    clear_disconnected_tcp(c);
    send_crypto_packets(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    for (i = 0; i < MAX_TCP_CONNECTIONS; ++i) {
        kill_TCP_connection(c->tcp_connections_new[i]);
        kill_TCP_connection(c->tcp_connections[i]);
    }

    pthread_mutex_destroy(&c->tcp_mutex);
    pthread_mutex_destroy(&c->connections_mutex);

    bs_list_free(&c->ip_port_list);
    networking_registerhandler(c->dht->net, NET_PACKET_COOKIE_REQUEST, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_COOKIE_RESPONSE, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_CRYPTO_HS, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_CRYPTO_DATA, NULL, NULL);
    memset(c, 0, sizeof(Net_Crypto));
    free(c);
}
