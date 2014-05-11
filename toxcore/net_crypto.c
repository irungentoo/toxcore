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
static uint8_t crypt_connection_id_not_valid(Net_Crypto *c, int crypt_connection_id)
{
    return (uint32_t)crypt_connection_id >= c->crypto_connections_length;
}

/* return 0 if connection is dead.
 * return 1 if connection is alive.
 */
static int is_alive(uint8_t status)
{
    if (status == CRYPTO_CONN_COOKIE_REQUESTING ||
            status == CRYPTO_CONN_HANDSHAKE_SENT ||
            status == CRYPTO_CONN_NOT_CONFIRMED ||
            status == CRYPTO_CONN_ESTABLISHED) {
        return 1;
    }

    return 0;
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
 * real_public_key is the real public key of the other.
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_REQUEST_LENGTH on success.
 */
static int create_cookie_request(Net_Crypto *c, uint8_t *packet, uint8_t *dht_public_key, uint8_t *real_public_key,
                                 uint64_t number, uint8_t *shared_key)
{
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];

    memcpy(plain, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + crypto_box_PUBLICKEYBYTES, real_public_key, crypto_box_PUBLICKEYBYTES);
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
static int create_cookie(uint8_t *cookie, uint8_t *bytes, uint8_t *encryption_key)
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
static int open_cookie(uint8_t *bytes, uint8_t *cookie, uint8_t *encryption_key)
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
static int create_cookie_response(Net_Crypto *c, uint8_t *packet, uint8_t *request_plain, uint8_t *shared_key)
{
    uint8_t plain[COOKIE_LENGTH + sizeof(uint64_t)];

    if (create_cookie(plain, request_plain, c->secret_symmetric_key) != 0)
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
static int handle_cookie_request(Net_Crypto *c, uint8_t *request_plain, uint8_t *shared_key, uint8_t *packet,
                                 uint16_t length)
{
    if (length != COOKIE_REQUEST_LENGTH)
        return -1;

    DHT_get_shared_key_sent(c->dht, shared_key, packet + 1);
    int len = decrypt_data_symmetric(shared_key, packet + 1 + crypto_box_PUBLICKEYBYTES,
                                     packet + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES, COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES,
                                     request_plain);

    if (len != COOKIE_REQUEST_PLAIN_LENGTH)
        return -1;

    return 0;
}

/* Handle the cookie request packet (for raw UDP)
 */
static int udp_handle_cookie_request(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Net_Crypto *c = object;
    uint8_t request_plain[COOKIE_REQUEST_PLAIN_LENGTH];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];

    if (handle_cookie_request(c, request_plain, shared_key, packet, length) != 0)
        return 1;

    uint8_t data[COOKIE_RESPONSE_LENGTH];

    if (create_cookie_response(c, data, request_plain, shared_key) != sizeof(data))
        return 1;

    if ((uint32_t)sendpacket(c->dht->net, source, data, sizeof(data)) != sizeof(data))
        return 1;

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
static int handle_cookie_response(uint8_t *cookie, uint64_t *number, uint8_t *packet, uint32_t length,
                                  uint8_t *shared_key)
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
static int create_crypto_handshake(Net_Crypto *c, uint8_t *packet, uint8_t *cookie, uint8_t *nonce, uint8_t *session_pk,
                                   uint8_t *peer_real_pk)
{
    uint8_t plain[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_hash_sha512_BYTES + COOKIE_LENGTH];
    memcpy(plain, nonce, crypto_box_NONCEBYTES);
    memcpy(plain + crypto_box_NONCEBYTES, session_pk, crypto_box_PUBLICKEYBYTES);
    crypto_hash_sha512(plain + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, cookie, COOKIE_LENGTH);
    uint8_t cookie_plain[COOKIE_DATA_LENGTH];
    memcpy(cookie_plain, peer_real_pk, crypto_box_PUBLICKEYBYTES);
    memcpy(cookie_plain + crypto_box_PUBLICKEYBYTES, c->self_public_key, crypto_box_PUBLICKEYBYTES);

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
 * the real public key of the peer in peer_real_pk and
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
static int handle_crypto_handshake(Net_Crypto *c, uint8_t *nonce, uint8_t *session_pk, uint8_t *peer_real_pk,
                                   uint8_t *cookie, uint8_t *packet, uint32_t length, uint8_t *expected_real_pk)
{
    if (length != HANDSHAKE_PACKET_LENGTH)
        return -1;

    uint8_t cookie_plain[COOKIE_DATA_LENGTH];

    if (open_cookie(cookie_plain, packet + 1, c->secret_symmetric_key) != 0)
        return -1;

    if (expected_real_pk)
        if (crypto_cmp(cookie_plain, expected_real_pk, crypto_box_PUBLICKEYBYTES) != 0)
            return -1;

    if (crypto_cmp(cookie_plain + crypto_box_PUBLICKEYBYTES, c->self_public_key, crypto_box_PUBLICKEYBYTES) != 0)
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
    return 0;
}


static Crypto_Connection *get_crypto_connection(Net_Crypto *c, int crypt_connection_id)
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
static int send_packet_to(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint16_t length)
{
//TODO TCP, etc...
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if ((uint32_t)sendpacket(c->dht->net, conn->ip_port, data, length) != length)
        return -1;

    return 0;
}

/** START: Array Related functions **/


/* Return number of packets in array
 * Note that holes are counted too.
 */
static uint32_t num_packets_array(Packets_Array *array)
{
    return array->buffer_end - array->buffer_start;
}

/* Add data with packet number to array.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int add_data_to_buffer(Packets_Array *array, uint32_t number, Packet_Data *data)
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
static int get_data_pointer(Packets_Array *array, Packet_Data **data, uint32_t number)
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
static int64_t add_data_end_of_buffer(Packets_Array *array, Packet_Data *data)
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
static int generate_request_packet(uint8_t *data, uint16_t length, Packets_Array *recv_array, uint32_t send_buffer_end)
{
    if (length <= (sizeof(uint32_t) * 2))
        return -1;

    uint32_t recv_buffer_start = htonl(recv_array->buffer_start);
    send_buffer_end = htonl(send_buffer_end);
    memcpy(data, &recv_buffer_start, sizeof(uint32_t));
    memcpy(data + sizeof(uint32_t), &send_buffer_end, sizeof(uint32_t));
    data[sizeof(uint32_t) * 2] = PACKET_ID_REQUEST;

    uint16_t cur_len = sizeof(uint32_t) * 2 + 1;

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
 * Remove all the packets the other recieved from the array.
 *
 * return -1 on failure.
 * return number of requested packets on success.
 */
static int handle_request_packet(Packets_Array *send_array, uint8_t *data, uint16_t length)
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
                send_array->buffer[num]->time = 0;
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
static int send_data_packet(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint16_t length)
{
    if (length == 0 || length + (1 + sizeof(uint16_t) + crypto_box_MACBYTES) > MAX_CRYPTO_PACKET_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t packet[1 + sizeof(uint16_t) + length + crypto_box_MACBYTES];
    packet[0] = NET_PACKET_CRYPTO_DATA;
    memcpy(packet + 1, conn->sent_nonce + (crypto_box_NONCEBYTES - sizeof(uint16_t)), sizeof(uint16_t));
    int len = encrypt_data_symmetric(conn->shared_key, conn->sent_nonce, data, length, packet + 1 + sizeof(uint16_t));

    if (len + 1 + sizeof(uint16_t) != sizeof(packet))
        return -1;

    increment_nonce(conn->sent_nonce);
    return send_packet_to(c, crypt_connection_id, packet, sizeof(packet));
}

/* Creates and sends a data packet with buffer_start and num to the peer using the fastest route.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int send_data_packet_helper(Net_Crypto *c, int crypt_connection_id, uint32_t buffer_start, uint32_t num,
                                   uint8_t *data, uint32_t length)
{
    num = htonl(num);
    buffer_start = htonl(buffer_start);
    uint8_t packet[sizeof(uint32_t) + sizeof(uint32_t) + length];
    memcpy(packet, &buffer_start, sizeof(uint32_t));
    memcpy(packet + sizeof(uint32_t), &num, sizeof(uint32_t));
    memcpy(packet + (sizeof(uint32_t) * 2), data, length);

    return send_data_packet(c, crypt_connection_id, packet, sizeof(packet));
}

/*  return -1 if data could not be put in packet queue.
 *  return positive packet number if data was put into the queue.
 */
static int64_t send_lossless_packet(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint32_t length)
{
    if (length == 0 || length > MAX_CRYPTO_DATA_SIZE)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    Packet_Data dt;
    dt.time = current_time_monotonic();
    dt.length = length;
    memcpy(dt.data, data, length);
    int64_t packet_num = add_data_end_of_buffer(&conn->send_array, &dt);

    if (packet_num == -1)
        return -1;

    if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, data, length) != 0)
        fprintf(stderr, "send_data_packet failed\n");

    return packet_num;
}

/* Get the lowest 2 bytes from the nonce and convert
 * them to host byte format before returning them.
 */
static uint16_t get_nonce_uint16(uint8_t *nonce)
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
static int handle_data_packet(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint8_t *packet, uint16_t length)
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

    uint8_t packet[MAX_DATA_DATA_PACKET_SIZE];
    int len = generate_request_packet(packet, sizeof(packet), &conn->recv_array, conn->send_array.buffer_end);

    if (len == -1)
        return -1;

    return send_data_packet(c, crypt_connection_id, packet, len);
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

        if (dt->time != 0) {
            continue;
        }

        dt->time = current_time_monotonic();

        if (send_data_packet_helper(c, crypt_connection_id, conn->recv_array.buffer_start, packet_num, dt->data,
                                    dt->length) == 0)
            ++num_sent;

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
static int new_temp_packet(Net_Crypto *c, int crypt_connection_id, uint8_t *packet, uint16_t length)
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
static int clear_temp_packet(Net_Crypto *c, int crypt_connection_id)
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
static int create_send_handshake(Net_Crypto *c, int crypt_connection_id, uint8_t *cookie)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

    if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionpublic_key,
                                conn->public_key) != sizeof(handshake_packet))
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

/* Handle a recieved data packet.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_data_packet_helper(Net_Crypto *c, int crypt_connection_id, uint8_t *packet, uint16_t length)
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

    if (real_data[0] == PACKET_ID_REQUEST) {
        int requested = handle_request_packet(&conn->send_array, real_data, real_length);

        if (requested == -1) {
            return -1;
        } else {
            //TODO?
        }

        set_buffer_end(&conn->recv_array, num);
    } else if (real_data[0] == PACKET_ID_KILL) {
        conn->killed = 1;
        return 0;
    } else {
        Packet_Data dt;
        dt.time = current_time_monotonic();
        dt.length = real_length;
        memcpy(dt.data, real_data, real_length);

        if (add_data_to_buffer(&conn->recv_array, num, &dt) != 0)
            return -1;

        while (read_data_beg_buffer(&conn->recv_array, &dt) != -1) {
            if (conn->connection_data_callback)
                conn->connection_data_callback(conn->connection_data_callback_object, conn->connection_data_callback_id, dt.data,
                                               dt.length);
        }

        /* Packet counter. */
        ++conn->packet_counter;
    }

    if (conn->status == CRYPTO_CONN_NOT_CONFIRMED) {
        if (conn->connection_status_callback)
            conn->connection_status_callback(conn->connection_status_callback_object, conn->connection_status_callback_id, 1);

        clear_temp_packet(c, crypt_connection_id);
        conn->status = CRYPTO_CONN_ESTABLISHED;
    }

    return 0;
}

/* Handle a packet that was recieved for the connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int handle_packet_connection(Net_Crypto *c, int crypt_connection_id, uint8_t *packet, uint16_t length)
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

            if (create_send_handshake(c, crypt_connection_id, cookie) != 0)
                return -1;

            conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            return 0;
        }

        case NET_PACKET_CRYPTO_HS: {
            if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING || conn->status == CRYPTO_CONN_HANDSHAKE_SENT) {
                uint8_t peer_real_pk[crypto_box_PUBLICKEYBYTES];
                uint8_t cookie[COOKIE_LENGTH];

                if (handle_crypto_handshake(c, conn->recv_nonce, conn->peersessionpublic_key, peer_real_pk, cookie, packet, length,
                                            conn->public_key) != 0)
                    return -1;

                encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

                if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
                    if (create_send_handshake(c, crypt_connection_id, cookie) != 0)
                        return -1;
                }

                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
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

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == -1)
        return -1;

    memset(&(c->crypto_connections[c->crypto_connections_length]), 0, sizeof(Crypto_Connection));
    int id = c->crypto_connections_length;
    ++c->crypto_connections_length;
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
    memset(&(c->crypto_connections[crypt_connection_id]), 0 , sizeof(Crypto_Connection));

    for (i = c->crypto_connections_length; i != 0; --i) {
        if (c->crypto_connections[i - 1].status != CRYPTO_CONN_NO_CONNECTION)
            break;
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
static int getcryptconnection_id(Net_Crypto *c, uint8_t *public_key)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION)
            if (memcmp(public_key, c->crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0)
                return i;
    }

    return -1;
}

/* Add a source to the crypto connection.
 * This is to be used only when we have recieved a packet from that source.
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
        conn->ip_port = source;
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
static int handle_new_connection_handshake(Net_Crypto *c, IP_Port source, uint8_t *data, uint16_t length)
{
    New_Connection n_c;
    n_c.cookie = malloc(COOKIE_LENGTH);

    if (n_c.cookie == NULL)
        return -1;

    n_c.source = source;
    n_c.cookie_length = COOKIE_LENGTH;

    if (handle_crypto_handshake(c, n_c.recv_nonce, n_c.peersessionpublic_key, n_c.public_key, n_c.cookie, data, length,
                                0) != 0) {
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

            if (create_send_handshake(c, crypt_connection_id, n_c.cookie) == 0) {
                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
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

    if (create_send_handshake(c, crypt_connection_id, n_c->cookie) != 0)
        return -1;

    send_temp_packet(c, crypt_connection_id);
    conn->status = CRYPTO_CONN_NOT_CONFIRMED;
    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;
    crypto_connection_add_source(c, crypt_connection_id, n_c->source);
    return crypt_connection_id;
}

/* Create a crypto connection.
 * If one to that real public key already exists, return it.
 *
 * return -1 on failure.
 * return connection id on success.
 */
int new_crypto_connection(Net_Crypto *c, uint8_t *real_public_key)
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
    return crypt_connection_id;
}

/* Set the DHT public key of the crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int set_conection_dht_public_key(Net_Crypto *c, int crypt_connection_id, uint8_t *dht_public_key)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (conn->dht_public_key_set == 1 && memcmp(conn->dht_public_key, dht_public_key, crypto_box_PUBLICKEYBYTES) == 0)
        return -1;

    memcpy(conn->dht_public_key, dht_public_key, crypto_box_PUBLICKEYBYTES);
    conn->dht_public_key_set = 1;

    if (conn->status == CRYPTO_CONN_COOKIE_REQUESTING) {
        conn->cookie_request_number = random_64b();
        uint8_t cookie_request[COOKIE_REQUEST_LENGTH];

        if (create_cookie_request(c, cookie_request, conn->dht_public_key, conn->public_key,
                                  conn->cookie_request_number, conn->shared_key) != sizeof(cookie_request))
            return -1;

        if (new_temp_packet(c, crypt_connection_id, cookie_request, sizeof(cookie_request)) != 0)
            return -1;
    }//TODO

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

    if (!ipport_equal(&ip_port, &conn->ip_port)) {
        conn->ip_port = ip_port;
        conn->direct_lastrecv_time = 0;
    }

    return 0;
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
int connection_status_handler(Net_Crypto *c, int crypt_connection_id, int (*connection_status_callback)(void *object,
                              int id, uint8_t status), void *object, int id)
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
int connection_data_handler(Net_Crypto *c, int crypt_connection_id, int (*connection_data_callback)(void *object,
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

/* Get the crypto connection id from the ip_port.
 *
 * return -1 on failure.
 * return connection id on success.
 */
static int crypto_id_ip_port(Net_Crypto *c, IP_Port ip_port)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (is_alive(c->crypto_connections[i].status))
            if (ipport_equal(&ip_port, &c->crypto_connections[i].ip_port))
                return i;
    }

    return -1;
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
static int udp_handle_packet(void *object, IP_Port source, uint8_t *packet, uint32_t length)
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

    conn->direct_lastrecv_time = current_time_monotonic();
    return 0;
}

/* The dT for the average packet recieving rate calculations.
   Also used as the */
#define PACKET_COUNTER_AVERAGE_INTERVAL 200

/* Ratio of recv queue size / recv packet rate (in seconds) times
 * the number of ms between request packets to send at that ratio
 */
#define REQUEST_PACKETS_COMPARE_CONSTANT (0.5 * 100.0)
static void send_crypto_packets(Net_Crypto *c)
{
    uint32_t i;
    uint64_t temp_time = current_time_monotonic();

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
            if (((double)num_packets_array(&conn->recv_array) / (conn->packet_recv_rate + 1.0)) * (double)(
                        temp_time - conn->last_request_packet_sent) > REQUEST_PACKETS_COMPARE_CONSTANT) {
                if (send_request_packet(c, i) == 0) {
                    conn->last_request_packet_sent = temp_time;
                }
            }

            if ((PACKET_COUNTER_AVERAGE_INTERVAL + conn->packet_counter_set) < temp_time) {
                conn->packet_recv_rate = (double)conn->packet_counter / ((double)(temp_time - conn->packet_counter_set) / 1000.0);
                conn->packet_counter = 0;
                conn->packet_counter_set = temp_time;

                if ((double)num_packets_array(&conn->send_array) < 0.3 * (conn->packet_send_rate)) {
                    conn->packet_send_rate *= 1.2;
                } else if ((double)num_packets_array(&conn->send_array) > 0.5 * (conn->packet_send_rate)) {
                    conn->packet_send_rate *= 0.8;
                }

                if (conn->packet_send_rate < CRYPTO_PACKET_MIN_RATE || !conn->sending)
                    conn->packet_send_rate = CRYPTO_PACKET_MIN_RATE;

                if (conn->packet_send_rate > CRYPTO_PACKET_BUFFER_SIZE * 8)
                    conn->packet_send_rate = CRYPTO_PACKET_BUFFER_SIZE * 8;

            }

            if (conn->last_packets_left_set == 0) {
                conn->last_packets_left_set = temp_time;
                conn->packets_left = conn->packet_send_rate;
            } else if (((1000.0 / conn->packet_send_rate) + conn->last_packets_left_set) < temp_time) {
                uint32_t num_packets = conn->packet_send_rate * ((double)(temp_time - conn->last_packets_left_set) / 1000.0);

                if (conn->packets_left > num_packets * 2 + CRYPTO_MIN_QUEUE_LENGTH) {
                    conn->packets_left = num_packets * 2 + CRYPTO_MIN_QUEUE_LENGTH;
                } else {
                    conn->packets_left += num_packets;
                }

                conn->last_packets_left_set = temp_time;
            }

            int ret = send_requested_packets(c, i, conn->packets_left);

            if (ret != -1) {
                conn->packets_left -= ret;
            }

            if (conn->sending != 0 && num_packets_array(&conn->send_array) < CRYPTO_MIN_QUEUE_LENGTH) {
                --conn->sending;
            }
        }
    }
}


/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(Net_Crypto *c, int crypt_connection_id)
{
    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return 0;

    return conn->packets_left;
}




/*  return -1 if data could not be put in packet queue.
 *  return positive packet number if data was put into the queue.
 */
int64_t write_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint32_t length)
{
    if (length == 0)
        return -1;

    if (data[0] < CRYPTO_RESERVED_PACKETS)
        return -1;

    Crypto_Connection *conn = get_crypto_connection(c, crypt_connection_id);

    if (conn == 0)
        return -1;

    if (conn->status != CRYPTO_CONN_ESTABLISHED)
        return -1;

    if (conn->packets_left == 0)
        return -1;

    int64_t ret = send_lossless_packet(c, crypt_connection_id, data, length);

    if (ret == -1)
        return -1;

    --conn->packets_left;
    conn->sending = CRYPTO_MIN_QUEUE_LENGTH;
    return ret;
}

/* Kill a crypto connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    //TODO
    send_kill_packet(c, crypt_connection_id);
    return wipe_crypto_connection(c, crypt_connection_id);
}

/*  return 0 if no connection.
 *  return 1 we have sent a handshake.
 *  return 2 if connection is not confirmed yet (we have received a handshake but no empty data packet).
 *  return 3 if the connection is established.
 *  return 4 if the connection is timed out and waiting to be killed.
 */
int is_cryptoconnected(Net_Crypto *c, int crypt_connection_id)
{
    if ((unsigned int)crypt_connection_id < c->crypto_connections_length)
        return c->crypto_connections[crypt_connection_id].status;

    return CRYPTO_CONN_NO_CONNECTION;
}

void new_keys(Net_Crypto *c)
{
    crypto_box_keypair(c->self_public_key, c->self_secret_key);
}

/* Save the public and private keys to the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void save_keys(Net_Crypto *c, uint8_t *keys)
{
    memcpy(keys, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(keys + crypto_box_PUBLICKEYBYTES, c->self_secret_key, crypto_box_SECRETKEYBYTES);
}

/* Load the public and private keys from the keys array.
 * Length must be crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES.
 */
void load_keys(Net_Crypto *c, uint8_t *keys)
{
    memcpy(c->self_public_key, keys, crypto_box_PUBLICKEYBYTES);
    memcpy(c->self_secret_key, keys + crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES);
}

/* Run this to (re)initialize net_crypto.
 * Sets all the global connection variables to their default values.
 */
Net_Crypto *new_net_crypto(DHT *dht)
{
    unix_time_update();

    if (dht == NULL)
        return NULL;

    Net_Crypto *temp = calloc(1, sizeof(Net_Crypto));

    if (temp == NULL)
        return NULL;

    temp->dht = dht;

    new_keys(temp);
    new_symmetric_key(temp->secret_symmetric_key);

    networking_registerhandler(dht->net, NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    networking_registerhandler(dht->net, NET_PACKET_COOKIE_RESPONSE, &udp_handle_packet, temp);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO_HS, &udp_handle_packet, temp);
    networking_registerhandler(dht->net, NET_PACKET_CRYPTO_DATA, &udp_handle_packet, temp);
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

/* Main loop. */
void do_net_crypto(Net_Crypto *c)
{
    unix_time_update();
    kill_timedout(c);
    send_crypto_packets(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    networking_registerhandler(c->dht->net, NET_PACKET_COOKIE_REQUEST, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_COOKIE_RESPONSE, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_CRYPTO_HS, NULL, NULL);
    networking_registerhandler(c->dht->net, NET_PACKET_CRYPTO_DATA, NULL, NULL);
    memset(c, 0, sizeof(Net_Crypto));
    free(c);
}
