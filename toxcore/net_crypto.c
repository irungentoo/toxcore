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

/* cookie timeout in seconds */
#define COOKIE_TIMEOUT 10
#define COOKIE_DATA_LENGTH (crypto_box_PUBLICKEYBYTES * 2)
#define COOKIE_CONTENTS_LENGTH (sizeof(uint64_t) + COOKIE_DATA_LENGTH)
#define COOKIE_LENGTH (crypto_box_NONCEBYTES + COOKIE_CONTENTS_LENGTH + crypto_box_MACBYTES)

#define COOKIE_REQUEST_PLAIN_LENGTH (COOKIE_DATA_LENGTH + sizeof(uint64_t))
#define COOKIE_REQUEST_LENGTH (1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + COOKIE_REQUEST_PLAIN_LENGTH + crypto_box_MACBYTES)
#define COOKIE_RESPONSE_LENGTH (1 + crypto_box_NONCEBYTES + COOKIE_LENGTH + sizeof(uint64_t) + crypto_box_MACBYTES)

/* Create a cookie request packet and put it in packet.
 *
 * packet must be of size COOKIE_REQUEST_LENGTH or bigger.
 *
 * return -1 on failure.
 * return COOKIE_REQUEST_LENGTH on success.
 */
static int create_cookie_request(Net_Crypto *c, uint8_t *packet, uint8_t *dht_public_key, uint8_t *real_public_key,
                                 uint64_t number)
{
    uint8_t plain[COOKIE_REQUEST_PLAIN_LENGTH];

    memcpy(plain, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + crypto_box_PUBLICKEYBYTES, real_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(plain + (crypto_box_PUBLICKEYBYTES * 2), &number, sizeof(uint64_t));

    uint8_t shared_key[crypto_box_BEFORENMBYTES];
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
static int handle_cookie_response(Net_Crypto *c, uint8_t *cookie, uint64_t *number, uint8_t *packet, uint32_t length,
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
//TODO


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

    conn->temp_packet_sent_time = current_time();
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
            if (conn->status != CRYPTO_CONN_COOKIE_REQUESTED)
                return -1;

            uint8_t cookie[COOKIE_LENGTH];
            uint64_t number;

            if (handle_cookie_response(c, cookie, &number, packet, length, conn->shared_key) != sizeof(cookie))
                return -1;

            if (number != conn->cookie_request_number)
                return -1;

            uint8_t handshake_packet[HANDSHAKE_PACKET_LENGTH];

            if (create_crypto_handshake(c, handshake_packet, cookie, conn->sent_nonce, conn->sessionpublic_key,
                                        conn->public_key) != sizeof(handshake_packet))
                return -1;

            if (new_temp_packet(c, crypt_connection_id, handshake_packet, sizeof(handshake_packet)) != 0)
                return -1;

            send_temp_packet(c, crypt_connection_id);
            conn->status = CRYPTO_CONN_HANDSHAKE_SENT;
            return 0;
        }

        case NET_PACKET_CRYPTO_HS: {
            if (conn->status == CRYPTO_CONN_COOKIE_REQUESTED || conn->status == CRYPTO_CONN_HANDSHAKE_SENT) {
                uint8_t peer_real_pk[crypto_box_PUBLICKEYBYTES];
                uint8_t cookie[COOKIE_LENGTH];

                if (handle_crypto_handshake(c, conn->recv_nonce, conn->peersessionpublic_key, peer_real_pk, cookie, packet, length,
                                            conn->public_key) != 0)
                    return -1;

                encrypt_precompute(conn->peersessionpublic_key, conn->sessionsecret_key, conn->shared_key);

                conn->status = CRYPTO_CONN_NOT_CONFIRMED;
            } else {
                return -1;
            }

            return 0;
        }

        case NET_PACKET_CRYPTO_DATA: {
            if (conn->status == CRYPTO_CONN_NOT_CONFIRMED || conn->status == CRYPTO_CONN_ESTABLISHED) {
                //TODO
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


void new_connection_handler(Net_Crypto *c, int (*new_connection_callback)(void *object, New_Connection *n_c),
                            void *object)
{
    c->new_connection_callback = new_connection_callback;
    c->new_connection_callback_object = object;
}

static int handle_new_connection_handshake(Net_Crypto *c, uint8_t *data, uint16_t length)
{


}

int accept_crypto_connection(Net_Crypto *c, New_Connection *n_c)
{


}
/*  return 0 if there is no received data in the buffer.
 *  return -1  if the packet was discarded.
 *  return length of received data if successful.
 */
int read_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_ESTABLISHED)
        return 0;

    uint8_t temp_data[MAX_DATA_SIZE];
    int length = read_packet(c->lossless_udp, c->crypto_connections[crypt_connection_id].number, temp_data);

    if (length == 0)
        return 0;

    if (temp_data[0] != 3)
        return -1;

    int len = decrypt_data_symmetric(c->crypto_connections[crypt_connection_id].shared_key,
                                     c->crypto_connections[crypt_connection_id].recv_nonce,
                                     temp_data + 1, length - 1, data);

    if (len != -1) {
        increment_nonce(c->crypto_connections[crypt_connection_id].recv_nonce);
        return len;
    }

    return -1;
}

/* returns the number of packet slots left in the sendbuffer.
 * return 0 if failure.
 */
uint32_t crypto_num_free_sendqueue_slots(Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    return num_free_sendqueue_slots(c->lossless_udp, c->crypto_connections[crypt_connection_id].number);
}

/*  return 0 if data could not be put in packet queue.
 *  return 1 if data was put into the queue.
 */
int write_cryptpacket(Net_Crypto *c, int crypt_connection_id, uint8_t *data, uint32_t length)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 0;

    if (length - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES > MAX_DATA_SIZE - 1)
        return 0;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_ESTABLISHED)
        return 0;

    uint8_t temp_data[MAX_DATA_SIZE];
    int len = encrypt_data_symmetric(c->crypto_connections[crypt_connection_id].shared_key,
                                     c->crypto_connections[crypt_connection_id].sent_nonce,
                                     data, length, temp_data + 1);

    if (len == -1)
        return 0;

    temp_data[0] = 3;

    if (write_packet(c->lossless_udp, c->crypto_connections[crypt_connection_id].number, temp_data, len + 1) == 0)
        return 0;

    increment_nonce(c->crypto_connections[crypt_connection_id].sent_nonce);
    return 1;
}


/* Send a crypto handshake packet containing an encrypted secret nonce and session public key
 * to peer with connection_id and public_key.
 * The packet is encrypted with a random nonce which is sent in plain text with the packet.
 */
static int send_cryptohandshake(Net_Crypto *c, int connection_id, uint8_t *public_key, uint8_t *secret_nonce,
                                uint8_t *session_key)
{
    uint8_t temp_data[MAX_DATA_SIZE];
    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];
    uint8_t nonce[crypto_box_NONCEBYTES];

    new_nonce(nonce);
    memcpy(temp, secret_nonce, crypto_box_NONCEBYTES);
    memcpy(temp + crypto_box_NONCEBYTES, session_key, crypto_box_PUBLICKEYBYTES);

    int len = encrypt_data(public_key, c->self_secret_key, nonce, temp, crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,
                           1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + temp_data);

    if (len == -1)
        return 0;

    temp_data[0] = 2;
    memcpy(temp_data + 1, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(temp_data + 1 + crypto_box_PUBLICKEYBYTES, nonce, crypto_box_NONCEBYTES);
    return write_packet(c->lossless_udp, connection_id, temp_data,
                        len + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
}

/* Extract secret nonce, session public key and public_key from a packet(data) with length length.
 *
 *  return 1 if successful.
 *  return 0 if failure.
 */
static int handle_cryptohandshake(Net_Crypto *c, uint8_t *public_key, uint8_t *secret_nonce,
                                  uint8_t *session_key, uint8_t *data, uint16_t length)
{
    int pad = (- crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);

    if (length != 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES
            + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad) {
        return 0;
    }

    if (data[0] != 2)
        return 0;

    uint8_t temp[crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES];

    memcpy(public_key, data + 1, crypto_box_PUBLICKEYBYTES);

    int len = decrypt_data(public_key, c->self_secret_key, data + 1 + crypto_box_PUBLICKEYBYTES,
                           data + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES,
                           crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + pad, temp);

    if (len != crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES)
        return 0;

    memcpy(secret_nonce, temp, crypto_box_NONCEBYTES);
    memcpy(session_key, temp + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);
    return 1;
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

/* Start a secure connection with other peer who has public_key and ip_port.
 *
 *  return -1 if failure.
 *  return crypt_connection_id of the initialized connection if everything went well.
 */
int crypto_connect(Net_Crypto *c, uint8_t *public_key, IP_Port ip_port)
{
    uint32_t i;
    int id_existing = getcryptconnection_id(c, public_key);

    if (id_existing != -1) {
        IP_Port c_ip = connection_ip(c->lossless_udp, c->crypto_connections[id_existing].number);

        if (ipport_equal(&c_ip, &ip_port))
            return -1;
    }

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == -1
            || c->crypto_connections == NULL)
        return -1;

    memset(&(c->crypto_connections[c->crypto_connections_length]), 0, sizeof(Crypto_Connection));
    c->crypto_connections[c->crypto_connections_length].number = ~0;

    for (i = 0; i <= c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION) {
            int id_new = new_connection(c->lossless_udp, ip_port);

            if (id_new == -1)
                return -1;

            c->crypto_connections[i].number = id_new;
            c->crypto_connections[i].status = CRYPTO_CONN_HANDSHAKE_SENT;
            random_nonce(c->crypto_connections[i].recv_nonce);
            memcpy(c->crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);
            crypto_box_keypair(c->crypto_connections[i].sessionpublic_key, c->crypto_connections[i].sessionsecret_key);
            c->crypto_connections[i].timeout = unix_time() + CRYPTO_HANDSHAKE_TIMEOUT;

            if (c->crypto_connections_length == i)
                ++c->crypto_connections_length;

            if (send_cryptohandshake(c, id_new, public_key,  c->crypto_connections[i].recv_nonce,
                                     c->crypto_connections[i].sessionpublic_key) == 1) {
                increment_nonce(c->crypto_connections[i].recv_nonce);
                return i;
            }

            return -1; /* This should never happen. */
        }
    }

    return -1;
}

/* Handle an incoming connection.
 *
 *  return -1 if no crypto inbound connection.
 *  return incoming connection id (Lossless_UDP one) if there is an incoming crypto connection.
 *
 * Put the public key of the peer in public_key, the secret_nonce from the handshake into secret_nonce
 * and the session public key for the connection in session_key.
 * to accept it see: accept_crypto_inbound(...).
 * to refuse it just call kill_connection(...) on the connection id.
 */
int crypto_inbound(Net_Crypto *c, uint8_t *public_key, uint8_t *secret_nonce, uint8_t *session_key)
{
    while (1) {
        int incoming_con = incoming_connection(c->lossless_udp, 1);

        if (incoming_con != -1) {
            if (is_connected(c->lossless_udp, incoming_con) == LUDP_TIMED_OUT) {
                kill_connection(c->lossless_udp, incoming_con);
                continue;
            }

            if (id_packet(c->lossless_udp, incoming_con) == 2) {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint16_t len = read_packet_silent(c->lossless_udp, incoming_con, temp_data);

                if (handle_cryptohandshake(c, public_key, secret_nonce, session_key, temp_data, len)) {
                    return incoming_con;
                } else {
                    kill_connection(c->lossless_udp, incoming_con);
                }
            } else {
                kill_connection(c->lossless_udp, incoming_con);
            }
        } else {
            break;
        }
    }

    return -1;
}

/* Kill a crypto connection.
 *
 *  return 0 if killed successfully.
 *  return 1 if there was a problem.
 */
int crypto_kill(Net_Crypto *c, int crypt_connection_id)
{
    if (crypt_connection_id_not_valid(c, crypt_connection_id))
        return 1;

    if (c->crypto_connections[crypt_connection_id].status != CRYPTO_CONN_NO_CONNECTION) {
        c->crypto_connections[crypt_connection_id].status = CRYPTO_CONN_NO_CONNECTION;
        kill_connection(c->lossless_udp, c->crypto_connections[crypt_connection_id].number);
        memset(&(c->crypto_connections[crypt_connection_id]), 0 , sizeof(Crypto_Connection));
        c->crypto_connections[crypt_connection_id].number = ~0;
        uint32_t i;

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

    return 1;
}

/* Accept an incoming connection using the parameters provided by crypto_inbound.
 *
 *  return -1 if not successful.
 *  return the crypt_connection_id if successful.
 */
int accept_crypto_inbound(Net_Crypto *c, int connection_id, uint8_t *public_key, uint8_t *secret_nonce,
                          uint8_t *session_key)
{
    uint32_t i;

    if (discard_packet(c->lossless_udp, connection_id) == -1)
        return -1;

    /*
     * if(getcryptconnection_id(public_key) != -1)
     * {
     *     return -1;
     * }
     */

    if (realloc_cryptoconnection(c, c->crypto_connections_length + 1) == -1
            || c->crypto_connections == NULL)
        return -1;

    memset(&(c->crypto_connections[c->crypto_connections_length]), 0, sizeof(Crypto_Connection));
    c->crypto_connections[c->crypto_connections_length].number = ~0;

    for (i = 0; i <= c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION) {
            c->crypto_connections[i].number = connection_id;
            c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED;
            c->crypto_connections[i].timeout = unix_time() + CRYPTO_HANDSHAKE_TIMEOUT;
            random_nonce(c->crypto_connections[i].recv_nonce);
            memcpy(c->crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
            memcpy(c->crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
            increment_nonce(c->crypto_connections[i].sent_nonce);
            memcpy(c->crypto_connections[i].public_key, public_key, crypto_box_PUBLICKEYBYTES);

            crypto_box_keypair(c->crypto_connections[i].sessionpublic_key, c->crypto_connections[i].sessionsecret_key);

            if (c->crypto_connections_length == i)
                ++c->crypto_connections_length;

            if (send_cryptohandshake(c, connection_id, public_key, c->crypto_connections[i].recv_nonce,
                                     c->crypto_connections[i].sessionpublic_key) == 1) {
                increment_nonce(c->crypto_connections[i].recv_nonce);
                uint32_t zero = 0;
                encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                   c->crypto_connections[i].sessionsecret_key,
                                   c->crypto_connections[i].shared_key);
                c->crypto_connections[i].status =
                    CRYPTO_CONN_ESTABLISHED; /* Connection status needs to be 3 for write_cryptpacket() to work. */
                write_cryptpacket(c, i, ((uint8_t *)&zero), sizeof(zero));
                c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED; /* Set it to its proper value right after. */
                return i;
            }

            return -1; /* This should never happen. */
        }
    }

    return -1;
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

/* Handle received packets for not yet established crypto connections. */
static void receive_crypto(Net_Crypto *c)
{
    uint32_t i;
    uint64_t temp_time = unix_time();

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status == CRYPTO_CONN_NO_CONNECTION)
            continue;

        if (c->crypto_connections[i].status == CRYPTO_CONN_HANDSHAKE_SENT) {
            uint8_t temp_data[MAX_DATA_SIZE];
            uint8_t secret_nonce[crypto_box_NONCEBYTES];
            uint8_t public_key[crypto_box_PUBLICKEYBYTES];
            uint8_t session_key[crypto_box_PUBLICKEYBYTES];
            uint16_t len;

            if (id_packet(c->lossless_udp, c->crypto_connections[i].number) == 2) { /* Handle handshake packet. */
                len = read_packet(c->lossless_udp, c->crypto_connections[i].number, temp_data);

                if (handle_cryptohandshake(c, public_key, secret_nonce, session_key, temp_data, len)) {
                    if (memcmp(public_key, c->crypto_connections[i].public_key, crypto_box_PUBLICKEYBYTES) == 0) {
                        memcpy(c->crypto_connections[i].sent_nonce, secret_nonce, crypto_box_NONCEBYTES);
                        memcpy(c->crypto_connections[i].peersessionpublic_key, session_key, crypto_box_PUBLICKEYBYTES);
                        increment_nonce(c->crypto_connections[i].sent_nonce);
                        uint32_t zero = 0;
                        encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                           c->crypto_connections[i].sessionsecret_key,
                                           c->crypto_connections[i].shared_key);
                        c->crypto_connections[i].status =
                            CRYPTO_CONN_ESTABLISHED; /* Connection status needs to be 3 for write_cryptpacket() to work. */
                        write_cryptpacket(c, i, ((uint8_t *)&zero), sizeof(zero));
                        c->crypto_connections[i].status = CRYPTO_CONN_NOT_CONFIRMED; /* Set it to its proper value right after. */
                    } else {
                        /* This should not happen, timeout the connection if it does. */
                        c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                    }
                } else {
                    /* This should not happen, timeout the connection if it does. */
                    c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                }
            } else if (id_packet(c->lossless_udp,
                                 c->crypto_connections[i].number) != (uint8_t)~0) {
                /* This should not happen, timeout the connection if it does. */
                c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
            }
        }

        if (c->crypto_connections[i].status == CRYPTO_CONN_NOT_CONFIRMED) {
            if (id_packet(c->lossless_udp, c->crypto_connections[i].number) == 3) {
                uint8_t temp_data[MAX_DATA_SIZE];
                uint8_t data[MAX_DATA_SIZE];
                int length = read_packet(c->lossless_udp, c->crypto_connections[i].number, temp_data);
                int len = decrypt_data(c->crypto_connections[i].peersessionpublic_key,
                                       c->crypto_connections[i].sessionsecret_key,
                                       c->crypto_connections[i].recv_nonce, temp_data + 1, length - 1, data);
                uint32_t zero = 0;

                if (len == sizeof(uint32_t) && memcmp(((uint8_t *)&zero), data, sizeof(uint32_t)) == 0) {
                    increment_nonce(c->crypto_connections[i].recv_nonce);
                    encrypt_precompute(c->crypto_connections[i].peersessionpublic_key,
                                       c->crypto_connections[i].sessionsecret_key,
                                       c->crypto_connections[i].shared_key);
                    c->crypto_connections[i].status = CRYPTO_CONN_ESTABLISHED;
                    c->crypto_connections[i].timeout = ~0;
                    /* Connection is accepted. */
                    confirm_connection(c->lossless_udp, c->crypto_connections[i].number);
                } else {
                    /* This should not happen, timeout the connection if it does. */
                    c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
                }
            } else if (id_packet(c->lossless_udp, c->crypto_connections[i].number) != (uint8_t)~0) {
                /* This should not happen, timeout the connection if it does. */
                c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
            }
        }

        if (temp_time > c->crypto_connections[i].timeout) {
            c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
        }
    }
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
    temp->lossless_udp = new_lossless_udp(dht->net);

    if (temp->lossless_udp == NULL) {
        free(temp);
        return NULL;
    }

    new_keys(temp);
    new_symmetric_key(temp->secret_symmetric_key);

    networking_registerhandler(dht->net, NET_PACKET_COOKIE_REQUEST, &udp_handle_cookie_request, temp);
    return temp;
}

static void kill_timedout(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        if (c->crypto_connections[i].status != CRYPTO_CONN_NO_CONNECTION
                && is_connected(c->lossless_udp, c->crypto_connections[i].number) == LUDP_TIMED_OUT)
            c->crypto_connections[i].status = CRYPTO_CONN_TIMED_OUT;
    }
}

/* Main loop. */
void do_net_crypto(Net_Crypto *c)
{
    unix_time_update();
    do_lossless_udp(c->lossless_udp);
    kill_timedout(c);
    receive_crypto(c);
}

void kill_net_crypto(Net_Crypto *c)
{
    uint32_t i;

    for (i = 0; i < c->crypto_connections_length; ++i) {
        crypto_kill(c, i);
    }

    kill_lossless_udp(c->lossless_udp);
    memset(c, 0, sizeof(Net_Crypto));
    free(c);
}
