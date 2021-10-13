#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/TCP_client.h"
#include "../toxcore/TCP_server.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#define NUM_PORTS 3

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

#if !USE_IPV6
#define net_family_ipv6 net_family_ipv4
#endif

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6;
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4;
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

static void do_TCP_server_delay(TCP_Server *tcp_s, Mono_Time *mono_time, int delay)
{
    c_sleep(delay);
    mono_time_update(mono_time);
    do_TCP_server(tcp_s, mono_time);
    c_sleep(delay);
}
static uint16_t ports[NUM_PORTS] = {13215, 33445, 25643};

START_TEST(test_basic)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    // Attempt to create a new TCP_Server instance.
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(logger, USE_IPV6, NUM_PORTS, ports, self_secret_key, nullptr);
    ck_assert_msg(tcp_s != nullptr, "Failed to create a TCP relay server.");
    ck_assert_msg(tcp_server_listen_count(tcp_s) == NUM_PORTS,
                  "Failed to bind a TCP relay server to all %d attempted ports.", NUM_PORTS);

    Socket sock = {0};

    // Check all opened ports for connectivity.
    for (uint8_t i = 0; i < NUM_PORTS; i++) {
        sock = net_socket(net_family_ipv6, TOX_SOCK_STREAM, TOX_PROTO_TCP);
        IP_Port ip_port_loopback;
        ip_port_loopback.ip = get_loopback();
        ip_port_loopback.port = net_htons(ports[i]);
        int ret = net_connect(sock, ip_port_loopback);
        ck_assert_msg(ret == 0, "Failed to connect to created TCP relay server on port %d.", ports[i]);

        // Leave open one connection for the next test.
        if (i + 1 < NUM_PORTS) {
            kill_sock(sock);
        }
    }

    // Key creation.
    uint8_t f_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t f_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t f_nonce[CRYPTO_NONCE_SIZE];
    crypto_new_keypair(f_public_key, f_secret_key);
    random_nonce(f_nonce);

    // Generation of the initial handshake.
    uint8_t t_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t handshake_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_new_keypair(handshake_plain, t_secret_key);
    memcpy(handshake_plain + CRYPTO_PUBLIC_KEY_SIZE, f_nonce, CRYPTO_NONCE_SIZE);
    uint8_t handshake[TCP_CLIENT_HANDSHAKE_SIZE];
    memcpy(handshake, f_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    random_nonce(handshake + CRYPTO_PUBLIC_KEY_SIZE);

    // Encrypting handshake
    int ret = encrypt_data(self_public_key, f_secret_key, handshake + CRYPTO_PUBLIC_KEY_SIZE, handshake_plain,
                           TCP_HANDSHAKE_PLAIN_SIZE, handshake + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);
    ck_assert_msg(ret == TCP_CLIENT_HANDSHAKE_SIZE - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE),
                  "encrypt_data() call failed.");

    // Sending the handshake
    ck_assert_msg(net_send(sock, handshake, TCP_CLIENT_HANDSHAKE_SIZE - 1) == TCP_CLIENT_HANDSHAKE_SIZE - 1,
                  "An attempt to send the initial handshake minus last byte failed.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    ck_assert_msg(net_send(sock, handshake + (TCP_CLIENT_HANDSHAKE_SIZE - 1), 1) == 1,
                  "The attempt to send the last byte of handshake failed.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    // Receiving server response and decrypting it
    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    uint8_t response_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    ck_assert_msg(net_recv(sock, response, TCP_SERVER_HANDSHAKE_SIZE) == TCP_SERVER_HANDSHAKE_SIZE,
                  "Could/did not receive a server response to the initial handshake.");
    ret = decrypt_data(self_public_key, f_secret_key, response, response + CRYPTO_NONCE_SIZE,
                       TCP_SERVER_HANDSHAKE_SIZE - CRYPTO_NONCE_SIZE, response_plain);
    ck_assert_msg(ret == TCP_HANDSHAKE_PLAIN_SIZE, "Failed to decrypt handshake response.");
    uint8_t f_nonce_r[CRYPTO_NONCE_SIZE];
    uint8_t f_shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(response_plain, t_secret_key, f_shared_key);
    memcpy(f_nonce_r, response_plain + CRYPTO_SHARED_KEY_SIZE, CRYPTO_NONCE_SIZE);

    // Building a request
    uint8_t r_req_p[1 + CRYPTO_PUBLIC_KEY_SIZE];
    r_req_p[0] = TCP_PACKET_ROUTING_REQUEST;
    memcpy(r_req_p + 1, f_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t r_req[2 + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE];
    uint16_t size = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE;
    size = net_htons(size);
    encrypt_data_symmetric(f_shared_key, f_nonce, r_req_p, 1 + CRYPTO_PUBLIC_KEY_SIZE, r_req + 2);
    increment_nonce(f_nonce);
    memcpy(r_req, &size, 2);

    // Sending the request at random intervals in random pieces.
    for (uint32_t i = 0; i < sizeof(r_req);) {
        uint8_t msg_length = rand() % 5 + 1; // msg_length = 1 to 5

        if (i + msg_length >= sizeof(r_req)) {
            msg_length = sizeof(r_req) - i;
        }

        ck_assert_msg(net_send(sock, r_req + i, msg_length) == msg_length,
                      "Failed to send request after completing the handshake.");
        i += msg_length;

        c_sleep(50);
        mono_time_update(mono_time);
        do_TCP_server(tcp_s, mono_time);
    }

    // Receiving the second response and verifying its validity
    uint8_t packet_resp[4096];
    int recv_data_len = net_recv(sock, packet_resp, 2 + 2 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);
    ck_assert_msg(recv_data_len == 2 + 2 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE,
                  "Failed to receive server response to request. %u", recv_data_len);
    memcpy(&size, packet_resp, 2);
    ck_assert_msg(net_ntohs(size) == 2 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE,
                  "Wrong packet size for request response.");

    uint8_t packet_resp_plain[4096];
    ret = decrypt_data_symmetric(f_shared_key, f_nonce_r, packet_resp + 2, recv_data_len - 2, packet_resp_plain);
    ck_assert_msg(ret != -1, "Failed to decrypt the TCP server's response.");
    increment_nonce(f_nonce_r);

    ck_assert_msg(packet_resp_plain[0] == TCP_PACKET_ROUTING_RESPONSE, "Server sent the wrong packet id: %u",
                  packet_resp_plain[0]);
    ck_assert_msg(packet_resp_plain[1] == 0, "Server did not refuse the connection.");
    ck_assert_msg(public_key_cmp(packet_resp_plain + 2, f_public_key) == 0, "Server sent the wrong public key.");

    // Closing connections.
    kill_sock(sock);
    kill_TCP_server(tcp_s);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

struct sec_TCP_con {
    Socket sock;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE];
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE];
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
};

static struct sec_TCP_con *new_TCP_con(TCP_Server *tcp_s, Mono_Time *mono_time)
{
    struct sec_TCP_con *sec_c = (struct sec_TCP_con *)malloc(sizeof(struct sec_TCP_con));
    ck_assert(sec_c != nullptr);
    Socket sock = net_socket(net_family_ipv6, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    IP_Port ip_port_loopback;
    ip_port_loopback.ip = get_loopback();
    ip_port_loopback.port = net_htons(ports[random_u32() % NUM_PORTS]);

    int ret = net_connect(sock, ip_port_loopback);
    ck_assert_msg(ret == 0, "Failed to connect to the test TCP relay server.");

    uint8_t f_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(sec_c->public_key, f_secret_key);
    random_nonce(sec_c->sent_nonce);

    uint8_t t_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t handshake_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_new_keypair(handshake_plain, t_secret_key);
    memcpy(handshake_plain + CRYPTO_PUBLIC_KEY_SIZE, sec_c->sent_nonce, CRYPTO_NONCE_SIZE);
    uint8_t handshake[TCP_CLIENT_HANDSHAKE_SIZE];
    memcpy(handshake, sec_c->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    random_nonce(handshake + CRYPTO_PUBLIC_KEY_SIZE);

    ret = encrypt_data(tcp_server_public_key(tcp_s), f_secret_key, handshake + CRYPTO_PUBLIC_KEY_SIZE, handshake_plain,
                       TCP_HANDSHAKE_PLAIN_SIZE, handshake + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE);
    ck_assert_msg(ret == TCP_CLIENT_HANDSHAKE_SIZE - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE),
                  "Failed to encrypt the outgoing handshake.");

    ck_assert_msg(net_send(sock, handshake, TCP_CLIENT_HANDSHAKE_SIZE - 1) == TCP_CLIENT_HANDSHAKE_SIZE - 1,
                  "Failed to send the first portion of the handshake to the TCP relay server.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    ck_assert_msg(net_send(sock, handshake + (TCP_CLIENT_HANDSHAKE_SIZE - 1), 1) == 1,
                  "Failed to send last byte of handshake.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    uint8_t response_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    ck_assert_msg(net_recv(sock, response, TCP_SERVER_HANDSHAKE_SIZE) == TCP_SERVER_HANDSHAKE_SIZE,
                  "Failed to receive server handshake response.");
    ret = decrypt_data(tcp_server_public_key(tcp_s), f_secret_key, response, response + CRYPTO_NONCE_SIZE,
                       TCP_SERVER_HANDSHAKE_SIZE - CRYPTO_NONCE_SIZE, response_plain);
    ck_assert_msg(ret == TCP_HANDSHAKE_PLAIN_SIZE, "Failed to decrypt server handshake response.");
    encrypt_precompute(response_plain, t_secret_key, sec_c->shared_key);
    memcpy(sec_c->recv_nonce, response_plain + CRYPTO_SHARED_KEY_SIZE, CRYPTO_NONCE_SIZE);
    sec_c->sock = sock;
    return sec_c;
}

static void kill_TCP_con(struct sec_TCP_con *con)
{
    kill_sock(con->sock);
    free(con);
}

static int write_packet_TCP_secure_connection(struct sec_TCP_con *con, uint8_t *data, uint16_t length)
{
    VLA(uint8_t, packet, sizeof(uint16_t) + length + CRYPTO_MAC_SIZE);

    uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (SIZEOF_VLA(packet) - sizeof(uint16_t))) {
        return -1;
    }

    increment_nonce(con->sent_nonce);

    ck_assert_msg(net_send(con->sock, packet, SIZEOF_VLA(packet)) == SIZEOF_VLA(packet), "Failed to send a packet.");
    return 0;
}

static int read_packet_sec_TCP(struct sec_TCP_con *con, uint8_t *data, uint16_t length)
{
    int rlen = net_recv(con->sock, data, length);
    ck_assert_msg(rlen == length, "Did not receive packet of correct length. Wanted %i, instead got %i", length, rlen);
    rlen = decrypt_data_symmetric(con->shared_key, con->recv_nonce, data + 2, length - 2, data);
    ck_assert_msg(rlen != -1, "Failed to decrypt a received packet from the Relay server.");
    increment_nonce(con->recv_nonce);
    return rlen;
}

START_TEST(test_some)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(logger, USE_IPV6, NUM_PORTS, ports, self_secret_key, nullptr);
    ck_assert_msg(tcp_s != nullptr, "Failed to create TCP relay server");
    ck_assert_msg(tcp_server_listen_count(tcp_s) == NUM_PORTS, "Failed to bind to all ports.");

    struct sec_TCP_con *con1 = new_TCP_con(tcp_s, mono_time);
    struct sec_TCP_con *con2 = new_TCP_con(tcp_s, mono_time);
    struct sec_TCP_con *con3 = new_TCP_con(tcp_s, mono_time);

    uint8_t requ_p[1 + CRYPTO_PUBLIC_KEY_SIZE];
    requ_p[0] = TCP_PACKET_ROUTING_REQUEST;

    // Sending wrong public keys to test server response.
    memcpy(requ_p + 1, con3->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    write_packet_TCP_secure_connection(con1, requ_p, sizeof(requ_p));
    memcpy(requ_p + 1, con1->public_key, CRYPTO_PUBLIC_KEY_SIZE);
    write_packet_TCP_secure_connection(con3, requ_p, sizeof(requ_p));

    do_TCP_server_delay(tcp_s, mono_time, 50);

    // Testing response from connection 1
    uint8_t data[2048];
    int len = read_packet_sec_TCP(con1, data, 2 + 1 + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == 1 + 1 + CRYPTO_PUBLIC_KEY_SIZE, "Wrong response packet length of %d.", len);
    ck_assert_msg(data[0] == TCP_PACKET_ROUTING_RESPONSE, "Wrong response packet id of %d.", data[0]);
    ck_assert_msg(data[1] == 16, "Server didn't refuse connection using wrong public key.");
    ck_assert_msg(public_key_cmp(data + 2, con3->public_key) == 0, "Key in response packet wrong.");

    // Connection 3
    len = read_packet_sec_TCP(con3, data, 2 + 1 + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == 1 + 1 + CRYPTO_PUBLIC_KEY_SIZE, "Wrong response packet length of %d.", len);
    ck_assert_msg(data[0] == TCP_PACKET_ROUTING_RESPONSE, "Wrong response packet id of %d.", data[0]);
    ck_assert_msg(data[1] == 16, "Server didn't refuse connection using wrong public key.");
    ck_assert_msg(public_key_cmp(data + 2, con1->public_key) == 0, "Key in response packet wrong.");

    uint8_t test_packet[512] = {16, 17, 16, 86, 99, 127, 255, 189, 78}; // What is this packet????

    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));

    do_TCP_server_delay(tcp_s, mono_time, 50);

    len = read_packet_sec_TCP(con1, data, 2 + 2 + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == 2, "wrong len %d", len);
    ck_assert_msg(data[0] == TCP_PACKET_CONNECTION_NOTIFICATION, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "wrong peer id %u", data[1]);
    len = read_packet_sec_TCP(con3, data, 2 + 2 + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == 2, "wrong len %d", len);
    ck_assert_msg(data[0] == TCP_PACKET_CONNECTION_NOTIFICATION, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "wrong peer id %u", data[1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    do_TCP_server_delay(tcp_s, mono_time, 50);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %d", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);

    uint8_t ping_packet[1 + sizeof(uint64_t)] = {TCP_PACKET_PING, 8, 6, 9, 67};
    write_packet_TCP_secure_connection(con1, ping_packet, sizeof(ping_packet));

    do_TCP_server_delay(tcp_s, mono_time, 50);

    len = read_packet_sec_TCP(con1, data, 2 + sizeof(ping_packet) + CRYPTO_MAC_SIZE);
    ck_assert_msg(len == sizeof(ping_packet), "wrong len %d", len);
    ck_assert_msg(data[0] == TCP_PACKET_PONG, "wrong packet id %u", data[0]);
    ck_assert_msg(memcmp(ping_packet + 1, data + 1, sizeof(uint64_t)) == 0, "wrong packet data");

    // Kill off the connections
    kill_TCP_server(tcp_s);
    kill_TCP_con(con1);
    kill_TCP_con(con2);
    kill_TCP_con(con3);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

static int response_callback_good;
static uint8_t response_callback_connection_id;
static uint8_t response_callback_public_key[CRYPTO_PUBLIC_KEY_SIZE];
static int response_callback(void *object, uint8_t connection_id, const uint8_t *public_key)
{
    if (set_tcp_connection_number((TCP_Client_Connection *)((char *)object - 2), connection_id, 7) != 0) {
        return 1;
    }

    response_callback_connection_id = connection_id;
    memcpy(response_callback_public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    response_callback_good++;
    return 0;
}
static int status_callback_good;
static uint8_t status_callback_connection_id;
static uint8_t status_callback_status;
static int status_callback(void *object, uint32_t number, uint8_t connection_id, uint8_t status)
{
    if (object != (void *)2) {
        return 1;
    }

    if (number != 7) {
        return 1;
    }

    status_callback_connection_id = connection_id;
    status_callback_status = status;
    status_callback_good++;
    return 0;
}
static int data_callback_good;
static int data_callback(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length,
                         void *userdata)
{
    if (object != (void *)3) {
        return 1;
    }

    if (number != 7) {
        return 1;
    }

    if (length != 5) {
        return 1;
    }

    if (data[0] == 1 && data[1] == 2 && data[2] == 3 && data[3] == 4 && data[4] == 5) {
        data_callback_good++;
        return 0;
    }

    return 1;
}

static int oob_data_callback_good;
static uint8_t oob_pubkey[CRYPTO_PUBLIC_KEY_SIZE];
static int oob_data_callback(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length,
                             void *userdata)
{
    if (object != (void *)4) {
        return 1;
    }

    if (length != 5) {
        return 1;
    }

    if (public_key_cmp(public_key, oob_pubkey) != 0) {
        return 1;
    }

    if (data[0] == 1 && data[1] == 2 && data[2] == 3 && data[3] == 4 && data[4] == 5) {
        oob_data_callback_good++;
        return 0;
    }

    return 1;
}

START_TEST(test_client)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(logger, USE_IPV6, NUM_PORTS, ports, self_secret_key, nullptr);
    ck_assert_msg(tcp_s != nullptr, "Failed to create a TCP relay server.");
    ck_assert_msg(tcp_server_listen_count(tcp_s) == NUM_PORTS, "Failed to bind the relay server to all ports.");

    uint8_t f_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t f_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(f_public_key, f_secret_key);
    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    ip_port_tcp_s.ip = get_loopback();

    TCP_Client_Connection *conn = new_TCP_connection(mono_time, ip_port_tcp_s, self_public_key, f_public_key, f_secret_key,
                                  nullptr);
    do_TCP_connection(logger, mono_time, conn, nullptr);
    c_sleep(50);

    // The connection status should be unconfirmed here because we have finished
    // sending our data and are awaiting a response.
    ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_UNCONFIRMED, "Wrong connection status. Expected: %d, is: %d.",
                  TCP_CLIENT_UNCONFIRMED, tcp_con_status(conn));

    do_TCP_server_delay(tcp_s, mono_time, 50); // Now let the server handle requests...

    const uint8_t LOOP_SIZE = 3;

    for (uint8_t i = 0; i < LOOP_SIZE; i++) {
        mono_time_update(mono_time);
        do_TCP_connection(logger, mono_time, conn, nullptr); // Run the connection loop.

        // The status of the connection should continue to be TCP_CLIENT_CONFIRMED after multiple subsequent do_TCP_connection() calls.
        ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_CONFIRMED, "Wrong connection status. Expected: %d, is: %d",
                      TCP_CLIENT_CONFIRMED, tcp_con_status(conn));

        c_sleep(i == LOOP_SIZE - 1 ? 0 : 500); // Sleep for 500ms on all except third loop.
    }

    do_TCP_server_delay(tcp_s, mono_time, 50);

    // And still after the server runs again.
    ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_CONFIRMED, "Wrong status. Expected: %d, is: %d", TCP_CLIENT_CONFIRMED,
                  tcp_con_status(conn));

    uint8_t f2_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t f2_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(f2_public_key, f2_secret_key);
    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    TCP_Client_Connection *conn2 = new_TCP_connection(mono_time, ip_port_tcp_s, self_public_key, f2_public_key,
                                   f2_secret_key, nullptr);

    // The client should call this function (defined earlier) during the routing process.
    routing_response_handler(conn, response_callback, (char *)conn + 2);
    // The client should call this function when it receives a connection notification.
    routing_status_handler(conn, status_callback, (void *)2);
    // The client should call this function when
    routing_data_handler(conn, data_callback, (void *)3);
    // The client should call this function when sending out of band packets.
    oob_data_handler(conn, oob_data_callback, (void *)4);

    // These integers will increment per successful callback.
    oob_data_callback_good = response_callback_good = status_callback_good = data_callback_good = 0;

    do_TCP_connection(logger, mono_time, conn, nullptr);
    do_TCP_connection(logger, mono_time, conn2, nullptr);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_TCP_connection(logger, mono_time, conn, nullptr);
    do_TCP_connection(logger, mono_time, conn2, nullptr);
    c_sleep(50);

    uint8_t data[5] = {1, 2, 3, 4, 5};
    memcpy(oob_pubkey, f2_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    send_oob_packet(conn2, f_public_key, data, 5);
    send_routing_request(conn, f2_public_key);
    send_routing_request(conn2, f_public_key);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_TCP_connection(logger, mono_time, conn, nullptr);
    do_TCP_connection(logger, mono_time, conn2, nullptr);

    // All callback methods save data should have run during the above network prodding.
    ck_assert_msg(oob_data_callback_good == 1, "OOB callback not called");
    ck_assert_msg(response_callback_good == 1, "Response callback not called.");
    ck_assert_msg(public_key_cmp(response_callback_public_key, f2_public_key) == 0, "Wrong public key.");
    ck_assert_msg(status_callback_good == 1, "Status callback not called.");
    ck_assert_msg(status_callback_status == 2, "Wrong status callback status.");
    ck_assert_msg(status_callback_connection_id == response_callback_connection_id,
                  "Status and response callback connection IDs are not equal.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    ck_assert_msg(send_data(conn2, 0, data, 5) == 1, "Failed a send_data() call.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_TCP_connection(logger, mono_time, conn, nullptr);
    do_TCP_connection(logger, mono_time, conn2, nullptr);
    ck_assert_msg(data_callback_good == 1, "Data callback was not called.");
    status_callback_good = 0;
    send_disconnect_request(conn2, 0);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_TCP_connection(logger, mono_time, conn, nullptr);
    do_TCP_connection(logger, mono_time, conn2, nullptr);
    ck_assert_msg(status_callback_good == 1, "Status callback not called");
    ck_assert_msg(status_callback_status == 1, "Wrong status callback status.");

    // Kill off all connections and servers.
    kill_TCP_server(tcp_s);
    kill_TCP_connection(conn);
    kill_TCP_connection(conn2);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

// Test how the client handles servers that don't respond.
START_TEST(test_client_invalid)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);

    uint8_t f_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t f_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(f_public_key, f_secret_key);
    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    ip_port_tcp_s.ip = get_loopback();
    TCP_Client_Connection *conn = new_TCP_connection(mono_time, ip_port_tcp_s, self_public_key, f_public_key, f_secret_key,
                                  nullptr);

    // Run the client's main loop but not the server.
    mono_time_update(mono_time);
    do_TCP_connection(logger, mono_time, conn, nullptr);
    c_sleep(50);

    // After 50ms of no response...
    ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_CONNECTING, "Wrong status. Expected: %d, is: %d.",
                  TCP_CLIENT_CONNECTING, tcp_con_status(conn));
    // After 5s...
    c_sleep(5000);
    mono_time_update(mono_time);
    do_TCP_connection(logger, mono_time, conn, nullptr);
    ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_CONNECTING, "Wrong status. Expected: %d, is: %d.",
                  TCP_CLIENT_CONNECTING, tcp_con_status(conn));
    // 11s... (Should wait for 10 before giving up.)
    c_sleep(6000);
    mono_time_update(mono_time);
    do_TCP_connection(logger, mono_time, conn, nullptr);
    ck_assert_msg(tcp_con_status(conn) == TCP_CLIENT_DISCONNECTED, "Wrong status. Expected: %d, is: %d.",
                  TCP_CLIENT_DISCONNECTED, tcp_con_status(conn));

    kill_TCP_connection(conn);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

#include "../toxcore/TCP_connection.h"

static bool tcp_data_callback_called;
static int tcp_data_callback(void *object, int id, const uint8_t *data, uint16_t length, void *userdata)
{
    if (object != (void *)120397) {
        return -1;
    }

    if (id != 123) {
        return -1;
    }

    if (length != 6) {
        return -1;
    }

    if (memcmp(data, "Gentoo", length) != 0) {
        return -1;
    }

    tcp_data_callback_called = 1;
    return 0;
}


START_TEST(test_tcp_connection)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    tcp_data_callback_called = 0;
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(logger, USE_IPV6, NUM_PORTS, ports, self_secret_key, nullptr);
    ck_assert_msg(public_key_cmp(tcp_server_public_key(tcp_s), self_public_key) == 0, "Wrong public key");

    TCP_Proxy_Info proxy_info;
    proxy_info.proxy_type = TCP_PROXY_NONE;
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Connections *tc_1 = new_tcp_connections(mono_time, self_secret_key, &proxy_info);
    ck_assert_msg(public_key_cmp(tcp_connections_public_key(tc_1), self_public_key) == 0, "Wrong public key");

    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Connections *tc_2 = new_tcp_connections(mono_time, self_secret_key, &proxy_info);
    ck_assert_msg(public_key_cmp(tcp_connections_public_key(tc_2), self_public_key) == 0, "Wrong public key");

    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    ip_port_tcp_s.ip = get_loopback();

    int connection = new_tcp_connection_to(tc_1, tcp_connections_public_key(tc_2), 123);
    ck_assert_msg(connection == 0, "Connection id wrong");
    ck_assert_msg(add_tcp_relay_connection(tc_1, connection, ip_port_tcp_s, tcp_server_public_key(tcp_s)) == 0,
                  "Could not add tcp relay to connection\n");

    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    connection = new_tcp_connection_to(tc_2, tcp_connections_public_key(tc_1), 123);
    ck_assert_msg(connection == 0, "Connection id wrong");
    ck_assert_msg(add_tcp_relay_connection(tc_2, connection, ip_port_tcp_s, tcp_server_public_key(tcp_s)) == 0,
                  "Could not add tcp relay to connection\n");

    ck_assert_msg(new_tcp_connection_to(tc_2, tcp_connections_public_key(tc_1), 123) == -1,
                  "Managed to read same connection\n");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    int ret = send_packet_tcp_connection(tc_1, 0, (const uint8_t *)"Gentoo", 6);
    ck_assert_msg(ret == 0, "could not send packet.");
    set_packet_tcp_connection_callback(tc_2, &tcp_data_callback, (void *) 120397);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    ck_assert_msg(tcp_data_callback_called, "could not recv packet.");
    ck_assert_msg(tcp_connection_to_online_tcp_relays(tc_1, 0) == 1, "Wrong number of connected relays");
    ck_assert_msg(kill_tcp_connection_to(tc_1, 0) == 0, "could not kill connection to\n");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    ck_assert_msg(send_packet_tcp_connection(tc_1, 0, (const uint8_t *)"Gentoo", 6) == -1, "could send packet.");
    ck_assert_msg(kill_tcp_connection_to(tc_2, 0) == 0, "could not kill connection to\n");

    kill_TCP_server(tcp_s);
    kill_tcp_connections(tc_1);
    kill_tcp_connections(tc_2);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

static bool tcp_oobdata_callback_called;
static int tcp_oobdata_callback(void *object, const uint8_t *public_key, unsigned int id, const uint8_t *data,
                                uint16_t length, void *userdata)
{
    TCP_Connections *tcp_c = (TCP_Connections *)object;

    if (length != 6) {
        return -1;
    }

    if (memcmp(data, "Gentoo", length) != 0) {
        return -1;
    }

    if (tcp_send_oob_packet(tcp_c, id, public_key, data, length) == 0) {
        tcp_oobdata_callback_called = 1;
    }

    return 0;
}

START_TEST(test_tcp_connection2)
{
    Mono_Time *mono_time = mono_time_new();
    Logger *logger = logger_new();

    tcp_oobdata_callback_called = 0;
    tcp_data_callback_called = 0;

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(logger, USE_IPV6, NUM_PORTS, ports, self_secret_key, nullptr);
    ck_assert_msg(public_key_cmp(tcp_server_public_key(tcp_s), self_public_key) == 0, "Wrong public key");

    TCP_Proxy_Info proxy_info;
    proxy_info.proxy_type = TCP_PROXY_NONE;
    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Connections *tc_1 = new_tcp_connections(mono_time, self_secret_key, &proxy_info);
    ck_assert_msg(public_key_cmp(tcp_connections_public_key(tc_1), self_public_key) == 0, "Wrong public key");

    crypto_new_keypair(self_public_key, self_secret_key);
    TCP_Connections *tc_2 = new_tcp_connections(mono_time, self_secret_key, &proxy_info);
    ck_assert_msg(public_key_cmp(tcp_connections_public_key(tc_2), self_public_key) == 0, "Wrong public key");

    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = net_htons(ports[random_u32() % NUM_PORTS]);
    ip_port_tcp_s.ip = get_loopback();

    int connection = new_tcp_connection_to(tc_1, tcp_connections_public_key(tc_2), 123);
    ck_assert_msg(connection == 0, "Connection id wrong");
    ck_assert_msg(add_tcp_relay_connection(tc_1, connection, ip_port_tcp_s, tcp_server_public_key(tcp_s)) == 0,
                  "Could not add tcp relay to connection\n");

    ck_assert_msg(add_tcp_relay_global(tc_2, ip_port_tcp_s, tcp_server_public_key(tcp_s)) == 0,
                  "Could not add global relay");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    int ret = send_packet_tcp_connection(tc_1, 0, (const uint8_t *)"Gentoo", 6);
    ck_assert_msg(ret == 0, "could not send packet.");
    set_oob_packet_tcp_connection_callback(tc_2, &tcp_oobdata_callback, tc_2);
    set_packet_tcp_connection_callback(tc_1, &tcp_data_callback, (void *) 120397);

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    ck_assert_msg(tcp_oobdata_callback_called, "could not recv packet.");

    do_TCP_server_delay(tcp_s, mono_time, 50);

    do_tcp_connections(logger, tc_1, nullptr);
    do_tcp_connections(logger, tc_2, nullptr);

    ck_assert_msg(tcp_data_callback_called, "could not recv packet.");
    ck_assert_msg(kill_tcp_connection_to(tc_1, 0) == 0, "could not kill connection to\n");

    kill_TCP_server(tcp_s);
    kill_tcp_connections(tc_1);
    kill_tcp_connections(tc_2);

    logger_kill(logger);
    mono_time_free(mono_time);
}
END_TEST

static Suite *TCP_suite(void)
{
    Suite *s = suite_create("TCP");

    DEFTESTCASE_SLOW(basic, 5);
    DEFTESTCASE_SLOW(some, 10);
    DEFTESTCASE_SLOW(client, 10);
    DEFTESTCASE_SLOW(client_invalid, 15);
    DEFTESTCASE_SLOW(tcp_connection, 20);
    DEFTESTCASE_SLOW(tcp_connection2, 20);
    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Suite *TCP = TCP_suite();
    SRunner *test_runner = srunner_create(TCP);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
