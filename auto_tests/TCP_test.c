#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/TCP_server.h"
#include "../toxcore/TCP_client.h"

#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define NUM_PORTS 3

uint16_t ports[NUM_PORTS] = {1234, 33445, 25643};

START_TEST(test_basic)
{
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(1, NUM_PORTS, ports, self_public_key, self_secret_key, NULL);
    ck_assert_msg(tcp_s != NULL, "Failed to create TCP relay server");
    ck_assert_msg(tcp_s->num_listening_socks == NUM_PORTS, "Failed to bind to all ports");

    sock_t sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in6 addr6_loopback = {0};
    addr6_loopback.sin6_family = AF_INET6;
    addr6_loopback.sin6_port = htons(ports[rand() % NUM_PORTS]);
    addr6_loopback.sin6_addr = in6addr_loopback;

    int ret = connect(sock, (struct sockaddr *)&addr6_loopback, sizeof(addr6_loopback));
    ck_assert_msg(ret == 0, "Failed to connect to TCP relay server");

    uint8_t f_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t f_secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t f_nonce[crypto_box_NONCEBYTES];
    crypto_box_keypair(f_public_key, f_secret_key);
    random_nonce(f_nonce);

    uint8_t t_secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t handshake_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_box_keypair(handshake_plain, t_secret_key);
    memcpy(handshake_plain + crypto_box_PUBLICKEYBYTES, f_nonce, crypto_box_NONCEBYTES);
    uint8_t handshake[TCP_CLIENT_HANDSHAKE_SIZE];
    memcpy(handshake, f_public_key, crypto_box_PUBLICKEYBYTES);
    new_nonce(handshake + crypto_box_PUBLICKEYBYTES);

    ret = encrypt_data(self_public_key, f_secret_key, handshake + crypto_box_PUBLICKEYBYTES, handshake_plain,
                       TCP_HANDSHAKE_PLAIN_SIZE, handshake + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
    ck_assert_msg(ret == TCP_CLIENT_HANDSHAKE_SIZE - (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES),
                  "Encrypt failed.");
    ck_assert_msg(send(sock, handshake, TCP_CLIENT_HANDSHAKE_SIZE - 1, 0) == TCP_CLIENT_HANDSHAKE_SIZE - 1, "send Failed.");
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    ck_assert_msg(send(sock, handshake + (TCP_CLIENT_HANDSHAKE_SIZE - 1), 1, 0) == 1, "send Failed.");
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    uint8_t response_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    ck_assert_msg(recv(sock, response, TCP_SERVER_HANDSHAKE_SIZE, 0) == TCP_SERVER_HANDSHAKE_SIZE, "recv Failed.");
    ret = decrypt_data(self_public_key, f_secret_key, response, response + crypto_box_NONCEBYTES,
                       TCP_SERVER_HANDSHAKE_SIZE - crypto_box_NONCEBYTES, response_plain);
    ck_assert_msg(ret == TCP_HANDSHAKE_PLAIN_SIZE, "Decrypt Failed.");
    uint8_t f_nonce_r[crypto_box_NONCEBYTES];
    uint8_t f_shared_key[crypto_box_BEFORENMBYTES];
    encrypt_precompute(response_plain, t_secret_key, f_shared_key);
    memcpy(f_nonce_r, response_plain + crypto_box_BEFORENMBYTES, crypto_box_NONCEBYTES);

    uint8_t r_req_p[1 + crypto_box_PUBLICKEYBYTES] = {0};
    memcpy(r_req_p + 1, f_public_key, crypto_box_PUBLICKEYBYTES);
    uint8_t r_req[2 + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES];
    uint16_t size = 1 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES;
    size = htons(size);
    ret = encrypt_data_symmetric(f_shared_key, f_nonce, r_req_p, 1 + crypto_box_PUBLICKEYBYTES, r_req + 2);
    increment_nonce(f_nonce);
    memcpy(r_req, &size, 2);
    uint32_t i;

    for (i = 0; i < sizeof(r_req); ++i) {
        ck_assert_msg(send(sock, r_req + i, 1, 0) == 1, "send Failed.");
        //ck_assert_msg(send(sock, r_req, sizeof(r_req), 0) == sizeof(r_req), "send Failed.");
        do_TCP_server(tcp_s);
        c_sleep(50);
    }

    do_TCP_server(tcp_s);
    c_sleep(50);
    uint8_t packet_resp[4096];
    int recv_data_len;
    ck_assert_msg((recv_data_len = recv(sock, packet_resp, 2 + 2 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES,
                                        0)) == 2 + 2 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES, "recv Failed. %u", recv_data_len);
    memcpy(&size, packet_resp, 2);
    ck_assert_msg(ntohs(size) == 2 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES, "Wrong packet size.");
    uint8_t packet_resp_plain[4096];
    ret = decrypt_data_symmetric(f_shared_key, f_nonce_r, packet_resp + 2, recv_data_len - 2, packet_resp_plain);
    ck_assert_msg(ret != -1, "decryption failed");
    increment_nonce(f_nonce_r);
    ck_assert_msg(packet_resp_plain[0] == 1, "wrong packet id %u", packet_resp_plain[0]);
    ck_assert_msg(packet_resp_plain[1] == 0, "connection not refused %u", packet_resp_plain[1]);
    ck_assert_msg(memcmp(packet_resp_plain + 2, f_public_key, crypto_box_PUBLICKEYBYTES) == 0, "key in packet wrong");
}
END_TEST

struct sec_TCP_con {
    sock_t  sock;
    uint8_t public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t recv_nonce[crypto_box_NONCEBYTES];
    uint8_t sent_nonce[crypto_box_NONCEBYTES];
    uint8_t shared_key[crypto_box_BEFORENMBYTES];
};

struct sec_TCP_con *new_TCP_con(TCP_Server *tcp_s)
{
    struct sec_TCP_con *sec_c = malloc(sizeof(struct sec_TCP_con));
    sock_t sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in6 addr6_loopback = {0};
    addr6_loopback.sin6_family = AF_INET6;
    addr6_loopback.sin6_port = htons(ports[rand() % NUM_PORTS]);
    addr6_loopback.sin6_addr = in6addr_loopback;

    int ret = connect(sock, (struct sockaddr *)&addr6_loopback, sizeof(addr6_loopback));
    ck_assert_msg(ret == 0, "Failed to connect to TCP relay server");

    uint8_t f_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(sec_c->public_key, f_secret_key);
    random_nonce(sec_c->sent_nonce);

    uint8_t t_secret_key[crypto_box_SECRETKEYBYTES];
    uint8_t handshake_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_box_keypair(handshake_plain, t_secret_key);
    memcpy(handshake_plain + crypto_box_PUBLICKEYBYTES, sec_c->sent_nonce, crypto_box_NONCEBYTES);
    uint8_t handshake[TCP_CLIENT_HANDSHAKE_SIZE];
    memcpy(handshake, sec_c->public_key, crypto_box_PUBLICKEYBYTES);
    new_nonce(handshake + crypto_box_PUBLICKEYBYTES);

    ret = encrypt_data(tcp_s->public_key, f_secret_key, handshake + crypto_box_PUBLICKEYBYTES, handshake_plain,
                       TCP_HANDSHAKE_PLAIN_SIZE, handshake + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES);
    ck_assert_msg(ret == TCP_CLIENT_HANDSHAKE_SIZE - (crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES),
                  "Encrypt failed.");
    ck_assert_msg(send(sock, handshake, TCP_CLIENT_HANDSHAKE_SIZE - 1, 0) == TCP_CLIENT_HANDSHAKE_SIZE - 1, "send Failed.");
    do_TCP_server(tcp_s);
    c_sleep(50);
    ck_assert_msg(send(sock, handshake + (TCP_CLIENT_HANDSHAKE_SIZE - 1), 1, 0) == 1, "send Failed.");
    c_sleep(50);
    do_TCP_server(tcp_s);
    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    uint8_t response_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    ck_assert_msg(recv(sock, response, TCP_SERVER_HANDSHAKE_SIZE, 0) == TCP_SERVER_HANDSHAKE_SIZE, "recv Failed.");
    ret = decrypt_data(tcp_s->public_key, f_secret_key, response, response + crypto_box_NONCEBYTES,
                       TCP_SERVER_HANDSHAKE_SIZE - crypto_box_NONCEBYTES, response_plain);
    ck_assert_msg(ret == TCP_HANDSHAKE_PLAIN_SIZE, "Decrypt Failed.");
    encrypt_precompute(response_plain, t_secret_key, sec_c->shared_key);
    memcpy(sec_c->recv_nonce, response_plain + crypto_box_BEFORENMBYTES, crypto_box_NONCEBYTES);
    sec_c->sock = sock;
    return sec_c;
}

int write_packet_TCP_secure_connection(struct sec_TCP_con *con, uint8_t *data, uint16_t length)
{
    uint8_t packet[sizeof(uint16_t) + length + crypto_box_MACBYTES];

    uint16_t c_length = htons(length + crypto_box_MACBYTES);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (sizeof(packet) - sizeof(uint16_t)))
        return -1;

    increment_nonce(con->sent_nonce);

    ck_assert_msg(send(con->sock, packet, sizeof(packet), 0) == sizeof(packet), "send failed");
    return 0;
}

int read_packet_sec_TCP(struct sec_TCP_con *con, uint8_t *data, uint16_t length)
{
    int len;
    ck_assert_msg((len = recv(con->sock, data, length, 0)) == length, "wrong len %i\n", len);
    ck_assert_msg((len = decrypt_data_symmetric(con->shared_key, con->recv_nonce, data + 2, length - 2, data)) != -1,
                  "Decrypt failed");
    increment_nonce(con->recv_nonce);
    return len;
}

START_TEST(test_some)
{
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(1, NUM_PORTS, ports, self_public_key, self_secret_key, NULL);
    ck_assert_msg(tcp_s != NULL, "Failed to create TCP relay server");
    ck_assert_msg(tcp_s->num_listening_socks == NUM_PORTS, "Failed to bind to all ports");

    struct sec_TCP_con *con1 = new_TCP_con(tcp_s);
    struct sec_TCP_con *con2 = new_TCP_con(tcp_s);
    struct sec_TCP_con *con3 = new_TCP_con(tcp_s);

    uint8_t requ_p[1 + crypto_box_PUBLICKEYBYTES];
    requ_p[0] = 0;
    memcpy(requ_p + 1, con3->public_key, crypto_box_PUBLICKEYBYTES);
    write_packet_TCP_secure_connection(con1, requ_p, sizeof(requ_p));
    memcpy(requ_p + 1, con1->public_key, crypto_box_PUBLICKEYBYTES);
    write_packet_TCP_secure_connection(con3, requ_p, sizeof(requ_p));
    do_TCP_server(tcp_s);
    c_sleep(50);
    uint8_t data[2048];
    int len = read_packet_sec_TCP(con1, data, 2 + 1 + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);
    ck_assert_msg(len == 1 + 1 + crypto_box_PUBLICKEYBYTES, "wrong len %u", len);
    ck_assert_msg(data[0] == 1, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "connection not refused %u", data[1]);
    ck_assert_msg(memcmp(data + 2, con3->public_key, crypto_box_PUBLICKEYBYTES) == 0, "key in packet wrong");
    len = read_packet_sec_TCP(con3, data, 2 + 1 + 1 + crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES);
    ck_assert_msg(len == 1 + 1 + crypto_box_PUBLICKEYBYTES, "wrong len %u", len);
    ck_assert_msg(data[0] == 1, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "connection not refused %u", data[1]);
    ck_assert_msg(memcmp(data + 2, con1->public_key, crypto_box_PUBLICKEYBYTES) == 0, "key in packet wrong");

    uint8_t test_packet[512] = {16, 17, 16, 86, 99, 127, 255, 189, 78};
    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con3, test_packet, sizeof(test_packet));
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    len = read_packet_sec_TCP(con1, data, 2 + 2 + crypto_box_MACBYTES);
    ck_assert_msg(len == 2, "wrong len %u", len);
    ck_assert_msg(data[0] == 2, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "wrong peer id %u", data[1]);
    len = read_packet_sec_TCP(con3, data, 2 + 2 + crypto_box_MACBYTES);
    ck_assert_msg(len == 2, "wrong len %u", len);
    ck_assert_msg(data[0] == 2, "wrong packet id %u", data[0]);
    ck_assert_msg(data[1] == 16, "wrong peer id %u", data[1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    write_packet_TCP_secure_connection(con1, test_packet, sizeof(test_packet));
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);
    len = read_packet_sec_TCP(con3, data, 2 + sizeof(test_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(test_packet), "wrong len %u", len);
    ck_assert_msg(memcmp(data, test_packet, sizeof(test_packet)) == 0, "packet is wrong %u %u %u %u", data[0], data[1],
                  data[sizeof(test_packet) - 2], data[sizeof(test_packet) - 1]);

    uint8_t ping_packet[1 + sizeof(uint64_t)] = {4, 8, 6, 9, 67};
    write_packet_TCP_secure_connection(con1, ping_packet, sizeof(ping_packet));
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    len = read_packet_sec_TCP(con1, data, 2 + sizeof(ping_packet) + crypto_box_MACBYTES);
    ck_assert_msg(len == sizeof(ping_packet), "wrong len %u", len);
    ck_assert_msg(data[0] == 5, "wrong packet id %u", data[0]);
    ck_assert_msg(memcmp(ping_packet + 1, data + 1, sizeof(uint64_t)) == 0, "wrong packet data");
}
END_TEST

static int response_callback_good;
static uint8_t response_callback_connection_id;
static uint8_t response_callback_public_key[crypto_box_PUBLICKEYBYTES];
static int response_callback(void *object, uint8_t connection_id, const uint8_t *public_key)
{
    if (set_tcp_connection_number(object - 2, connection_id, 7) != 0)
        return 1;

    response_callback_connection_id = connection_id;
    memcpy(response_callback_public_key, public_key, crypto_box_PUBLICKEYBYTES);
    response_callback_good++;
    return 0;
}
static int status_callback_good;
static uint8_t status_callback_connection_id;
static uint8_t status_callback_status;
static int status_callback(void *object, uint32_t number, uint8_t connection_id, uint8_t status)
{
    if (object != (void *)2)
        return 1;

    if (number != 7)
        return 1;

    status_callback_connection_id = connection_id;
    status_callback_status = status;
    status_callback_good++;
    return 0;
}
static int data_callback_good;
static int data_callback(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data, uint16_t length)
{
    if (object != (void *)3)
        return 1;

    if (number != 7)
        return 1;

    if (length != 5)
        return 1;

    if (data[0] == 1 && data[1] == 2 && data[2] == 3 && data[3] == 4 && data[4] == 5) {
        data_callback_good++;
        return 0;
    }

    return 1;
}

static int oob_data_callback_good;
static uint8_t oob_pubkey[crypto_box_PUBLICKEYBYTES];
static int oob_data_callback(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length)
{
    if (object != (void *)4)
        return 1;

    if (length != 5)
        return 1;

    if (memcmp(public_key, oob_pubkey, crypto_box_PUBLICKEYBYTES) != 0)
        return 1;

    if (data[0] == 1 && data[1] == 2 && data[2] == 3 && data[3] == 4 && data[4] == 5) {
        oob_data_callback_good++;
        return 0;
    }

    return 1;
}

START_TEST(test_client)
{
    unix_time_update();
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(1, NUM_PORTS, ports, self_public_key, self_secret_key, NULL);
    ck_assert_msg(tcp_s != NULL, "Failed to create TCP relay server");
    ck_assert_msg(tcp_s->num_listening_socks == NUM_PORTS, "Failed to bind to all ports");

    uint8_t f_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t f_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(f_public_key, f_secret_key);
    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = htons(ports[rand() % NUM_PORTS]);
    ip_port_tcp_s.ip.family = AF_INET6;
    ip_port_tcp_s.ip.ip6.in6_addr = in6addr_loopback;
    TCP_Client_Connection *conn = new_TCP_connection(ip_port_tcp_s, self_public_key, f_public_key, f_secret_key);
    c_sleep(50);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_UNCONFIRMED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_UNCONFIRMED,
                  conn->status);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_CONFIRMED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONFIRMED,
                  conn->status);
    c_sleep(500);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_CONFIRMED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONFIRMED,
                  conn->status);
    c_sleep(500);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_CONFIRMED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONFIRMED,
                  conn->status);
    do_TCP_server(tcp_s);
    c_sleep(50);
    ck_assert_msg(conn->status == TCP_CLIENT_CONFIRMED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONFIRMED,
                  conn->status);

    uint8_t f2_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t f2_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(f2_public_key, f2_secret_key);
    TCP_Client_Connection *conn2 = new_TCP_connection(ip_port_tcp_s, self_public_key, f2_public_key, f2_secret_key);
    routing_response_handler(conn, response_callback, ((void *)conn) + 2);
    routing_status_handler(conn, status_callback, (void *)2);
    routing_data_handler(conn, data_callback, (void *)3);
    oob_data_handler(conn, oob_data_callback, (void *)4);
    oob_data_callback_good = response_callback_good = status_callback_good = data_callback_good = 0;
    c_sleep(50);
    do_TCP_connection(conn);
    do_TCP_connection(conn2);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_connection(conn);
    do_TCP_connection(conn2);
    c_sleep(50);
    uint8_t data[5] = {1, 2, 3, 4, 5};
    memcpy(oob_pubkey, f2_public_key, crypto_box_PUBLICKEYBYTES);
    send_oob_packet(conn2, f_public_key, data, 5);
    send_routing_request(conn, f2_public_key);
    send_routing_request(conn2, f_public_key);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_connection(conn);
    do_TCP_connection(conn2);
    ck_assert_msg(oob_data_callback_good == 1, "oob callback not called");
    ck_assert_msg(response_callback_good == 1, "response callback not called");
    ck_assert_msg(memcmp(response_callback_public_key, f2_public_key, crypto_box_PUBLICKEYBYTES) == 0, "wrong public key");
    ck_assert_msg(status_callback_good == 1, "status callback not called");
    ck_assert_msg(status_callback_status == 2, "wrong status");
    ck_assert_msg(status_callback_connection_id == response_callback_connection_id, "connection ids not equal");
    c_sleep(50);
    do_TCP_server(tcp_s);
    ck_assert_msg(send_data(conn2, 0, data, 5) == 1, "send data failed");
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_connection(conn);
    do_TCP_connection(conn2);
    ck_assert_msg(data_callback_good == 1, "data callback not called");
    status_callback_good = 0;
    send_disconnect_request(conn2, 0);
    c_sleep(50);
    do_TCP_server(tcp_s);
    c_sleep(50);
    do_TCP_connection(conn);
    do_TCP_connection(conn2);
    ck_assert_msg(status_callback_good == 1, "status callback not called");
    ck_assert_msg(status_callback_status == 1, "wrong status");
}
END_TEST

START_TEST(test_client_invalid)
{
    unix_time_update();
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(self_public_key, self_secret_key);

    uint8_t f_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t f_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(f_public_key, f_secret_key);
    IP_Port ip_port_tcp_s;

    ip_port_tcp_s.port = htons(ports[rand() % NUM_PORTS]);
    ip_port_tcp_s.ip.family = AF_INET6;
    ip_port_tcp_s.ip.ip6.in6_addr = in6addr_loopback;
    TCP_Client_Connection *conn = new_TCP_connection(ip_port_tcp_s, self_public_key, f_public_key, f_secret_key);
    c_sleep(50);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_CONNECTING, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONNECTING,
                  conn->status);
    c_sleep(5000);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_CONNECTING, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_CONNECTING,
                  conn->status);
    c_sleep(6000);
    do_TCP_connection(conn);
    ck_assert_msg(conn->status == TCP_CLIENT_DISCONNECTED, "Wrong status. Expected: %u, is: %u", TCP_CLIENT_DISCONNECTED,
                  conn->status);
}
END_TEST

#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);
Suite *TCP_suite(void)
{
    Suite *s = suite_create("TCP");

    DEFTESTCASE_SLOW(basic, 5);
    DEFTESTCASE_SLOW(some, 10);
    DEFTESTCASE_SLOW(client, 10);
    DEFTESTCASE_SLOW(client_invalid, 15);
    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *TCP = TCP_suite();
    SRunner *test_runner = srunner_create(TCP);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
