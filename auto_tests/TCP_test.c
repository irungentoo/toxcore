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
#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

#define NUM_PORTS 3

START_TEST(test_basic)
{
    uint16_t ports[NUM_PORTS] = {12345, 33445, 25643};
    uint8_t self_public_key[crypto_box_PUBLICKEYBYTES];
    uint8_t self_secret_key[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(self_public_key, self_secret_key);
    TCP_Server *tcp_s = new_TCP_server(1, NUM_PORTS, ports, self_public_key, self_secret_key);
    ck_assert_msg(tcp_s != NULL, "Failed to create TCP relay server");

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
