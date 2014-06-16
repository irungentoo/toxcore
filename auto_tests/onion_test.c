#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/onion.h"
#include "../toxcore/onion_announce.h"
#include "../toxcore/onion_client.h"
#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

void do_onion(Onion *onion)
{
    networking_poll(onion->net);
    do_DHT(onion->dht);
}

static int handled_test_1;
static int handle_test_1(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (memcmp(packet, "Install Gentoo", sizeof("Install Gentoo")) != 0)
        return 1;

    if (send_onion_response(onion->net, source, (uint8_t *)"install gentoo", sizeof("install gentoo"),
                            packet + sizeof("Install Gentoo")) == -1)
        return 1;

    handled_test_1 = 1;
    return 0;
}

static int handled_test_2;
static int handle_test_2(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    if (length != sizeof("install Gentoo"))
        return 1;

    if (memcmp(packet, (uint8_t *)"install gentoo", sizeof("install gentoo")) != 0)
        return 1;

    handled_test_2 = 1;
    return 0;
}
/*
void print_client_id(uint8_t *client_id, uint32_t length)
{
    uint32_t j;

    for (j = 0; j < length; j++) {
        printf("%02hhX", client_id[j]);
    }
    printf("\n");
}
*/
uint8_t sb_data[ONION_ANNOUNCE_SENDBACK_DATA_LENGTH];
static int handled_test_3;
uint8_t test_3_pub_key[crypto_box_PUBLICKEYBYTES];
uint8_t test_3_ping_id[crypto_hash_sha256_BYTES];
static int handle_test_3(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length != (1 + crypto_box_NONCEBYTES + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + 1 + crypto_hash_sha256_BYTES +
                   crypto_box_MACBYTES))
        return 1;

    uint8_t plain[1 + crypto_hash_sha256_BYTES];
    //print_client_id(packet, length);
    int len = decrypt_data(test_3_pub_key, onion->dht->self_secret_key, packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH,
                           packet + 1 + ONION_ANNOUNCE_SENDBACK_DATA_LENGTH + crypto_box_NONCEBYTES,
                           1 + crypto_hash_sha256_BYTES + crypto_box_MACBYTES, plain);

    if (len == -1)
        return 1;


    if (memcmp(packet + 1, sb_data, ONION_ANNOUNCE_SENDBACK_DATA_LENGTH) != 0)
        return 1;

    memcpy(test_3_ping_id, plain + 1, crypto_hash_sha256_BYTES);
    //print_client_id(test_3_ping_id, sizeof(test_3_ping_id));
    handled_test_3 = 1;
    return 0;
}

uint8_t nonce[crypto_box_NONCEBYTES];
static int handled_test_4;
static int handle_test_4(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (length != (1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + sizeof("Install gentoo") + crypto_box_MACBYTES))
        return 1;

    uint8_t plain[sizeof("Install gentoo")] = {0};

    if (memcmp(nonce, packet + 1, crypto_box_NONCEBYTES) != 0)
        return 1;

    int len = decrypt_data(packet + 1 + crypto_box_NONCEBYTES, onion->dht->self_secret_key, packet + 1,
                           packet + 1 + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, sizeof("Install gentoo") + crypto_box_MACBYTES, plain);

    if (len == -1)
        return 1;

    if (memcmp(plain, "Install gentoo", sizeof("Install gentoo")) != 0)
        return 1;

    handled_test_4 = 1;
    return 0;
}

START_TEST(test_basic)
{
    IP ip;
    ip_init(&ip, 1);
    ip.ip6.uint8[15] = 1;
    Onion *onion1 = new_onion(new_DHT(new_networking(ip, 34567)));
    Onion *onion2 = new_onion(new_DHT(new_networking(ip, 34568)));
    ck_assert_msg((onion1 != NULL) && (onion2 != NULL), "Onion failed initializing.");
    networking_registerhandler(onion2->net, 'I', &handle_test_1, onion2);

    IP_Port on1 = {ip, onion1->net->port};
    Node_format n1;
    memcpy(n1.client_id, onion1->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    n1.ip_port = on1;

    IP_Port on2 = {ip, onion2->net->port};
    Node_format n2;
    memcpy(n2.client_id, onion2->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    n2.ip_port = on2;

    Node_format nodes[4];
    nodes[0] = n1;
    nodes[1] = n2;
    nodes[2] = n1;
    nodes[3] = n2;
    Onion_Path path;
    create_onion_path(onion1->dht, &path, nodes);
    int ret = send_onion_packet(onion1->net, &path, nodes[3].ip_port, (uint8_t *)"Install Gentoo",
                                sizeof("Install Gentoo"));
    ck_assert_msg(ret == 0, "Failed to create/send onion packet.");

    handled_test_1 = 0;

    while (handled_test_1 == 0) {
        do_onion(onion1);
        do_onion(onion2);
    }

    networking_registerhandler(onion1->net, 'i', &handle_test_2, onion1);
    handled_test_2 = 0;

    while (handled_test_2 == 0) {
        do_onion(onion1);
        do_onion(onion2);
    }

    Onion_Announce *onion1_a = new_onion_announce(onion1->dht);
    Onion_Announce *onion2_a = new_onion_announce(onion2->dht);
    networking_registerhandler(onion1->net, NET_PACKET_ANNOUNCE_RESPONSE, &handle_test_3, onion1);
    ck_assert_msg((onion1_a != NULL) && (onion2_a != NULL), "Onion_Announce failed initializing.");
    uint8_t zeroes[64] = {0};
    randombytes(sb_data, sizeof(sb_data));
    uint64_t s;
    memcpy(&s, sb_data, sizeof(uint64_t));
    memcpy(test_3_pub_key, nodes[3].client_id, crypto_box_PUBLICKEYBYTES);
    ret = send_announce_request(onion1->net, &path, nodes[3], onion1->dht->self_public_key,
                                onion1->dht->self_secret_key,
                                zeroes, onion1->dht->self_public_key, onion1->dht->self_public_key, s);
    ck_assert_msg(ret == 0, "Failed to create/send onion announce_request packet.");
    handled_test_3 = 0;

    while (handled_test_3 == 0) {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    }

    randombytes(sb_data, sizeof(sb_data));
    memcpy(&s, sb_data, sizeof(uint64_t));
    memcpy(onion2_a->entries[1].public_key, onion2->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    onion2_a->entries[1].time = unix_time();
    networking_registerhandler(onion1->net, NET_PACKET_ONION_DATA_RESPONSE, &handle_test_4, onion1);
    send_announce_request(onion1->net, &path, nodes[3], onion1->dht->self_public_key, onion1->dht->self_secret_key,
                          test_3_ping_id, onion1->dht->self_public_key, onion1->dht->self_public_key, s);

    while (memcmp(onion2_a->entries[ONION_ANNOUNCE_MAX_ENTRIES - 2].public_key, onion1->dht->self_public_key,
                  crypto_box_PUBLICKEYBYTES) != 0) {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    }

    c_sleep(1000);
    Onion *onion3 = new_onion(new_DHT(new_networking(ip, 34569)));
    ck_assert_msg((onion3 != NULL), "Onion failed initializing.");

    new_nonce(nonce);
    ret = send_data_request(onion3->net, &path, nodes[3].ip_port, onion1->dht->self_public_key,
                            onion1->dht->self_public_key,
                            nonce, (uint8_t *)"Install gentoo", sizeof("Install gentoo"));
    ck_assert_msg(ret == 0, "Failed to create/send onion data_request packet.");
    handled_test_4 = 0;

    while (handled_test_4 == 0) {
        do_onion(onion1);
        do_onion(onion2);
        c_sleep(50);
    }
}
END_TEST

typedef struct {
    Onion *onion;
    Onion_Announce *onion_a;
    Onion_Client *onion_c;
} Onions;

Onions *new_onions(uint16_t port)
{
    IP ip;
    ip_init(&ip, 1);
    ip.ip6.uint8[15] = 1;
    Onions *on = malloc(sizeof(Onions));
    DHT *dht = new_DHT(new_networking(ip, port));
    on->onion = new_onion(dht);
    on->onion_a = new_onion_announce(dht);
    on->onion_c = new_onion_client(new_net_crypto(dht));

    if (on->onion && on->onion_a && on->onion_c)
        return on;

    return NULL;
}

void do_onions(Onions *on)
{
    networking_poll(on->onion->net);
    do_DHT(on->onion->dht);
    do_onion_client(on->onion_c);
}

#define NUM_ONIONS 50

START_TEST(test_announce)
{
    uint32_t i, j;
    Onions *onions[NUM_ONIONS];

    for (i = 0; i < NUM_ONIONS; ++i) {
        onions[i] = new_onions(i + 34655);
        ck_assert_msg(onions[i] != 0, "Failed to create onions. %u");
    }

    IP ip;
    ip_init(&ip, 1);
    ip.ip6.uint8[15] = 1;

    for (i = 3; i < NUM_ONIONS; ++i) {
        IP_Port ip_port = {ip, onions[i - 1]->onion->net->port};
        DHT_bootstrap(onions[i]->onion->dht, ip_port, onions[i - 1]->onion->dht->self_public_key);
        IP_Port ip_port1 = {ip, onions[i - 2]->onion->net->port};
        DHT_bootstrap(onions[i]->onion->dht, ip_port1, onions[i - 2]->onion->dht->self_public_key);
        IP_Port ip_port2 = {ip, onions[i - 3]->onion->net->port};
        DHT_bootstrap(onions[i]->onion->dht, ip_port2, onions[i - 3]->onion->dht->self_public_key);
    }

    uint32_t connected = 0;

    while (connected != NUM_ONIONS) {
        connected = 0;

        for (i = 0; i < NUM_ONIONS; ++i) {
            do_onions(onions[i]);
            connected += DHT_isconnected(onions[i]->onion->dht);
        }

        c_sleep(50);
    }

    for (i = 0; i < 25 * 2; ++i) {
        for (j = 0; j < NUM_ONIONS; ++j) {
            do_onions(onions[j]);
        }

        c_sleep(50);
    }

    onion_addfriend(onions[7]->onion_c, onions[37]->onion_c->c->self_public_key);
    int frnum = onion_addfriend(onions[37]->onion_c, onions[7]->onion_c->c->self_public_key);

    int ok = -1;

    IP_Port ip_port;

    while (ok == -1) {
        for (i = 0; i < NUM_ONIONS; ++i) {
            networking_poll(onions[i]->onion->net);
            do_onion_client(onions[i]->onion_c);
        }

        ok = onion_getfriendip(onions[37]->onion_c, frnum, &ip_port);

        c_sleep(50);
    }

    printf("id discovered\n");

    while (ok != 1) {
        for (i = 0; i < NUM_ONIONS; ++i) {
            do_onions(onions[i]);
        }

        ok = onion_getfriendip(onions[37]->onion_c, frnum, &ip_port);

        c_sleep(50);
    }

    ck_assert_msg(ip_port.port == onions[7]->onion->net->port, "Port in returned ip not correct.");
}
END_TEST

#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);
Suite *onion_suite(void)
{
    Suite *s = suite_create("Onion");

    DEFTESTCASE_SLOW(basic, 5);
    DEFTESTCASE_SLOW(announce, 200);
    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *onion = onion_suite();
    SRunner *test_runner = srunner_create(onion);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
