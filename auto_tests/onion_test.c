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


void do_onion(Onion *onion)
{
    networking_poll(onion->net);
    do_DHT(onion->dht);
}

static int handled_test_1;
static int handle_test_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    Onion *onion = object;

    if (memcmp(packet, "Install Gentoo", sizeof("Install Gentoo")) != 0)
        return 1;

    uint8_t data[1024];
    data[0] = NET_PACKET_ONION_RECV_3;
    memcpy(data + 1, packet + sizeof("Install Gentoo"), length - sizeof("Install Gentoo"));
    memcpy(data + 1 + length - sizeof("Install Gentoo"), "install gentoo", sizeof("install gentoo"));
    uint32_t data_len = 1 + length;

    if ((uint32_t)sendpacket(onion->net, source, data, data_len) != data_len)
        return 1;

    handled_test_1 = 1;
    return 0;
}

static int handled_test_2;
static int handle_test_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    if (length != sizeof("install Gentoo"))
        return 1;

    if (memcmp(packet, "install gentoo", sizeof("install gentoo")) != 0)
        return 1;

    handled_test_2 = 1;
    return 0;
}
START_TEST(test_basic)
{
    IP ip;
    ip_init(&ip, 1);
    ip.ip6.uint8[15] = 1;
    Onion *onion1 = new_onion(new_DHT(new_net_crypto(new_networking(ip, 34567))));
    Onion *onion2 = new_onion(new_DHT(new_net_crypto(new_networking(ip, 34568))));
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
    int ret = send_onion_packet(onion1, nodes, "Install Gentoo", sizeof("Install Gentoo"));
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
