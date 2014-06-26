#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/group_announce.h"
#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif

void do_announce(ANNOUNCE *announce)
{
    networking_poll(announce->dht->net);
    do_DHT(announce->dht);
}

static int handled_test_1;
static int handle_test_1(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
}

static int handled_test_2;
static int handle_test_2(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
}

static int handled_test_3;
static int handle_test_3(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
}

START_TEST(test_basic)
{
    IP ip;
    ip_init(&ip, 1);
    ip.ip6.uint8[15] = 1;
    ANNOUNCE *announce1 = new_announce(new_DHT(new_networking(ip, 34567)));
    ANNOUNCE *announce2 = new_announce(new_DHT(new_networking(ip, 34568)));
    ANNOUNCE *announce3 = new_announce(new_DHT(new_networking(ip, 34569)));    
    ck_assert_msg((announce1 != NULL) && (announce2 != NULL) && (announce3 != NULL), "ANNOUNCE failed initializing.");

    networking_registerhandler(announce2->dht->net, NET_PACKET_ANNOUNCE_REQUEST, &handle_test_1, announce2->dht);
    networking_registerhandler(announce3->dht->net, NET_PACKET_GET_ANNOUNCED_NODES, &handle_test_2, announce3->dht);
    networking_registerhandler(announce2->dht->net, NET_PACKET_SEND_ANNOUNCED_NODES, &handle_test_3, announce2->dht);

    IP_Port on1 = {ip, announce1->dht->net->port};
    Node_format n1;
    memcpy(n1.client_id, announce1->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    n1.ip_port = on1;

    IP_Port on2 = {ip, announce2->dht->net->port};
    Node_format n2;
    memcpy(n2.client_id, announce2->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    n2.ip_port = on2;

    IP_Port on3 = {ip, announce3->dht->net->port};
    Node_format n3;
    memcpy(n3.client_id, announce3->dht->self_public_key, crypto_box_PUBLICKEYBYTES);
    n3.ip_port = on3;


}
END_TEST

#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

#define DEFTESTCASE_SLOW(NAME, TIMEOUT) \
    DEFTESTCASE(NAME) \
    tcase_set_timeout(tc_##NAME, TIMEOUT);

Suite *announce_suite(void)
{
    Suite *s = suite_create("ANNOUNCE");

    DEFTESTCASE_SLOW(basic, 5);
    //DEFTESTCASE_SLOW(announce, 200);
    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *announce = announce_suite();
    SRunner *test_runner = srunner_create(announce);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
    return;
}
