#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>

#define AUTO_TESTS
#include "../toxcore/rendezvous.h"
#include "../toxcore/net_crypto.h"

typedef struct found {
    uint8_t found;
    uint8_t client_id[crypto_box_PUBLICKEYBYTES];
} found;

static void callback_found(void *data, uint8_t *client_id)
{
    found *found = data;
    found->found++;
    memcpy(found->client_id, client_id, crypto_box_PUBLICKEYBYTES);
}

typedef struct cross {
    uint16_t portA;
    uint16_t portB;

    RendezVous *rdvA;
    RendezVous *rdvB;
} cross;

static int sendpacket_overwrite(Networking_Core *net, IP_Port ip_port, uint8_t *data, uint32_t len)
{
/*
 * TODO
 */
#if 0
    cross *crs = (cross *)net;
    if (ip_port.port == crs->portA)
        crs->rdvA->receive_packet();
    if (ip_port.port == crs->portB)
        crs->rdvB->receive_packet();
#endif

    return 0;
}

START_TEST(test_meetup)
{
    /* create three toxes */
    /* tox A wants to find tox B */
    /* tox C is the intermediate */

    /* a random secret. maybe should check that the length is decent, at least 64 bytes */
    char secret[] = "Our deepest fear is not that we are inadequate. "
            "Our deepest fear is that we are powerful beyond measure. "
            "It is our light, not our darkness that most frightens us. "
            "We ask ourselves, "
            "Who am I "
            "to be brilliant, gorgeous, talented, fabulous? "
            "Actually, who are you not to be? "
            "You are a child of God. "
            "Your playing small does not serve the world. "
            "There is nothing enlightened about shrinking "
            "so that other people won't feel insecure around you. "
            "We are all meant to shine, as children do. "
            "We were born to make manifest the glory of God that is within us. "
            "It's not just in some of us; it's in everyone. "
            "And as we let our own light shine, "
            "we unconsciously give other people permission to do the same. "
            "As we are liberated from our own fear, "
            "our presence automatically liberates others.";

    uint64_t now = unix_time();
    uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);

    cross crs;
    crs.portA = 65530;
    crs.portB = 65531;

    IP ip;
    ip_init(&ip, TOX_ENABLE_IPV6_DEFAULT);
    Networking_Core *netA = new_networking(ip, crs.portA);
    Networking_Core *netB = new_networking(ip, crs.portB);

    ck_assert_msg(netA && netB, "Failed to setup network structure.");

    RendezVous *rdvA = rendezvous_new(NULL, netA);
    RendezVous *rdvB = rendezvous_new(NULL, netB);

    ck_assert_msg(rdvA && rdvB, "Failed to setup rendezvous structure.");

    Net_Crypto *cryA = new_net_crypto(netA);
    Net_Crypto *cryB = new_net_crypto(netB);

    ck_assert_msg(cryA && cryB, "Failed to setup crypto structure.");

    rendezvous_init(rdvA, cryA->self_public_key, cryA->self_secret_key);
    rendezvous_init(rdvB, cryB->self_public_key, cryB->self_secret_key);

    rendezvous_testing(rdvA, (Networking_Core *)&crs, sendpacket_overwrite);

    RendezVous_callbacks callbacks;
    callbacks.found_function = callback_found;

    found foundA;
    memset(&foundA, 0, sizeof(foundA));
    rendezvous_publish(rdvA, secret, now_floored, &callbacks, &foundA);

    found foundB;
    memset(&foundB, 0, sizeof(foundB));
    rendezvous_publish(rdvB, secret, now_floored, &callbacks, &foundB);

#if 0
    /* example test */
    uint8_t test = 0;
    ck_assert_msg(test == 0, "test: expected result 0, got %u.", test);
#endif
}
END_TEST


#define DEFTESTCASE(NAME) \
    TCase *tc_##NAME = tcase_create(#NAME); \
    tcase_add_test(tc_##NAME, test_##NAME); \
    suite_add_tcase(s, tc_##NAME);

Suite *rendezvous_suite(void)
{
    Suite *s = suite_create("RendezVous");

    DEFTESTCASE(meetup);

    return s;
}

int main(int argc, char *argv[])
{
    srand((unsigned int) time(NULL));

    Suite *rendezvous = rendezvous_suite();
    SRunner *test_runner = srunner_create(rendezvous);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}

