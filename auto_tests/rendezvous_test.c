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
#include "../toxcore/tox.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/rendezvous.h"

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

typedef struct tox_data {
} tox_data;

START_TEST(test_meetup)
{
    /* create three toxes */
    /* tox A wants to find tox B */
    /* tox C is the intermediate */

    Tox *toxA = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    Tox *toxB = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    ck_assert_msg(toxA && toxB, "Failed to setup tox structure(s).");

    tox_data dataA;
    memset(&dataA, 0, sizeof(dataA));

    tox_data dataB;
    memset(&dataB, 0, sizeof(dataB));

    Messenger *mA = (Messenger *)toxA;
    Messenger *mB = (Messenger *)toxB;

    tox_IP_Port ippA;
    ippA.ip.family = AF_INET;
    ippA.ip.ip4.i = htonl(0x7F000001);
    ippA.port = mA->dht->c->lossless_udp->net->port;

    tox_IP_Port ippB;
    ippB.ip.family = AF_INET;
    ippB.ip.ip4.i = htonl(0x7F000001);
    ippB.port = mB->dht->c->lossless_udp->net->port;

    tox_bootstrap_from_ip(toxA, ippB, mB->dht->c->self_public_key);
    tox_bootstrap_from_ip(toxB, ippA, mA->dht->c->self_public_key);

    size_t i;

    for (i = 0; i < 20; i++) {
        tox_do(toxA);
        tox_do(toxB);
        usleep(10000);
    }

    ck_assert_msg(tox_isconnected(toxA) && tox_isconnected(toxB), "Failed to setup tox structure(s).");

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

    RendezVous *rdvA = rendezvous_new(NULL, mA->dht->c->lossless_udp->net);
    RendezVous *rdvB = rendezvous_new(NULL, mB->dht->c->lossless_udp->net);

    ck_assert_msg(rdvA && rdvB, "Failed to setup rendezvous structure.");

    rendezvous_init(rdvA, mA->dht->c->self_public_key);
    rendezvous_init(rdvB, mB->dht->c->self_public_key);

    RendezVous_callbacks callbacks;
    callbacks.found_function = callback_found;

    found foundA;
    memset(&foundA, 0, sizeof(foundA));
    rendezvous_publish(rdvA, secret, now_floored, &callbacks, &foundA);

    found foundB;
    memset(&foundB, 0, sizeof(foundB));
    rendezvous_publish(rdvB, secret, now_floored, &callbacks, &foundB);

    for (i = 0; i < 20; i++) {
        tox_do(toxA);
        tox_do(toxB);
        usleep(10000);
    }

    ck_assert_msg(foundA.found && foundB.found, "Expected A&B to find someone.");

    ck_assert_msg(id_equal(foundA.client_id, mB->dht->c->self_public_key), "Expected A to find B.");
    ck_assert_msg(id_equal(foundB.client_id, mA->dht->c->self_public_key), "Expected B to find A.");

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

