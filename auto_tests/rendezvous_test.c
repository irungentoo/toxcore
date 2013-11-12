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
#include "../toxcore/assoc.h"

typedef struct callback_data {
    uint8_t found;
    uint8_t client_id[crypto_box_PUBLICKEYBYTES];
} callback_data;

static void callback_found(void *data, uint8_t *client_id)
{
    callback_data *cbdata = data;
    cbdata->found++;
    memcpy(cbdata->client_id, client_id, crypto_box_PUBLICKEYBYTES);
}

static uint8_t callback_timeout(void *data)
{
    return 1;
}

START_TEST(test_meetup)
{
#ifdef LOGGING
    loginit(33);
    /* fprintf(stderr, "Logfile is %s.\n", logbuffer); */
    loglog("== rendezvous test start ==\n");
#endif

    /* create three toxes */
    /* tox A wants to find tox B */
    /* tox C is the intermediate */

    Tox *toxA = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    Tox *toxB = tox_new(TOX_ENABLE_IPV6_DEFAULT);
    ck_assert_msg(toxA && toxB, "Failed to setup tox structure(s).");

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
    char secret[] = "Twenty years from now "
                    "you will be more disappointed by the things that you didn’t do "
                    "than by the ones you did do, "
                    "so throw off the bowlines, "
                    "sail away from safe harbor, "
                    "catch the trade winds in your sails. "
                    " "
                    "Explore, "
                    "Dream, "
                    "Discover. "
                    " "
                    "-- Mark Twain";

    uint64_t now = unix_time();
    uint64_t now_floored = now - (now % RENDEZVOUS_INTERVAL);

#ifdef ASSOC_AVAILABLE
    RendezVous *rdvA = new_rendezvous(mA->dht->assoc, mA->dht->c->lossless_udp->net);
    RendezVous *rdvB = new_rendezvous(mB->dht->assoc, mB->dht->c->lossless_udp->net);
#else
    RendezVous *rdvA = new_rendezvous(mA->dht, mA->dht->c->lossless_udp->net);
    RendezVous *rdvB = new_rendezvous(mB->dht, mB->dht->c->lossless_udp->net);
#endif

    ck_assert_msg(rdvA && rdvB, "Failed to setup rendezvous structure.");

    rendezvous_init(rdvA, mA->dht->c->self_public_key);
    rendezvous_init(rdvB, mB->dht->c->self_public_key);

    RendezVous_callbacks callbacks;
    callbacks.found_function = callback_found;
    callbacks.timeout_function = callback_timeout; /* we might happen to be just around a timeframe border */

    uint8_t idA[FRIEND_ADDRESS_SIZE];
    getaddress(mA, idA);

    callback_data foundA;
    memset(&foundA, 0, sizeof(foundA));
    ck_assert_msg(rendezvous_publish(rdvA, idA + CLIENT_ID_SIZE, secret, now_floored, &callbacks, &foundA),
                  "A::publish() failed.");

    uint8_t idB[FRIEND_ADDRESS_SIZE];
    getaddress(mB, idB);

    callback_data foundB;
    memset(&foundB, 0, sizeof(foundB));
    ck_assert_msg(rendezvous_publish(rdvB, idB + CLIENT_ID_SIZE, secret, now_floored, &callbacks, &foundB),
                  "B::publish() failed.");

    for (i = 0; i < 20; i++) {
        tox_do(toxA);
        tox_do(toxB);
        usleep(10000);
    }

    ck_assert_msg(foundA.found && foundB.found, "Expected A&B to find someone.");

    ck_assert_msg(id_equal(foundA.client_id, mB->dht->c->self_public_key), "Expected A to find B.");
    ck_assert_msg(id_equal(foundB.client_id, mA->dht->c->self_public_key), "Expected B to find A.");

    kill_rendezvous(rdvA);
    kill_rendezvous(rdvB);

#ifdef LOGGING
    loglog("== rendezvous test done ==\n");
    logexit();
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

