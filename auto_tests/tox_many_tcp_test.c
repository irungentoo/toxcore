/* Auto Tests: Many TCP.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

static bool enable_broken_tests = false;

static void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (*((uint32_t *)userdata) != 974536) {
        return;
    }

    if (length == 7 && memcmp("Gentoo", data, 7) == 0) {
        tox_friend_add_norequest(m, public_key, nullptr);
    }
}

#define NUM_FRIENDS 50
#define NUM_TOXES_TCP 40

#ifdef TCP_RELAY_PORT
#undef TCP_RELAY_PORT
#endif
#define TCP_RELAY_PORT 33448

START_TEST(test_many_clients_tcp)
{
    long long unsigned int cur_time = time(nullptr);
    Tox *toxes[NUM_TOXES_TCP];
    uint32_t index[NUM_TOXES_TCP];
    uint32_t i, j;
    uint32_t to_comp = 974536;

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        struct Tox_Options *opts = tox_options_new(nullptr);

        if (i == 0) {
            tox_options_set_tcp_port(opts, TCP_RELAY_PORT);
        } else {
            tox_options_set_udp_enabled(opts, false);
        }

        index[i] = i + 1;
        toxes[i] = tox_new_log(opts, nullptr, &index[i]);
        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], accept_friend_request);
        uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dpk);
        Tox_Err_Bootstrap error = TOX_ERR_BOOTSTRAP_OK;
        ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, TCP_RELAY_PORT, dpk, &error), "add relay error, %u, %d", i,
                      error);
        uint16_t first_port = tox_self_get_udp_port(toxes[0], nullptr);
        ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, first_port, dpk, nullptr), "Bootstrap error");

        tox_options_free(opts);
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    for (i = 0; i < NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = random_u32() % NUM_TOXES_TCP;
        pairs[i].tox2 = (pairs[i].tox1 + random_u32() % (NUM_TOXES_TCP - 1) + 1) % NUM_TOXES_TCP;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox1 && pairs[j].tox1 == pairs[i].tox2) {
                goto loop_top;
            }
        }

        tox_self_get_address(toxes[pairs[i].tox1], address);

        Tox_Err_Friend_Add test;
        uint32_t num = tox_friend_add(toxes[pairs[i].tox2], address, (const uint8_t *)"Gentoo", 7, &test);

        if (test == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
            goto loop_top;
        }

        ck_assert_msg(num != UINT32_MAX && test == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend error code: %i", test);
    }

    while (true) {
        uint16_t counter = 0;

        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            for (j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_TCP) {
                    ++counter;
                }
            }
        }

        if (counter == NUM_FRIENDS * 2) {
            break;
        }

        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(50);
    }

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients_tcp succeeded, took %llu seconds\n", time(nullptr) - cur_time);
}
END_TEST

#define NUM_TCP_RELAYS 3

START_TEST(test_many_clients_tcp_b)
{
    long long unsigned int cur_time = time(nullptr);
    Tox *toxes[NUM_TOXES_TCP];
    uint32_t index[NUM_TOXES_TCP];
    uint32_t i, j;
    uint32_t to_comp = 974536;

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        struct Tox_Options *opts = tox_options_new(nullptr);

        if (i < NUM_TCP_RELAYS) {
            tox_options_set_tcp_port(opts, TCP_RELAY_PORT + i);
        } else {
            tox_options_set_udp_enabled(opts, 0);
        }

        index[i] = i + 1;
        toxes[i] = tox_new_log(opts, nullptr, &index[i]);
        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instances %u", i);
        tox_callback_friend_request(toxes[i], accept_friend_request);
        uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[(i % NUM_TCP_RELAYS)], dpk);
        ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, TCP_RELAY_PORT + (i % NUM_TCP_RELAYS), dpk, nullptr),
                      "add relay error");
        tox_self_get_dht_id(toxes[0], dpk);
        uint16_t first_port = tox_self_get_udp_port(toxes[0], nullptr);
        ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, first_port, dpk, nullptr), "Bootstrap error");

        tox_options_free(opts);
    }

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    for (i = 0; i < NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = random_u32() % NUM_TOXES_TCP;
        pairs[i].tox2 = (pairs[i].tox1 + random_u32() % (NUM_TOXES_TCP - 1) + 1) % NUM_TOXES_TCP;

        for (j = 0; j < i; ++j) {
            if (pairs[j].tox2 == pairs[i].tox1 && pairs[j].tox1 == pairs[i].tox2) {
                goto loop_top;
            }
        }

        tox_self_get_address(toxes[pairs[i].tox1], address);

        Tox_Err_Friend_Add test;
        uint32_t num = tox_friend_add(toxes[pairs[i].tox2], address, (const uint8_t *)"Gentoo", 7, &test);

        if (test == TOX_ERR_FRIEND_ADD_ALREADY_SENT) {
            goto loop_top;
        }

        ck_assert_msg(num != UINT32_MAX && test == TOX_ERR_FRIEND_ADD_OK, "Failed to add friend error code: %i", test);
    }

    uint16_t last_count = 0;

    while (true) {
        uint16_t counter = 0;

        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            for (j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_TCP) {
                    ++counter;
                }
            }
        }

        if (counter != last_count) {
            printf("many_clients_tcp_b got to %u\n", counter);
            last_count = counter;
        }

        if (counter == NUM_FRIENDS * 2) {
            break;
        }

        for (i = 0; i < NUM_TOXES_TCP; ++i) {
            tox_iterate(toxes[i], &to_comp);
        }

        c_sleep(30);
    }

    for (i = 0; i < NUM_TOXES_TCP; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients_tcp_b succeeded, took %llu seconds\n", time(nullptr) - cur_time);
}
END_TEST


static Suite *tox_suite(void)
{
    Suite *s = suite_create("Tox many tcp");

    /* Each tox connects to a single tox TCP    */
    DEFTESTCASE(many_clients_tcp);

    if (enable_broken_tests) {
        /* Try to make a connection to each "older sibling" tox instance via TCP */
        /* Currently this test intermittently fails for unknown reasons. */
        DEFTESTCASE(many_clients_tcp_b);
    }

    return s;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    int number_failed = 0;
    srunner_run_all(test_runner, CK_NORMAL);
    number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
