/* Auto Tests: Many TCP.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

#ifdef TOX_LOCALHOST
#undef TOX_LOCALHOST
#endif
#if USE_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

typedef struct State {
    uint32_t to_comp;
    Tox *tox;
} State;

static bool enable_broken_tests = false;

static void accept_friend_request(const Tox_Event_Friend_Request *event, void *userdata)
{
    State *state = (State *)userdata;

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *message = tox_event_friend_request_get_message(event);
    const uint32_t message_length = tox_event_friend_request_get_message_length(event);

    if (state->to_comp != 974536) {
        return;
    }

    if (message_length == 7 && memcmp("Gentoo", message, 7) == 0) {
        tox_friend_add_norequest(state->tox, public_key, nullptr);
    }
}

#define NUM_FRIENDS 50
#define NUM_TOXES_TCP 40

static uint16_t tcp_relay_port = 33448;

static void test_many_clients_tcp(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    long long unsigned int cur_time = time(nullptr);
    Tox *toxes[NUM_TOXES_TCP];
    uint32_t index[NUM_TOXES_TCP];
    uint32_t to_comp = 974536;

    for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
        struct Tox_Options *opts = tox_options_new(nullptr);

        if (i == 0) {
            tox_options_set_tcp_port(opts, tcp_relay_port);
        } else {
            tox_options_set_udp_enabled(opts, false);
        }

        index[i] = i + 1;
        Tox_Err_New err;
        toxes[i] = tox_new_log(opts, &err, &index[i]);
        if (i == 0 && err == TOX_ERR_NEW_PORT_ALLOC) {
            ck_assert(toxes[i] == nullptr);
            --i;
            ++tcp_relay_port;
            tox_options_free(opts);
            continue;
        }
        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instances %u", i);
        tox_events_init(toxes[i]);
        uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dpk);
        Tox_Err_Bootstrap error;
        ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, tcp_relay_port, dpk, &error), "add relay error, %u, %d", i,
                      error);
        uint16_t first_port = tox_self_get_udp_port(toxes[0], nullptr);
        ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, first_port, dpk, nullptr), "Bootstrap error");

        tox_options_free(opts);
    }

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert(dispatch != nullptr);

    tox_events_callback_friend_request(dispatch, accept_friend_request);

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    for (uint32_t i = 0; i < NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = random_u32(rng) % NUM_TOXES_TCP;
        pairs[i].tox2 = (pairs[i].tox1 + random_u32(rng) % (NUM_TOXES_TCP - 1) + 1) % NUM_TOXES_TCP;

        for (uint32_t j = 0; j < i; ++j) {
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

        for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
            for (uint32_t j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
                if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_TCP) {
                    ++counter;
                }
            }
        }

        if (counter == NUM_FRIENDS * 2) {
            break;
        }

        for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(toxes[i], true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            State state = {to_comp, toxes[i]};
            tox_dispatch_invoke(dispatch, events, &state);
            tox_events_free(events);
        }

        c_sleep(50);
    }

    tox_dispatch_free(dispatch);
    for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients_tcp succeeded, took %llu seconds\n", time(nullptr) - cur_time);
}

#define NUM_TCP_RELAYS 3

static void test_many_clients_tcp_b(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    long long unsigned int cur_time = time(nullptr);
    Tox *toxes[NUM_TOXES_TCP];
    uint32_t index[NUM_TOXES_TCP];
    uint32_t to_comp = 974536;

    for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
        struct Tox_Options *opts = tox_options_new(nullptr);

        if (i < NUM_TCP_RELAYS) {
            tox_options_set_tcp_port(opts, tcp_relay_port + i);
        } else {
            tox_options_set_udp_enabled(opts, 0);
        }

        index[i] = i + 1;
        toxes[i] = tox_new_log(opts, nullptr, &index[i]);
        ck_assert_msg(toxes[i] != nullptr, "Failed to create tox instances %u", i);
        tox_events_init(toxes[i]);
        uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[(i % NUM_TCP_RELAYS)], dpk);
        ck_assert_msg(tox_add_tcp_relay(toxes[i], TOX_LOCALHOST, tcp_relay_port + (i % NUM_TCP_RELAYS), dpk, nullptr),
                      "add relay error");
        tox_self_get_dht_id(toxes[0], dpk);
        uint16_t first_port = tox_self_get_udp_port(toxes[0], nullptr);
        ck_assert_msg(tox_bootstrap(toxes[i], TOX_LOCALHOST, first_port, dpk, nullptr), "Bootstrap error");

        tox_options_free(opts);
    }

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert(dispatch != nullptr);

    tox_events_callback_friend_request(dispatch, accept_friend_request);

    struct {
        uint16_t tox1;
        uint16_t tox2;
    } pairs[NUM_FRIENDS];

    uint8_t address[TOX_ADDRESS_SIZE];

    for (uint32_t i = 0; i < NUM_FRIENDS; ++i) {
loop_top:
        pairs[i].tox1 = random_u32(rng) % NUM_TOXES_TCP;
        pairs[i].tox2 = (pairs[i].tox1 + random_u32(rng) % (NUM_TOXES_TCP - 1) + 1) % NUM_TOXES_TCP;

        for (uint32_t j = 0; j < i; ++j) {
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

        for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
            for (uint32_t j = 0; j < tox_self_get_friend_list_size(toxes[i]); ++j) {
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

        for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
            Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
            Tox_Events *events = tox_events_iterate(toxes[i], true, &err);
            ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
            State state = {to_comp, toxes[i]};
            tox_dispatch_invoke(dispatch, events, &state);
            tox_events_free(events);
        }

        c_sleep(30);
    }

    tox_dispatch_free(dispatch);
    for (uint32_t i = 0; i < NUM_TOXES_TCP; ++i) {
        tox_kill(toxes[i]);
    }

    printf("test_many_clients_tcp_b succeeded, took %llu seconds\n", time(nullptr) - cur_time);
}

static void tox_suite(void)
{
    /* Each tox connects to a single tox TCP    */
    test_many_clients_tcp();

    if (enable_broken_tests) {
        /* Try to make a connection to each "older sibling" tox instance via TCP */
        /* Currently this test intermittently fails for unknown reasons. */
        test_many_clients_tcp_b();
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    tox_suite();
    return 0;
}
