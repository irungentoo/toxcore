#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"

static bool all_connected(uint32_t tox_count, Tox **toxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (tox_self_get_connection_status(toxes[i]) == TOX_CONNECTION_NONE) {
            return false;
        }
    }

    return true;
}

static bool all_friends_connected(uint32_t tox_count, Tox **toxes)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        const size_t friend_count = tox_self_get_friend_list_size(toxes[i]);

        for (size_t j = 0; j < friend_count; j++) {
            if (tox_friend_get_connection_status(toxes[i], j, nullptr) == TOX_CONNECTION_NONE) {
                return false;
            }
        }
    }

    return true;
}

static bool iterate_all(uint32_t tox_count, Tox **toxes, State *state)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        tox_iterate(toxes[i], &state[i]);
    }

    return true;
}

static void run_auto_test(uint32_t tox_count, void test(Tox **toxes, State *state))
{
    printf("initialising %u toxes\n", tox_count);
    Tox **toxes = (Tox **)calloc(tox_count, sizeof(Tox *));
    State *state = (State *)calloc(tox_count, sizeof(State));

    for (uint32_t i = 0; i < tox_count; i++) {
        state[i].index = i;
        toxes[i] = tox_new_log(nullptr, nullptr, &state[i].index);
        ck_assert_msg(toxes[i], "failed to create %u tox instances", i + 1);
    }

    printf("toxes all add each other as friends\n");

    for (uint32_t i = 0; i < tox_count; i++) {
        for (uint32_t j = 0; j < tox_count; j++) {
            if (i != j) {
                uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
                tox_self_get_public_key(toxes[j], public_key);
                tox_friend_add_norequest(toxes[i], public_key, nullptr);
            }
        }
    }


    printf("bootstrapping all toxes off toxes[0]\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(toxes[0], dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

    for (uint32_t i = 1; i < tox_count; i++) {
        tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);
    }

    while (!all_connected(tox_count, toxes)) {
        iterate_all(tox_count, toxes, state);

        c_sleep(ITERATION_INTERVAL);
    }

    printf("toxes are online\n");

    while (!all_friends_connected(tox_count, toxes)) {
        iterate_all(tox_count, toxes, state);

        c_sleep(ITERATION_INTERVAL);
    }

    printf("tox clients connected\n");

    test(toxes, state);

    for (uint32_t i = 0; i < tox_count; i++) {
        tox_kill(toxes[i]);
    }

    free(state);
    free(toxes);
}
