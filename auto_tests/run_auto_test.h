#include <stdlib.h>  // calloc, free
#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"

// List of live bootstrap nodes. These nodes should have TCP server enabled.
static const struct BootstrapNodes {
    const char   *ip;
    uint16_t      port;
    const uint8_t key[32];
} BootstrapNodes[] = {
#ifndef USE_TEST_NETWORK
    {
        "tox.abilinski.com", 33445,
        0x10, 0xC0, 0x0E, 0xB2, 0x50, 0xC3, 0x23, 0x3E,
        0x34, 0x3E, 0x2A, 0xEB, 0xA0, 0x71, 0x15, 0xA5,
        0xC2, 0x89, 0x20, 0xE9, 0xC8, 0xD2, 0x94, 0x92,
        0xF6, 0xD0, 0x0B, 0x29, 0x04, 0x9E, 0xDC, 0x7E,
    },
    {
        "tox.initramfs.io", 33445,
        0x02, 0x80, 0x7C, 0xF4, 0xF8, 0xBB, 0x8F, 0xB3,
        0x90, 0xCC, 0x37, 0x94, 0xBD, 0xF1, 0xE8, 0x44,
        0x9E, 0x9A, 0x83, 0x92, 0xC5, 0xD3, 0xF2, 0x20,
        0x00, 0x19, 0xDA, 0x9F, 0x1E, 0x81, 0x2E, 0x46,
    },
    {
        "tox.plastiras.org", 33445,
        0x8E, 0x8B, 0x63, 0x29, 0x9B, 0x3D, 0x52, 0x0F,
        0xB3, 0x77, 0xFE, 0x51, 0x00, 0xE6, 0x5E, 0x33,
        0x22, 0xF7, 0xAE, 0x5B, 0x20, 0xA0, 0xAC, 0xED,
        0x29, 0x81, 0x76, 0x9F, 0xC5, 0xB4, 0x37, 0x25,
    },
    {
        "tox.novg.net", 33445,
        0xD5, 0x27, 0xE5, 0x84, 0x7F, 0x83, 0x30, 0xD6,
        0x28, 0xDA, 0xB1, 0x81, 0x4F, 0x0A, 0x42, 0x2F,
        0x6D, 0xC9, 0xD0, 0xA3, 0x00, 0xE6, 0xC3, 0x57,
        0x63, 0x4E, 0xE2, 0xDA, 0x88, 0xC3, 0x54, 0x63,
    },
#else
    {
        "172.93.52.70", 33445,
        0x79, 0xCA, 0xDA, 0x49, 0x74, 0xB0, 0x92, 0x6F,
        0x28, 0x6F, 0x02, 0x5C, 0xD5, 0xFF, 0xDF, 0x3E,
        0x65, 0x4A, 0x37, 0x58, 0xC5, 0x3E, 0x02, 0x73,
        0xEC, 0xFC, 0x4D, 0x12, 0xC2, 0x1D, 0xCA, 0x48,
    },
#endif  // USE_TEST_NETWORK
    { nullptr, 0, 0 },
};

static void bootstrap_toxes_live_network(Tox **toxes, uint32_t tox_count, bool enable_tcp)
{
    for (size_t i = 0; i < tox_count; ++i) {
        for (size_t j = 0; BootstrapNodes[j].ip != nullptr; ++j) {
            const char *ip = BootstrapNodes[j].ip;
            uint16_t port = BootstrapNodes[j].port;
            const uint8_t *key = BootstrapNodes[j].key;

            Tox_Err_Bootstrap err;
            tox_bootstrap(toxes[i], ip, port, key, &err);

            if (err != TOX_ERR_BOOTSTRAP_OK) {
                fprintf(stderr, "Failed to bootstrap node %zu (%s): error %d\n", j, ip, err);
            }

            if (enable_tcp) {
                tox_add_tcp_relay(toxes[i], ip, port, key, &err);

                if (err != TOX_ERR_BOOTSTRAP_OK) {
                    fprintf(stderr, "Failed to add TCP relay %zu (%s): error %d\n", j, ip, err);
                }
            }
        }
    }
}

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

static void iterate_all_wait(uint32_t tox_count, Tox **toxes, State *state, uint32_t wait)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        tox_iterate(toxes[i], &state[i]);
        state[i].clock += wait;
    }

    /* Also actually sleep a little, to allow for local network processing */
    c_sleep(5);
}

static uint64_t get_state_clock_callback(Mono_Time *mono_time, void *user_data)
{
    const State *state = (const State *)user_data;
    return state->clock;
}

static void set_mono_time_callback(Tox *tox, State *state)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    Mono_Time *mono_time = ((Messenger *)tox)->mono_time;

    state->clock = current_time_monotonic(mono_time);
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, state);
}

static void add_friend(uint32_t i, uint32_t j, Tox **toxes)
{
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(toxes[j], public_key);
    Tox_Err_Friend_Add err;
    tox_friend_add_norequest(toxes[i], public_key, &err);
    ck_assert(err == TOX_ERR_FRIEND_ADD_OK);
}

static void build_friend_graph(uint32_t tox_count, bool chain, Tox **toxes)
{
    if (chain) {
        printf("each tox adds adjacent toxes as friends\n");

        for (uint32_t i = 0; i < tox_count; i++) {
            for (uint32_t j = i - 1; j != i + 3; j += 2) {
                if (j >= tox_count) {
                    continue;
                }

                add_friend(i, j, toxes);
            }
        }
    } else {
        printf("toxes all add each other as friends\n");

        for (uint32_t i = 0; i < tox_count; i++) {
            for (uint32_t j = 0; j < tox_count; j++) {
                if (i != j) {
                    add_friend(i, j, toxes);
                }
            }
        }
    }
}

static void wait_friend_connections(uint32_t tox_count, Tox **toxes, State *state)
{
    do {
        iterate_all_wait(tox_count, toxes, state, ITERATION_INTERVAL);
    } while (!all_connected(tox_count, toxes));

    printf("toxes are online\n");

    do {
        iterate_all_wait(tox_count, toxes, state, ITERATION_INTERVAL);
    } while (!all_friends_connected(tox_count, toxes));

    printf("tox clients connected\n");
}

static void run_auto_test(struct Tox_Options *options, uint32_t tox_count, void test(Tox **toxes, State *state),
                          bool chain)
{
    printf("initialising %u toxes\n", tox_count);
    Tox **toxes = (Tox **)calloc(tox_count, sizeof(Tox *));
    State *state = (State *)calloc(tox_count, sizeof(State));

    ck_assert(toxes != nullptr);
    ck_assert(state != nullptr);

    for (uint32_t i = 0; i < tox_count; i++) {
        state[i].index = i;
        toxes[i] = tox_new_log(options, nullptr, &state[i].index);
        ck_assert_msg(toxes[i], "failed to create %u tox instances", i + 1);

        set_mono_time_callback(toxes[i], &state[i]);
    }

    build_friend_graph(tox_count, chain, toxes);

    const bool udp_enabled = options != nullptr ? tox_options_get_udp_enabled(options) : true;
    Tox_Err_Bootstrap err;

    if (udp_enabled) {
        printf("bootstrapping all toxes off toxes[0]\n");

        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);

        for (uint32_t i = 1; i < tox_count; i++) {
            tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, &err);
            ck_assert(err == TOX_ERR_BOOTSTRAP_OK);
        }
    } else {
        printf("bootstrapping all toxes to tcp relays\n");
        bootstrap_toxes_live_network(toxes, tox_count, true);
    }

    wait_friend_connections(tox_count, toxes, state);

    test(toxes, state);

    for (uint32_t i = 0; i < tox_count; i++) {
        tox_kill(toxes[i]);
    }

    free(state);
    free(toxes);
}
