#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"

#include "auto_test_support.h"

const Run_Auto_Options default_run_auto_options = { GRAPH_COMPLETE, nullptr };

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

void bootstrap_tox_live_network(Tox *tox, bool enable_tcp)
{
    for (size_t j = 0; BootstrapNodes[j].ip != nullptr; ++j) {
        const char *ip = BootstrapNodes[j].ip;
        uint16_t port = BootstrapNodes[j].port;
        const uint8_t *key = BootstrapNodes[j].key;

        Tox_Err_Bootstrap err;
        tox_bootstrap(tox, ip, port, key, &err);

        if (err != TOX_ERR_BOOTSTRAP_OK) {
            fprintf(stderr, "Failed to bootstrap node %zu (%s): error %d\n", j, ip, err);
        }

        if (enable_tcp) {
            tox_add_tcp_relay(tox, ip, port, key, &err);

            if (err != TOX_ERR_BOOTSTRAP_OK) {
                fprintf(stderr, "Failed to add TCP relay %zu (%s): error %d\n", j, ip, err);
            }
        }
    }
}

bool all_connected(uint32_t tox_count, AutoTox *autotoxes)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        if (tox_self_get_connection_status(autotoxes[i].tox) == TOX_CONNECTION_NONE) {
            return false;
        }
    }

    return true;
}

bool all_friends_connected(uint32_t tox_count, AutoTox *autotoxes)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        const size_t friend_count = tox_self_get_friend_list_size(autotoxes[i].tox);

        for (size_t j = 0; j < friend_count; ++j) {
            if (tox_friend_get_connection_status(autotoxes[i].tox, j, nullptr) == TOX_CONNECTION_NONE) {
                return false;
            }
        }
    }

    return true;
}

void iterate_all_wait(uint32_t tox_count, AutoTox *autotoxes, uint32_t wait)
{
    for (uint32_t i = 0; i < tox_count; ++i) {
        if (autotoxes[i].alive) {
            tox_iterate(autotoxes[i].tox, &autotoxes[i]);
            autotoxes[i].clock += wait;
        }
    }

    /* Also actually sleep a little, to allow for local network processing */
    c_sleep(5);
}

static uint64_t get_state_clock_callback(Mono_Time *mono_time, void *user_data)
{
    const uint64_t *clock = (const uint64_t *)user_data;
    return *clock;
}

void set_mono_time_callback(AutoTox *autotox)
{
    // TODO(iphydf): Don't rely on toxcore internals.
    Mono_Time *mono_time = ((Messenger *)autotox->tox)->mono_time;

    autotox->clock = current_time_monotonic(mono_time);
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, &autotox->clock);
}

void save_autotox(AutoTox *autotox)
{
    ck_assert(autotox != nullptr);

    fprintf(stderr, "Saving #%u\n", autotox->index);

    free(autotox->save_state);
    autotox->save_state = nullptr;

    autotox->save_size = tox_get_savedata_size(autotox->tox);
    ck_assert_msg(autotox->save_size > 0, "save is invalid size %u", (unsigned)autotox->save_size);
    autotox->save_state = (uint8_t *)malloc(autotox->save_size);
    ck_assert_msg(autotox->save_state != nullptr, "malloc failed");
    tox_get_savedata(autotox->tox, autotox->save_state);
}

void kill_autotox(AutoTox *autotox)
{
    ck_assert(autotox != nullptr);
    ck_assert(autotox->alive);
    fprintf(stderr, "Killing #%u\n", autotox->index);
    autotox->alive = false;
    tox_kill(autotox->tox);
}

void reload(AutoTox *autotox)
{
    ck_assert(autotox != nullptr);

    if (autotox->alive) {
        kill_autotox(autotox);
    }

    fprintf(stderr, "Reloading #%u\n", autotox->index);
    ck_assert(autotox->save_state != nullptr);

    struct Tox_Options *const options = tox_options_new(nullptr);
    ck_assert(options != nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, autotox->save_state, autotox->save_size);
    autotox->tox = tox_new_log(options, nullptr, &autotox->index);
    ck_assert(autotox->tox != nullptr);
    tox_options_free(options);

    set_mono_time_callback(autotox);
    autotox->alive = true;
}

static void initialise_autotox(struct Tox_Options *options, AutoTox *autotox, uint32_t index, uint32_t state_size,
                               const Run_Auto_Options *autotest_opts)
{
    autotox->index = index;
    autotox->tox = tox_new_log(options, nullptr, &autotox->index);
    ck_assert_msg(autotox->tox != nullptr, "failed to create tox instance #%u", index);

    set_mono_time_callback(autotox);

    autotox->alive = true;
    autotox->save_state = nullptr;

    if (state_size > 0) {
        autotox->state = calloc(1, state_size);
        ck_assert(autotox->state != nullptr);
        ck_assert_msg(autotox->state != nullptr, "failed to allocate state");
    } else {
        autotox->state = nullptr;
    }

    if (autotest_opts->init_autotox != nullptr) {
        autotest_opts->init_autotox(autotox, index);
    }
}

static void autotox_add_friend(AutoTox *autotoxes, uint32_t adding, uint32_t added)
{
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(autotoxes[added].tox, public_key);
    Tox_Err_Friend_Add err;
    tox_friend_add_norequest(autotoxes[adding].tox, public_key, &err);
    ck_assert(err == TOX_ERR_FRIEND_ADD_OK);
}

static void initialise_friend_graph(Graph_Type graph, uint32_t num_toxes, AutoTox *autotoxes)
{
    if (graph == GRAPH_LINEAR) {
        printf("toxes #%u-#%u each add adjacent toxes as friends\n", 0, num_toxes - 1);

        for (uint32_t i = 0; i < num_toxes; ++i) {
            for (uint32_t j = i - 1; j != i + 3; j += 2) {
                if (j < num_toxes) {
                    autotox_add_friend(autotoxes, i, j);
                }
            }
        }
    } else if (graph == GRAPH_COMPLETE) {
        printf("toxes #%u-#%u add each other as friends\n", 0, num_toxes - 1);

        for (uint32_t i = 0; i < num_toxes; ++i) {
            for (uint32_t j = 0; j < num_toxes; ++j) {
                if (i != j) {
                    autotox_add_friend(autotoxes, i, j);
                }
            }
        }
    } else {
        ck_abort_msg("Unknown graph type");
    }
}

static void bootstrap_autotoxes(struct Tox_Options *options, uint32_t tox_count, const Run_Auto_Options *autotest_opts,
                                AutoTox *autotoxes)
{
    const bool udp_enabled = options != nullptr ? tox_options_get_udp_enabled(options) : true;

    if (udp_enabled) {
        printf("bootstrapping all toxes off tox 0\n");
        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(autotoxes[0].tox, dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(autotoxes[0].tox, nullptr);

        for (uint32_t i = 1; i < tox_count; ++i) {
            Tox_Err_Bootstrap err;
            tox_bootstrap(autotoxes[i].tox, "localhost", dht_port, dht_key, &err);
            ck_assert(err == TOX_ERR_BOOTSTRAP_OK);
        }
    } else {
        printf("bootstrapping all toxes to tcp relays\n");

        for (uint32_t i = 0; i < tox_count; ++i) {
            bootstrap_tox_live_network(autotoxes[i].tox, true);
        }
    }
}

void run_auto_test(struct Tox_Options *options, uint32_t tox_count, void test(AutoTox *autotoxes),
                   uint32_t state_size, const Run_Auto_Options *autotest_opts)
{
    printf("initialising %u toxes\n", tox_count);

    AutoTox *autotoxes = (AutoTox *)calloc(tox_count, sizeof(AutoTox));

    ck_assert(autotoxes != nullptr);

    for (uint32_t i = 0; i < tox_count; ++i) {
        initialise_autotox(options, &autotoxes[i], i, state_size, autotest_opts);
    }

    initialise_friend_graph(autotest_opts->graph, tox_count, autotoxes);

    bootstrap_autotoxes(options, tox_count, autotest_opts, autotoxes);

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_connected(tox_count, autotoxes));

    printf("toxes are online\n");

    do {
        iterate_all_wait(tox_count, autotoxes, ITERATION_INTERVAL);
    } while (!all_friends_connected(tox_count, autotoxes));

    printf("tox clients connected\n");

    test(autotoxes);

    for (uint32_t i = 0; i < tox_count; ++i) {
        tox_kill(autotoxes[i].tox);
        free(autotoxes[i].state);
        free(autotoxes[i].save_state);
    }

    free(autotoxes);
}
