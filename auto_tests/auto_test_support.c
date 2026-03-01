#include <assert.h>  // assert
#include <stdlib.h>  // calloc, free

#include "check_compat.h"
#include "../testing/misc_tools.h"
#include "../toxcore/Messenger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/tox_dispatch.h"
#include "../toxcore/tox_events.h"
#include "../toxcore/tox_struct.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/DHT.h"

#include "auto_test_support.h"

#ifndef ABORT_ON_LOG_ERROR
#define ABORT_ON_LOG_ERROR true
#endif

static const uint8_t *auto_test_nc_dht_get_shared_key_sent_wrapper(void *dht, const uint8_t *public_key)
{
    return dht_get_shared_key_sent((DHT *)dht, public_key);
}

static const uint8_t *auto_test_nc_dht_get_self_public_key_wrapper(const void *dht)
{
    return dht_get_self_public_key((const DHT *)dht);
}

static const uint8_t *auto_test_nc_dht_get_self_secret_key_wrapper(const void *dht)
{
    return dht_get_self_secret_key((const DHT *)dht);
}

const Net_Crypto_DHT_Funcs auto_test_dht_funcs = {
    auto_test_nc_dht_get_shared_key_sent_wrapper,
    auto_test_nc_dht_get_self_public_key_wrapper,
    auto_test_nc_dht_get_self_secret_key_wrapper,
};

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

// List of live bootstrap nodes. These nodes should have TCP server enabled.
static const struct BootstrapNodes {
    const char   *ip;
    uint16_t      port;
    const uint8_t key[32];
} bootstrap_nodes[] = {
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
    { nullptr, 0, 0 },
};

void bootstrap_tox_live_network(Tox *tox, bool enable_tcp)
{
    ck_assert(tox != nullptr);

    for (size_t j = 0; bootstrap_nodes[j].ip != nullptr; ++j) {
        const char *ip = bootstrap_nodes[j].ip;
        uint16_t port = bootstrap_nodes[j].port;
        const uint8_t *key = bootstrap_nodes[j].key;

        Tox_Err_Bootstrap err;
        tox_bootstrap(tox, ip, port, key, &err);

        if (err != TOX_ERR_BOOTSTRAP_OK) {
            fprintf(stderr, "Failed to bootstrap node %zu (%s): error %u\n", j, ip, err);
        }

        if (enable_tcp) {
            tox_add_tcp_relay(tox, ip, port, key, &err);

            if (err != TOX_ERR_BOOTSTRAP_OK) {
                fprintf(stderr, "Failed to add TCP relay %zu (%s): error %u\n", j, ip, err);
            }
        }
    }
}

typedef void autotox_test_cb(AutoTox *autotoxes);

static const char *tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

void print_debug_log(Tox *m, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
                     const char *message, void *user_data)
{
    if (level == TOX_LOG_LEVEL_TRACE) {
        return;
    }

    const uint32_t index = user_data ? *(uint32_t *)user_data : 0;
    fprintf(stderr, "[#%u] %s %s:%u\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);

    if (level == TOX_LOG_LEVEL_ERROR && ABORT_ON_LOG_ERROR) {
        fputs("Aborting test program\n", stderr);
        abort();
    }
}

void print_debug_logger(void *context, Logger_Level level, const char *file, uint32_t line, const char *func, const char *message, void *userdata)
{
    print_debug_log(nullptr, (Tox_Log_Level) level, file, line, func, message, userdata);
}

Tox *tox_new_log_lan(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data, bool lan_discovery)
{
    struct Tox_Options *log_options = options;

    if (log_options == nullptr) {
        log_options = tox_options_new(nullptr);
    }

    assert(log_options != nullptr);

    tox_options_set_ipv6_enabled(log_options, USE_IPV6);
    tox_options_set_local_discovery_enabled(log_options, lan_discovery);
    // Use a higher start port for non-LAN-discovery tests so it's more likely for the LAN discovery
    // test to get the default port 33445.
    const uint16_t start_port = lan_discovery ? 33445 : 33545;
    tox_options_set_start_port(log_options, start_port);
    tox_options_set_end_port(log_options, start_port + 2000);
    tox_options_set_log_callback(log_options, &print_debug_log);
    tox_options_set_log_user_data(log_options, log_user_data);
    Tox *tox = tox_new(log_options, err);

    if (options == nullptr) {
        tox_options_free(log_options);
    }

    return tox;
}

Tox *tox_new_log(struct Tox_Options *options, Tox_Err_New *err, void *log_user_data)
{
    return tox_new_log_lan(options, err, log_user_data, false);
}
