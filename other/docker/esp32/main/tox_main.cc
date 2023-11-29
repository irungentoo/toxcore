#include "../main/tox_main.h"

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <memory>

#include "../../../../toxcore/ccompat.h"
#include "../../../../toxcore/tox.h"
#include "../../../../toxcore/tox_events.h"

static const char *color(int index)
{
    switch (index) {
    case 0:
        return "\033"
               "[35m";
    case 1:
        return "\033"
               "[36m";
    }

    return "\033"
           "[0m";
}

static tox_log_cb log_handler;
static void log_handler(Tox *tox, Tox_Log_Level level, const char *file, uint32_t line,
    const char *func, const char *msg, void *user_data)
{
    const int *index = static_cast<const int *>(user_data);
    const uint16_t udp_port = tox_self_get_udp_port(tox, nullptr);
    printf("%s#%d (:%d) [%c] %s:%u(%s): %s\n", color(*index), *index, udp_port,
        tox_log_level_to_string(level)[0], file, static_cast<unsigned int>(line), func, msg);
}

using Tox_Options_Ptr = std::unique_ptr<Tox_Options, void (*)(Tox_Options *)>;
using Tox_Ptr = std::unique_ptr<Tox, void (*)(Tox *)>;

void tox_main()
{
    printf("Hello Tox!\n");

    Tox_Options_Ptr opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);

    tox_options_set_ipv6_enabled(opts.get(), false);
    tox_options_set_local_discovery_enabled(opts.get(), false);

    tox_options_set_log_callback(opts.get(), log_handler);

    Tox_Err_New err;

    int index[] = {0, 1};

    tox_options_set_log_user_data(opts.get(), &index[0]);
    Tox_Ptr tox0(tox_new(opts.get(), &err), tox_kill);
    printf("tox_new(#0): %p\n", static_cast<void *>(tox0.get()));

    if (err != TOX_ERR_NEW_OK) {
        printf("tox_new(#0): %s\n", tox_err_new_to_string(err));
        return;
    }

    tox_options_set_log_user_data(opts.get(), &index[1]);
    Tox_Ptr tox1(tox_new(opts.get(), &err), tox_kill);
    printf("tox_new(#1): %p\n", static_cast<void *>(tox0.get()));

    if (err != TOX_ERR_NEW_OK) {
        printf("tox_new(#1): %s\n", tox_err_new_to_string(err));
        return;
    }

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox0.get(), pk);
    tox_bootstrap(tox1.get(), "localhost", tox_self_get_udp_port(tox0.get(), nullptr), pk, nullptr);

#if 0
    tox_self_get_public_key(tox0.get(), pk);
    tox_friend_add_norequest(tox1.get(), pk, nullptr);

    tox_self_get_public_key(tox1.get(), pk);
    tox_friend_add_norequest(tox0.get(), pk, nullptr);
#endif

    printf("bootstrapping and connecting 2 toxes\n");

    while (tox_self_get_connection_status(tox1.get()) == TOX_CONNECTION_NONE
        || tox_self_get_connection_status(tox0.get()) == TOX_CONNECTION_NONE) {
        tox_events_free(tox_events_iterate(tox0.get(), true, nullptr));
        tox_events_free(tox_events_iterate(tox1.get(), true, nullptr));

        usleep(tox_iteration_interval(tox0.get()) * 1000);
        usleep(250);  // a bit less noise in the log
    }
}
