#include <stdio.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox_struct.h"
#include "auto_test_support.h"

static uint64_t get_state_clock_callback(void *user_data)
{
    const uint64_t *clock = (const uint64_t *)user_data;
    return *clock;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox *tox1 = tox_new_log_lan(nullptr, nullptr, nullptr, /* lan_discovery */true);
    Tox *tox2 = tox_new_log_lan(nullptr, nullptr, nullptr, /* lan_discovery */true);
    ck_assert(tox1 != nullptr);
    ck_assert(tox2 != nullptr);

    uint64_t clock = current_time_monotonic(tox1->mono_time);
    Mono_Time *mono_time;

    mono_time = tox1->mono_time;
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, &clock);

    mono_time = tox2->mono_time;
    mono_time_set_current_time_callback(mono_time, get_state_clock_callback, &clock);

    printf("Waiting for LAN discovery. This loop will attempt to run until successful.");

    do {
        printf(".");
        fflush(stdout);

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        c_sleep(5);
        clock += 100;
    } while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE);

    printf(" %d <-> %d\n",
           tox_self_get_connection_status(tox1),
           tox_self_get_connection_status(tox2));

    tox_kill(tox2);
    tox_kill(tox1);
    return 0;
}
