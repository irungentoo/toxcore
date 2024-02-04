/* Auto Tests: Reconnection.
 *
 * This test checks that when a tox instance is suspended for long enough that
 * its friend connections time out, those connections are promptly
 * re-established when the instance is resumed.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/friend_connection.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

#define TOX_COUNT 2
#define RECONNECT_TIME_MAX (FRIEND_CONNECTION_TIMEOUT + 3)

#include "auto_test_support.h"

static uint32_t tox_connected_count(uint32_t tox_count, AutoTox *autotoxes, uint32_t index)
{
    const size_t friend_count = tox_self_get_friend_list_size(autotoxes[index].tox);
    uint32_t connected_count = 0;

    for (size_t j = 0; j < friend_count; j++) {
        if (tox_friend_get_connection_status(autotoxes[index].tox, j, nullptr) != TOX_CONNECTION_NONE) {
            ++connected_count;
        }
    }

    return connected_count;
}

static bool all_disconnected_from(uint32_t tox_count, AutoTox *autotoxes, uint32_t index)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (i == index) {
            continue;
        }

        if (tox_connected_count(tox_count, autotoxes, i) >= tox_count - 1) {
            return false;
        }
    }

    return true;
}

static void test_reconnect(AutoTox *autotoxes)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    const time_t test_start_time = time(nullptr);

    printf("letting connections settle\n");

    do {
        iterate_all_wait(autotoxes, TOX_COUNT, ITERATION_INTERVAL);
    } while (time(nullptr) - test_start_time < 2);

    const uint16_t disconnect = random_u16(rng) % TOX_COUNT;
    printf("disconnecting #%u\n", autotoxes[disconnect].index);

    do {
        for (uint16_t i = 0; i < TOX_COUNT; ++i) {
            if (i != disconnect) {
                Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
                Tox_Events *events = tox_events_iterate(autotoxes[i].tox, true, &err);
                ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
                tox_dispatch_invoke(autotoxes[i].dispatch, events, &autotoxes[i]);
                tox_events_free(events);

                autotoxes[i].clock += 1000;
            }
        }

        c_sleep(20);
    } while (!all_disconnected_from(TOX_COUNT, autotoxes, disconnect));

    const uint64_t reconnect_start_time = autotoxes[0].clock;

    printf("reconnecting\n");

    do {
        iterate_all_wait(autotoxes, TOX_COUNT, ITERATION_INTERVAL);
    } while (!all_friends_connected(autotoxes, TOX_COUNT));

    const uint64_t reconnect_time = autotoxes[0].clock - reconnect_start_time;
    ck_assert_msg(reconnect_time <= RECONNECT_TIME_MAX * 1000, "reconnection took %d seconds; expected at most %d seconds",
                  (int)(reconnect_time / 1000), RECONNECT_TIME_MAX);

    printf("test_reconnect succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    run_auto_test(nullptr, TOX_COUNT, test_reconnect, 0, &options);

    return 0;
}
