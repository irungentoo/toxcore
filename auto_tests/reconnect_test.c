/* Auto Tests: Reconnection.
 *
 * This test checks that when a tox instance is suspended for long enough that
 * its friend connections time out, those connections are promptly
 * re-established when the instance is resumed.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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

typedef struct State {
    uint32_t index;
} State;

#include "run_auto_test.h"

static uint32_t tox_connected_count(uint32_t tox_count, Tox **toxes, State *state, uint32_t index)
{
    const size_t friend_count = tox_self_get_friend_list_size(toxes[index]);
    uint32_t connected_count = 0;

    for (size_t j = 0; j < friend_count; j++) {
        if (tox_friend_get_connection_status(toxes[index], j, nullptr) != TOX_CONNECTION_NONE) {
            ++connected_count;
        }
    }

    return connected_count;
}

static bool all_disconnected_from(uint32_t tox_count, Tox **toxes, State *state, uint32_t index)
{
    for (uint32_t i = 0; i < tox_count; i++) {
        if (i == index) {
            continue;
        }

        if (tox_connected_count(tox_count, toxes, state, i) >= tox_count - 1) {
            return false;
        }
    }

    return true;
}

static void test_reconnect(Tox **toxes, State *state)
{
    const time_t test_start_time = time(nullptr);

    printf("letting connections settle\n");

    do {
        iterate_all(TOX_COUNT, toxes, state);

        c_sleep(ITERATION_INTERVAL);
    } while (time(nullptr) - test_start_time < 2);

    uint16_t disconnect = random_u16() % TOX_COUNT;
    printf("disconnecting #%u\n", state[disconnect].index);

    do {
        for (uint16_t i = 0; i < TOX_COUNT; ++i) {
            if (i != disconnect) {
                tox_iterate(toxes[i], &state[i]);
            }
        }

        c_sleep(ITERATION_INTERVAL);
    } while (!all_disconnected_from(TOX_COUNT, toxes, state, disconnect));

    const time_t reconnect_start_time = time(nullptr);

    printf("reconnecting\n");

    do {
        iterate_all(TOX_COUNT, toxes, state);

        c_sleep(ITERATION_INTERVAL);
    } while (!all_friends_connected(TOX_COUNT, toxes));

    const int reconnect_time = (int)(time(nullptr) - reconnect_start_time);
    ck_assert_msg(reconnect_time <= RECONNECT_TIME_MAX, "reconnection took %d seconds; expected at most %d seconds",
                  reconnect_time, RECONNECT_TIME_MAX);

    printf("test_reconnect succeeded, took %d seconds\n", (int)(time(nullptr) - test_start_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(TOX_COUNT, test_reconnect);
    return 0;
}
