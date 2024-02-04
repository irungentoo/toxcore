/* Tests what happens when spamming friend requests from lots of temporary toxes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../testing/misc_tools.h"
#include "auto_test_support.h"
#include "check_compat.h"

#define FR_MESSAGE "Gentoo"
// TODO(iphydf): Investigate friend request spam: receiving more than 32 at a time means any further
// friend requests are dropped on the floor and aren't seen again.
#define FR_TOX_COUNT 33

typedef struct State {
    bool unused;
} State;

static void accept_friend_request(const Tox_Event_Friend_Request *event,
                                  void *userdata)
{
    AutoTox *autotox = (AutoTox *)userdata;

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *data = tox_event_friend_request_get_message(event);
    const size_t length = tox_event_friend_request_get_message_length(event);

    ck_assert_msg(length == sizeof(FR_MESSAGE) && memcmp(FR_MESSAGE, data, sizeof(FR_MESSAGE)) == 0,
                  "unexpected friend request message");
    tox_friend_add_norequest(autotox->tox, public_key, nullptr);
}

static void test_friend_request(AutoTox *autotoxes)
{
    const time_t con_time = time(nullptr);

    printf("All toxes add tox1 as friend.\n");
    tox_events_callback_friend_request(autotoxes[0].dispatch, accept_friend_request);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(autotoxes[0].tox, address);

    for (uint32_t i = 2; i < FR_TOX_COUNT; ++i) {
        Tox_Err_Friend_Add err;
        tox_friend_add(autotoxes[i].tox, address, (const uint8_t *)FR_MESSAGE, sizeof(FR_MESSAGE), &err);
        ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "tox %u failed to add friend error code: %d", autotoxes[i].index, err);
    }

    for (uint32_t t = 0; t < 100; ++t) {
        if (all_friends_connected(autotoxes, FR_TOX_COUNT)) {
            break;
        }

        iterate_all_wait(autotoxes, FR_TOX_COUNT, ITERATION_INTERVAL);
    }

    const size_t size = tox_self_get_friend_list_size(autotoxes[0].tox);
    printf("Tox clients connected took %lu seconds; tox1 has %u friends.\n",
           (unsigned long)(time(nullptr) - con_time), (unsigned int)size);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    run_auto_test(nullptr, FR_TOX_COUNT, test_friend_request, sizeof(State), &options);

    return 0;
}
