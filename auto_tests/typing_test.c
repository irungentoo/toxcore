/* Tests that our typing notifications work.
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    bool friend_is_typing;
} State;

#include "auto_test_support.h"

static void typing_callback(const Tox_Event_Friend_Typing *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    //const uint32_t friend_number = tox_event_friend_typing_get_friend_number(event);
    const bool typing = tox_event_friend_typing_get_typing(event);

    state->friend_is_typing = typing;
}

static void test_typing(AutoTox *autotoxes)
{
    time_t cur_time = time(nullptr);

    tox_events_callback_friend_typing(autotoxes[1].dispatch, &typing_callback);
    tox_self_set_typing(autotoxes[0].tox, 0, true, nullptr);

    do {
        iterate_all_wait(autotoxes, 2, 200);
    } while (!((State *)autotoxes[1].state)->friend_is_typing);

    ck_assert_msg(tox_friend_get_typing(autotoxes[1].tox, 0, nullptr) == 1,
                  "tox_friend_get_typing should have returned true, but it didn't");
    tox_self_set_typing(autotoxes[0].tox, 0, false, nullptr);

    do {
        iterate_all_wait(autotoxes, 2, 200);
    } while (((State *)autotoxes[1].state)->friend_is_typing);

    Tox_Err_Friend_Query err_t;
    ck_assert_msg(tox_friend_get_typing(autotoxes[1].tox, 0, &err_t) == 0,
                  "tox_friend_get_typing should have returned false, but it didn't");
    ck_assert_msg(err_t == TOX_ERR_FRIEND_QUERY_OK, "tox_friend_get_typing call did not return correct error");

    printf("test_typing succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    run_auto_test(nullptr, 2, test_typing, sizeof(State), &options);

    return 0;
}
