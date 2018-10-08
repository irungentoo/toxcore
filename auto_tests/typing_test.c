/* Tests that our typing notifications work.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool friend_is_typing;
} State;

#include "run_auto_test.h"

static void typing_callback(Tox *m, uint32_t friendnumber, bool typing, void *userdata)
{
    State *state = (State *)userdata;
    state->friend_is_typing = typing;
}

static void test_typing(Tox **toxes, State *state)
{
    time_t cur_time = time(nullptr);

    tox_callback_friend_typing(toxes[1], &typing_callback);
    tox_self_set_typing(toxes[0], 0, true, nullptr);

    do {
        iterate_all_wait(2, toxes, state, 200);
    } while (!state[1].friend_is_typing);

    ck_assert_msg(tox_friend_get_typing(toxes[1], 0, nullptr) == 1,
                  "tox_friend_get_typing should have returned true, but it didn't");
    tox_self_set_typing(toxes[0], 0, false, nullptr);

    do {
        iterate_all_wait(2, toxes, state, 200);
    } while (state[1].friend_is_typing);

    Tox_Err_Friend_Query err_t;
    ck_assert_msg(tox_friend_get_typing(toxes[1], 0, &err_t) == 0,
                  "tox_friend_get_typing should have returned false, but it didn't");
    ck_assert_msg(err_t == TOX_ERR_FRIEND_QUERY_OK, "tox_friend_get_typing call did not return correct error");

    printf("test_typing succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    run_auto_test(2, test_typing, false);
    return 0;
}
