#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    bool self_online;
    bool friend_online;

    bool joined;
    uint32_t conference;
} State;

#include "auto_test_support.h"

static void handle_conference_invite(
    const Tox_Event_Conference_Invite *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    const uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
    const Tox_Conference_Type type = tox_event_conference_invite_get_type(event);
    const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
    const size_t length = tox_event_conference_invite_get_cookie_length(event);

    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            autotox->index, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", autotox->index);

    ck_assert_msg(!state->joined, "invitation callback generated for already joined conference");

    if (friend_number != -1) {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(autotox->tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                      "attempting to join the conference returned with an error: %d", err);
        fprintf(stderr, "tox%u joined conference %u\n", autotox->index, state->conference);
        state->joined = true;
    }
}

static void conference_double_invite_test(AutoTox *autotoxes)
{
    // Conference callbacks.
    tox_events_callback_conference_invite(autotoxes[0].dispatch, handle_conference_invite);
    tox_events_callback_conference_invite(autotoxes[1].dispatch, handle_conference_invite);

    State *state[2];
    state[0] = (State *)autotoxes[0].state;
    state[1] = (State *)autotoxes[1].state;

    {
        // Create new conference, tox0 is the founder.
        Tox_Err_Conference_New err;
        state[0]->conference = tox_conference_new(autotoxes[0].tox, &err);
        state[0]->joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state[0]->conference);
    }

    {
        // Invite friend.
        Tox_Err_Conference_Invite err;
        tox_conference_invite(autotoxes[0].tox, 0, state[0]->conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK,
                      "attempting to invite a friend returned with an error: %d", err);
        fprintf(stderr, "tox0 invited tox1\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive\n");

    do {
        iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
    } while (!state[0]->joined || !state[1]->joined);

    fprintf(stderr, "Invitations accepted\n");

    fprintf(stderr, "Sending second invitation; should be ignored\n");
    tox_conference_invite(autotoxes[0].tox, 0, state[0]->conference, nullptr);

    iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, 2, conference_double_invite_test, sizeof(State), &options);

    return 0;
}
