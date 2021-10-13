#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;

    bool self_online;
    bool friend_online;

    bool joined;
    uint32_t conference;
} State;

#include "run_auto_test.h"

static void handle_conference_invite(
    Tox *tox, uint32_t friend_number, Tox_Conference_Type type,
    const uint8_t *cookie, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->index, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->index);

    ck_assert_msg(!state->joined, "invitation callback generated for already joined conference");

    if (friend_number != -1) {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                      "attempting to join the conference returned with an error: %d", err);
        fprintf(stderr, "tox%u joined conference %u\n", state->index, state->conference);
        state->joined = true;
    }
}

static void conference_double_invite_test(Tox **toxes, State *state)
{
    // Conference callbacks.
    tox_callback_conference_invite(toxes[0], handle_conference_invite);
    tox_callback_conference_invite(toxes[1], handle_conference_invite);

    {
        // Create new conference, tox0 is the founder.
        Tox_Err_Conference_New err;
        state[0].conference = tox_conference_new(toxes[0], &err);
        state[0].joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state[0].conference);
    }

    {
        // Invite friend.
        Tox_Err_Conference_Invite err;
        tox_conference_invite(toxes[0], 0, state[0].conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK,
                      "attempting to invite a friend returned with an error: %d", err);
        fprintf(stderr, "tox0 invited tox1\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive\n");

    do {
        iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
    } while (!state[0].joined || !state[1].joined);

    fprintf(stderr, "Invitations accepted\n");

    fprintf(stderr, "Sending second invitation; should be ignored\n");
    tox_conference_invite(toxes[0], 0, state[0].conference, nullptr);

    iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, conference_double_invite_test, false);
    return 0;
}
