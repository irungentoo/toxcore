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
    Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type,
    const uint8_t *cookie, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->index, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->index);

    if (friend_number != -1) {
        TOX_ERR_CONFERENCE_JOIN err;
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
        TOX_ERR_CONFERENCE_NEW err;
        state[0].conference = tox_conference_new(toxes[0], &err);
        state[0].joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state[0].conference);
    }

    {
        // Invite friend.
        TOX_ERR_CONFERENCE_INVITE err;
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

    // Invite one more time, resulting in friend -1 inviting tox1 (toxes[1]).
    tox_conference_invite(toxes[0], 0, state[0].conference, nullptr);

    iterate_all_wait(2, toxes, state, ITERATION_INTERVAL);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, conference_double_invite_test);
    return 0;
}
