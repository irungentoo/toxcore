#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    uint32_t index;
    bool self_online;
    bool friend_online;
    bool friend_in_group;

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

    TOX_ERR_CONFERENCE_JOIN err;
    state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                  "attempting to join the conference returned with an error: %d", err);
    fprintf(stderr, "tox%u joined conference %u\n", state->index, state->conference);
    state->joined = true;
}

static void handle_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_peer_list_changed(#%u, %u, _)\n",
            state->index, conference_number);

    TOX_ERR_CONFERENCE_PEER_QUERY err;
    uint32_t const count = tox_conference_peer_count(tox, conference_number, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                  "failed to get conference peer count: err = %d", err);
    printf("tox%u has %u peers\n", state->index, count);
    state->friend_in_group = count == 2;
}

static void rebuild_peer_list(Tox *tox)
{
    for (uint32_t conference_number = 0;
            conference_number < tox_conference_get_chatlist_size(tox);
            ++conference_number) {
        TOX_ERR_CONFERENCE_PEER_QUERY err;
        uint32_t const count = tox_conference_peer_count(tox, conference_number, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                      "failed to get conference peer count for conference %u: err = %d", conference_number, err);

        for (uint32_t peer_number = 0; peer_number < count; peer_number++) {
            size_t size = tox_conference_peer_get_name_size(tox, conference_number, peer_number, &err);
            ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                          "failed to get conference peer %u's name size (conference = %u): err = %d", peer_number, conference_number, err);

            uint8_t *const name = (uint8_t *)malloc(size);
            tox_conference_peer_get_name(tox, conference_number, peer_number, name, &err);
            ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                          "failed to get conference peer %u's name (conference = %u): err = %d", peer_number, conference_number, err);
            free(name);
        }
    }
}

static void conference_peer_nick_test(Tox **toxes, State *state)
{
    // Conference callbacks.
    tox_callback_conference_invite(toxes[0], handle_conference_invite);
    tox_callback_conference_invite(toxes[1], handle_conference_invite);
    tox_callback_conference_peer_list_changed(toxes[0], handle_peer_list_changed);
    tox_callback_conference_peer_list_changed(toxes[1], handle_peer_list_changed);

    // Set the names of the toxes.
    tox_self_set_name(toxes[0], (const uint8_t *)"test-tox-0", 10, nullptr);
    tox_self_set_name(toxes[1], (const uint8_t *)"test-tox-1", 10, nullptr);

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

    fprintf(stderr, "Waiting for invitation to arrive and peers to be in the group\n");

    do {
        tox_iterate(toxes[0], &state[0]);
        tox_iterate(toxes[1], &state[1]);

        c_sleep(ITERATION_INTERVAL);
    } while (!state[0].joined || !state[1].joined || !state[0].friend_in_group || !state[1].friend_in_group);

    fprintf(stderr, "Running tox0, but not tox1, waiting for tox1 to drop out\n");

    do {
        tox_iterate(toxes[0], &state[0]);

        // Rebuild peer list after every iteration.
        rebuild_peer_list(toxes[0]);

        c_sleep(ITERATION_INTERVAL);
    } while (state[0].friend_in_group);

    fprintf(stderr, "Invitations accepted\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(2, conference_peer_nick_test);
    return 0;
}
