#include <stdbool.h>
#include <stdint.h>

typedef struct State {
    bool self_online;
    bool friend_online;
    bool friend_in_group;

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

    Tox_Err_Conference_Join err;
    state->conference = tox_conference_join(autotox->tox, friend_number, cookie, length, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                  "attempting to join the conference returned with an error: %d", err);
    fprintf(stderr, "tox%u joined conference %u\n", autotox->index, state->conference);
    state->joined = true;
}

static void handle_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    const uint32_t conference_number = tox_event_conference_peer_list_changed_get_conference_number(event);
    fprintf(stderr, "handle_peer_list_changed(#%u, %u, _)\n",
            autotox->index, conference_number);

    Tox_Err_Conference_Peer_Query err;
    uint32_t const count = tox_conference_peer_count(autotox->tox, conference_number, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                  "failed to get conference peer count: err = %d", err);
    printf("tox%u has %u peers\n", autotox->index, count);
    state->friend_in_group = count == 2;
}

static void rebuild_peer_list(Tox *tox)
{
    for (uint32_t conference_number = 0;
            conference_number < tox_conference_get_chatlist_size(tox);
            ++conference_number) {
        Tox_Err_Conference_Peer_Query err;
        uint32_t const count = tox_conference_peer_count(tox, conference_number, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                      "failed to get conference peer count for conference %u: err = %d", conference_number, err);

        for (uint32_t peer_number = 0; peer_number < count; peer_number++) {
            size_t size = tox_conference_peer_get_name_size(tox, conference_number, peer_number, &err);
            ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                          "failed to get conference peer %u's name size (conference = %u): err = %d", peer_number, conference_number, err);

            uint8_t *const name = (uint8_t *)malloc(size);
            ck_assert(name != nullptr);
            tox_conference_peer_get_name(tox, conference_number, peer_number, name, &err);
            ck_assert_msg(err == TOX_ERR_CONFERENCE_PEER_QUERY_OK,
                          "failed to get conference peer %u's name (conference = %u): err = %d", peer_number, conference_number, err);
            free(name);
        }
    }
}

static void conference_peer_nick_test(AutoTox *autotoxes)
{
    // Conference callbacks.
    tox_events_callback_conference_invite(autotoxes[0].dispatch, handle_conference_invite);
    tox_events_callback_conference_invite(autotoxes[1].dispatch, handle_conference_invite);
    tox_events_callback_conference_peer_list_changed(autotoxes[0].dispatch, handle_peer_list_changed);
    tox_events_callback_conference_peer_list_changed(autotoxes[1].dispatch, handle_peer_list_changed);

    // Set the names of the toxes.
    tox_self_set_name(autotoxes[0].tox, (const uint8_t *)"test-tox-0", 10, nullptr);
    tox_self_set_name(autotoxes[1].tox, (const uint8_t *)"test-tox-1", 10, nullptr);

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

    fprintf(stderr, "Waiting for invitation to arrive and peers to be in the group\n");

    do {
        iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
    } while (!state[0]->joined || !state[1]->joined || !state[0]->friend_in_group || !state[1]->friend_in_group);

    fprintf(stderr, "Running tox0, but not tox1, waiting for tox1 to drop out\n");

    do {
        iterate_all_wait(autotoxes, 1, 1000);

        // Rebuild peer list after every iteration.
        rebuild_peer_list(autotoxes[0].tox);
    } while (state[0]->friend_in_group);

    fprintf(stderr, "Invitations accepted\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    run_auto_test(nullptr, 2, conference_peer_nick_test, sizeof(State), &options);

    return 0;
}
