#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct State {
    bool connected;
    uint32_t conference;
} State;

#define NUM_INVITE_MERGE_TOX 5

#include "auto_test_support.h"

static void handle_conference_invite(
    const Tox_Event_Conference_Invite *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    const uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
    const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
    const size_t length = tox_event_conference_invite_get_cookie_length(event);

    if (friend_number != -1) {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(autotox->tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                      "attempting to join the conference returned with an error: %d", err);
        fprintf(stderr, "#%u accepted invite to conference %u\n", autotox->index, state->conference);
    }
}

static void handle_conference_connected(
    const Tox_Event_Conference_Connected *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    fprintf(stderr, "#%u connected to conference %u\n", autotox->index, state->conference);
    state->connected = true;
}

static void wait_connected(AutoTox *autotoxes, const AutoTox *autotox, uint32_t friendnumber)
{
    do {
        iterate_all_wait(autotoxes, NUM_INVITE_MERGE_TOX, ITERATION_INTERVAL);
    } while (tox_friend_get_connection_status(autotox->tox, friendnumber, nullptr) == TOX_CONNECTION_NONE);
}

static void do_invite(AutoTox *autotoxes, AutoTox *inviter, AutoTox *invitee, uint32_t friendnum)
{
    fprintf(stderr, "#%u inviting #%u\n", inviter->index, invitee->index);

    Tox_Err_Conference_Invite err;
    tox_conference_invite(inviter->tox, friendnum, ((State *)inviter->state)->conference, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK,
                  "#%u attempting to invite #%u (friendnumber %u) returned with an error: %d", inviter->index, invitee->index,
                  friendnum, err);

    do {
        iterate_all_wait(autotoxes, NUM_INVITE_MERGE_TOX, ITERATION_INTERVAL);
    } while (!((State *)invitee->state)->connected);
}

static bool group_complete(AutoTox *autotoxes)
{
    int c = -1, size = 0;

    for (int i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        if (!autotoxes[i].alive) {
            continue;
        }

        const int ct = tox_conference_peer_count(autotoxes[i].tox, ((State *)autotoxes[i].state)->conference, nullptr);

        if (c == -1) {
            c = ct;
        } else if (c != ct) {
            return false;
        }

        ++size;
    }

    return (c == size);
}

static void wait_group_complete(AutoTox *autotoxes)
{
    do {
        iterate_all_wait(autotoxes, NUM_INVITE_MERGE_TOX, ITERATION_INTERVAL);
    } while (!group_complete(autotoxes));
}

static void conference_invite_merge_test(AutoTox *autotoxes)
{
    // Test that an explicit invite between peers in different connected
    // components will cause a split group to merge

    for (int i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        tox_events_callback_conference_invite(autotoxes[i].dispatch, handle_conference_invite);
        tox_events_callback_conference_connected(autotoxes[i].dispatch, handle_conference_connected);
    }

    State *state2 = (State *)autotoxes[2].state;

    {
        // Create new conference, tox 2 is the founder.
        Tox_Err_Conference_New err;
        state2->conference = tox_conference_new(autotoxes[2].tox, &err);
        state2->connected = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state2->conference);
    }

    save_autotox(&autotoxes[2]);

    do_invite(autotoxes, &autotoxes[2], &autotoxes[1], 0);
    do_invite(autotoxes, &autotoxes[1], &autotoxes[0], 0);

    save_autotox(&autotoxes[1]);
    kill_autotox(&autotoxes[1]);

    do {
        iterate_all_wait(autotoxes, NUM_INVITE_MERGE_TOX, ITERATION_INTERVAL);
    } while (tox_conference_peer_count(autotoxes[2].tox, state2->conference, nullptr) != 1);

    do_invite(autotoxes, &autotoxes[2], &autotoxes[3], 1);
    do_invite(autotoxes, &autotoxes[3], &autotoxes[4], 1);

    kill_autotox(&autotoxes[2]);

    reload(&autotoxes[1]);

    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(autotoxes[1].tox, public_key);
    tox_friend_add_norequest(autotoxes[3].tox, public_key, nullptr);
    tox_self_get_public_key(autotoxes[3].tox, public_key);
    tox_friend_add_norequest(autotoxes[1].tox, public_key, nullptr);
    wait_connected(autotoxes, &autotoxes[1], 2);

    do_invite(autotoxes, &autotoxes[1], &autotoxes[3], 2);

    fprintf(stderr, "Waiting for group to merge\n");

    wait_group_complete(autotoxes);

    fprintf(stderr, "Group merged\n");

    reload(&autotoxes[2]);
    wait_connected(autotoxes, &autotoxes[2], 0);
    do_invite(autotoxes, &autotoxes[2], &autotoxes[1], 0);

    fprintf(stderr, "Waiting for #2 to rejoin\n");

    wait_group_complete(autotoxes);

    kill_autotox(&autotoxes[2]);
    wait_group_complete(autotoxes);
    reload(&autotoxes[2]);
    wait_connected(autotoxes, &autotoxes[2], 0);
    wait_connected(autotoxes, &autotoxes[1], 1);

    do_invite(autotoxes, &autotoxes[1], &autotoxes[2], 1);

    fprintf(stderr, "Waiting for #2 to rejoin\n");

    wait_group_complete(autotoxes);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, NUM_INVITE_MERGE_TOX, conference_invite_merge_test, sizeof(State), &options);

    return 0;
}
