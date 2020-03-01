#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;

    size_t save_size;
    uint8_t *save_state;
    bool alive;

    bool connected;
    uint32_t conference;
} State;

#define NUM_INVITE_MERGE_TOX 5

#include "run_auto_test.h"

static void handle_conference_invite(
    Tox *tox, uint32_t friend_number, Tox_Conference_Type type,
    const uint8_t *cookie, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    if (friend_number != -1) {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK,
                      "attempting to join the conference returned with an error: %d", err);
        fprintf(stderr, "#%u accepted invite to conference %u\n", state->index, state->conference);
    }
}

static void handle_conference_connected(
    Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;
    fprintf(stderr, "#%u connected to conference %u\n", state->index, state->conference);
    state->connected = true;
}

static void iterate_alive(Tox **toxes, State *state)
{
    for (uint32_t i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        if (!state[i].alive) {
            continue;
        }

        tox_iterate(toxes[i], &state[i]);
        state[i].clock += ITERATION_INTERVAL;
    }

    c_sleep(20);
}

static void save(Tox **toxes, State *state, uint32_t n)
{
    fprintf(stderr, "Saving #%u\n", state[n].index);

    if (state[n].save_state != nullptr) {
        free(state[n].save_state);
    }

    state[n].save_size = tox_get_savedata_size(toxes[n]);
    state[n].save_state = (uint8_t *)malloc(state[n].save_size);
    ck_assert_msg(state[n].save_state != nullptr, "malloc failed");
    tox_get_savedata(toxes[n], state[n].save_state);
}

static void kill(Tox **toxes, State *state, uint32_t n)
{
    fprintf(stderr, "Killing #%u\n", state[n].index);
    state[n].alive = false;
    tox_kill(toxes[n]);
}

static void reload(Tox **toxes, State *state, uint32_t n)
{
    if (state[n].alive) {
        state[n].alive = false;
        tox_kill(toxes[n]);
    }

    fprintf(stderr, "Reloading #%u\n", state[n].index);
    ck_assert(state[n].save_state != nullptr);

    struct Tox_Options *const options = tox_options_new(nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, state[n].save_state, state[n].save_size);
    toxes[n] = tox_new_log(options, nullptr, &state[n].index);
    tox_options_free(options);

    set_mono_time_callback(toxes[n], &state[n]);
    state[n].alive = true;
}

static void wait_connected(Tox **toxes, State *state, uint32_t n, uint32_t friendnumber)
{
    do {
        iterate_alive(toxes, state);
    } while (tox_friend_get_connection_status(toxes[n], friendnumber, nullptr) == TOX_CONNECTION_NONE);
}

static void do_invite(Tox **toxes, State *state, uint32_t inviter, uint32_t invitee, uint32_t friendnum)
{
    fprintf(stderr, "#%u inviting #%u\n", state[inviter].index, state[invitee].index);

    Tox_Err_Conference_Invite err;
    tox_conference_invite(toxes[inviter], friendnum, state[inviter].conference, &err);
    ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK,
                  "#%u attempting to invite #%u (friendnumber %u) returned with an error: %d", state[inviter].index, state[invitee].index,
                  friendnum, err);

    do {
        iterate_alive(toxes, state);
    } while (!state[invitee].connected);
}

static bool group_complete(Tox **toxes, State *state)
{
    int c = -1, size = 0;

    for (int i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        if (!state[i].alive) {
            continue;
        }

        const int ct = tox_conference_peer_count(toxes[i], state[i].conference, nullptr);

        if (c == -1) {
            c = ct;
        } else if (c != ct) {
            return false;
        }

        ++size;
    }

    return (c == size);
}

static void wait_group_complete(Tox **toxes, State *state)
{
    do {
        iterate_alive(toxes, state);
    } while (!group_complete(toxes, state));
}

static void conference_invite_merge_test(Tox **toxes, State *state)
{
    // Test that an explicit invite between peers in different connected
    // components will cause a split group to merge

    for (int i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        tox_callback_conference_invite(toxes[i], handle_conference_invite);
        tox_callback_conference_connected(toxes[i], &handle_conference_connected);
        state[i].alive = true;
        state[i].save_state = nullptr;
    }

    {
        // Create new conference, tox 2 is the founder.
        Tox_Err_Conference_New err;
        state[2].conference = tox_conference_new(toxes[2], &err);
        state[2].connected = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK,
                      "attempting to create a new conference returned with an error: %d", err);
        fprintf(stderr, "Created conference: index=%u\n", state[2].conference);
    }

    save(toxes, state, 2);

    do_invite(toxes, state, 2, 1, 0);
    do_invite(toxes, state, 1, 0, 0);

    save(toxes, state, 1);
    kill(toxes, state, 1);

    do {
        iterate_alive(toxes, state);
    } while (tox_conference_peer_count(toxes[2], state[2].conference, nullptr) != 1);

    do_invite(toxes, state, 2, 3, 1);
    do_invite(toxes, state, 3, 4, 1);

    kill(toxes, state, 2);

    reload(toxes, state, 1);

    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(toxes[1], public_key);
    tox_friend_add_norequest(toxes[3], public_key, nullptr);
    tox_self_get_public_key(toxes[3], public_key);
    tox_friend_add_norequest(toxes[1], public_key, nullptr);
    wait_connected(toxes, state, 1, 2);

    do_invite(toxes, state, 1, 3, 2);

    fprintf(stderr, "Waiting for group to merge\n");

    wait_group_complete(toxes, state);

    fprintf(stderr, "Group merged\n");

    reload(toxes, state, 2);
    wait_connected(toxes, state, 2, 0);
    do_invite(toxes, state, 2, 1, 0);

    fprintf(stderr, "Waiting for #2 to rejoin\n");

    wait_group_complete(toxes, state);

    kill(toxes, state, 2);
    wait_group_complete(toxes, state);
    reload(toxes, state, 2);
    wait_connected(toxes, state, 2, 0);
    wait_connected(toxes, state, 1, 1);

    do_invite(toxes, state, 1, 2, 1);

    fprintf(stderr, "Waiting for #2 to rejoin\n");

    wait_group_complete(toxes, state);

    for (int i = 0; i < NUM_INVITE_MERGE_TOX; i++) {
        if (state[i].save_state != nullptr) {
            free(state[i].save_state);
        }
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_INVITE_MERGE_TOX, conference_invite_merge_test, true);
    return 0;
}
