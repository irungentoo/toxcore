#define _XOPEN_SOURCE 600

#include "../toxcore/tox.h"

#include <assert.h>
#include <stdlib.h>

#include "helpers.h"

typedef struct State {
    uint32_t id;
    bool self_online;
    bool friend_online;

    bool joined;
    uint32_t conference;

    bool received;

    uint32_t peers;
} State;

static void handle_self_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "\nself_connection_status(#%d, %d, _)\n", state->id, connection_status);
    state->self_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_friend_connection_status(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "\nhandle_friend_connection_status(#%d, %d, %d, _)\n", state->id, friend_number, connection_status);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_conference_invite(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type, const uint8_t *cookie,
                                     size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "\nhandle_conference_invite(#%d, %d, %d, uint8_t[%zd], _)\n", state->id, friend_number, type, length);
    fprintf(stderr, "tox%d joining conference\n", state->id);

    TOX_ERR_CONFERENCE_JOIN err;
    state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
    assert(err == TOX_ERR_CONFERENCE_JOIN_OK);
    fprintf(stderr, "tox%d Joined conference %d\n", state->id, state->conference);
    state->joined = true;

    // We're tox2, so now we invite tox3.
    if (state->id == 2) {
        TOX_ERR_CONFERENCE_INVITE err;
        tox_conference_invite(tox, 1, state->conference, &err);

        if (err != TOX_ERR_CONFERENCE_INVITE_OK) {
            fprintf(stderr, "ERROR: %d\n", err);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "tox2 invited tox3\n");
    }
}

static void handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                      TOX_MESSAGE_TYPE type, const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "\nhandle_conference_message(#%d, %d, %d, %d, uint8_t[%zd], _)\n",
            state->id, conference_number, peer_number, type, length);

    fprintf(stderr, "tox%d got message: %s\n", state->id, (const char *)message);
    state->received = true;
}

static void handle_conference_namelist_change(Tox *tox, uint32_t conference_number, uint32_t peer_number,
        TOX_CONFERENCE_STATE_CHANGE change, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "\nhandle_conference_namelist_change(#%d, %d, %d, %d, _)\n",
            state->id, conference_number, peer_number, change);

    if (change != TOX_CONFERENCE_STATE_CHANGE_PEER_NAME_CHANGE) {
        TOX_ERR_CONFERENCE_PEER_QUERY err;
        uint32_t count = tox_conference_peer_count(tox, conference_number, &err);

        if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
            fprintf(stderr, "ERROR: %d\n", err);
            exit(EXIT_FAILURE);
        }

        fprintf(stderr, "tox%d has %d peers online\n", state->id, count);
        state->peers = count;
    }
}

int main()
{
    State state1 = {1};
    State state2 = {2};
    State state3 = {3};

    // Create toxes.
    Tox *tox1 = tox_new_log(NULL, NULL, &state1.id);
    Tox *tox2 = tox_new_log(NULL, NULL, &state2.id);
    Tox *tox3 = tox_new_log(NULL, NULL, &state3.id);

    // tox1 <-> tox2, tox2 <-> tox3
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, key);
    tox_friend_add_norequest(tox1, key, NULL);  // tox1 -> tox2
    tox_self_get_public_key(tox1, key);
    tox_friend_add_norequest(tox2, key, NULL);  // tox2 -> tox1
    tox_self_get_public_key(tox3, key);
    tox_friend_add_norequest(tox2, key, NULL);  // tox2 -> tox3
    tox_self_get_public_key(tox2, key);
    tox_friend_add_norequest(tox3, key, NULL);  // tox3 -> tox2

    // Connection callbacks.
    tox_callback_self_connection_status(tox1, handle_self_connection_status);
    tox_callback_self_connection_status(tox2, handle_self_connection_status);
    tox_callback_self_connection_status(tox3, handle_self_connection_status);

    tox_callback_friend_connection_status(tox1, handle_friend_connection_status);
    tox_callback_friend_connection_status(tox2, handle_friend_connection_status);
    tox_callback_friend_connection_status(tox3, handle_friend_connection_status);

    // Conference callbacks.
    tox_callback_conference_invite(tox1, handle_conference_invite);
    tox_callback_conference_invite(tox2, handle_conference_invite);
    tox_callback_conference_invite(tox3, handle_conference_invite);

    tox_callback_conference_message(tox1, handle_conference_message);
    tox_callback_conference_message(tox2, handle_conference_message);
    tox_callback_conference_message(tox3, handle_conference_message);

    tox_callback_conference_namelist_change(tox1, handle_conference_namelist_change);
    tox_callback_conference_namelist_change(tox2, handle_conference_namelist_change);
    tox_callback_conference_namelist_change(tox3, handle_conference_namelist_change);

    // Wait for self connection.
    fprintf(stderr, "Waiting for toxes to come online");

    while (!state1.self_online || !state2.self_online || !state3.self_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(1000);
        fprintf(stderr, ".");
    }

    fprintf(stderr, "\nToxes are online\n");

    // Wait for friend connection.
    fprintf(stderr, "Waiting for friends to connect");

    while (!state1.friend_online || !state2.friend_online || !state3.friend_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(1000);
        fprintf(stderr, ".");
    }

    fprintf(stderr, "\nFriends are connected\n");

    {
        // Create new conference, tox1 is the founder.
        TOX_ERR_CONFERENCE_NEW err;
        state1.conference = tox_conference_new(tox1, &err);
        state1.joined = true;
        assert(err == TOX_ERR_CONFERENCE_NEW_OK);
        fprintf(stderr, "Created conference: id=%d\n", state1.conference);
    }

    {
        // Invite friend.
        TOX_ERR_CONFERENCE_INVITE err;
        tox_conference_invite(tox1, 0, state1.conference, &err);
        assert(err == TOX_ERR_CONFERENCE_INVITE_OK);
        fprintf(stderr, "tox1 invited tox2\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive");

    while (!state1.joined || !state2.joined || !state3.joined) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(1000);
        fprintf(stderr, ".");
    }

    fprintf(stderr, "\nInvitations accepted\n");

    fprintf(stderr, "Waiting for peers to come online");

    while (state1.peers == 0 || state2.peers == 0 || state3.peers == 0) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(1000);
        fprintf(stderr, ".");
    }

    fprintf(stderr, "\nAll peers are online\n");

    {
        fprintf(stderr, "tox1 sends a message to the group: \"hello!\"\n");
        TOX_ERR_CONFERENCE_SEND_MESSAGE err;
        tox_conference_send_message(tox1, state1.conference, TOX_MESSAGE_TYPE_NORMAL,
                                    (const uint8_t *)"hello!", 7, &err);

        if (err != TOX_ERR_CONFERENCE_SEND_MESSAGE_OK) {
            fprintf(stderr, "ERROR: %d\n", err);
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stderr, "Waiting for messages to arrive");

    while (!state2.received || !state3.received) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(1000);
        fprintf(stderr, ".");
    }

    fprintf(stderr, "\nMessages received. Test complete.\n");

    tox_kill(tox3);
    tox_kill(tox2);
    tox_kill(tox1);

    return 0;
}
