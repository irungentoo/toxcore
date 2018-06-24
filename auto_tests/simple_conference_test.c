#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif

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

    fprintf(stderr, "self_connection_status(#%d, %d, _)\n", state->id, connection_status);
    state->self_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_friend_connection_status(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_friend_connection_status(#%d, %d, %d, _)\n", state->id, friend_number, connection_status);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_conference_invite(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type, const uint8_t *cookie,
                                     size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_invite(#%d, %d, %d, uint8_t[%u], _)\n",
            state->id, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%d joining conference\n", state->id);

    {
        TOX_ERR_CONFERENCE_JOIN err;
        state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
        assert(err == TOX_ERR_CONFERENCE_JOIN_OK);
        fprintf(stderr, "tox%d Joined conference %d\n", state->id, state->conference);
        state->joined = true;
    }

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

    fprintf(stderr, "handle_conference_message(#%d, %d, %d, %d, uint8_t[%u], _)\n",
            state->id, conference_number, peer_number, type, (unsigned)length);

    fprintf(stderr, "tox%d got message: %s\n", state->id, (const char *)message);
    state->received = true;
}

static void handle_conference_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_peer_list_changed(#%d, %d, _)\n",
            state->id, conference_number);

    TOX_ERR_CONFERENCE_PEER_QUERY err;
    uint32_t count = tox_conference_peer_count(tox, conference_number, &err);

    if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        fprintf(stderr, "ERROR: %d\n", err);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "tox%d has %d peers online\n", state->id, count);
    state->peers = count;
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    State state1 = {1};
    State state2 = {2};
    State state3 = {3};

    // Create toxes.
    Tox *tox1 = tox_new_log(nullptr, nullptr, &state1.id);
    Tox *tox2 = tox_new_log(nullptr, nullptr, &state2.id);
    Tox *tox3 = tox_new_log(nullptr, nullptr, &state3.id);

    // tox1 <-> tox2, tox2 <-> tox3
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, key);
    tox_friend_add_norequest(tox1, key, nullptr);  // tox1 -> tox2
    tox_self_get_public_key(tox1, key);
    tox_friend_add_norequest(tox2, key, nullptr);  // tox2 -> tox1
    tox_self_get_public_key(tox3, key);
    tox_friend_add_norequest(tox2, key, nullptr);  // tox2 -> tox3
    tox_self_get_public_key(tox2, key);
    tox_friend_add_norequest(tox3, key, nullptr);  // tox3 -> tox2

    printf("bootstrapping tox2 and tox3 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(tox3, "localhost", dht_port, dht_key, nullptr);

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

    tox_callback_conference_peer_list_changed(tox1, handle_conference_peer_list_changed);
    tox_callback_conference_peer_list_changed(tox2, handle_conference_peer_list_changed);
    tox_callback_conference_peer_list_changed(tox3, handle_conference_peer_list_changed);

    // Wait for self connection.
    fprintf(stderr, "Waiting for toxes to come online\n");

    while (!state1.self_online || !state2.self_online || !state3.self_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(100);
    }

    fprintf(stderr, "Toxes are online\n");

    // Wait for friend connection.
    fprintf(stderr, "Waiting for friends to connect\n");

    while (!state1.friend_online || !state2.friend_online || !state3.friend_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(100);
    }

    fprintf(stderr, "Friends are connected\n");

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

    fprintf(stderr, "Waiting for invitation to arrive\n");

    while (!state1.joined || !state2.joined || !state3.joined) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(100);
    }

    fprintf(stderr, "Invitations accepted\n");

    fprintf(stderr, "Waiting for peers to come online\n");

    while (state1.peers == 0 || state2.peers == 0 || state3.peers == 0) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(100);
    }

    fprintf(stderr, "All peers are online\n");

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

    fprintf(stderr, "Waiting for messages to arrive\n");

    while (!state2.received || !state3.received) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);
        tox_iterate(tox3, &state3);

        c_sleep(100);
    }

    fprintf(stderr, "Messages received. Test complete.\n");

    tox_kill(tox3);
    tox_kill(tox2);
    tox_kill(tox1);

    return 0;
}
