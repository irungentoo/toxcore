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
} State;

static void handle_self_connection_status(Tox *tox, TOX_CONNECTION connection_status, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "self_connection_status(#%u, %d, _)\n", state->id, connection_status);
    state->self_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_friend_connection_status(Tox *tox, uint32_t friend_number, TOX_CONNECTION connection_status,
        void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_friend_connection_status(#%u, %u, %d, _)\n", state->id, friend_number, connection_status);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_conference_invite(Tox *tox, uint32_t friend_number, TOX_CONFERENCE_TYPE type, const uint8_t *cookie,
                                     size_t length, void *user_data)
{
    State *state = (State *)user_data;

    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->id, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->id);

    if (friend_number != -1) {
        TOX_ERR_CONFERENCE_JOIN err;
        state->conference = tox_conference_join(tox, friend_number, cookie, length, &err);
        assert(err == TOX_ERR_CONFERENCE_JOIN_OK);
        fprintf(stderr, "tox%u Joined conference %u\n", state->id, state->conference);
        state->joined = true;
    }
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    State state1 = {1};
    State state2 = {2};

    // Create toxes.
    Tox *tox1 = tox_new_log(nullptr, nullptr, &state1.id);
    Tox *tox2 = tox_new_log(nullptr, nullptr, &state2.id);

    // tox1 <-> tox2
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, key);
    tox_friend_add_norequest(tox1, key, nullptr);  // tox1 -> tox2
    tox_self_get_public_key(tox1, key);
    tox_friend_add_norequest(tox2, key, nullptr);  // tox2 -> tox1

    printf("bootstrapping tox2 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);

    // Connection callbacks.
    tox_callback_self_connection_status(tox1, handle_self_connection_status);
    tox_callback_self_connection_status(tox2, handle_self_connection_status);

    tox_callback_friend_connection_status(tox1, handle_friend_connection_status);
    tox_callback_friend_connection_status(tox2, handle_friend_connection_status);

    // Conference callbacks.
    tox_callback_conference_invite(tox1, handle_conference_invite);
    tox_callback_conference_invite(tox2, handle_conference_invite);

    // Wait for self connection.
    fprintf(stderr, "Waiting for toxes to come online\n");

    while (!state1.self_online || !state2.self_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);

        c_sleep(100);
    }

    fprintf(stderr, "Toxes are online\n");

    // Wait for friend connection.
    fprintf(stderr, "Waiting for friends to connect\n");

    while (!state1.friend_online || !state2.friend_online) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);

        c_sleep(100);
    }

    fprintf(stderr, "Friends are connected\n");

    {
        // Create new conference, tox1 is the founder.
        TOX_ERR_CONFERENCE_NEW err;
        state1.conference = tox_conference_new(tox1, &err);
        state1.joined = true;
        assert(err == TOX_ERR_CONFERENCE_NEW_OK);
        fprintf(stderr, "Created conference: id=%u\n", state1.conference);
    }

    {
        // Invite friend.
        TOX_ERR_CONFERENCE_INVITE err;
        tox_conference_invite(tox1, 0, state1.conference, &err);
        assert(err == TOX_ERR_CONFERENCE_INVITE_OK);
        fprintf(stderr, "tox1 invited tox2\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive\n");

    while (!state1.joined || !state2.joined) {
        tox_iterate(tox1, &state1);
        tox_iterate(tox2, &state2);

        c_sleep(100);
    }

    fprintf(stderr, "Invitations accepted\n");

    // Invite one more time, resulting in friend -1 inviting tox2.
    tox_conference_invite(tox1, 0, state1.conference, 0);

    tox_iterate(tox1, &state1);
    tox_iterate(tox2, &state2);

    tox_kill(tox2);
    tox_kill(tox1);

    return 0;
}
