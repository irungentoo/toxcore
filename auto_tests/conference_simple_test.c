#include <stdio.h>
#include <stdlib.h>

#include "../testing/misc_tools.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_dispatch.h"
#include "../toxcore/tox_events.h"
#include "auto_test_support.h"
#include "check_compat.h"

typedef struct State {
    uint32_t id;
    Tox *tox;
    bool self_online;
    bool friend_online;
    bool invited_next;

    bool joined;
    uint32_t conference;

    bool received;

    uint32_t peers;
} State;

static void handle_self_connection_status(const Tox_Event_Self_Connection_Status *event, void *user_data)
{
    State *state = (State *)user_data;

    const Tox_Connection connection_status = tox_event_self_connection_status_get_connection_status(event);
    fprintf(stderr, "self_connection_status(#%u, %d, _)\n", state->id, connection_status);
    state->self_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_friend_connection_status(const Tox_Event_Friend_Connection_Status *event,
        void *user_data)
{
    State *state = (State *)user_data;

    const uint32_t friend_number = tox_event_friend_connection_status_get_friend_number(event);
    const Tox_Connection connection_status = tox_event_friend_connection_status_get_connection_status(event);
    fprintf(stderr, "handle_friend_connection_status(#%u, %u, %d, _)\n", state->id, friend_number, connection_status);
    state->friend_online = connection_status != TOX_CONNECTION_NONE;
}

static void handle_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    State *state = (State *)user_data;

    const uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
    const Tox_Conference_Type type = tox_event_conference_invite_get_type(event);
    const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
    const size_t length = tox_event_conference_invite_get_cookie_length(event);
    fprintf(stderr, "handle_conference_invite(#%u, %u, %d, uint8_t[%u], _)\n",
            state->id, friend_number, type, (unsigned)length);
    fprintf(stderr, "tox%u joining conference\n", state->id);

    {
        Tox_Err_Conference_Join err;
        state->conference = tox_conference_join(state->tox, friend_number, cookie, length, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_JOIN_OK, "failed to join a conference: err = %d", err);
        fprintf(stderr, "tox%u Joined conference %u\n", state->id, state->conference);
        state->joined = true;
    }
}

static void handle_conference_message(const Tox_Event_Conference_Message *event, void *user_data)
{
    State *state = (State *)user_data;

    const uint32_t conference_number = tox_event_conference_message_get_conference_number(event);
    const uint32_t peer_number = tox_event_conference_message_get_peer_number(event);
    const Tox_Message_Type type = tox_event_conference_message_get_type(event);
    const uint8_t *message = tox_event_conference_message_get_message(event);
    const size_t length = tox_event_conference_message_get_message_length(event);

    fprintf(stderr, "handle_conference_message(#%u, %u, %u, %d, uint8_t[%u], _)\n",
            state->id, conference_number, peer_number, type, (unsigned)length);

    fprintf(stderr, "tox%u got message: %s\n", state->id, (const char *)message);
    state->received = true;
}

static void handle_conference_peer_list_changed(const Tox_Event_Conference_Peer_List_Changed *event, void *user_data)
{
    State *state = (State *)user_data;

    const uint32_t conference_number = tox_event_conference_peer_list_changed_get_conference_number(event);
    fprintf(stderr, "handle_conference_peer_list_changed(#%u, %u, _)\n",
            state->id, conference_number);

    Tox_Err_Conference_Peer_Query err;
    uint32_t count = tox_conference_peer_count(state->tox, conference_number, &err);

    if (err != TOX_ERR_CONFERENCE_PEER_QUERY_OK) {
        fprintf(stderr, "ERROR: %d\n", err);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "tox%u has %u peers online\n", state->id, count);
    state->peers = count;
}

static void handle_conference_connected(const Tox_Event_Conference_Connected *event, void *user_data)
{
    State *state = (State *)user_data;

    // We're tox2, so now we invite tox3.
    if (state->id == 2 && !state->invited_next) {
        Tox_Err_Conference_Invite err;
        tox_conference_invite(state->tox, 1, state->conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "tox2 failed to invite tox3: err = %d", err);

        state->invited_next = true;
        fprintf(stderr, "tox2 invited tox3\n");
    }
}

static void iterate_one(
    Tox *tox, State *state, const Tox_Dispatch *dispatch)
{
    Tox_Err_Events_Iterate err;
    Tox_Events *events = tox_events_iterate(tox, true, &err);
    ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
    tox_dispatch_invoke(dispatch, events, state);
    tox_events_free(events);
}

static void iterate3_wait(
    State *state1, State *state2, State *state3,
    const Tox_Dispatch *dispatch, int interval)
{
    iterate_one(state1->tox, state1, dispatch);
    iterate_one(state2->tox, state2, dispatch);
    iterate_one(state3->tox, state3, dispatch);

    c_sleep(interval);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    State state1 = {1};
    State state2 = {2};
    State state3 = {3};

    // Create toxes.
    state1.tox = tox_new_log(nullptr, nullptr, &state1.id);
    state2.tox = tox_new_log(nullptr, nullptr, &state2.id);
    state3.tox = tox_new_log(nullptr, nullptr, &state3.id);

    tox_events_init(state1.tox);
    tox_events_init(state2.tox);
    tox_events_init(state3.tox);

    // tox1 <-> tox2, tox2 <-> tox3
    uint8_t key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(state2.tox, key);
    tox_friend_add_norequest(state1.tox, key, nullptr);  // tox1 -> tox2
    tox_self_get_public_key(state1.tox, key);
    tox_friend_add_norequest(state2.tox, key, nullptr);  // tox2 -> tox1
    tox_self_get_public_key(state3.tox, key);
    tox_friend_add_norequest(state2.tox, key, nullptr);  // tox2 -> tox3
    tox_self_get_public_key(state2.tox, key);
    tox_friend_add_norequest(state3.tox, key, nullptr);  // tox3 -> tox2

    printf("bootstrapping tox2 and tox3 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(state1.tox, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(state1.tox, nullptr);

    tox_bootstrap(state2.tox, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(state3.tox, "localhost", dht_port, dht_key, nullptr);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert(dispatch != nullptr);

    // Connection callbacks.
    tox_events_callback_self_connection_status(dispatch, handle_self_connection_status);
    tox_events_callback_friend_connection_status(dispatch, handle_friend_connection_status);

    // Conference callbacks.
    tox_events_callback_conference_invite(dispatch, handle_conference_invite);
    tox_events_callback_conference_connected(dispatch, handle_conference_connected);
    tox_events_callback_conference_message(dispatch, handle_conference_message);
    tox_events_callback_conference_peer_list_changed(dispatch, handle_conference_peer_list_changed);

    // Wait for self connection.
    fprintf(stderr, "Waiting for toxes to come online\n");

    do {
        iterate3_wait(&state1, &state2, &state3, dispatch, 100);
    } while (!state1.self_online || !state2.self_online || !state3.self_online);

    fprintf(stderr, "Toxes are online\n");

    // Wait for friend connection.
    fprintf(stderr, "Waiting for friends to connect\n");

    do {
        iterate3_wait(&state1, &state2, &state3, dispatch, 100);
    } while (!state1.friend_online || !state2.friend_online || !state3.friend_online);

    fprintf(stderr, "Friends are connected\n");

    {
        // Create new conference, tox1 is the founder.
        Tox_Err_Conference_New err;
        state1.conference = tox_conference_new(state1.tox, &err);
        state1.joined = true;
        ck_assert_msg(err == TOX_ERR_CONFERENCE_NEW_OK, "failed to create a conference: err = %d", err);
        fprintf(stderr, "Created conference: id = %u\n", state1.conference);
    }

    {
        // Invite friend.
        Tox_Err_Conference_Invite err;
        tox_conference_invite(state1.tox, 0, state1.conference, &err);
        ck_assert_msg(err == TOX_ERR_CONFERENCE_INVITE_OK, "failed to invite a friend: err = %d", err);
        state1.invited_next = true;
        fprintf(stderr, "tox1 invited tox2\n");
    }

    fprintf(stderr, "Waiting for invitation to arrive\n");

    do {
        iterate3_wait(&state1, &state2, &state3, dispatch, 100);
    } while (!state1.joined || !state2.joined || !state3.joined);

    fprintf(stderr, "Invitations accepted\n");

    fprintf(stderr, "Waiting for peers to come online\n");

    do {
        iterate3_wait(&state1, &state2, &state3, dispatch, 100);
    } while (state1.peers == 0 || state2.peers == 0 || state3.peers == 0);

    fprintf(stderr, "All peers are online\n");

    {
        fprintf(stderr, "tox1 sends a message to the group: \"hello!\"\n");
        Tox_Err_Conference_Send_Message err;
        tox_conference_send_message(state1.tox, state1.conference, TOX_MESSAGE_TYPE_NORMAL,
                                    (const uint8_t *)"hello!", 7, &err);

        if (err != TOX_ERR_CONFERENCE_SEND_MESSAGE_OK) {
            fprintf(stderr, "ERROR: %d\n", err);
            exit(EXIT_FAILURE);
        }
    }

    fprintf(stderr, "Waiting for messages to arrive\n");

    do {
        iterate3_wait(&state1, &state2, &state3, dispatch, 100);
        c_sleep(100);
    } while (!state2.received || !state3.received);

    fprintf(stderr, "Messages received. Test complete.\n");

    tox_dispatch_free(dispatch);
    tox_kill(state3.tox);
    tox_kill(state2.tox);
    tox_kill(state1.tox);

    return 0;
}
