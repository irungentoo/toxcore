#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_NODES 4

typedef struct {
    bool invited_next;
    uint32_t audio_received_mask;
    uint32_t group_number;
    bool joined;
} State;

static void audio_callback(void *tox, uint32_t group_number, uint32_t peer_number, const int16_t *pcm,
                           unsigned int samples, uint8_t channels, uint32_t sample_rate, void *user_data)
{
    (void)tox;
    (void)group_number;
    (void)sample_rate;
    (void)channels;
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    if (samples > 0) {
        state->audio_received_mask |= (1 << peer_number);
    }
}

static void on_conference_invite(const Tox_Event_Conference_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
    const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
    size_t length = tox_event_conference_invite_get_cookie_length(event);

    tox_node_log(self, "Received conference invite from friend %u", friend_number);
    state->group_number = toxav_join_av_groupchat(tox_node_get_tox(self), friend_number, cookie, length, audio_callback, self);
    ck_assert(state->group_number != (uint32_t) -1);
    state->joined = true;
}

static void on_conference_connected(const Tox_Event_Conference_Connected *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    uint32_t group_number = tox_event_conference_connected_get_conference_number(event);

    if (state->invited_next) {
        return;
    }

    // In a linear graph, friend 0 is i-1, friend 1 is i+1 (if exists)
    // We want to invite the next peer.
    uint32_t friend_count = tox_self_get_friend_list_size(tox_node_get_tox(self));
    if (friend_count > 1 || tox_node_get_index(self) == 0) {
        uint32_t friend_to_invite = (tox_node_get_index(self) == 0) ? 0 : 1;
        if (friend_to_invite < friend_count) {
            Tox_Err_Conference_Invite err;
            tox_conference_invite(tox_node_get_tox(self), friend_to_invite, group_number, &err);
            if (err == TOX_ERR_CONFERENCE_INVITE_OK) {
                tox_node_log(self, "Invited next friend (%u)", friend_to_invite);
                state->invited_next = true;
            }
        }
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);

    tox_events_callback_conference_invite(dispatch, on_conference_invite);
    tox_events_callback_conference_connected(dispatch, on_conference_connected);

    WAIT_UNTIL(tox_node_is_self_connected(self));

    if (tox_node_get_index(self) == 0) {
        tox_node_log(self, "Creating AV group...");
        state->group_number = toxav_add_av_groupchat(tox, audio_callback, self);
        ck_assert(state->group_number != (uint32_t) -1);
        state->joined = true;

        // Peer 0 has only one friend (Peer 1)
        WAIT_UNTIL(tox_node_is_friend_connected(self, 0));
        tox_conference_invite(tox, 0, state->group_number, nullptr);
        state->invited_next = true;
    }

    // Wait until joined and everyone is in the group
    WAIT_UNTIL(state->joined);
    while (tox_node_get_conference_peer_count(self, state->group_number) < (uint32_t)NUM_NODES) {
        tox_scenario_yield(self);
    }
    tox_node_log(self, "All %u peers in group!", (uint32_t)NUM_NODES);

    // Send audio for a bit
    const int16_t pcm[960] = {0};
    for (int i = 0; i < 40; i++) {
        toxav_group_send_audio(tox, state->group_number, pcm, 960, 1, 48000);
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Audio sent. Received audio mask: %u", state->audio_received_mask);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);
    State states[NUM_NODES] = {0};
    ToxNode *nodes[NUM_NODES];

    for (uint32_t i = 0; i < NUM_NODES; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Peer-%u", i);
        nodes[i] = tox_scenario_add_node(s, name, peer_script, &states[i], sizeof(State));
    }

    // Linear graph
    for (uint32_t i = 0; i < NUM_NODES - 1; i++) {
        tox_node_bootstrap(nodes[i + 1], nodes[i]);
        tox_node_friend_add(nodes[i], nodes[i + 1]);
        tox_node_friend_add(nodes[i + 1], nodes[i]);
    }

    ToxScenarioStatus res = tox_scenario_run(s);
    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
