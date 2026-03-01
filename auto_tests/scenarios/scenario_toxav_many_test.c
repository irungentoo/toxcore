#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define NUM_BOBS 3

typedef struct {
    bool incoming;
    uint32_t state;
} CallState;

static void on_call(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    CallState *states = (CallState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Received call from friend %u", friend_number);
    states[friend_number].incoming = true;
}

static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    CallState *states = (CallState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Call state for friend %u changed to %u", friend_number, state);
    states[friend_number].state = state;
}

static void on_audio_receive(ToxAV *av, uint32_t friend_number, int16_t const *pcm, size_t sample_count,
                             uint8_t channels, uint32_t sampling_rate, void *user_data)
{
}

static void on_video_receive(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                             uint8_t const *y, uint8_t const *u, uint8_t const *v,
                             int32_t ystride, int32_t ustride, int32_t vstride, void *user_data)
{
}

static void alice_script(ToxNode *self, void *ctx)
{
    CallState *states = (CallState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, on_call, self);
    toxav_callback_call_state(av, on_call_state, self);
    toxav_callback_audio_receive_frame(av, on_audio_receive, self);
    toxav_callback_video_receive_frame(av, on_video_receive, self);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    for (uint32_t i = 0; i < NUM_BOBS; i++) {
        WAIT_UNTIL(tox_node_is_friend_connected(self, i));
    }

    tox_node_log(self, "All Bobs connected. Calling them...");

    for (uint32_t i = 0; i < NUM_BOBS; i++) {
        Toxav_Err_Call call_err;
        toxav_call(av, i, 48, 3000, &call_err);
        ck_assert(call_err == TOXAV_ERR_CALL_OK);
    }

    int16_t pcm[960] = {0};
    uint8_t *video_y = (uint8_t *)calloc(800 * 600, sizeof(uint8_t));
    uint8_t *video_u = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));
    uint8_t *video_v = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));

    // Send a few frames to verify flow
    for (int i = 0; i < 20; i++) {
        toxav_iterate(av);
        for (uint32_t j = 0; j < NUM_BOBS; j++) {
            if (states[j].state & TOXAV_FRIEND_CALL_STATE_SENDING_A) {
                toxav_audio_send_frame(av, j, pcm, 960, 1, 48000, nullptr);
            }
            if (states[j].state & TOXAV_FRIEND_CALL_STATE_SENDING_V) {
                toxav_video_send_frame(av, j, 800, 600, video_y, video_u, video_v, nullptr);
            }
        }
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Hanging up all calls...");
    for (uint32_t i = 0; i < NUM_BOBS; i++) {
        toxav_call_control(av, i, TOXAV_CALL_CONTROL_CANCEL, nullptr);
    }

    // Give it a few ticks to send hangup packets
    for (int i = 0; i < 5; i++) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }

    free(video_y);
    free(video_u);
    free(video_v);
    toxav_kill(av);
}

static void bob_script(ToxNode *self, void *ctx)
{
    CallState *states = (CallState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, on_call, self);
    toxav_callback_call_state(av, on_call_state, self);
    toxav_callback_audio_receive_frame(av, on_audio_receive, self);
    toxav_callback_video_receive_frame(av, on_video_receive, self);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    while (!states[0].incoming && tox_scenario_is_running(self)) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Answering call...");
    Toxav_Err_Answer answer_err;
    toxav_answer(av, 0, 8, 500, &answer_err);
    ck_assert(answer_err == TOXAV_ERR_ANSWER_OK);

    int16_t pcm[960] = {0};
    uint8_t *video_y = (uint8_t *)calloc(800 * 600, sizeof(uint8_t));
    uint8_t *video_u = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));
    uint8_t *video_v = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));

    while (!(states[0].state & TOXAV_FRIEND_CALL_STATE_FINISHED) && tox_scenario_is_running(self)) {
        toxav_iterate(av);
        if (states[0].state & TOXAV_FRIEND_CALL_STATE_SENDING_A) {
            toxav_audio_send_frame(av, 0, pcm, 960, 1, 48000, nullptr);
        }
        if (states[0].state & TOXAV_FRIEND_CALL_STATE_SENDING_V) {
            toxav_video_send_frame(av, 0, 800, 600, video_y, video_u, video_v, nullptr);
        }
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Call finished.");

    free(video_y);
    free(video_u);
    free(video_v);
    toxav_kill(av);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    CallState alice_states[NUM_BOBS] = {0};
    Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, false);

    ToxNode *alice = tox_scenario_add_node_ex(s, "Alice", alice_script, alice_states, sizeof(alice_states), opts);

    ToxNode *bobs[NUM_BOBS];
    CallState bob_states[NUM_BOBS];
    for (int i = 0; i < NUM_BOBS; i++) {
        char name[32];
        snprintf(name, sizeof(name), "Bob-%d", i);
        bob_states[i] = (CallState) {
            0
        };
        bobs[i] = tox_scenario_add_node_ex(s, name, bob_script, &bob_states[i], sizeof(CallState), opts);

        tox_node_bootstrap(bobs[i], alice);
        tox_node_friend_add(alice, bobs[i]);
        tox_node_friend_add(bobs[i], alice);
    }

    tox_options_free(opts);

    ToxScenarioStatus res = tox_scenario_run(s);
    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
