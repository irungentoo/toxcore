#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    bool incoming;
    uint32_t state;
} CallState;

#define WAIT_UNTIL_AV(av, cond) do { \
    while(!(cond) && tox_scenario_is_running(self)) { \
        toxav_iterate(av); \
        tox_scenario_yield(self); \
    } \
} while(0)

static void on_call(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    CallState *state = (CallState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Received call from friend %u", friend_number);
    state->incoming = true;
}

static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    CallState *cs = (CallState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Call state changed to %u", state);
    cs->state = state;
}

static void on_audio_receive(ToxAV *av, uint32_t friend_number, int16_t const *pcm, size_t sample_count,
                             uint8_t channels, uint32_t sampling_rate, void *user_data)
{
    (void)av;
    (void)friend_number;
    (void)pcm;
    (void)sample_count;
    (void)channels;
    (void)sampling_rate;
    (void)user_data;
}

static void on_video_receive(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                             uint8_t const *y, uint8_t const *u, uint8_t const *v,
                             int32_t ystride, int32_t ustride, int32_t vstride, void *user_data)
{
    (void)av;
    (void)friend_number;
    (void)width;
    (void)height;
    (void)y;
    (void)u;
    (void)v;
    (void)ystride;
    (void)ustride;
    (void)vstride;
    (void)user_data;
}

static void alice_script(ToxNode *self, void *ctx)
{
    CallState *state = (CallState *)ctx;
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

    // 1. Regular AV call - Alice calls, Bob answers, Bob hangs up
    tox_node_log(self, "--- Starting Regular AV Call ---");
    state->state = 0;
    Toxav_Err_Call call_err;
    toxav_call(av, 0, 48, 4000, &call_err);
    ck_assert(call_err == TOXAV_ERR_CALL_OK);

    WAIT_UNTIL_AV(av, state->state & TOXAV_FRIEND_CALL_STATE_FINISHED);
    tox_node_log(self, "Regular AV Call finished (state=%u)", state->state);

    tox_scenario_barrier_wait(self);

    // 2. Reject flow - Alice calls, Bob rejects
    tox_node_log(self, "--- Starting Reject Flow ---");
    state->state = 0;
    toxav_call(av, 0, 48, 0, &call_err);
    ck_assert(call_err == TOXAV_ERR_CALL_OK);

    WAIT_UNTIL_AV(av, state->state & TOXAV_FRIEND_CALL_STATE_FINISHED);
    tox_node_log(self, "Reject Flow finished");

    tox_scenario_barrier_wait(self);

    // 3. Cancel flow - Alice calls, Alice cancels
    tox_node_log(self, "--- Starting Cancel Flow ---");
    state->state = 0;
    toxav_call(av, 0, 48, 0, &call_err);
    ck_assert(call_err == TOXAV_ERR_CALL_OK);

    // Wait for Bob to see it ringing
    tox_scenario_barrier_wait(self);

    tox_node_log(self, "Alice: Canceling call...");
    Toxav_Err_Call_Control cc_err;
    toxav_call_control(av, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);
    ck_assert(cc_err == TOXAV_ERR_CALL_CONTROL_OK);

    // Alice doesn't receive FINISHED state when SHE cancels
    tox_node_log(self, "Alice: Cancel Flow finished");

    tox_scenario_barrier_wait(self);

    toxav_kill(av);
}

static void bob_script(ToxNode *self, void *ctx)
{
    CallState *state = (CallState *)ctx;
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

    // 1. Regular AV call - Bob answers, then hangs up
    WAIT_UNTIL_AV(av, state->incoming);
    state->incoming = false;
    Toxav_Err_Answer answer_err;
    toxav_answer(av, 0, 48, 4000, &answer_err);
    ck_assert(answer_err == TOXAV_ERR_ANSWER_OK);

    // Wait a bit and hang up
    for (int i = 0; i < 10; i++) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Bob: Hanging up...");
    Toxav_Err_Call_Control cc_err;
    toxav_call_control(av, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);
    ck_assert(cc_err == TOXAV_ERR_CALL_CONTROL_OK);

    tox_scenario_barrier_wait(self);

    // 2. Reject flow - Bob rejects
    WAIT_UNTIL_AV(av, state->incoming);
    state->incoming = false;
    tox_node_log(self, "Bob: Rejecting call...");
    toxav_call_control(av, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);
    ck_assert(cc_err == TOXAV_ERR_CALL_CONTROL_OK);

    tox_scenario_barrier_wait(self);

    // 3. Cancel flow - Alice cancels
    WAIT_UNTIL_AV(av, state->incoming);
    state->incoming = false;
    tox_scenario_barrier_wait(self); // Alice will now cancel

    WAIT_UNTIL_AV(av, state->state & TOXAV_FRIEND_CALL_STATE_FINISHED);
    tox_node_log(self, "Bob: Cancel Flow finished (Alice canceled)");

    tox_scenario_barrier_wait(self);

    toxav_kill(av);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 60000);

    CallState alice_state = {0};
    CallState bob_state = {0};

    Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(opts, false);
    tox_options_set_local_discovery_enabled(opts, false);

    ToxNode *alice = tox_scenario_add_node_ex(s, "Alice", alice_script, &alice_state, sizeof(CallState), opts);
    ToxNode *bob = tox_scenario_add_node_ex(s, "Bob", bob_script, &bob_state, sizeof(CallState), opts);

    tox_options_free(opts);

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    tox_scenario_free(s);
    return (res == TOX_SCENARIO_DONE) ? 0 : 1;
}
