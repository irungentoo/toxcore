#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENDED (TOXAV_FRIEND_CALL_STATE_FINISHED | TOXAV_FRIEND_CALL_STATE_ERROR)

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
}

static ToxAV *start_av(ToxNode *self)
{
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox_node_get_tox(self), &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, on_call, self);
    toxav_callback_call_state(av, on_call_state, self);
    // Answering fails without a frame receive callback.
    toxav_callback_audio_receive_frame(av, on_audio_receive, self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);
    return av;
}

static void run_for(ToxNode *self, ToxAV *av, uint64_t ms)
{
    ToxScenario *s = tox_node_get_scenario(self);
    const uint64_t until = tox_scenario_get_time(s) + ms;
    WAIT_UNTIL_AV(av, tox_scenario_get_time(s) >= until);
}

static void hang_up(ToxAV *av)
{
    Toxav_Err_Call_Control err;
    toxav_call_control(av, 0, TOXAV_CALL_CONTROL_CANCEL, &err);
    ck_assert(err == TOXAV_ERR_CALL_CONTROL_OK);
}

static void alice_script(ToxNode *self, void *ctx)
{
    CallState *state = (CallState *)ctx;
    ToxAV *av = start_av(self);

    for (int call = 0; call < 2; ++call) {
        state->state = 0;
        Toxav_Err_Call call_err;
        toxav_call(av, 0, 48, 0, &call_err);
        ck_assert(call_err == TOXAV_ERR_CALL_OK);
        WAIT_UNTIL_AV(av, state->state & TOXAV_FRIEND_CALL_STATE_SENDING_A);

        if (call == 0) {
            // Both hang up at once.
            tox_scenario_barrier_wait(self);
            hang_up(av);
            // Long enough for what's left of it to reach the other end.
            run_for(self, av, 1000);
        }
    }

    // The next call stays up.
    run_for(self, av, 2000);
    ck_assert((state->state & ENDED) == 0);
    tox_node_log(self, "The call after the crossed hang-up stayed up.");

    tox_scenario_barrier_wait(self);
    hang_up(av);
    toxav_kill(av);
}

static void bob_script(ToxNode *self, void *ctx)
{
    CallState *state = (CallState *)ctx;
    ToxAV *av = start_av(self);

    for (int call = 0; call < 2; ++call) {
        WAIT_UNTIL_AV(av, state->incoming);
        state->incoming = false;
        state->state = 0;
        Toxav_Err_Answer answer_err;
        toxav_answer(av, 0, 48, 0, &answer_err);
        ck_assert(answer_err == TOXAV_ERR_ANSWER_OK);

        if (call == 0) {
            tox_scenario_barrier_wait(self);
            hang_up(av);
        }
    }

    run_for(self, av, 2000);
    ck_assert((state->state & ENDED) == 0);

    tox_scenario_barrier_wait(self);
    WAIT_UNTIL_AV(av, state->state & TOXAV_FRIEND_CALL_STATE_FINISHED);
    toxav_kill(av);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 30000);

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

#undef ENDED
