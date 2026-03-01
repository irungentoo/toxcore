#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t state;
} AliceState;

typedef struct {
    uint32_t state;
} BobState;

static void on_call_state_alice(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *cs = (AliceState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Call state changed to %u", state);
    cs->state = state;
}

static void on_call_state_bob(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *cs = (BobState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Call state changed to %u", state);
    cs->state = state;
}

static void on_audio_receive_dummy(ToxAV *av, uint32_t friend_number, int16_t const *pcm, size_t sample_count,
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

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);

    toxav_callback_call_state(av, on_call_state_alice, self);
    toxav_callback_audio_receive_frame(av, on_audio_receive_dummy, self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_node_log(self, "Calling Bob...");
    Toxav_Err_Call call_err;
    toxav_call(av, 0, 48, 0, &call_err);
    ck_assert(call_err == TOXAV_ERR_CALL_OK);

    // Wait until call is active
    while (!(state->state & TOXAV_FRIEND_CALL_STATE_SENDING_A) && tox_scenario_is_running(self)) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Call is active, Alice deletes Bob to trigger offline branch in ToxAV...");
    Tox_Err_Friend_Delete fr_err;
    tox_friend_delete(tox, 0, &fr_err);
    ck_assert(fr_err == TOX_ERR_FRIEND_DELETE_OK);

    tox_node_log(self, "Alice deleted Bob, running toxav_iterate to trigger UAF...");
    toxav_iterate(av);

    tox_node_log(self, "Successfully finished toxav_iterate");
    toxav_kill(av);
}

static void on_call_bob(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    tox_node_log(self, "Received call from Alice, answering...");
    Toxav_Err_Answer err;
    toxav_answer(av, friend_number, 48, 0, &err);
    ck_assert(err == TOXAV_ERR_ANSWER_OK);
}

static void bob_script(ToxNode *self, void *ctx)
{
    BobState *state = (BobState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, on_call_bob, self);
    toxav_callback_call_state(av, on_call_state_bob, self);
    toxav_callback_audio_receive_frame(av, on_audio_receive_dummy, self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    // Run until the call is finished (Alice deletes us or hangs up)
    while (tox_scenario_is_running(self)) {
        toxav_iterate(av);
        if (state->state & (TOXAV_FRIEND_CALL_STATE_FINISHED | TOXAV_FRIEND_CALL_STATE_ERROR)) {
            break;
        }
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Bob script finished");
    toxav_kill(av);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 30000);

    AliceState alice_state = {0};
    BobState bob_state = {0};

    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(BobState));

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %d\n", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
