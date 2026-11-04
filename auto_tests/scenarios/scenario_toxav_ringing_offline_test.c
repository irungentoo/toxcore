#include "framework/framework.h"
#include "../../toxav/toxav.h"
#include <stdio.h>

typedef struct {
    uint32_t state;
} AliceState;

typedef struct {
    bool incoming;
} BobState;

static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    AliceState *cs = (AliceState *)tox_node_get_script_ctx(self);
    tox_node_log(self, "Call state changed to %u", state);
    cs->state = state;
}

static void on_call(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    BobState *bs = (BobState *)tox_node_get_script_ctx(self);
    bs->incoming = true;
}

static void alice_script(ToxNode *self, void *ctx)
{
    AliceState *state = (AliceState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);
    toxav_callback_call_state(av, on_call_state, self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Toxav_Err_Call call_err;
    toxav_call(av, 0, 48, 0, &call_err);
    ck_assert(call_err == TOXAV_ERR_CALL_OK);

    // Bob goes offline while it rings, which ends the call.
    while (state->state != TOXAV_FRIEND_CALL_STATE_ERROR && tox_scenario_is_running(self)) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }
    ck_assert(state->state == TOXAV_FRIEND_CALL_STATE_ERROR);

    toxav_kill(av);
}

static void bob_script(ToxNode *self, void *ctx)
{
    BobState *state = (BobState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    Toxav_Err_New av_err;
    ToxAV *av = toxav_new(tox, &av_err);
    ck_assert(av_err == TOXAV_ERR_NEW_OK);
    toxav_callback_call(av, on_call, self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    while (!state->incoming && tox_scenario_is_running(self)) {
        toxav_iterate(av);
        tox_scenario_yield(self);
    }
    tox_node_log(self, "Going offline without answering");
    tox_node_set_offline(self, true);

    const ToxNode *alice = tox_scenario_get_node(tox_node_get_scenario(self), 0);
    while (!tox_node_is_finished(alice) && tox_scenario_is_running(self)) {
        tox_scenario_yield(self);
    }

    toxav_kill(av);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 120000);
    AliceState alice_state = {0};
    BobState bob_state = {false};

    tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(AliceState));
    tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(BobState));

    ToxNode *alice = tox_scenario_get_node(s, 0);
    ToxNode *bob = tox_scenario_get_node(s, 1);

    tox_node_bootstrap(alice, bob);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        fprintf(stderr, "Scenario failed with status %d\n", (int)res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
