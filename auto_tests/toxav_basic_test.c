#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <vpx/vpx_image.h>

#include "../testing/misc_tools.h"
#include "../toxav/toxav.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/logger.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#define TEST_REGULAR_AV 1
#define TEST_REGULAR_A 1
#define TEST_REGULAR_V 1
#define TEST_REJECT 1
#define TEST_CANCEL 1
#define TEST_MUTE_UNMUTE 1
#define TEST_STOP_RESUME_PAYLOAD 1
#define TEST_PAUSE_RESUME_SEND 1

#define ck_assert_call_control(a, b, c) do { \
    Toxav_Err_Call_Control cc_err; \
    bool ok = toxav_call_control(a, b, c, &cc_err); \
    if (!ok) { \
        printf("toxav_call_control returned error %d\n", cc_err); \
    } \
    ck_assert(ok); \
    ck_assert(cc_err == TOXAV_ERR_CALL_CONTROL_OK); \
} while (0)

typedef struct {
    bool incoming;
    uint32_t state;
} CallControl;

static void clear_call_control(CallControl *cc)
{
    const CallControl empty = {0};
    *cc = empty;
}

/**
 * Callbacks
 */
static void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    printf("Handling CALL callback\n");
    ((CallControl *)user_data)->incoming = true;
}

static void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %u\n", state);
    ((CallControl *)user_data)->state = state;
}

static void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
        uint16_t width, uint16_t height,
        uint8_t const *y, uint8_t const *u, uint8_t const *v,
        int32_t ystride, int32_t ustride, int32_t vstride,
        void *user_data)
{
    printf("Received video payload\n");
}

static void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
        int16_t const *pcm,
        size_t sample_count,
        uint8_t channels,
        uint32_t sampling_rate,
        void *user_data)
{
    printf("Received audio payload\n");
}

static void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                                       void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        ck_assert(tox_friend_add_norequest(m, public_key, nullptr) != (uint32_t) -1);
    }
}

/**
 * Iterate helper
 */
static void iterate_tox(Tox *bootstrap, Tox *alice, Tox *bob)
{
    c_sleep(100);
    tox_iterate(bootstrap, nullptr);
    tox_iterate(alice, nullptr);
    tox_iterate(bob, nullptr);
}

static bool toxav_audio_send_frame_helper(ToxAV *av, uint32_t friend_number, Toxav_Err_Send_Frame *error)
{
    static const int16_t pcm[960] = {0};
    return toxav_audio_send_frame(av, 0, pcm, 960, 1, 48000, nullptr);
}

static void regular_call_flow(
    Tox *alice, Tox *bob, Tox *bootstrap,
    ToxAV *alice_av, ToxAV *bob_av,
    CallControl *alice_cc, CallControl *bob_cc,
    int a_br, int v_br)
{
    clear_call_control(alice_cc);
    clear_call_control(bob_cc);

    Toxav_Err_Call call_err;
    toxav_call(alice_av, 0, a_br, v_br, &call_err);

    ck_assert_msg(call_err == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", call_err);

    const time_t start_time = time(nullptr);

    do {
        if (bob_cc->incoming) {
            Toxav_Err_Answer answer_err;
            toxav_answer(bob_av, 0, a_br, v_br, &answer_err);

            ck_assert_msg(answer_err == TOXAV_ERR_ANSWER_OK, "toxav_answer failed: %d\n", answer_err);

            bob_cc->incoming = false;
        } else { /* TODO(mannol): rtp */
            if (time(nullptr) - start_time >= 1) {

                Toxav_Err_Call_Control cc_err;
                toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);

                ck_assert_msg(cc_err == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", cc_err);
            }
        }

        iterate_tox(bootstrap, alice, bob);
    } while (bob_cc->state != TOXAV_FRIEND_CALL_STATE_FINISHED);

    printf("Success!\n");
}

static void test_av_flows(void)
{
    Tox *alice, *bob, *bootstrap;
    ToxAV *alice_av, *bob_av;
    uint32_t index[] = { 1, 2, 3 };

    CallControl alice_cc, bob_cc;

    {
        Tox_Err_New error;

        bootstrap = tox_new_log(nullptr, &error, &index[0]);
        ck_assert(error == TOX_ERR_NEW_OK);

        alice = tox_new_log(nullptr, &error, &index[1]);
        ck_assert(error == TOX_ERR_NEW_OK);

        bob = tox_new_log(nullptr, &error, &index[2]);
        ck_assert(error == TOX_ERR_NEW_OK);
    }

    printf("Created 3 instances of Tox\n");
    printf("Preparing network...\n");
    long long unsigned int cur_time = time(nullptr);

    uint8_t address[TOX_ADDRESS_SIZE];

    tox_callback_friend_request(alice, t_accept_friend_request_cb);
    tox_self_get_address(alice, address);

    printf("bootstrapping Alice and Bob off a third bootstrap node\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(bootstrap, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(bootstrap, nullptr);

    tox_bootstrap(alice, "localhost", dht_port, dht_key, nullptr);
    tox_bootstrap(bob, "localhost", dht_port, dht_key, nullptr);

    ck_assert(tox_friend_add(bob, address, (const uint8_t *)"gentoo", 7, nullptr) != (uint32_t) -1);

    uint8_t off = 1;

    while (true) {
        iterate_tox(bootstrap, alice, bob);

        if (tox_self_get_connection_status(bootstrap) &&
                tox_self_get_connection_status(alice) &&
                tox_self_get_connection_status(bob) && off) {
            printf("Toxes are online, took %llu seconds\n", time(nullptr) - cur_time);
            off = 0;
        }

        if (tox_friend_get_connection_status(alice, 0, nullptr) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(bob, 0, nullptr) == TOX_CONNECTION_UDP) {
            break;
        }

        c_sleep(20);
    }

    {
        Toxav_Err_New error;
        alice_av = toxav_new(alice, &error);
        ck_assert(error == TOXAV_ERR_NEW_OK);

        bob_av = toxav_new(bob, &error);
        ck_assert(error == TOXAV_ERR_NEW_OK);
    }

    toxav_callback_call(alice_av, t_toxav_call_cb, &alice_cc);
    toxav_callback_call_state(alice_av, t_toxav_call_state_cb, &alice_cc);
    toxav_callback_video_receive_frame(alice_av, t_toxav_receive_video_frame_cb, &alice_cc);
    toxav_callback_audio_receive_frame(alice_av, t_toxav_receive_audio_frame_cb, &alice_cc);

    toxav_callback_call(bob_av, t_toxav_call_cb, &bob_cc);
    toxav_callback_call_state(bob_av, t_toxav_call_state_cb, &bob_cc);
    toxav_callback_video_receive_frame(bob_av, t_toxav_receive_video_frame_cb, &bob_cc);
    toxav_callback_audio_receive_frame(bob_av, t_toxav_receive_audio_frame_cb, &bob_cc);

    printf("Created 2 instances of ToxAV\n");
    printf("All set after %llu seconds!\n", time(nullptr) - cur_time);

    if (TEST_REGULAR_AV) {
        printf("\nTrying regular call (Audio and Video)...\n");
        regular_call_flow(alice, bob, bootstrap, alice_av, bob_av, &alice_cc, &bob_cc,
                          48, 4000);
    }

    if (TEST_REGULAR_A) {
        printf("\nTrying regular call (Audio only)...\n");
        regular_call_flow(alice, bob, bootstrap, alice_av, bob_av, &alice_cc, &bob_cc,
                          48, 0);
    }

    if (TEST_REGULAR_V) {
        printf("\nTrying regular call (Video only)...\n");
        regular_call_flow(alice, bob, bootstrap, alice_av, bob_av, &alice_cc, &bob_cc,
                          0, 4000);
    }

    if (TEST_REJECT) { /* Alice calls; Bob rejects */
        printf("\nTrying reject flow...\n");

        clear_call_control(&alice_cc);
        clear_call_control(&bob_cc);

        {
            Toxav_Err_Call rc;
            toxav_call(alice_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (!bob_cc.incoming);

        /* Reject */
        {
            Toxav_Err_Call_Control rc;
            toxav_call_control(bob_av, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (alice_cc.state != TOXAV_FRIEND_CALL_STATE_FINISHED);

        printf("Success!\n");
    }

    if (TEST_CANCEL) { /* Alice calls; Alice cancels while ringing */
        printf("\nTrying cancel (while ringing) flow...\n");

        clear_call_control(&alice_cc);
        clear_call_control(&bob_cc);

        {
            Toxav_Err_Call rc;
            toxav_call(alice_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (!bob_cc.incoming);

        /* Cancel */
        {
            Toxav_Err_Call_Control rc;
            toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", rc);
        }

        /* Alice will not receive end state */
        do {
            iterate_tox(bootstrap, alice, bob);
        } while (bob_cc.state != TOXAV_FRIEND_CALL_STATE_FINISHED);

        printf("Success!\n");
    }

    if (TEST_MUTE_UNMUTE) { /* Check Mute-Unmute etc */
        printf("\nTrying mute functionality...\n");

        clear_call_control(&alice_cc);
        clear_call_control(&bob_cc);

        /* Assume sending audio and video */
        {
            Toxav_Err_Call rc;
            toxav_call(alice_av, 0, 48, 1000, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (!bob_cc.incoming);

        /* At first try all stuff while in invalid state */
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_PAUSE, nullptr));
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_RESUME, nullptr));
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_MUTE_AUDIO, nullptr));
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_UNMUTE_AUDIO, nullptr));
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_HIDE_VIDEO, nullptr));
        ck_assert(!toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_SHOW_VIDEO, nullptr));

        {
            Toxav_Err_Answer rc;
            toxav_answer(bob_av, 0, 48, 4000, &rc);

            ck_assert_msg(rc == TOXAV_ERR_ANSWER_OK, "toxav_answer failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);

        /* Pause and Resume */
        printf("Pause and Resume\n");
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_PAUSE);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state == 0);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_RESUME);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state & (TOXAV_FRIEND_CALL_STATE_SENDING_A | TOXAV_FRIEND_CALL_STATE_SENDING_V));

        /* Mute/Unmute single */
        printf("Mute/Unmute single\n");
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_MUTE_AUDIO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state ^ TOXAV_FRIEND_CALL_STATE_ACCEPTING_A);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_UNMUTE_AUDIO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A);

        /* Mute/Unmute both */
        printf("Mute/Unmute both\n");
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_MUTE_AUDIO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state ^ TOXAV_FRIEND_CALL_STATE_ACCEPTING_A);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_HIDE_VIDEO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state ^ TOXAV_FRIEND_CALL_STATE_ACCEPTING_V);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_UNMUTE_AUDIO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_A);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_SHOW_VIDEO);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state & TOXAV_FRIEND_CALL_STATE_ACCEPTING_V);

        {
            Toxav_Err_Call_Control rc;
            toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state == TOXAV_FRIEND_CALL_STATE_FINISHED);

        printf("Success!\n");
    }

    if (TEST_STOP_RESUME_PAYLOAD) { /* Stop and resume audio/video payload */
        printf("\nTrying stop/resume functionality...\n");

        clear_call_control(&alice_cc);
        clear_call_control(&bob_cc);

        /* Assume sending audio and video */
        {
            Toxav_Err_Call rc;
            toxav_call(alice_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (!bob_cc.incoming);

        {
            Toxav_Err_Answer rc;
            toxav_answer(bob_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_ANSWER_OK, "toxav_answer failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);

        printf("Call started as audio only\n");
        printf("Turning on video for Alice...\n");
        ck_assert(toxav_video_set_bit_rate(alice_av, 0, 1000, nullptr));

        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state & TOXAV_FRIEND_CALL_STATE_SENDING_V);

        printf("Turning off video for Alice...\n");
        ck_assert(toxav_video_set_bit_rate(alice_av, 0, 0, nullptr));

        iterate_tox(bootstrap, alice, bob);
        ck_assert(!(bob_cc.state & TOXAV_FRIEND_CALL_STATE_SENDING_V));

        printf("Turning off audio for Alice...\n");
        ck_assert(toxav_audio_set_bit_rate(alice_av, 0, 0, nullptr));

        iterate_tox(bootstrap, alice, bob);
        ck_assert(!(bob_cc.state & TOXAV_FRIEND_CALL_STATE_SENDING_A));

        {
            Toxav_Err_Call_Control rc;
            toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state == TOXAV_FRIEND_CALL_STATE_FINISHED);

        printf("Success!\n");
    }

    if (TEST_PAUSE_RESUME_SEND) { /* Stop and resume audio/video payload and test send options */
        printf("\nTrying stop/resume functionality...\n");

        clear_call_control(&alice_cc);
        clear_call_control(&bob_cc);

        /* Assume sending audio and video */
        {
            Toxav_Err_Call rc;
            toxav_call(alice_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_OK, "toxav_call failed: %d\n", rc);
        }

        do {
            iterate_tox(bootstrap, alice, bob);
        } while (!bob_cc.incoming);

        {
            Toxav_Err_Answer rc;
            toxav_answer(bob_av, 0, 48, 0, &rc);

            ck_assert_msg(rc == TOXAV_ERR_ANSWER_OK, "toxav_answer failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_PAUSE);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(!toxav_audio_send_frame_helper(alice_av, 0, nullptr));
        ck_assert(!toxav_audio_send_frame_helper(bob_av, 0, nullptr));
        ck_assert_call_control(alice_av, 0, TOXAV_CALL_CONTROL_RESUME);
        iterate_tox(bootstrap, alice, bob);
        ck_assert(toxav_audio_send_frame_helper(alice_av, 0, nullptr));
        ck_assert(toxav_audio_send_frame_helper(bob_av, 0, nullptr));
        iterate_tox(bootstrap, alice, bob);

        {
            Toxav_Err_Call_Control rc;
            toxav_call_control(alice_av, 0, TOXAV_CALL_CONTROL_CANCEL, &rc);

            ck_assert_msg(rc == TOXAV_ERR_CALL_CONTROL_OK, "toxav_call_control failed: %d\n", rc);
        }

        iterate_tox(bootstrap, alice, bob);
        ck_assert(bob_cc.state == TOXAV_FRIEND_CALL_STATE_FINISHED);

        printf("Success!\n");
    }

    toxav_kill(bob_av);
    toxav_kill(alice_av);
    tox_kill(bob);
    tox_kill(alice);
    tox_kill(bootstrap);

    printf("\nTest successful!\n");
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_av_flows();
    return 0;
}
