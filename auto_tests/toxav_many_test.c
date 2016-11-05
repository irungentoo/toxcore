#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "helpers.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <vpx/vpx_image.h>

#include "../toxav/toxav.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/logger.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <pthread.h>
#include <unistd.h>
#define c_sleep(x) usleep(1000*x)
#endif


typedef struct {
    bool incoming;
    uint32_t state;
} CallControl;

typedef struct {
    ToxAV *AliceAV;
    ToxAV *BobAV;
    CallControl *AliceCC;
    CallControl *BobCC;
    uint32_t friend_number;
} thread_data;

/**
 * Callbacks
 */
static void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    (void) av;
    (void) audio_enabled;
    (void) video_enabled;

    printf("Handling CALL callback\n");
    ((CallControl *)user_data)[friend_number].incoming = true;
}
static void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %d %p\n", state, (void *)av);
    ((CallControl *)user_data)[friend_number].state = state;
}
static void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
        uint16_t width, uint16_t height,
        uint8_t const *y, uint8_t const *u, uint8_t const *v,
        int32_t ystride, int32_t ustride, int32_t vstride,
        void *user_data)
{
    (void) av;
    (void) friend_number;
    (void) width;
    (void) height;
    (void) y;
    (void) u;
    (void) v;
    (void) ystride;
    (void) ustride;
    (void) vstride;
    (void) user_data;
}
static void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
        int16_t const *pcm,
        size_t sample_count,
        uint8_t channels,
        uint32_t sampling_rate,
        void *user_data)
{
    (void) av;
    (void) friend_number;
    (void) pcm;
    (void) sample_count;
    (void) channels;
    (void) sampling_rate;
    (void) user_data;
}
static void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                                       void *userdata)
{
    (void) userdata;

    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        ck_assert(tox_friend_add_norequest(m, public_key, NULL) != (uint32_t) ~0);
    }
}


/**
 * Iterate helper
 */
static ToxAV *setup_av_instance(Tox *tox, CallControl *CC)
{
    TOXAV_ERR_NEW error;

    ToxAV *av = toxav_new(tox, &error);
    ck_assert(error == TOXAV_ERR_NEW_OK);

    toxav_callback_call(av, t_toxav_call_cb, CC);
    toxav_callback_call_state(av, t_toxav_call_state_cb, CC);
    toxav_callback_video_receive_frame(av, t_toxav_receive_video_frame_cb, CC);
    toxav_callback_audio_receive_frame(av, t_toxav_receive_audio_frame_cb, CC);

    return av;
}
static void *call_thread(void *pd)
{
    ToxAV *AliceAV = ((thread_data *) pd)->AliceAV;
    ToxAV *BobAV = ((thread_data *) pd)->BobAV;
    CallControl *AliceCC = ((thread_data *) pd)->AliceCC;
    CallControl *BobCC = ((thread_data *) pd)->BobCC;
    uint32_t friend_number = ((thread_data *) pd)->friend_number;

    memset(AliceCC, 0, sizeof(CallControl));
    memset(BobCC, 0, sizeof(CallControl));

    { /* Call */
        TOXAV_ERR_CALL rc;
        toxav_call(AliceAV, friend_number, 48, 3000, &rc);

        if (rc != TOXAV_ERR_CALL_OK) {
            printf("toxav_call failed: %d\n", rc);
            ck_assert(0);
        }
    }

    while (!BobCC->incoming) {
        c_sleep(10);
    }

    { /* Answer */
        TOXAV_ERR_ANSWER rc;
        toxav_answer(BobAV, 0, 8, 500, &rc);

        if (rc != TOXAV_ERR_ANSWER_OK) {
            printf("toxav_answer failed: %d\n", rc);
            ck_assert(0);
        }
    }

    c_sleep(30);

    int16_t *PCM = (int16_t *)calloc(960, sizeof(int16_t));
    uint8_t *video_y = (uint8_t *)calloc(800 * 600, sizeof(uint8_t));
    uint8_t *video_u = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));
    uint8_t *video_v = (uint8_t *)calloc(800 * 600 / 4, sizeof(uint8_t));

    time_t start_time = time(NULL);

    while (time(NULL) - start_time < 4) {
        toxav_iterate(AliceAV);
        toxav_iterate(BobAV);

        toxav_audio_send_frame(AliceAV, friend_number, PCM, 960, 1, 48000, NULL);
        toxav_audio_send_frame(BobAV, 0, PCM, 960, 1, 48000, NULL);

        toxav_video_send_frame(AliceAV, friend_number, 800, 600, video_y, video_u, video_v, NULL);
        toxav_video_send_frame(BobAV, 0, 800, 600, video_y, video_u, video_v, NULL);

        c_sleep(10);
    }

    { /* Hangup */
        TOXAV_ERR_CALL_CONTROL rc;
        toxav_call_control(AliceAV, friend_number, TOXAV_CALL_CONTROL_CANCEL, &rc);

        if (rc != TOXAV_ERR_CALL_CONTROL_OK) {
            printf("toxav_call_control failed: %d %p %p\n", rc, (void *)AliceAV, (void *)BobAV);
        }
    }

    c_sleep(30);

    free(PCM);
    free(video_y);
    free(video_u);
    free(video_v);

    printf("Closing thread\n");
    pthread_exit(NULL);
}


START_TEST(test_AV_three_calls)
{
    uint32_t index[] = { 1, 2, 3, 4, 5 };
    Tox *Alice, *bootstrap, *Bobs[3];
    ToxAV *AliceAV, *BobsAV[3];

    CallControl AliceCC[3], BobsCC[3];

    {
        TOX_ERR_NEW error;

        bootstrap = tox_new_log(NULL, &error, &index[0]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Alice = tox_new_log(NULL, &error, &index[1]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[0] = tox_new_log(NULL, &error, &index[2]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[1] = tox_new_log(NULL, &error, &index[3]);
        ck_assert(error == TOX_ERR_NEW_OK);

        Bobs[2] = tox_new_log(NULL, &error, &index[4]);
        ck_assert(error == TOX_ERR_NEW_OK);
    }

    printf("Created 5 instances of Tox\n");
    printf("Preparing network...\n");
    long long unsigned int cur_time = time(NULL);

    uint8_t address[TOX_ADDRESS_SIZE];

    tox_callback_friend_request(Alice, t_accept_friend_request_cb);
    tox_self_get_address(Alice, address);


    ck_assert(tox_friend_add(Bobs[0], address, (const uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);
    ck_assert(tox_friend_add(Bobs[1], address, (const uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);
    ck_assert(tox_friend_add(Bobs[2], address, (const uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);

    uint8_t off = 1;

    while (1) {
        tox_iterate(bootstrap, NULL);
        tox_iterate(Alice, NULL);
        tox_iterate(Bobs[0], NULL);
        tox_iterate(Bobs[1], NULL);
        tox_iterate(Bobs[2], NULL);

        if (tox_self_get_connection_status(bootstrap) &&
                tox_self_get_connection_status(Alice) &&
                tox_self_get_connection_status(Bobs[0]) &&
                tox_self_get_connection_status(Bobs[1]) &&
                tox_self_get_connection_status(Bobs[2]) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }

        if (tox_friend_get_connection_status(Alice, 0, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Alice, 1, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Alice, 2, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[0], 0, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[1], 0, NULL) == TOX_CONNECTION_UDP &&
                tox_friend_get_connection_status(Bobs[2], 0, NULL) == TOX_CONNECTION_UDP) {
            break;
        }

        c_sleep(20);
    }

    AliceAV = setup_av_instance(Alice, AliceCC);
    BobsAV[0] = setup_av_instance(Bobs[0], BobsCC + 0);
    BobsAV[1] = setup_av_instance(Bobs[1], BobsCC + 1);
    BobsAV[2] = setup_av_instance(Bobs[2], BobsCC + 2);

    printf("Created 4 instances of ToxAV\n");
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);

    thread_data tds[3];
    tds[0].AliceAV = AliceAV;
    tds[0].BobAV = BobsAV[0];
    tds[0].AliceCC = AliceCC + 0;
    tds[0].BobCC = BobsCC + 0;
    tds[0].friend_number = 0;

    tds[1].AliceAV = AliceAV;
    tds[1].BobAV = BobsAV[1];
    tds[1].AliceCC = AliceCC + 1;
    tds[1].BobCC = BobsCC + 1;
    tds[1].friend_number = 1;

    tds[2].AliceAV = AliceAV;
    tds[2].BobAV = BobsAV[2];
    tds[2].AliceCC = AliceCC + 2;
    tds[2].BobCC = BobsCC + 2;
    tds[2].friend_number = 2;

    pthread_t tids[3];
    (void) pthread_create(tids + 0, NULL, call_thread, tds + 0);
    (void) pthread_create(tids + 1, NULL, call_thread, tds + 1);
    (void) pthread_create(tids + 2, NULL, call_thread, tds + 2);

    (void) pthread_detach(tids[0]);
    (void) pthread_detach(tids[1]);
    (void) pthread_detach(tids[2]);

    time_t start_time = time(NULL);

    while (time(NULL) - start_time < 5) {
        tox_iterate(Alice, NULL);
        tox_iterate(Bobs[0], NULL);
        tox_iterate(Bobs[1], NULL);
        tox_iterate(Bobs[2], NULL);
        c_sleep(20);
    }

    (void) pthread_join(tids[0], NULL);
    (void) pthread_join(tids[1], NULL);
    (void) pthread_join(tids[2], NULL);

    printf("Killing all instances\n");
    toxav_kill(BobsAV[0]);
    toxav_kill(BobsAV[1]);
    toxav_kill(BobsAV[2]);
    toxav_kill(AliceAV);
    tox_kill(Bobs[0]);
    tox_kill(Bobs[1]);
    tox_kill(Bobs[2]);
    tox_kill(Alice);
    tox_kill(bootstrap);

    printf("\nTest successful!\n");
}
END_TEST


static Suite *tox_suite(void)
{
    Suite *s = suite_create("ToxAV");

    TCase *tc_av_three_calls = tcase_create("AV_three_calls");
    tcase_add_test(tc_av_three_calls, test_AV_three_calls);
    tcase_set_timeout(tc_av_three_calls, 150);
    suite_add_tcase(s, tc_av_three_calls);

    return s;
}

int main(int argc, char *argv[])
{
    (void) argc;
    (void) argv;

    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    setbuf(stdout, NULL);

    srunner_run_all(test_runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
