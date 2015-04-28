#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <check.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>

#include <vpx/vpx_image.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../toxcore/logger.h"
#include "../toxcore/crypto_core.h"
#include "../toxav/toxav.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(1*x)
#else
#include <unistd.h>
#include <pthread.h>
#define c_sleep(x) usleep(1000*x)
#endif


typedef struct {
    bool incoming;
    uint32_t state;
    
} CallControl;


/**
 * Callbacks 
 */
void t_toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data)
{
    printf("Handling CALL callback\n");
    ((CallControl*)user_data)->incoming = true;
}
void t_toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
{
    printf("Handling CALL STATE callback: %d\n", state);
    ((CallControl*)user_data)->state = state;
}
void t_toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
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
void t_toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
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
void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        assert(tox_friend_add_norequest(m, public_key, NULL) != (uint32_t) ~0);
    }
}


/**
 * Iterate helper
 */
ToxAV* setup_av_instance(Tox* tox, CallControl *CC)
{
    TOXAV_ERR_NEW error;
    
    ToxAV* av = toxav_new(tox, &error);
    assert(error == TOXAV_ERR_NEW_OK);
    
    toxav_callback_call(av, t_toxav_call_cb, CC);
    toxav_callback_call_state(av, t_toxav_call_state_cb, CC);
    toxav_callback_receive_video_frame(av, t_toxav_receive_video_frame_cb, CC);
    toxav_callback_receive_audio_frame(av, t_toxav_receive_audio_frame_cb, CC);
    
    return av;
}
void* call_thread(ToxAV* Alice, ToxAV* Bob)
{
    pthread_exit(NULL);
}

START_TEST(test_AV_three_calls)
{
    Tox* Alice, *bootstrap, *Bobs[3];
    ToxAV* AliceAV, *BobsAV[3];
    
    CallControl AliceCC[3], BobsCC[3];
    
    int i = 0;
    {
        TOX_ERR_NEW error;
        
        bootstrap = tox_new(NULL, NULL, 0, &error);
        assert(error == TOX_ERR_NEW_OK);
        
        Alice = tox_new(NULL, NULL, 0, &error);
        assert(error == TOX_ERR_NEW_OK);
        
        for (; i < 3; i ++) {
            BobsAV[i] = tox_new(NULL, NULL, 0, &error);
            assert(error == TOX_ERR_NEW_OK);
        }
    }
    
    printf("Created 5 instances of Tox\n");
    printf("Preparing network...\n");
    long long unsigned int cur_time = time(NULL);
    
    uint32_t to_compare = 974536;
    uint8_t address[TOX_ADDRESS_SIZE];
    
    tox_callback_friend_request(Alice, t_accept_friend_request_cb, &to_compare);
    tox_self_get_address(Alice, address);
    
    
    assert(tox_friend_add(Bobs[0], address, (uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);
    assert(tox_friend_add(Bobs[1], address, (uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);
    assert(tox_friend_add(Bobs[2], address, (uint8_t *)"gentoo", 7, NULL) != (uint32_t) ~0);
    
    uint8_t off = 1;
    
    while (1) {
        tox_iterate(bootstrap);
        tox_iterate(Alice);
        tox_iterate(Bobs[0]);
        tox_iterate(Bobs[1]);
        tox_iterate(Bobs[2]);
        
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
            tox_friend_get_connection_status(Bobs[2], 0, NULL) == TOX_CONNECTION_UDP)
            break;
        
        c_sleep(20);
    }
    
    AliceAV = setup_av_instance(Alice, &AliceCC);
    BobsAV[0] = setup_av_instance(Bobs[0], &BobsCC[0]);
    BobsAV[1] = setup_av_instance(Bobs[1], &BobsCC[1]);
    BobsAV[2] = setup_av_instance(Bobs[2], &BobsCC[2]);
    
    printf("Created 4 instances of ToxAV\n");
    printf("All set after %llu seconds!\n", time(NULL) - cur_time);
    
    
    
    tox_kill(bootstrap);
    tox_kill(Alice);
    toxav_kill(AliceAV);
    
    for (i = 0; i < 3; i ++) {
        tox_kill(Bobs[i]);
        toxav_kill(BobsAV[i]);
    }
    
    printf("\nTest successful!\n");
}
END_TEST




Suite *tox_suite(void)
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
    Suite *tox = tox_suite();
    SRunner *test_runner = srunner_create(tox);

    setbuf(stdout, NULL);

    srunner_run_all(test_runner, CK_NORMAL);
    int number_failed = srunner_ntests_failed(test_runner);

    srunner_free(test_runner);

    return number_failed;
}
