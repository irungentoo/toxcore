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

#include "../toxcore/tox.h"
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

pthread_mutex_t muhmutex;

typedef enum _CallStatus {
    none,
    InCall,
    Ringing,
    Ended,
    Rejected,
    Cancel

} CallStatus;

typedef struct _Party {
    CallStatus status;
    ToxAv *av;
    int id;
} Party;

typedef struct _ACall {
    pthread_t tid;
    int idx;

    Party Caller;
    Party Callee;
} ACall;

typedef struct _Status {
    ACall calls[3]; /* Make 3 calls for this test */
} Status;

Status status_control;

void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/******************************************************************************/
void callback_recv_invite ( void *av, int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Ringing;*/
}
void callback_recv_ringing ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;
    cast->calls[call_index].Caller.status = Ringing;
}
void callback_recv_starting ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;
    cast->calls[call_index].Caller.status = InCall;
}
void callback_recv_ending ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;
    cast->calls[call_index].Caller.status = Ended;
}

void callback_call_started ( void *av, int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = InCall;*/
}
void callback_call_canceled ( void *av, int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Cancel;*/
}
void callback_call_rejected ( void *av, int32_t call_index, void *_arg )
{
    Status *cast = _arg;
    cast->calls[call_index].Caller.status = Rejected;
}
void callback_call_ended ( void *av, int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Ended;*/
}

void callback_requ_timeout ( void *av, int32_t call_index, void *_arg )
{
    //ck_assert_msg(0, "No answer!");
}

static void callback_audio(ToxAv *av, int32_t call_index, int16_t *data, int length, void *userdata)
{
}

static void callback_video(ToxAv *av, int32_t call_index, vpx_image_t *img, void *userdata)
{
}

void register_callbacks(ToxAv *av, void *data)
{
    toxav_register_callstate_callback(av, callback_call_started, av_OnStart, data);
    toxav_register_callstate_callback(av, callback_call_canceled, av_OnCancel, data);
    toxav_register_callstate_callback(av, callback_call_rejected, av_OnReject, data);
    toxav_register_callstate_callback(av, callback_call_ended, av_OnEnd, data);
    toxav_register_callstate_callback(av, callback_recv_invite, av_OnInvite, data);

    toxav_register_callstate_callback(av, callback_recv_ringing, av_OnRinging, data);
    toxav_register_callstate_callback(av, callback_recv_starting, av_OnStarting, data);
    toxav_register_callstate_callback(av, callback_recv_ending, av_OnEnding, data);

    toxav_register_callstate_callback(av, callback_requ_timeout, av_OnRequestTimeout, data);


    toxav_register_audio_recv_callback(av, callback_audio, NULL);
    toxav_register_video_recv_callback(av, callback_video, NULL);
}
/*************************************************************************************************/

int call_running[3];

void *in_thread_call (void *arg)
{
#define call_print(call, what, args...) printf("[%d] " what "\n", call, ##args)

    ACall *this_call = arg;
    uint64_t start = 0;
    int step = 0;
    int call_idx;

    call_running[this_call->idx] = 1;

    const int frame_size = (av_DefaultSettings.audio_sample_rate * av_DefaultSettings.audio_frame_duration / 1000);
    int16_t sample_payload[frame_size];
    randombytes((uint8_t *)sample_payload, sizeof(int16_t) * frame_size);

    uint8_t prepared_payload[RTP_PAYLOAD_SIZE];

    register_callbacks(this_call->Caller.av, &status_control);
    register_callbacks(this_call->Callee.av, arg);

    /* NOTE: CALLEE WILL ALWAHYS NEED CALL_IDX == 0 */
    while (call_running[this_call->idx]) {

        switch ( step ) {
            case 0: /* CALLER */
                toxav_call(this_call->Caller.av, &call_idx, this_call->Callee.id, &av_DefaultSettings, 10);
                call_print(call_idx, "Calling ...");
                step++;
                break;

            case 1: /* CALLEE */
                if (this_call->Caller.status == Ringing) {
                    call_print(call_idx, "Callee answers ...");
                    toxav_answer(this_call->Callee.av, 0, &av_DefaultSettings);
                    step++;
                    start = time(NULL);
                }

                break;

            case 2: /* Rtp transmission */
                if (this_call->Caller.status == InCall) { /* I think this is okay */
                    call_print(call_idx, "Sending rtp ...");

                    c_sleep(1000); /* We have race condition here */
                    toxav_prepare_transmission(this_call->Callee.av, 0, 3, 0, 1);
                    toxav_prepare_transmission(this_call->Caller.av, call_idx, 3, 0, 1);

                    int payload_size = toxav_prepare_audio_frame(this_call->Caller.av, call_idx, prepared_payload, RTP_PAYLOAD_SIZE,
                                       sample_payload, frame_size);

                    if ( payload_size < 0 ) {
                        //ck_assert_msg ( 0, "Failed to encode payload" );
                    }


                    while (time(NULL) - start < 10) { /* 10 seconds */
                        /* Both send */
                        toxav_send_audio(this_call->Caller.av, call_idx, prepared_payload, payload_size);

                        toxav_send_audio(this_call->Callee.av, 0, prepared_payload, payload_size);

                        /* Both receive */
                        int16_t storage[RTP_PAYLOAD_SIZE];
                        int recved;

                        c_sleep(20);
                    }

                    step++; /* This terminates the loop */

                    pthread_mutex_lock(&muhmutex);
                    toxav_kill_transmission(this_call->Callee.av, 0);
                    toxav_kill_transmission(this_call->Caller.av, call_idx);
                    pthread_mutex_unlock(&muhmutex);

                    /* Call over CALLER hangs up */
                    toxav_hangup(this_call->Caller.av, call_idx);
                    call_print(call_idx, "Hanging up ...");
                }

                break;

            case 3: /* Wait for Both to have status ended */
                if (this_call->Caller.status == Ended) {
                    c_sleep(1000); /* race condition */
                    this_call->Callee.status = Ended;
                    call_running[this_call->idx] = 0;
                }

                break;

        }

        c_sleep(20);
    }

    call_print(call_idx, "Call ended successfully!");
    pthread_exit(NULL);
}





// START_TEST(test_AV_three_calls)
void test_AV_three_calls()
{
    long long unsigned int cur_time = time(NULL);
    Tox *bootstrap_node = tox_new(0);
    Tox *caller = tox_new(0);
    Tox *callees[3] = {
        tox_new(0),
        tox_new(0),
        tox_new(0),
    };


    //ck_assert_msg(bootstrap_node != NULL, "Failed to create bootstrap node");

    int i = 0;

    for (; i < 3; i ++) {
        //ck_assert_msg(callees[i] != NULL, "Failed to create 3 tox instances");
    }

    for ( i = 0; i < 3; i ++ ) {
        uint32_t to_compare = 974536;
        tox_callback_friend_request(callees[i], accept_friend_request, &to_compare);
        uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
        tox_get_address(callees[i], address);

        int test = tox_add_friend(caller, address, (uint8_t *)"gentoo", 7);
        //ck_assert_msg( test == i, "Failed to add friend error code: %i", test);
    }

    uint8_t off = 1;

    while (1) {
        tox_do(bootstrap_node);
        tox_do(caller);

        for (i = 0; i < 3; i ++) {
            tox_do(callees[i]);
        }


        if (tox_isconnected(bootstrap_node) &&
                tox_isconnected(caller) &&
                tox_isconnected(callees[0]) &&
                tox_isconnected(callees[1]) &&
                tox_isconnected(callees[2]) && off) {
            printf("Toxes are online, took %llu seconds\n", time(NULL) - cur_time);
            off = 0;
        }


        if (tox_get_friend_connection_status(caller, 0) == 1 &&
                tox_get_friend_connection_status(caller, 1) == 1 &&
                tox_get_friend_connection_status(caller, 2) == 1 )
            break;

        c_sleep(20);
    }

    printf("All set after %llu seconds! Starting call...\n", time(NULL) - cur_time);

    ToxAv *uniqcallerav = toxav_new(caller, 3);

    for (i = 0; i < 3; i ++) {
        status_control.calls[i].idx = i;

        status_control.calls[i].Caller.av = uniqcallerav;
        status_control.calls[i].Caller.id = 0;
        status_control.calls[i].Caller.status = none;

        status_control.calls[i].Callee.av = toxav_new(callees[i], 1);
        status_control.calls[i].Callee.id = i;
        status_control.calls[i].Callee.status = none;
    }

    pthread_mutex_init(&muhmutex, NULL);

    for ( i = 0; i < 3; i++ )
        pthread_create(&status_control.calls[i].tid, NULL, in_thread_call, &status_control.calls[i]);

    /* Now start 3 calls and they'll run for 10 s */

    for ( i = 0; i < 3; i++ )
        pthread_detach(status_control.calls[i].tid);

    while (call_running[0] || call_running[1] || call_running[2]) {
        pthread_mutex_lock(&muhmutex);

        tox_do(bootstrap_node);
        tox_do(caller);
        tox_do(callees[0]);
        tox_do(callees[1]);
        tox_do(callees[2]);

        pthread_mutex_unlock(&muhmutex);
        c_sleep(20);
    }

    toxav_kill(status_control.calls[0].Caller.av);
    toxav_kill(status_control.calls[0].Callee.av);
    toxav_kill(status_control.calls[1].Callee.av);
    toxav_kill(status_control.calls[2].Callee.av);

    tox_kill(bootstrap_node);
    tox_kill(caller);

    for ( i = 0; i < 3; i ++)
        tox_kill(callees[i]);

}
// END_TEST




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
//     Suite *tox = tox_suite();
//     SRunner *test_runner = srunner_create(tox);
//
//     setbuf(stdout, NULL);
//
//     srunner_run_all(test_runner, CK_NORMAL);
//     int number_failed = srunner_ntests_failed(test_runner);
//
//     srunner_free(test_runner);
//
//     return number_failed;

    test_AV_three_calls();

    return 0;
}
