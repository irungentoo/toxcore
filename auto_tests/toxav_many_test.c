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

    Party Caller;
    Party Callee;
} ACall;

typedef struct _Status {
    ACall calls[3]; /* Make 3 calls for this test */
} Status;

void accept_friend_request(Tox *m, const uint8_t *public_key, const uint8_t *data, uint16_t length, void *userdata)
{
    if (length == 7 && memcmp("gentoo", data, 7) == 0) {
        tox_add_friend_norequest(m, public_key);
    }
}


/******************************************************************************/
void callback_recv_invite ( int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Ringing;*/
}
void callback_recv_ringing ( int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    cast->calls[call_index].Caller.status = Ringing;
}
void callback_recv_starting ( int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    cast->calls[call_index].Caller.status = InCall;
}
void callback_recv_ending ( int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    cast->calls[call_index].Caller.status = Ended;
}

void callback_recv_error ( int32_t call_index, void *_arg )
{
    ck_assert_msg(0, "AV internal error");
}

void callback_call_started ( int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = InCall;*/
}
void callback_call_canceled ( int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Cancel;*/
}
void callback_call_rejected ( int32_t call_index, void *_arg )
{
    Status *cast = _arg;

    cast->calls[call_index].Caller.status = Rejected;
}
void callback_call_ended ( int32_t call_index, void *_arg )
{
    /*
       Status *cast = _arg;

       cast->calls[call_index].Callee.status = Ended;*/
}

void callback_requ_timeout ( int32_t call_index, void *_arg )
{
    ck_assert_msg(0, "No answer!");
}
/*************************************************************************************************/


void *in_thread_call (void *arg)
{
#define call_print(call, what, args...) printf("[%d] " what "\n", call, ##args)

    ACall *this_call = arg;
    uint64_t start = 0;
    int step = 0, running = 1;
    int call_idx;

    const int frame_size = (av_DefaultSettings.audio_sample_rate * av_DefaultSettings.audio_frame_duration / 1000);
    int16_t sample_payload[frame_size];
    randombytes((uint8_t *)sample_payload, sizeof(int16_t) * frame_size);

    uint8_t prepared_payload[RTP_PAYLOAD_SIZE];


    /* NOTE: CALLEE WILL ALWAHYS NEED CALL_IDX == 0 */
    while (running) {

        switch ( step ) {
            case 0: /* CALLER */
                toxav_call(this_call->Caller.av, &call_idx, this_call->Callee.id, TypeVideo, 10);
                call_print(call_idx, "Calling ...");
                step++;
                break;

            case 1: /* CALLEE */
                if (this_call->Caller.status == Ringing) {
                    call_print(call_idx, "Callee answers ...");
                    toxav_answer(this_call->Callee.av, 0, TypeVideo);
                    step++;
                    start = time(NULL);
                }

                break;

            case 2: /* Rtp transmission */
                if (this_call->Caller.status == InCall) { /* I think this is okay */
                    call_print(call_idx, "Sending rtp ...");

                    ToxAvCodecSettings cast = av_DefaultSettings;

                    c_sleep(1000); /* We have race condition here */
                    toxav_prepare_transmission(this_call->Callee.av, 0, &cast, 1);
                    toxav_prepare_transmission(this_call->Caller.av, call_idx, &cast, 1);

                    int payload_size = toxav_prepare_audio_frame(this_call->Caller.av, call_idx, prepared_payload, RTP_PAYLOAD_SIZE,
                                       sample_payload, frame_size);

                    if ( payload_size < 0 ) {
                        ck_assert_msg ( 0, "Failed to encode payload" );
                    }


                    while (time(NULL) - start < 10) { /* 10 seconds */
                        /* Both send */
                        toxav_send_audio(this_call->Caller.av, call_idx, prepared_payload, payload_size);

                        toxav_send_audio(this_call->Callee.av, 0, prepared_payload, payload_size);

                        /* Both receive */
                        int16_t storage[RTP_PAYLOAD_SIZE];
                        int recved;

                        /* Payload from CALLER */
                        recved = toxav_recv_audio(this_call->Callee.av, 0, frame_size, storage);

                        if ( recved ) {
                            /*ck_assert_msg(recved == 10 && memcmp(storage, sample_payload, 10) == 0, "Payload from CALLER is invalid");*/
                        }

                        /* Payload from CALLEE */
                        recved = toxav_recv_audio(this_call->Caller.av, call_idx, frame_size, storage);

                        if ( recved ) {
                            /*ck_assert_msg(recved == 10 && memcmp(storage, sample_payload, 10) == 0, "Payload from CALLEE is invalid");*/
                        }

                        c_sleep(20);
                    }

                    step++; /* This terminates the loop */

                    toxav_kill_transmission(this_call->Callee.av, 0);
                    toxav_kill_transmission(this_call->Caller.av, call_idx);

                    /* Call over CALLER hangs up */
                    toxav_hangup(this_call->Caller.av, call_idx);
                    call_print(call_idx, "Hanging up ...");
                }

                break;

            case 3: /* Wait for Both to have status ended */
                if (this_call->Caller.status == Ended) {
                    c_sleep(1000); /* race condition */
                    this_call->Callee.status = Ended;
                    running = 0;
                }

                break;

        }

        c_sleep(20);
    }

    call_print(call_idx, "Call ended successfully!");
    pthread_exit(NULL);
}





START_TEST(test_AV_three_calls)
// void test_AV_three_calls()
{
    long long unsigned int cur_time = time(NULL);
    Tox *bootstrap_node = tox_new(0);
    Tox *caller = tox_new(0);
    Tox *callees[3] = {
        tox_new(0),
        tox_new(0),
        tox_new(0),
    };


    ck_assert_msg(bootstrap_node != NULL, "Failed to create bootstrap node");

    int i = 0;

    for (; i < 3; i ++) {
        ck_assert_msg(callees[i] != NULL, "Failed to create 3 tox instances");
    }

    for ( i = 0; i < 3; i ++ ) {
        uint32_t to_compare = 974536;
        tox_callback_friend_request(callees[i], accept_friend_request, &to_compare);
        uint8_t address[TOX_FRIEND_ADDRESS_SIZE];
        tox_get_address(callees[i], address);

        int test = tox_add_friend(caller, address, (uint8_t *)"gentoo", 7);
        ck_assert_msg( test == i, "Failed to add friend error code: %i", test);
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

    Status status_control = {
        0,
        {none, uniqcallerav, 0},
        {none, toxav_new(callees[0], 1), 0},

        0,
        {none, uniqcallerav},
        {none, toxav_new(callees[1], 1), 1},

        0,
        {none, uniqcallerav},
        {none, toxav_new(callees[2], 1), 2}
    };


    toxav_register_callstate_callback(callback_call_started, av_OnStart, &status_control);
    toxav_register_callstate_callback(callback_call_canceled, av_OnCancel, &status_control);
    toxav_register_callstate_callback(callback_call_rejected, av_OnReject, &status_control);
    toxav_register_callstate_callback(callback_call_ended, av_OnEnd, &status_control);
    toxav_register_callstate_callback(callback_recv_invite, av_OnInvite, &status_control);

    toxav_register_callstate_callback(callback_recv_ringing, av_OnRinging, &status_control);
    toxav_register_callstate_callback(callback_recv_starting, av_OnStarting, &status_control);
    toxav_register_callstate_callback(callback_recv_ending, av_OnEnding, &status_control);

    toxav_register_callstate_callback(callback_recv_error, av_OnError, &status_control);
    toxav_register_callstate_callback(callback_requ_timeout, av_OnRequestTimeout, &status_control);



    for ( i = 0; i < 3; i++ )
        pthread_create(&status_control.calls[i].tid, NULL, in_thread_call, &status_control.calls[i]);


    /* Now start 3 calls and they'll run for 10 s */

    for ( i = 0; i < 3; i++ )
        pthread_detach(status_control.calls[i].tid);

    while (
        status_control.calls[0].Callee.status != Ended && status_control.calls[0].Caller.status != Ended &&
        status_control.calls[1].Callee.status != Ended && status_control.calls[1].Caller.status != Ended &&
        status_control.calls[2].Callee.status != Ended && status_control.calls[2].Caller.status != Ended
    ) {
        tox_do(bootstrap_node);
        tox_do(caller);
        tox_do(callees[0]);
        tox_do(callees[1]);
        tox_do(callees[2]);
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

//     test_AV_three_calls();
//
//     return 0;
}