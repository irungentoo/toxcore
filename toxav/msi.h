/**  toxmsi.h
 *
 *   Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *   This file is part of Tox.
 *
 *   Tox is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Tox is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Tox. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __TOXMSI
#define __TOXMSI

#include <inttypes.h>
#include <pthread.h>

#include "../toxcore/Messenger.h"

/* define size for call_id */
#define CALL_ID_LEN 12


typedef void ( *MSICallback ) ( int32_t, void *arg );


/**
 * @brief Call type identifier. Also used as rtp callback prefix.
 */
typedef enum {
    type_audio = 192,
    type_video
} MSICallType;


/**
 * @brief Call state identifiers.
 */
typedef enum {
    call_inviting, /* when sending call invite */
    call_starting, /* when getting call invite */
    call_active,
    call_hold,
    call_hanged_up

} MSICallState;



/**
 * @brief The call struct.
 *
 */
typedef struct _MSICall {                  /* Call info structure */
    struct _MSISession *session;           /* Session pointer */

    MSICallState        state;

    MSICallType         type_local;        /* Type of payload user is ending */
    MSICallType        *type_peer;         /* Type of payload others are sending */

    uint8_t             id[CALL_ID_LEN];   /* Random value identifying the call */

    int                 ringing_tout_ms;   /* Ringing timeout in ms */

    int                 request_timer_id;  /* Timer id for outgoing request/action */
    int                 ringing_timer_id;  /* Timer id for ringing timeout */


    pthread_mutex_t     mutex[1];             /* */
    uint32_t           *peers;
    uint16_t            peer_count;

    int32_t             call_idx;          /* Index of this call in MSISession */
} MSICall;


/**
 * @brief Control session struct
 *
 */
typedef struct _MSISession {

    /* Call handlers */
    struct _MSICall **calls;
    int32_t max_calls;

    int            last_error_id; /* Determine the last error */
    const uint8_t *last_error_str;

    void *agent_handler; /* Pointer to an object that is handling msi */
    Messenger  *messenger_handle;

    uint32_t frequ;
    uint32_t call_timeout; /* Time of the timeout for some action to end; 0 if infinite */

    pthread_mutex_t mutex[1];

    void *timer_handler;
} MSISession;


/**
 * @brief Callbacks ids that handle the states
 */
typedef enum {
    /* Requests */
    MSI_OnInvite,
    MSI_OnStart,
    MSI_OnCancel,
    MSI_OnReject,
    MSI_OnEnd,

    /* Responses */
    MSI_OnRinging,
    MSI_OnStarting,
    MSI_OnEnding,

    /* Protocol */
    MSI_OnError,
    MSI_OnRequestTimeout,
    MSI_OnPeerTimeout

} MSICallbackID;


/**
 * @brief Callback setter.
 *
 * @param callback The callback.
 * @param id The id.
 * @return void
 */
void msi_register_callback(MSICallback callback, MSICallbackID id, void *userdata);


/**
 * @brief Start the control session.
 *
 * @param messenger Tox* object.
 * @param max_calls Amount of calls possible
 * @return MSISession* The created session.
 * @retval NULL Error occurred.
 */
MSISession *msi_init_session ( Messenger *messenger, int32_t max_calls );


/**
 * @brief Terminate control session.
 *
 * @param session The session
 * @return int
 */
int msi_terminate_session ( MSISession *session );


/**
 * @brief Send invite request to friend_id.
 *
 * @param session Control session.
 * @param call_index Set to new call index.
 * @param call_type Type of the call. Audio or Video(both audio and video)
 * @param rngsec Ringing timeout.
 * @param friend_id The friend.
 * @return int
 */
int msi_invite ( MSISession *session, int32_t *call_index, MSICallType call_type, uint32_t rngsec, uint32_t friend_id );


/**
 * @brief Hangup active call.
 *
 * @param session Control session.
 * @param call_index To which call is this action handled.
 * @return int
 * @retval -1 Error occurred.
 * @retval 0 Success.
 */
int msi_hangup ( MSISession *session, int32_t call_index );


/**
 * @brief Answer active call request.
 *
 * @param session Control session.
 * @param call_index To which call is this action handled.
 * @param call_type Answer with Audio or Video(both).
 * @return int
 */
int msi_answer ( MSISession *session, int32_t call_index, MSICallType call_type );


/**
 * @brief Cancel request.
 *
 * @param session Control session.
 * @param call_index To which call is this action handled.
 * @param peer To which peer.
 * @param reason Set optional reason header. Pass NULL if none.
 * @return int
 */
int msi_cancel ( MSISession *session, int32_t call_index, uint32_t peer, const char *reason );


/**
 * @brief Reject request.
 *
 * @param session Control session.
 * @param call_index To which call is this action handled.
 * @param reason Set optional reason header. Pass NULL if none.
 * @return int
 */
int msi_reject ( MSISession *session, int32_t call_index, const uint8_t *reason );


/**
 * @brief Terminate the current call.
 *
 * @param session Control session.
 * @param call_index To which call is this action handled.
 * @return int
 */
int msi_stopcall ( MSISession *session, int32_t call_index );

#endif /* __TOXMSI */
