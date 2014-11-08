/**  msi.h
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

typedef uint8_t MSICallIDType[12];
typedef uint8_t MSIReasonStrType[255];
typedef void ( *MSICallbackType ) ( void *agent, int32_t call_idx, void *arg );

/**
 * Call type identifier. Also used as rtp callback prefix.
 */
typedef enum {
    type_audio = 192,
    type_video
} MSICallType;


/**
 * Call state identifiers.
 */
typedef enum {
    call_inviting, /* when sending call invite */
    call_starting, /* when getting call invite */
    call_active,
    call_hold,
    call_hanged_up

} MSICallState;


/**
 * Encoding settings.
 */
typedef struct _MSICodecSettings {
    MSICallType call_type;

    uint32_t video_bitrate; /* In kbits/s */
    uint16_t max_video_width; /* In px */
    uint16_t max_video_height; /* In px */

    uint32_t audio_bitrate; /* In bits/s */
    uint16_t audio_frame_duration; /* In ms */
    uint32_t audio_sample_rate; /* In Hz */
    uint32_t audio_channels;
} MSICSettings;


/**
 * Callbacks ids that handle the states
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
    MSI_OnRequestTimeout,
    MSI_OnPeerTimeout,
    MSI_OnMediaChange
} MSICallbackID;


/**
 * Callbacks container
 */
typedef struct _MSICallbackCont {
    MSICallbackType function;
    void *data;
} MSICallbackCont;

/**
 * The call struct.
 */
typedef struct _MSICall {                  /* Call info structure */
    struct _MSISession *session;           /* Session pointer */

    MSICallState        state;

    MSICSettings        csettings_local;   /* Local call settings */
    MSICSettings       *csettings_peer;    /* Peers call settings */

    MSICallIDType       id;                /* Random value identifying the call */

    int                 ringing_tout_ms;   /* Ringing timeout in ms */

    int                 request_timer_id;  /* Timer id for outgoing request/action */
    int                 ringing_timer_id;  /* Timer id for ringing timeout */

    uint32_t           *peers;
    uint16_t            peer_count;

    int32_t             call_idx;          /* Index of this call in MSISession */
} MSICall;


/**
 * Control session struct
 */
typedef struct _MSISession {

    /* Call handlers */
    MSICall       **calls;
    int32_t         max_calls;

    void           *agent_handler;
    Messenger      *messenger_handle;

    uint32_t        frequ;
    uint32_t        call_timeout;  /* Time of the timeout for some action to end; 0 if infinite */

    pthread_mutex_t mutex;

    void           *timer_handler;
    MSICallbackCont callbacks[11]; /* Callbacks used by this session */
} MSISession;

/**
 * Callback setter.
 */
void msi_register_callback(MSISession *session, MSICallbackType callback, MSICallbackID id, void *userdata);

/**
 * Start the control session.
 */
MSISession *msi_init_session ( Messenger *messenger, int32_t max_calls );

/**
 * Terminate control session.
 */
int msi_terminate_session ( MSISession *session );

/**
 * Send invite request to friend_id.
 */
int msi_invite ( MSISession *session, 
                 int32_t *call_index, 
                 const MSICSettings* csettings, 
                 uint32_t rngsec,
                 uint32_t friend_id );

/**
 * Hangup active call.
 */
int msi_hangup ( MSISession *session, int32_t call_index );

/**
 * Answer active call request.
 */
int msi_answer ( MSISession *session, int32_t call_index, const MSICSettings* csettings );

/**
 * Cancel request.
 */
int msi_cancel ( MSISession *session, int32_t call_index, uint32_t peer, const char *reason );

/**
 * Reject incoming call.
 */
int msi_reject ( MSISession *session, int32_t call_index, const char *reason );

/** 
 * Terminate the call. 
 */
int msi_stopcall ( MSISession *session, int32_t call_index );

/**
 * Change codec settings of the current call.
 */
int msi_change_csettings ( MSISession* session, int32_t call_index, const MSICSettings* csettings );

/** 
 * Main msi loop 
 */
void msi_do( MSISession* session );

#endif /* __TOXMSI */
