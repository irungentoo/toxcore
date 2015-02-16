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

#ifndef MSI_H
#define MSI_H

#include <inttypes.h>
#include <pthread.h>

#include "codec.h"
#include "../toxcore/Messenger.h"

typedef uint8_t MSICallIDType[12];
typedef uint8_t MSIReasonStrType[255];
typedef void ( *MSICallbackType ) ( void *agent, int32_t call_idx);

/**
 * Call type identifier. Also used as rtp callback prefix.
 */
typedef enum {
    msi_TypeAudio = 192,
    msi_TypeVideo
} MSICallType;

/**
 * Error codes.
 */
typedef enum {
    msi_ErrUndisclosed,
} MSIError;

/**
 * Supported capabilities
 */
typedef enum {
    msi_CapSAudio = 1, /* sending audio */
    msi_CapSVideo = 2, /* sending video */
    msi_CapRAudio = 4, /* receiving audio */
    msi_CapRVideo = 8, /* receiving video */
} MSICapabilities;


/**
 * Call state identifiers.
 */
typedef enum {
    msi_CallRequesting, /* when sending call invite */
    msi_CallRequested, /* when getting call invite */
    msi_CallActive,
    msi_CallHold,
    msi_CallOver

} MSICallState;


/**
 * Encoding settings.
 */
typedef struct {
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
    msi_OnInvite, /* Incoming call */
    msi_OnRinging, /* When peer is ready to accept/reject the call */
    msi_OnStart, /* Call (RTP transmission) started */
    msi_OnReject, /* The side that was invited rejected the call */
    msi_OnEnd, /* Call that was active ended */
    msi_OnError, /* Call that was active ended */
    msi_OnRequestTimeout, /* When the requested action didn't get response in specified time */
    msi_OnPeerTimeout, /* Peer timed out; stop the call */
    msi_OnPeerCSChange, /* Peer requested Csettings change */
    msi_OnSelfCSChange /* Csettings change confirmation */
} MSICallbackID;

/**
 * Errors
 */
typedef enum {
    msi_ErrorNoCall = -20, /* Trying to perform call action while not in a call */
    msi_ErrorInvalidState = -21, /* Trying to perform call action while in invalid state*/
    msi_ErrorAlreadyInCallWithPeer = -22, /* Trying to call peer when already in a call with peer */
    msi_ErrorReachedCallLimit = -23, /* Cannot handle more calls */
} MSIError;

/**
 * The call struct. Please do not modify outside msi.c
 */
typedef struct MSICall_s {
    struct MSISession_s *session;   /* Session pointer */

    MSICallState         state;
    uint8_t              capabilities;      /* Active capabilities */
    
    uint32_t             friend_id; /* Index of this call in MSISession */
    
    struct MSICall_s*    next;
    struct MSICall_s*    prev;
} MSICall;


/**
 * Control session struct. Please do not modify outside msi.c
 */
typedef struct MSISession_s {
    /* Call handlers */
    MSICall       **calls;
    uint32_t        calls_tail;
    uint32_t        calls_head;
    
    void           *agent_handler;
    Messenger      *messenger_handle;

    pthread_mutex_t mutex[1];
    MSICallbackType callbacks[10];
} MSISession;

/**
 * Start the control session.
 */
MSISession *msi_new ( Messenger *messenger, int32_t max_calls );

/**
 * Terminate control session. NOTE: all calls will be freed
 */
int msi_kill ( MSISession *session );

/**
 * Callback setter.
 */
void msi_register_callback(MSISession *session, MSICallbackType callback, MSICallbackID id);

/**
 * Send invite request to friend_id.
 */
int msi_invite ( MSISession* session, MSICall** call, uint32_t friend_id, uint8_t capabilities );

/**
 * Hangup call. NOTE: 'call' will be freed
 */
int msi_hangup ( MSICall* call );

/**
 * Answer call request.
 */
int msi_answer ( MSICall* call, uint8_t capabilities );

/**
 * Reject incoming call. NOTE: 'call' will be freed
 */
int msi_reject ( MSICall* call );

/**
 * Change capabilities of the call.
 */
int msi_change_capabilities ( MSICall* call, uint8_t capabilities );

#endif /* MSI_H */
