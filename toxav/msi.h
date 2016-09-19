/**  msi.h
 *
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
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

#include "audio.h"
#include "video.h"

#include "../toxcore/Messenger.h"

#include <inttypes.h>
#include <pthread.h>

/**
 * Error codes.
 */
typedef enum {
    msi_ENone,
    msi_EInvalidMessage,
    msi_EInvalidParam,
    msi_EInvalidState,
    msi_EStrayMessage,
    msi_ESystem,
    msi_EHandle,
    msi_EUndisclosed, /* NOTE: must be last enum otherwise parsing will not work */
} MSIError;

/**
 * Supported capabilities
 */
typedef enum {
    msi_CapSAudio = 4,  /* sending audio */
    msi_CapSVideo = 8,  /* sending video */
    msi_CapRAudio = 16, /* receiving audio */
    msi_CapRVideo = 32, /* receiving video */
} MSICapabilities;


/**
 * Call state identifiers.
 */
typedef enum {
    msi_CallInactive, /* Default */
    msi_CallActive,
    msi_CallRequesting, /* when sending call invite */
    msi_CallRequested, /* when getting call invite */
} MSICallState;

/**
 * Callbacks ids that handle the states
 */
typedef enum {
    msi_OnInvite, /* Incoming call */
    msi_OnStart, /* Call (RTP transmission) started */
    msi_OnEnd, /* Call that was active ended */
    msi_OnError, /* On protocol error */
    msi_OnPeerTimeout, /* Peer timed out; stop the call */
    msi_OnCapabilities, /* Peer requested capabilities change */
} MSICallbackID;

/**
 * The call struct. Please do not modify outside msi.c
 */
typedef struct MSICall_s {
    struct MSISession_s *session;           /* Session pointer */

    MSICallState         state;
    uint8_t              peer_capabilities; /* Peer capabilities */
    uint8_t              self_capabilities; /* Self capabilities */
    uint16_t             peer_vfpsz;        /* Video frame piece size */
    uint32_t             friend_number;     /* Index of this call in MSISession */
    MSIError             error;             /* Last error */

    void                *av_call;           /* Pointer to av call handler */

    struct MSICall_s    *next;
    struct MSICall_s    *prev;
} MSICall;


/**
 * Expected return on success is 0, if any other number is
 * returned the call is considered errored and will be handled
 * as such which means it will be terminated without any notice.
 */
typedef int msi_action_cb(void *av, MSICall *call);

/**
 * Control session struct. Please do not modify outside msi.c
 */
typedef struct MSISession_s {
    /* Call handlers */
    MSICall       **calls;
    uint32_t        calls_tail;
    uint32_t        calls_head;

    void           *av;
    Messenger      *messenger;

    pthread_mutex_t mutex[1];
    msi_action_cb *callbacks[7];
} MSISession;

/**
 * Start the control session.
 */
MSISession *msi_new(Messenger *m);
/**
 * Terminate control session. NOTE: all calls will be freed
 */
int msi_kill(MSISession *session);
/**
 * Callback setter.
 */
void msi_register_callback(MSISession *session, msi_action_cb *callback, MSICallbackID id);
/**
 * Send invite request to friend_number.
 */
int msi_invite(MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities);
/**
 * Hangup call. NOTE: 'call' will be freed
 */
int msi_hangup(MSICall *call);
/**
 * Answer call request.
 */
int msi_answer(MSICall *call, uint8_t capabilities);
/**
 * Change capabilities of the call.
 */
int msi_change_capabilities(MSICall *call, uint8_t capabilities);

#endif /* MSI_H */
