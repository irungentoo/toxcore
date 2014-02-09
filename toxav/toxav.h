/**  toxav.h
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
 * 
 *   Report bugs/suggestions to me ( mannol ) at either #tox-dev @ freenode.net:6667 or
 *   my email: eniz_vukovic@hotmail.com
 */


#ifndef __TOXAV
#define __TOXAV
#include <inttypes.h>

typedef void* ( *ToxAVCallback ) ( void* arg );
typedef struct _ToxAv ToxAv;

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

#define RTP_PAYLOAD_SIZE 10400

/** 
 * @brief Callbacks ids that handle the call states 
 */
typedef enum {
    /* Requests */
    OnInvite,
    OnStart,
    OnCancel,
    OnReject,
    OnEnd,
    
    /* Responses */
    OnRinging,
    OnStarting,
    OnEnding,
    
    /* Protocol */
    OnError,
    OnTimeout
    
} ToxAvCallbackID;


/**
 * @brief Call type identifier.
 */
typedef enum {
    TypeAudio = 70,
    TypeVideo
} ToxAvCallType;


typedef enum {
    ErrorNone = 0,
    ErrorInternal = -1, /* Internal error */
    ErrorAlreadyInCall = -2, /* Already has an active call */
    ErrorNoCall = -3, /* Trying to perform call action while not in a call */
    ErrorInvalidState = -4, /* Trying to perform call action while in invalid state*/
    ErrorNoRtpSession = -5, /* Trying to perform rtp action on invalid session */
    ErrorAudioPacketLost = -6, /* Indicating packet loss */
    ErrorStartingAudioRtp = -7, /* Error in toxav_prepare_transmission() */
    ErrorStartingVideoRtp = -8 , /* Error in toxav_prepare_transmission() */
    ErrorNoTransmission = -9, /* Returned in toxav_kill_transmission() */
    ErrorTerminatingAudioRtp = -10, /* Returned in toxav_kill_transmission() */
    ErrorTerminatingVideoRtp = -11, /* Returned in toxav_kill_transmission() */
    
} ToxAvError;


ToxAv* toxav_new(Tox* messenger, void* useragent, const char* ua_name);
void toxav_kill(ToxAv* av);

void toxav_register_callstate_callback (ToxAVCallback callback, ToxAvCallbackID id);


int toxav_call(ToxAv* av, int user, ToxAvCallType call_type, int ringing_seconds);
int toxav_hangup(ToxAv* av);
int toxav_answer(ToxAv* av, ToxAvCallType call_type );
int toxav_reject(ToxAv* av, const char* reason);
int toxav_cancel(ToxAv* av, const char* reason);
int toxav_stop_call(ToxAv* av);

int toxav_prepare_transmission(ToxAv* av);
int toxav_kill_transmission(ToxAv* av);


int toxav_send_rtp_payload(ToxAv* av, ToxAvCallType type, const uint8_t* payload, uint16_t length);

/* Return length of received packet. Returns 0 if nothing recved. Dest has to have 
 * MAX_RTP_PAYLOAD_SIZE space available. Returns -1 if packet is not ready (ready < 1) for deque.
 * For video packets set 'ready' at _any_ value.
 */
int toxav_recv_rtp_payload(ToxAv* av, ToxAvCallType type, int ready, uint8_t* dest);




int toxav_decode_audio( ToxAv* av, const uint8_t* payload, uint16_t length, int frame_size, short int* dest );

/* Please make sure 'dest' has enough storage for RTP_PAYLOAD_SIZE length of data */
int toxav_encode_audio( ToxAv* av, const short int* frame, int frame_size, uint8_t* dest );



int toxav_get_peer_transmission_type ( ToxAv* av, int peer );
void* toxav_get_agent_handler ( ToxAv* av );

/* Use this to get handle of CodecState from ToxAv struct */
void* get_cs_temp( ToxAv* av );
#endif /* __TOXAV */