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

/* vpx_image_t */
#include <vpx/vpx_image.h>

typedef void* ( *ToxAVCallback ) ( void* arg );
typedef struct _ToxAv ToxAv;

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

#define RTP_PAYLOAD_SIZE 65535

/* Default video bitrate in bytes/s */
#define VIDEO_BITRATE   10*1000*100

/* Default audio bitrate in bits/s */
#define AUDIO_BITRATE   64000

/* Number of audio channels. */
#define AUDIO_CHANNELS 1

/* Audio frame duration in miliseconds */
#define AUDIO_FRAME_DURATION    20

/* Audio sample rate recommended to be 48kHz for Opus */
#define AUDIO_SAMPLE_RATE   48000

/* The amount of samples in one audio frame */
#define AUDIO_FRAME_SIZE    AUDIO_SAMPLE_RATE*AUDIO_FRAME_DURATION/1000

/* Assume 60 fps*/
#define MAX_ENCODE_TIME_US ((1000 / 60) * 1000)


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
    OnRequestTimeout
    
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


ToxAv* toxav_new(Tox* messenger, void* useragent, const char* ua_name, uint16_t video_width, uint16_t video_height) ;
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




/* Return length of received packet. Returns 0 if nothing recved. Dest has to have 
 * MAX_RTP_PAYLOAD_SIZE space available. Returns -1 if packet is not ready (ready < 1) for deque.
 * For video packets set 'ready' at _any_ value.
 */

/* returns 0 on success */
int toxav_recv_video ( ToxAv* av, vpx_image_t **output);

int toxav_recv_audio( ToxAv* av, int frame_size, int16_t* dest );

int toxav_send_video ( ToxAv* av, vpx_image_t *input);
/* Encode and send audio frame. */
int toxav_send_audio ( ToxAv* av, const int16_t* frame, int frame_size);



int toxav_get_peer_transmission_type ( ToxAv* av, int peer );
void* toxav_get_agent_handler ( ToxAv* av );

#endif /* __TOXAV */