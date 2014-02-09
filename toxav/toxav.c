/**  toxav.c
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
 *   Report bugs/suggestions at either #tox-dev @ freenode.net:6667 or
 *   my email: eniz_vukovic@hotmail.com
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxav.h"
#include "../toxcore/tox.h"
#include "rtp.h"
#include "msi.h"
#include "media.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define inline__ inline __attribute__((always_inline))

static const uint8_t audio_index = 0, video_index = 1;


typedef enum {
    ts_closing,
    ts_running,
    ts_closed
    
} ThreadState;

typedef struct _ToxAv
{
    Tox* messenger;
    
    MSISession* msi_session; /** Main msi session */
    
    RTPSession* rtp_sessions[2]; /* Audio is first and video is second */
    
    /* TODO: Add media session */
    struct jitter_buffer* j_buf;
    CodecState* cs;
    /* TODO: Add media session threads */
    
    
    void* agent_handler;    
} ToxAv;





/********************************************************************************************************************  
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 * 
 * 
 * 
 * PUBLIC API FUNCTIONS IMPLEMENTATIONS
 * 
 * 
 * 
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************
 ********************************************************************************************************************/



ToxAv* toxav_new( Tox* messenger, void* useragent, const char* ua_name ) 
{    
    ToxAv* av = calloc ( sizeof(ToxAv), 1);
        
    av->msi_session = msi_init_session(messenger, (const unsigned char*) ua_name );
    av->msi_session->agent_handler = av;
    
    av->rtp_sessions[0] = av->rtp_sessions [1] = NULL;
 
    av->messenger = messenger;
    
    /* NOTE: This should be user defined or? */
    av->j_buf = create_queue(20);
    
    av->cs = codec_init_session(AUDIO_BITRATE, AUDIO_FRAME_DURATION, AUDIO_SAMPLE_RATE, 1, VIDEO_BITRATE, DEFAULT_WEBCAM, VIDEO_DRIVER);
    
    av->agent_handler = useragent;
    
    return av;
}

void toxav_kill ( ToxAv* av ) 
{    
    msi_terminate_session(av->msi_session);
    
    if ( av->rtp_sessions[audio_index] ) {
        rtp_terminate_session(av->rtp_sessions[audio_index], av->msi_session->messenger_handle);
    }
    
    if ( av->rtp_sessions[video_index] ) {
        rtp_terminate_session(av->rtp_sessions[video_index], av->msi_session->messenger_handle);
    }
    
    codec_terminate_session(av->cs);
    
    free(av);
}

void toxav_register_callstate_callback ( ToxAVCallback callback, ToxAvCallbackID id ) 
{
    msi_register_callback((MSICallback)callback, (MSICallbackID) id);
}



int toxav_call (ToxAv* av, int user, ToxAvCallType call_type, int ringing_seconds ) 
{
    if ( av->msi_session->call ) {
        return ErrorAlreadyInCall;
    }
    
    return msi_invite(av->msi_session, call_type, ringing_seconds * 1000, user);
}

int toxav_hangup ( ToxAv* av ) 
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }
    
    if ( av->msi_session->call->state != call_active ) {
        return ErrorInvalidState;
    }
    
    return msi_hangup(av->msi_session);
}

int toxav_answer ( ToxAv* av, ToxAvCallType call_type ) 
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }
    
    if ( av->msi_session->call->state != call_starting ) {
        return ErrorInvalidState;
    }
    
    return msi_answer(av->msi_session, call_type);
}

int toxav_reject ( ToxAv* av, const char* reason ) 
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->call->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_reject(av->msi_session, (const uint8_t*) reason);
}

int toxav_cancel ( ToxAv* av, const char* reason )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }
    
    return msi_cancel(av->msi_session, 0, (const uint8_t*)reason);
}

/* You can stop the call at any state */
int toxav_stop_call ( ToxAv* av ) 
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }
    
    return msi_stopcall(av->msi_session);
}


int toxav_prepare_transmission ( ToxAv* av ) 
{
    assert(av->msi_session);
    if ( !av->msi_session || !av->msi_session->call ) {
        return ErrorNoCall;
    }
    
    av->rtp_sessions[audio_index] = rtp_init_session(
                                    type_audio,
                                    av->messenger, 
                                    av->msi_session->call->peers[0],
                                    av->msi_session->call->key_peer,
                                    av->msi_session->call->key_local,
                                    av->msi_session->call->nonce_peer,
                                    av->msi_session->call->nonce_local
                                    );
    
    
    if ( !av->rtp_sessions[audio_index] ) {
        fprintf(stderr, "Error while starting audio RTP session!\n");
        return ErrorStartingAudioRtp;
    }
    
    av->rtp_sessions[video_index] = rtp_init_session ( 
                                    type_video,
                                    av->messenger, 
                                    av->msi_session->call->peers[0],
                                    av->msi_session->call->key_peer,
                                    av->msi_session->call->key_local,
                                    av->msi_session->call->nonce_peer,
                                    av->msi_session->call->nonce_local
                                    );
    
    
    if ( !av->rtp_sessions[video_index] ) {
        fprintf(stderr, "Error while starting video RTP session!\n");
        return ErrorStartingVideoRtp;
    }
    
    return ErrorNone;
}


int toxav_kill_transmission ( ToxAv* av ) 
{
    /* Both sessions should be active at any time */
    if ( !av->rtp_sessions[0] || !av->rtp_sessions[0] )
        return ErrorNoTransmission;
    
    
    if ( -1 == rtp_terminate_session(av->rtp_sessions[audio_index], av->messenger) ) {
        fprintf(stderr, "Error while terminating audio RTP session!\n");
        return ErrorTerminatingAudioRtp;
    }
    
    if ( -1 == rtp_terminate_session(av->rtp_sessions[video_index], av->messenger) ) {
        fprintf(stderr, "Error while terminating video RTP session!\n");
        return ErrorTerminatingVideoRtp;
    }
    
    return ErrorNone;
}


inline__ int toxav_send_rtp_payload ( ToxAv* av, ToxAvCallType type, const uint8_t* payload, uint16_t length ) 
{
    if ( av->rtp_sessions[type - TypeAudio] )
        return rtp_send_msg ( av->rtp_sessions[type - TypeAudio], av->msi_session->messenger_handle, payload, length );
    else return -1;
}

inline__ int toxav_recv_rtp_payload ( ToxAv* av, ToxAvCallType type, int ready, uint8_t* dest ) 
{
    if ( !dest ) return ErrorInternal;
    
    if ( !av->rtp_sessions[type - TypeAudio] ) return ErrorNoRtpSession;
    
    RTPMessage* message;
    
    if ( type == TypeAudio ) {
        
        message = rtp_recv_msg(av->rtp_sessions[audio_index]);
        
        if (message) {
            /* push the packet into the queue */
            queue(av->j_buf, message);
        }
        
        if (ready) {
            int success = 0;
            message = dequeue(av->j_buf, &success);
                        
            if ( success == 2) return ErrorAudioPacketLost;
        } 
        else return 0;
    }
    else {
        message = rtp_recv_msg(av->rtp_sessions[video_index]);
    }
        
    if ( message ) {    
        memcpy(dest, message->data, message->length);
        
        int length = message->length;
        
        rtp_free_msg(NULL, message);
                
        return length;
    }
    
    return 0;
}

inline__ int toxav_decode_audio ( ToxAv* av, const uint8_t* payload, uint16_t length, int frame_size, short int* dest ) 
{
    if ( !dest ) return ErrorInternal;
    
    return opus_decode(av->cs->audio_decoder, payload, length, dest, frame_size, payload ? 0 : 1);
}

inline__ int toxav_encode_audio ( ToxAv* av, const short int* frame, int frame_size, uint8_t* dest ) 
{
    if ( !dest )
        return ErrorInternal;
    
    return opus_encode(av->cs->audio_encoder, frame, frame_size, dest, RTP_PAYLOAD_SIZE);
}

int toxav_get_peer_transmission_type ( ToxAv* av, int peer ) 
{
    assert(av->msi_session);
    if ( peer < 0 || !av->msi_session->call || av->msi_session->call->peer_count <= peer )
        return ErrorInternal;
    
    return av->msi_session->call->type_peer[peer];
}

void* toxav_get_agent_handler ( ToxAv* av ) 
{
    return av->agent_handler;
}


/* Only temporary */
void* get_cs_temp(ToxAv* av) 
{
    return av->cs;
}
