/**  toxav.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "msi.h" /* Includes codec.h, rtp.h and toxav.h */

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENCODE_TIME_US ((1000 / 24) * 1000)

enum {
    audio_index,
    video_index,
};

typedef struct ToxAVCall_s {
    ToxAV* av;
    RTPSession *rtps[2]; /* Audio is first and video is second */
    CSession *cs;
    
    pthread_mutex_t mutex_audio_sending[1];
    pthread_mutex_t mutex_video_sending[1];
    /* Only audio or video can be decoded at the time */
    pthread_mutex_t mutex_decoding[1];
    
    bool active;
    MSICall* msi_call;
    uint32_t friend_id;
    
    uint32_t audio_bit_rate; /* Sending audio bitrate */
    uint32_t video_bit_rate; /* Sending video bitrate */
    
    uint8_t last_self_capabilities;
    uint8_t last_peer_capabilities;
    
    /** Quality control */
    uint64_t time_audio_good;
    uint32_t last_bad_audio_bit_rate;
    uint64_t time_video_good;
    uint32_t last_bad_video_bit_rate;
    
    struct ToxAVCall_s *prev;
    struct ToxAVCall_s *next;
} ToxAVCall;

struct toxAV {
    Messenger* m;
    MSISession* msi;
    
    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall** calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t mutex[1];
    
    PAIR(toxav_call_cb *, void*) ccb; /* Call callback */
    PAIR(toxav_call_state_cb *, void *) scb; /* Call state callback */
    PAIR(toxav_receive_audio_frame_cb *, void *) acb; /* Audio frame receive callback */
    PAIR(toxav_receive_video_frame_cb *, void *) vcb; /* Video frame receive callback */
    PAIR(toxav_video_frame_request_cb *, void *) rvcb; /* Video request callback */
    PAIR(toxav_audio_frame_request_cb *, void *) racb; /* Audio request callback */
    
    /** Decode time measures */
    int32_t dmssc; /** Measure count */
    int32_t dmsst; /** Last cycle total */
    int32_t dmssa; /** Average decoding time in ms */
    
    uint32_t interval; /** Calculated interval */
};


int callback_invite(void* toxav_inst, MSICall* call);
int callback_start(void* toxav_inst, MSICall* call);
int callback_end(void* toxav_inst, MSICall* call);
int callback_error(void* toxav_inst, MSICall* call);
int callback_capabilites(void* toxav_inst, MSICall* call);

bool audio_bitrate_invalid(uint32_t bitrate);
bool video_bitrate_invalid(uint32_t bitrate);
void invoke_call_state(ToxAV* av, uint32_t friend_number, uint32_t state);
ToxAVCall* call_new(ToxAV* av, uint32_t friend_number, TOXAV_ERR_CALL* error);
ToxAVCall* call_get(ToxAV* av, uint32_t friend_number);
void qc_do(ToxAVCall* call);
void call_remove(ToxAVCall* call);
bool call_prepare_transmission(ToxAVCall* call);
void call_kill_transmission(ToxAVCall* call);



ToxAV* toxav_new(Tox* tox, TOXAV_ERR_NEW* error)
{
    TOXAV_ERR_NEW rc = TOXAV_ERR_NEW_OK;
    ToxAV *av = NULL;
    
    if (tox == NULL) {
        rc = TOXAV_ERR_NEW_NULL;
        goto FAILURE;
    }
    
    if (((Messenger*)tox)->msi_packet) {
        rc = TOXAV_ERR_NEW_MULTIPLE;
        goto FAILURE;
    }
    
    av = calloc (sizeof(ToxAV), 1);
    
    if (av == NULL) {
        LOGGER_WARNING("Allocation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto FAILURE;
    }
    
    if (create_recursive_mutex(av->mutex) != 0) {
        LOGGER_WARNING("Mutex creation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto FAILURE;
    }
    
    av->m = (Messenger *)tox;
    av->msi = msi_new(av->m);
    
    if (av->msi == NULL) {
        pthread_mutex_destroy(av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto FAILURE;
    }
    
    av->interval = 200;
    av->msi->av = av;
    
    msi_register_callback(av->msi, callback_invite, msi_OnInvite);
    msi_register_callback(av->msi, callback_start, msi_OnStart);
    msi_register_callback(av->msi, callback_end, msi_OnEnd);
    msi_register_callback(av->msi, callback_error, msi_OnError);
    msi_register_callback(av->msi, callback_error, msi_OnPeerTimeout);
    msi_register_callback(av->msi, callback_capabilites, msi_OnCapabilities);
    
    
    if (error)
        *error = rc;
    
    return av;
    
FAILURE:
    if (error)
        *error = rc;
    
    free(av);
    
    return NULL;
}

void toxav_kill(ToxAV* av)
{
    if (av == NULL)
        return;
    LOGGED_LOCK(av->mutex);
    
    msi_kill(av->msi);
    
    /* Msi kill will hang up all calls so just clean these calls */
    if (av->calls) {
        ToxAVCall* it = call_get(av, av->calls_head);
        for (; it; it = it->next) {
            call_kill_transmission(it);
            call_remove(it); /* This will eventually free av->calls */
        }
    }
    
    LOGGED_UNLOCK(av->mutex);
    pthread_mutex_destroy(av->mutex);
    free(av);
}

Tox* toxav_get_tox(ToxAV* av)
{
    return (Tox*) av->m;
}

uint32_t toxav_iteration_interval(const ToxAV* av)
{
    /* If no call is active interval is 200 */
    return av->calls ? av->interval : 200;
}

void toxav_iterate(ToxAV* av)
{
    LOGGED_LOCK(av->mutex);
    if (av->calls == NULL) {
        LOGGED_UNLOCK(av->mutex);
        return;
    }
    
    uint64_t start = current_time_monotonic();
    uint32_t rc = 500;
    
    ToxAVCall* i = av->calls[av->calls_head];
    for (; i; i = i->next) {
        if (i->active) {
            LOGGED_LOCK(i->mutex_decoding);
            LOGGED_UNLOCK(av->mutex);
            
            cs_do(i->cs);
            rtp_do(i->rtps[audio_index]);
            rtp_do(i->rtps[video_index]);
            qc_do(i);
            
            if (i->last_self_capabilities & msi_CapRAudio) /* Receiving audio */
                rc = MIN(i->cs->last_packet_frame_duration, rc);
            if (i->last_self_capabilities & msi_CapRVideo) /* Receiving video */
                rc = MIN(i->cs->lcfd, rc); /* TODO handle on/off */
            
            uint32_t fid = i->friend_id;
            
            LOGGED_UNLOCK(i->mutex_decoding);
            LOGGED_LOCK(av->mutex);
            
            /* In case this call is popped from container stop iteration */
            if (call_get(av, fid) != i)
                break;
        }
    }
    LOGGED_UNLOCK(av->mutex);
    
    av->interval = rc < av->dmssa ? 0 : (rc - av->dmssa);
//     av->interval = rc < 5 ? 1: rc - 5;
    av->dmsst += current_time_monotonic() - start;
    
    if (++av->dmssc == 3) {
        av->dmssa = av->dmsst / 3 + 2 /* NOTE Magic Offset for precission */;
        av->dmssc = 0;
        av->dmsst = 0;
    }
}

bool toxav_call(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_CALL* error)
{
    LOGGED_LOCK(av->mutex);
    ToxAVCall* call = call_new(av, friend_number, error);
    if (call == NULL) {
        LOGGED_UNLOCK(av->mutex);
        return false;
    }
    
    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;
    
    call->last_self_capabilities = msi_CapRAudio | msi_CapRVideo;
    
    call->last_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->last_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_invite(av->msi, &call->msi_call, friend_number, call->last_self_capabilities) != 0) {
        call_remove(call);
        if (error)
            *error = TOXAV_ERR_CALL_MALLOC;
        LOGGED_UNLOCK(av->mutex);
        return false;
    }
    
    call->msi_call->av_call = call;
    LOGGED_UNLOCK(av->mutex);
    
    return true;
}

void toxav_callback_call(ToxAV* av, toxav_call_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->ccb.first = function;
    av->ccb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}

bool toxav_answer(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_ANSWER* error)
{
    LOGGED_LOCK(av->mutex);
    
    TOXAV_ERR_ANSWER rc = TOXAV_ERR_ANSWER_OK;
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if ((audio_bit_rate && audio_bitrate_invalid(audio_bit_rate))
      ||(video_bit_rate && video_bitrate_invalid(video_bit_rate))
    ) {
        rc = TOXAV_ERR_CALL_INVALID_BIT_RATE;
        goto END;
    }
    
    ToxAVCall* call = call_get(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;
        goto END;
    }
    
    if (!call_prepare_transmission(call)) {
		rc = TOXAV_ERR_ANSWER_MALLOC;
		goto END;
	}
    
    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;
    
    call->last_self_capabilities = msi_CapRAudio | msi_CapRVideo;
    
    call->last_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->last_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_answer(call->msi_call, call->last_self_capabilities) != 0)
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING; /* the only reason for msi_answer to fail */
    
    
END:
    LOGGED_UNLOCK(av->mutex);
    
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_ANSWER_OK;
}

void toxav_callback_call_state(ToxAV* av, toxav_call_state_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->scb.first = function;
    av->scb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}

bool toxav_call_control(ToxAV* av, uint32_t friend_number, TOXAV_CALL_CONTROL control, TOXAV_ERR_CALL_CONTROL* error)
{
    LOGGED_LOCK(av->mutex);
    TOXAV_ERR_CALL_CONTROL rc = TOXAV_ERR_CALL_CONTROL_OK;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
        goto END;
    }
    
    
    ToxAVCall* call = call_get(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME: {
            if (!call->active) {
                rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                goto END;
            }
            
            /* Only act if paused and had media transfer active before */
            if (call->msi_call->self_capabilities == 0 && 
                call->last_self_capabilities ) {
                
                if (msi_change_capabilities(call->msi_call, 
                    call->last_self_capabilities) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->rtps[audio_index]);
                rtp_start_receiving(call->rtps[video_index]);
            }
        } break;
        
        case TOXAV_CALL_CONTROL_PAUSE: {
            if (!call->active) {
                rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                goto END;
            }
            
            /* Only act if not already paused */
            if (call->msi_call->self_capabilities) {
                call->last_self_capabilities = call->msi_call->self_capabilities;
                
                if (msi_change_capabilities(call->msi_call, 0) == -1 ) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->rtps[audio_index]);
                rtp_stop_receiving(call->rtps[video_index]);
            }
        } break;
        
        case TOXAV_CALL_CONTROL_CANCEL: {
            /* Hang up */
            msi_hangup(call->msi_call);
            
            /* No mather the case, terminate the call */
            call_kill_transmission(call);
            call_remove(call);
        } break;
        
        case TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO: {
            if (!call->active) {
                rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                goto END;
            }
            
            if (call->msi_call->self_capabilities & msi_CapRAudio) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities ^ msi_CapRAudio) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->rtps[audio_index]);
            } else {
                /* This call was already muted so notify the friend that he can
                 * start sending audio again
                 */
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities | msi_CapRAudio) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->rtps[audio_index]);
            }
        } break;
        
        case TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO: {
            if (!call->active) {
                rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                goto END;
            }
            
            if (call->msi_call->self_capabilities & msi_CapRVideo) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities ^ msi_CapRVideo) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->rtps[video_index]);
            } else {
                /* This call was already muted so notify the friend that he can
                 * start sending video again
                 */
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities | msi_CapRVideo) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->rtps[video_index]);
            }
        } break;
    }
    
END:
    LOGGED_UNLOCK(av->mutex);
    
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}

bool toxav_set_audio_bit_rate(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, TOXAV_ERR_BIT_RATE* error)
{
    TOXAV_ERR_BIT_RATE rc = TOXAV_ERR_BIT_RATE_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_BIT_RATE_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (audio_bitrate_invalid(audio_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_INVALID;
        goto END;
    }
    
    LOGGED_LOCK(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        LOGGED_UNLOCK(av->mutex);
        rc = TOXAV_ERR_BIT_RATE_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    /* Decoding mutex is locked because of quality control */
    LOGGED_LOCK(call->mutex_decoding);
    call->audio_bit_rate = audio_bit_rate;
    LOGGED_UNLOCK(call->mutex_decoding);
    LOGGED_UNLOCK(av->mutex);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_BIT_RATE_OK;
}

bool toxav_set_video_bit_rate(ToxAV* av, uint32_t friend_number, uint32_t video_bit_rate, TOXAV_ERR_BIT_RATE* error)
{
    TOXAV_ERR_BIT_RATE rc = TOXAV_ERR_BIT_RATE_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_BIT_RATE_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (video_bitrate_invalid(video_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_INVALID;
        goto END;
    }
    
    LOGGED_LOCK(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        LOGGED_UNLOCK(av->mutex);
        rc = TOXAV_ERR_BIT_RATE_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    /* Decoding mutex is locked because of quality control */
    LOGGED_LOCK(call->mutex_decoding);
    call->video_bit_rate = video_bit_rate;
    LOGGED_UNLOCK(call->mutex_decoding);
    LOGGED_UNLOCK(av->mutex);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_BIT_RATE_OK;
}

void toxav_callback_video_frame_request(ToxAV* av, toxav_video_frame_request_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->rvcb.first = function;
    av->rvcb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}

bool toxav_send_video_frame(ToxAV* av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t* y, const uint8_t* u, const uint8_t* v, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    LOGGED_LOCK(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        LOGGED_UNLOCK(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    LOGGED_LOCK(call->mutex_video_sending);
    LOGGED_UNLOCK(av->mutex);
    
    if ( y == NULL || u == NULL || v == NULL ) {
        LOGGED_UNLOCK(call->mutex_video_sending);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( cs_reconfigure_video_encoder(call->cs, call->video_bit_rate, width, height) != 0 ) {
        LOGGED_UNLOCK(call->mutex_video_sending);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }
    
    { /* Encode */
        vpx_image_t img;
        img.w = img.h = img.d_w = img.d_h = 0;
        vpx_img_alloc(&img, VPX_IMG_FMT_VPXI420, width, height, 1);
        
        /* I420 "It comprises an NxM Y plane followed by (N/2)x(M/2) V and U planes." 
         * http://fourcc.org/yuv.php#IYUV
         */
        memcpy(img.planes[VPX_PLANE_Y], y, width * height);
        memcpy(img.planes[VPX_PLANE_U], u, (width/2) * (height/2));
        memcpy(img.planes[VPX_PLANE_V], v, (width/2) * (height/2));
        
        int vrc = vpx_codec_encode(call->cs->v_encoder, &img, 
                                   call->cs->frame_counter, 1, 0, MAX_ENCODE_TIME_US);
        
        vpx_img_free(&img);
        if ( vrc != VPX_CODEC_OK) {
            LOGGED_UNLOCK(call->mutex_video_sending);
            LOGGER_ERROR("Could not encode video frame: %s\n", vpx_codec_err_to_string(vrc));
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
    }
    
    ++call->cs->frame_counter;
    
    { /* Split and send */
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t *pkt;
        
        cs_init_video_splitter_cycle(call->cs);
        
        while ( (pkt = vpx_codec_get_cx_data(call->cs->v_encoder, &iter)) ) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                int parts = cs_update_video_splitter_cycle(call->cs, pkt->data.frame.buf, 
                                                           pkt->data.frame.sz);
                
                if (parts < 0) /* Should never happen though */
                    continue;
                
                uint16_t part_size;
                const uint8_t *iter;
                
                int i;
                for (i = 0; i < parts; i++) {
                    iter = cs_iterate_split_video_frame(call->cs, &part_size);
                    
                    if (rtp_send_msg(call->rtps[video_index], iter, part_size) < 0) {
                        LOGGED_UNLOCK(call->mutex_video_sending);
                        LOGGER_WARNING("Could not send video frame: %s\n", strerror(errno));
                        goto END;
                    }
                }
            }
        }
    }
    
    LOGGED_UNLOCK(call->mutex_video_sending);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_audio_frame_request(ToxAV* av, toxav_audio_frame_request_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->racb.first = function;
    av->racb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}

bool toxav_send_audio_frame(ToxAV* av, uint32_t friend_number, const int16_t* pcm, size_t sample_count, uint8_t channels, uint32_t sampling_rate, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    LOGGED_LOCK(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        LOGGED_UNLOCK(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    LOGGED_LOCK(call->mutex_audio_sending);
    LOGGED_UNLOCK(av->mutex);
    
    if ( pcm == NULL ) {
        LOGGED_UNLOCK(call->mutex_audio_sending);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( channels > 2 ) {
        LOGGED_UNLOCK(call->mutex_audio_sending);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }
    
    { /* Encode and send */
        if (cs_reconfigure_audio_encoder(call->cs, call->audio_bit_rate * 1000, sampling_rate, channels) != 0) {
            LOGGED_UNLOCK(call->mutex_audio_sending);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        uint8_t dest[sample_count + sizeof(sampling_rate)]; /* This is more than enough always */
        
        sampling_rate = htonl(sampling_rate);
        memcpy(dest, &sampling_rate, sizeof(sampling_rate));
        int vrc = opus_encode(call->cs->audio_encoder, pcm, sample_count,
                              dest + sizeof(sampling_rate), sizeof(dest) - sizeof(sampling_rate));
        
        if (vrc < 0) {
            LOGGER_WARNING("Failed to encode frame %s", opus_strerror(vrc));
            LOGGED_UNLOCK(call->mutex_audio_sending);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
//         LOGGER_DEBUG("Sending encoded audio frame size: %d; channels: %d; srate: %d", vrc, channels,
//                      ntohl(sampling_rate));
        
		if (rtp_send_msg(call->rtps[audio_index], dest, vrc + sizeof(sampling_rate)) != 0) {
			LOGGER_WARNING("Failed to send audio packet");
			rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
		}
    }
    
    LOGGED_UNLOCK(call->mutex_audio_sending);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_receive_video_frame(ToxAV* av, toxav_receive_video_frame_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->vcb.first = function;
    av->vcb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}

void toxav_callback_receive_audio_frame(ToxAV* av, toxav_receive_audio_frame_cb* function, void* user_data)
{
    LOGGED_LOCK(av->mutex);
    av->acb.first = function;
    av->acb.second = user_data;
    LOGGED_UNLOCK(av->mutex);
}


/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
int callback_invite(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    LOGGED_LOCK(toxav->mutex);
    
    ToxAVCall* av_call = call_new(toxav, call->friend_id, NULL);
    if (av_call == NULL) {
        LOGGER_WARNING("Failed to initialize call...");
        LOGGED_UNLOCK(toxav->mutex);
        return -1;
    }
    
    call->av_call = av_call;
    av_call->msi_call = call;
    
    if (toxav->ccb.first)
        toxav->ccb.first(toxav, call->friend_id, call->peer_capabilities & msi_CapSAudio, 
                         call->peer_capabilities & msi_CapSVideo, toxav->ccb.second);
    
    LOGGED_UNLOCK(toxav->mutex);
    return 0;
}

int callback_start(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    LOGGED_LOCK(toxav->mutex);
    
    ToxAVCall* av_call = call_get(toxav, call->friend_id);
    
    if (av_call == NULL) {
        /* Should this ever happen? */
        LOGGED_UNLOCK(toxav->mutex);
        return -1;
    }
    
    if (!call_prepare_transmission(av_call)) {
        callback_error(toxav_inst, call);
        call_remove(av_call);
        LOGGED_UNLOCK(toxav->mutex);
        return -1;
    }
    
    invoke_call_state(toxav, call->friend_id, call->peer_capabilities);
    
    LOGGED_UNLOCK(toxav->mutex);
    return 0;
}

int callback_end(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    LOGGED_LOCK(toxav->mutex);
    
    invoke_call_state(toxav, call->friend_id, TOXAV_CALL_STATE_END);
    
    call_kill_transmission(call->av_call);
    call_remove(call->av_call);
    
    LOGGED_UNLOCK(toxav->mutex);
    return 0;
}

int callback_error(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    LOGGED_LOCK(toxav->mutex);
    
    invoke_call_state(toxav, call->friend_id, TOXAV_CALL_STATE_ERROR);
    
    call_kill_transmission(call->av_call);
    call_remove(call->av_call);
    
    LOGGED_UNLOCK(toxav->mutex);
    return 0;
}

int callback_capabilites(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    LOGGED_LOCK(toxav->mutex);
    
    /* TODO modify cs? */
    
    invoke_call_state(toxav, call->friend_id, call->peer_capabilities);
    
    LOGGED_UNLOCK(toxav->mutex);
    return 0;
}

bool audio_bitrate_invalid(uint32_t bitrate)
{
    /* Opus RFC 6716 section-2.1.1 dictates the following:
     * Opus supports all bitrates from 6 kbit/s to 510 kbit/s.
     */
    return bitrate < 6 || bitrate > 510;
}

bool video_bitrate_invalid(uint32_t bitrate)
{
    /* TODO: If anyone knows the answer to this one please fill it up */
    return false;
}

void invoke_call_state(ToxAV* av, uint32_t friend_number, uint32_t state)
{
    if (av->scb.first)
        av->scb.first(av, friend_number, state, av->scb.second);
}

ToxAVCall* call_new(ToxAV* av, uint32_t friend_number, TOXAV_ERR_CALL* error)
{
    /* Assumes mutex locked */
    TOXAV_ERR_CALL rc = TOXAV_ERR_CALL_OK;
    ToxAVCall* call = NULL;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (m_get_friend_connectionstatus(av->m, friend_number) < 1) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;
        goto END;
    }
    
    if (call_get(av, friend_number) != NULL) {
        rc = TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;
        goto END;
    }
    
    
    call = calloc(sizeof(ToxAVCall), 1);
    
    if (call == NULL) {
        rc = TOXAV_ERR_CALL_MALLOC;
        goto END;
    }
    
    call->av = av;
    call->friend_id = friend_number;
    
    if (av->calls == NULL) { /* Creating */
        av->calls = calloc (sizeof(ToxAVCall*), friend_number + 1);
        
        if (av->calls == NULL) {
            free(call);
            call = NULL;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto END;
        }
        
        av->calls_tail = av->calls_head = friend_number;
        
    } else if (av->calls_tail < friend_number) { /* Appending */
        void* tmp = realloc(av->calls, sizeof(ToxAVCall*) * friend_number + 1);
        
        if (tmp == NULL) {
            free(call);
            call = NULL;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto END;
        }
        
        av->calls = tmp;
        
        /* Set fields in between to null */
        int32_t i = av->calls_tail;
        for (; i < friend_number; i ++)
            av->calls[i] = NULL;
        
        call->prev = av->calls[av->calls_tail];
        av->calls[av->calls_tail]->next = call;
        
        av->calls_tail = friend_number;
        
    } else if (av->calls_head > friend_number) { /* Inserting at front */
        call->next = av->calls[av->calls_head];
        av->calls[av->calls_head]->prev = call;
        av->calls_head = friend_number;
    }
    
    av->calls[friend_number] = call;
    
END:
    if (error)
        *error = rc;
    
    return call;
}

ToxAVCall* call_get(ToxAV* av, uint32_t friend_number)
{
    /* Assumes mutex locked */
    if (av->calls == NULL || av->calls_tail < friend_number)
        return NULL;
    
    return av->calls[friend_number];
}

void qc_do(ToxAVCall* call)
{
    /* Please NOTE: The quality control is rather basic,
     * advanced algorithms will be applied in the future
     */
    switch(call->rtps[audio_index]->tstate) {
    case rtp_StateBad:
        LOGGER_DEBUG("Suggesting lower bitrate for audio...");
        call->time_audio_good = 0;
        call->last_bad_audio_bit_rate = call->audio_bit_rate;
        invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_DECREASE_AUDIO_BITRATE);
        break;
    case rtp_StateGood:
        if (call->time_audio_good == 0)
            call->time_audio_good = current_time_monotonic();
        else if (current_time_monotonic() - call->time_audio_good >= 30000 && 
            64 > call->audio_bit_rate)
            if (call->last_bad_audio_bit_rate > call->audio_bit_rate) {
                if (current_time_monotonic() - call->time_audio_good >= 45000)
                    invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_INCREASE_AUDIO_BITRATE);
                call->last_bad_audio_bit_rate = 0;
            } else
                invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_INCREASE_AUDIO_BITRATE);
        break;
    case rtp_StateNormal:
        call->time_audio_good = 0;
        break;
    }
    
    switch(call->rtps[video_index]->tstate) {
    case rtp_StateBad:
        LOGGER_DEBUG("Suggesting lower bitrate for video...");
        call->time_video_good = 0;
        call->last_bad_video_bit_rate = call->video_bit_rate;
        invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_DECREASE_VIDEO_BITRATE);
        break;
    case rtp_StateGood:
        if (call->time_video_good == 0)
            call->time_video_good = current_time_monotonic();
        else if (current_time_monotonic() - call->time_video_good >= 30000)
            if (call->last_bad_video_bit_rate > call->video_bit_rate) {
                if (current_time_monotonic() - call->time_video_good >= 45000)
                    invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_INCREASE_VIDEO_BITRATE);
                call->last_bad_video_bit_rate = 0;
            } else
                invoke_call_state(call->av, call->friend_id, TOXAV_CALL_STATE_INCREASE_VIDEO_BITRATE);
        break;
    case rtp_StateNormal:
        call->time_video_good = 0;
        break;
    }
    
}

void call_remove(ToxAVCall* call)
{
    if (call == NULL)
        return;
    
    uint32_t friend_id = call->friend_id;
    ToxAV* av = call->av;
    
    ToxAVCall* prev = call->prev;
    ToxAVCall* next = call->next;
    
    free(call);
    
    if (prev)
        prev->next = next;
    else if (next)
        av->calls_head = next->friend_id;
    else goto CLEAR;
    
    if (next)
        next->prev = prev;
    else if (prev)
        av->calls_tail = prev->friend_id;
    else goto CLEAR;
    
    av->calls[friend_id] = NULL;
    return;
    
CLEAR:
    av->calls_head = av->calls_tail = 0;
    free(av->calls);
    av->calls = NULL;
}

bool call_prepare_transmission(ToxAVCall* call)
{
    /* Assumes mutex locked */
    
    if (call == NULL)
        return false;
    
    ToxAV* av = call->av;
    
    if (!av->acb.first && !av->vcb.first)
        /* It makes no sense to have CSession without callbacks */
        return false;
    
    if (call->active) {
        LOGGER_WARNING("Call already active!\n");
        return true;
    }
    
    if (create_recursive_mutex(call->mutex_audio_sending) != 0)
        return false;
    
    if (create_recursive_mutex(call->mutex_video_sending) != 0) {
        goto AUDIO_SENDING_MUTEX_CLEANUP;
    }
    
    if (create_recursive_mutex(call->mutex_decoding) != 0) {
        goto VIDEO_SENDING_MUTEX_CLEANUP;
    }
    
    /* Creates both audio and video encoders and decoders with some default values.
     * Make sure to reconfigure encoders dynamically when sending data
     */
    call->cs = cs_new(call->msi_call->peer_vfpsz);
    
    if ( !call->cs ) {
        LOGGER_ERROR("Error while starting Codec State!\n");
        goto FAILURE;
    }
    
    call->cs->av = av;
    call->cs->friend_id = call->friend_id;
    
    memcpy(&call->cs->acb, &av->acb, sizeof(av->acb));
    memcpy(&call->cs->vcb, &av->vcb, sizeof(av->vcb));
    
    { /* Prepare audio RTP */
        call->rtps[audio_index] = rtp_new(rtp_TypeAudio, av->m, call->friend_id);
        
        if ( !call->rtps[audio_index] ) {
            LOGGER_ERROR("Error while starting audio RTP session!\n");
            goto FAILURE;
        }
        
        call->rtps[audio_index]->cs = call->cs;
        
        if (rtp_start_receiving(call->rtps[audio_index]) != 0) {
            LOGGER_WARNING("Failed to enable audio receiving!");
            goto FAILURE;
        }
    }
    
    { /* Prepare video RTP */
        call->rtps[video_index] = rtp_new(rtp_TypeVideo, av->m, call->friend_id);
        
        if ( !call->rtps[video_index] ) {
            LOGGER_ERROR("Error while starting video RTP session!\n");
            goto FAILURE;
        }
        
        call->rtps[video_index]->cs = call->cs;
        
        if (rtp_start_receiving(call->rtps[video_index]) != 0) {
            LOGGER_WARNING("Failed to enable audio receiving!");
            goto FAILURE;
        }
    }
    
    call->active = 1;
    return true;
    
FAILURE:
    rtp_kill(call->rtps[audio_index]);
    call->rtps[audio_index] = NULL;
    rtp_kill(call->rtps[video_index]);
    call->rtps[video_index] = NULL;
    cs_kill(call->cs);
    call->cs = NULL;
    pthread_mutex_destroy(call->mutex_decoding);
VIDEO_SENDING_MUTEX_CLEANUP:
    pthread_mutex_destroy(call->mutex_video_sending);
AUDIO_SENDING_MUTEX_CLEANUP:
    pthread_mutex_destroy(call->mutex_audio_sending);
    return false;
}

void call_kill_transmission(ToxAVCall* call)
{
    if (call == NULL || call->active == 0)
        return;
    
    call->active = 0;
    
    rtp_kill(call->rtps[audio_index]);
    call->rtps[audio_index] = NULL;
    rtp_kill(call->rtps[video_index]);
    call->rtps[video_index] = NULL;
    
    LOGGED_LOCK(call->mutex_audio_sending);
    LOGGED_UNLOCK(call->mutex_audio_sending);
    LOGGED_LOCK(call->mutex_video_sending);
    LOGGED_UNLOCK(call->mutex_video_sending);
    LOGGED_LOCK(call->mutex_decoding);
    LOGGED_UNLOCK(call->mutex_decoding);
    
    cs_kill(call->cs);
    call->cs = NULL;
    
    pthread_mutex_destroy(call->mutex_audio_sending);
    pthread_mutex_destroy(call->mutex_video_sending);
    pthread_mutex_destroy(call->mutex_decoding);
}
