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

typedef struct ToxAVCall_s
{
    pthread_mutex_t mutex_control[1];
    pthread_mutex_t mutex_encoding_audio[1];
    pthread_mutex_t mutex_encoding_video[1];
    pthread_mutex_t mutex_do[1];
    RTPSession *rtps[2]; /* Audio is first and video is second */
    CSSession *cs;
    bool active;
    MSICall* msi_call;
    uint32_t friend_id;
    
    uint32_t s_audio_b; /* Sending audio bitrate */
    uint32_t s_video_b; /* Sending video bitrate */
    
    struct ToxAVCall_s *prev;
    struct ToxAVCall_s *next;
} ToxAVCall;

struct toxAV
{
    Messenger* m;
    MSISession* msi;
    
    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall** calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    
    PAIR(toxav_call_cb *, void*) ccb; /* Call callback */
    PAIR(toxav_call_state_cb *, void *) scb; /* Call state callback */
    PAIR(toxav_receive_audio_frame_cb *, void *) acb; /* Audio frame receive callback */
    PAIR(toxav_receive_video_frame_cb *, void *) vcb; /* Video frame receive callback */
    
    /** Decode time measures */
    int32_t dmssc; /** Measure count */
    int32_t dmsst; /** Last cycle total */
    int32_t dmssa; /** Average decoding time in ms */
    
    uint32_t interval; /** Calculated interval */
};


void i_callback_invite(void* toxav_inst, MSICall* call);
void i_callback_ringing(void* toxav_inst, MSICall* call);
void i_callback_start(void* toxav_inst, MSICall* call);
void i_callback_end(void* toxav_inst, MSICall* call);
void i_callback_error(void* toxav_inst, MSICall* call);
void i_callback_capabilites(void* toxav_inst, MSICall* call);

TOXAV_CALL_STATE capabilities_to_state(uint8_t capabilities);
ToxAVCall* i_toxav_get_call(ToxAV* av, uint32_t friend_number);
ToxAVCall* i_toxav_add_call(ToxAV* av, uint32_t friend_number);
void i_toxav_remove_call(ToxAV* av, uint32_t friend_number);
ToxAVCall* i_toxav_init_call(ToxAV* av, uint32_t friend_number, TOXAV_ERR_CALL* error);
bool i_toxav_audio_bitrate_invalid(uint32_t bitrate);
bool i_toxav_video_bitrate_invalid(uint32_t bitrate);
bool i_toxav_prepare_transmission(ToxAV* av, ToxAVCall* call);
void i_toxav_kill_transmission(ToxAV* av, uint32_t friend_number);



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
    
    av = calloc ( sizeof(ToxAV), 1);
    
    if (av == NULL) {
        LOGGER_WARNING("Allocation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto FAILURE;
    }
    
    av->m = (Messenger *)tox;
    av->msi = msi_new(av->m);
    
    if (av->msi == NULL) {
        rc = TOXAV_ERR_NEW_MALLOC;
        goto FAILURE;
    }
    
    av->interval = 200;
    av->msi->av = av;
    
    msi_register_callback(av->msi, i_callback_invite, msi_OnInvite);
    msi_register_callback(av->msi, i_callback_ringing, msi_OnRinging);
    msi_register_callback(av->msi, i_callback_start, msi_OnStart);
    msi_register_callback(av->msi, i_callback_end, msi_OnReject);
    msi_register_callback(av->msi, i_callback_end, msi_OnEnd);
    msi_register_callback(av->msi, i_callback_error, msi_OnError);
    msi_register_callback(av->msi, i_callback_error, msi_OnPeerTimeout);
    msi_register_callback(av->msi, i_callback_capabilites, msi_OnCapabilities);
    
    
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
    
    msi_kill(av->msi);
    /* TODO iterate over calls */
    free(av);
}

Tox* toxav_get_tox(ToxAV* av)
{
    return (Tox*) av->m;
}

uint32_t toxav_iteration_interval(const ToxAV* av)
{
    return av->calls ? av->interval : 200;
}

void toxav_iteration(ToxAV* av)
{
    if (av->calls == NULL)
        return;
    
    uint64_t start = current_time_monotonic();
    uint32_t rc = 200 + av->dmssa; /* If no call is active interval is 200 */
    
    ToxAVCall* i = av->calls[av->calls_head];
    for (; i; i = i->next) {
        if (i->active) {
            cs_do(i->cs);
            rc = MIN(i->cs->last_packet_frame_duration, rc);
        }
    }
    
    av->interval = rc < av->dmssa ? 0 : rc - av->dmssa;
    av->dmsst += current_time_monotonic() - start;
    
    if (++av->dmssc == 3) {
        av->dmssa = av->dmsst / 3 + 2 /* NOTE Magic Offset for precission */;
        av->dmssc = 0;
        av->dmsst = 0;
    }
}

bool toxav_call(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_CALL* error)
{
    ToxAVCall* call = i_toxav_init_call(av, friend_number, error);
    if (call == NULL)
        return false;
    
    call->s_audio_b = audio_bit_rate;
    call->s_video_b = video_bit_rate;
    
    uint8_t capabilities = 0;
    
    capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_invite(av->msi, &call->msi_call, friend_number, capabilities) != 0) {
        i_toxav_remove_call(av, friend_number);
        if (error)
            *error = TOXAV_ERR_CALL_MALLOC;
        return false;
    }
    
    return true;
}

void toxav_callback_call(ToxAV* av, toxav_call_cb* function, void* user_data)
{
    av->ccb.first = function;
    av->ccb.second = user_data;
}

bool toxav_answer(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_ANSWER* error)
{
    TOXAV_ERR_ANSWER rc = TOXAV_ERR_ANSWER_OK;
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if ((audio_bit_rate && i_toxav_audio_bitrate_invalid(audio_bit_rate))
      ||(video_bit_rate && i_toxav_video_bitrate_invalid(video_bit_rate))
    ) {
        rc = TOXAV_ERR_CALL_INVALID_BIT_RATE;
        goto END;
    }
    
    ToxAVCall* call = i_toxav_get_call(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;
        goto END;
    }
    
    call->s_audio_b = audio_bit_rate;
    call->s_video_b = video_bit_rate;
    
    uint8_t capabilities = 0;
    
    capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_answer(call->msi_call, capabilities) != 0)
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING; /* the only reason for msi_answer to fail */
    
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_ANSWER_OK;
}

void toxav_callback_call_state(ToxAV* av, toxav_call_state_cb* function, void* user_data)
{
    av->scb.first = function;
    av->scb.second = user_data;
}

bool toxav_call_control(ToxAV* av, uint32_t friend_number, TOXAV_CALL_CONTROL control, TOXAV_ERR_CALL_CONTROL* error)
{
    TOXAV_ERR_CALL_CONTROL rc = TOXAV_ERR_CALL_CONTROL_OK;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
        goto END;
    }
    
    
    ToxAVCall* call = i_toxav_get_call(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    /* TODO rest of these */
    switch (control)
    {
        case TOXAV_CALL_CONTROL_RESUME: {
            
        } break;
        
        case TOXAV_CALL_CONTROL_PAUSE: {
            
        } break;
        
        case TOXAV_CALL_CONTROL_CANCEL: {
            if (call->msi_call->state == msi_CallActive 
             || call->msi_call->state == msi_CallRequesting) {
                /* Hang up */
                msi_hangup(call->msi_call);
             } else if (call->msi_call->state == msi_CallRequested) {
                 /* Reject the call */
                msi_reject(call->msi_call);
            }
            
            // No mather the case, terminate the call
            i_toxav_remove_call(av, friend_number);
        } break;
        
        case TOXAV_CALL_CONTROL_MUTE_AUDIO: {
            
        } break;
        
        case TOXAV_CALL_CONTROL_MUTE_VIDEO: {
            
        } break;
    }
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}

bool toxav_set_audio_bit_rate(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, TOXAV_ERR_BIT_RATE* error)
{
    /* TODO */
}

bool toxav_set_video_bit_rate(ToxAV* av, uint32_t friend_number, uint32_t video_bit_rate, TOXAV_ERR_BIT_RATE* error)
{
    /* TODO */
}

void toxav_callback_request_video_frame(ToxAV* av, toxav_request_video_frame_cb* function, void* user_data)
{
    /* TODO */
}

bool toxav_send_video_frame(ToxAV* av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t* y, const uint8_t* u, const uint8_t* v, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    call = i_toxav_get_call(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->msi_call->state != msi_CallActive) {
        /* TODO */
        rc = TOXAV_ERR_SEND_FRAME_NOT_REQUESTED;
        goto END;
    }
    
    if ( y == NULL || u == NULL || v == NULL ) {
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( cs_set_sending_video_resolution(call->cs, width, height) != 0 ) {
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
        
        vpx_img_free(&img); /* FIXME don't free? */
        if ( vrc != VPX_CODEC_OK) {
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
                    
                    if (rtp_send_msg(call->rtps[video_index], iter, part_size) < 0)
                        goto END;
                }
            }
        }
    }
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_request_audio_frame(ToxAV* av, toxav_request_audio_frame_cb* function, void* user_data)
{
    /* TODO */
}

bool toxav_send_audio_frame(ToxAV* av, uint32_t friend_number, const int16_t* pcm, size_t sample_count, uint8_t channels, uint32_t sampling_rate, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    call = i_toxav_get_call(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->msi_call->state != msi_CallActive) {
        /* TODO */
        rc = TOXAV_ERR_SEND_FRAME_NOT_REQUESTED;
        goto END;
    }
    
    if ( pcm == NULL ) {
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( channels != 1 || channels != 2 ) {
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }
    
    { /* Encode and send */
        /* TODO redundant? */
        cs_set_sending_audio_channels(call->cs, channels);
        cs_set_sending_audio_sampling_rate(call->cs, sampling_rate);
        
        uint8_t dest[sample_count * channels * 2 /* sizeof(uint16_t) */];
        int vrc = opus_encode(call->cs->audio_encoder, pcm, sample_count, dest, sizeof (dest));
        
        if (vrc < 0) {
            LOGGER_WARNING("Failed to encode frame");
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        vrc = rtp_send_msg(call->rtps[audio_index], dest, vrc);
        /* TODO check for error? */
    }
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_receive_video_frame(ToxAV* av, toxav_receive_video_frame_cb* function, void* user_data)
{
    av->vcb.first = function;
    av->vcb.second = user_data;
}

void toxav_callback_receive_audio_frame(ToxAV* av, toxav_receive_audio_frame_cb* function, void* user_data)
{
    av->acb.first = function;
    av->acb.second = user_data;
}


/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
/** TODO: 
 * - If crutial callback not present send error.
 * - Error handling by return values from callbacks and setting 'error'.
 */
void i_callback_invite(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    
    ToxAVCall* av_call = i_toxav_init_call(toxav, call->friend_id, NULL);
    if (av_call == NULL) {
        LOGGER_WARNING("Failed to start call, rejecting...");
        msi_reject(call);
        return;
    }
    
    call->av_call = av_call;
    av_call->msi_call = call;
    
    if (toxav->ccb.first)
        toxav->ccb.first(toxav, call->friend_id, call->peer_capabilities & msi_CapSAudio, 
                         call->peer_capabilities & msi_CapSVideo, toxav->ccb.second);
}

void i_callback_ringing(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    if (toxav->scb.first)
        toxav->scb.first(toxav, call->friend_id, TOXAV_CALL_STATE_RINGING, toxav->scb.second);
}

void i_callback_start(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    
    ToxAVCall* av_call = i_toxav_get_call(toxav, call->friend_id);
    
    if (av_call == NULL || !i_toxav_prepare_transmission(toxav, av_call)) {
        /* TODO send error */
        i_toxav_remove_call(toxav, call->friend_id);
        return;
    }
    
    TOXAV_CALL_STATE state = capabilities_to_state(av_call->msi_call->peer_capabilities);
    
    if (toxav->scb.first)
        toxav->scb.first(toxav, call->friend_id, state, toxav->scb.second);
}

void i_callback_end(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    
    i_toxav_kill_transmission(toxav, call->friend_id);
    i_toxav_remove_call(toxav, call->friend_id);
    
    if (toxav->scb.first)
        toxav->scb.first(toxav, call->friend_id, TOXAV_CALL_STATE_END, toxav->scb.second);
}

void i_callback_error(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    if (toxav->scb.first)
        toxav->scb.first(toxav, call->friend_id, TOXAV_CALL_STATE_ERROR, toxav->scb.second);
}

void i_callback_capabilites(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    /* TODO handle this */
}

TOXAV_CALL_STATE capabilities_to_state(uint8_t capabilities)
{
    if ((capabilities & msi_CapSAudio) && (capabilities & msi_CapSVideo))
        return TOXAV_CALL_STATE_SENDING_AV;
    else if (capabilities & msi_CapSAudio)
        return TOXAV_CALL_STATE_SENDING_A;
    else if (capabilities & msi_CapSVideo)
        return TOXAV_CALL_STATE_SENDING_V;
    else
        return TOXAV_CALL_STATE_PAUSED;
}

ToxAVCall* i_toxav_get_call(ToxAV* av, uint32_t friend_number)
{
    if (av->calls == NULL || av->calls_tail < friend_number)
        return NULL;
    
    return av->calls[friend_number];
}

ToxAVCall* i_toxav_add_call(ToxAV* av, uint32_t friend_number)
{
    ToxAVCall* rc = calloc(sizeof(ToxAVCall), 1);
    
    if (rc == NULL)
        return NULL;
    
    rc->friend_id = friend_number;
    
    if (create_recursive_mutex(rc->mutex_control) != 0) {
        free(rc);
        return NULL;
    }
    
    if (create_recursive_mutex(rc->mutex_do) != 0) {
        pthread_mutex_destroy(rc->mutex_control);
        free(rc);
        return NULL;
    }
    
    
    if (av->calls == NULL) { /* Creating */
        av->calls = calloc (sizeof(ToxAVCall*), friend_number + 1);
        
        if (av->calls == NULL) {
            pthread_mutex_destroy(rc->mutex_control);
            pthread_mutex_destroy(rc->mutex_do);
            free(rc);
            return NULL;
        }
        
        av->calls_tail = av->calls_head = friend_number;
        
    } else if (av->calls_tail < friend_number) { /* Appending */
        void* tmp = realloc(av->calls, sizeof(ToxAVCall*) * friend_number + 1);
        
        if (tmp == NULL) {
            pthread_mutex_destroy(rc->mutex_control);
            pthread_mutex_destroy(rc->mutex_do);
            free(rc);
            return NULL;
        }
        
        av->calls = tmp;
        
        /* Set fields in between to null */
        int32_t i = av->calls_tail;
        for (; i < friend_number; i ++)
            av->calls[i] = NULL;
        
        rc->prev = av->calls[av->calls_tail];
        av->calls[av->calls_tail]->next = rc;
        
        av->calls_tail = friend_number;
        
    } else if (av->calls_head > friend_number) { /* Inserting at front */
        rc->next = av->calls[av->calls_head];
        av->calls[av->calls_head]->prev = rc;
        av->calls_head = friend_number;
    }
    
    av->calls[friend_number] = rc;
    return rc;
}

void i_toxav_remove_call(ToxAV* av, uint32_t friend_number)
{
    ToxAVCall* tc = i_toxav_get_call(av, friend_number);
    
    if (tc == NULL)
        return;
    
    ToxAVCall* prev = tc->prev;
    ToxAVCall* next = tc->next;
    
    pthread_mutex_destroy(tc->mutex_control);
    pthread_mutex_destroy(tc->mutex_do);
    
    free(tc);
    
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
    
    av->calls[friend_number] = NULL;
    return;
    
CLEAR:
    av->calls_head = av->calls_tail = 0;
    free(av->calls);
    av->calls = NULL;
}

ToxAVCall* i_toxav_init_call(ToxAV* av, uint32_t friend_number, TOXAV_ERR_CALL* error)
{
    TOXAV_ERR_CALL rc = TOXAV_ERR_CALL_OK;
    ToxAVCall* call = NULL;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (m_get_friend_connectionstatus(av->m, friend_number) != 1) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;
        goto END;
    }
    
    if (i_toxav_get_call(av, friend_number) != NULL) {
        rc = TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;
        goto END;
    }
    
    call = i_toxav_add_call(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_CALL_MALLOC;
    }
    
    END:
    if (error)
        *error = rc;
    
    return call;
}

bool i_toxav_audio_bitrate_invalid(uint32_t bitrate)
{
    /* Opus RFC 6716 section-2.1.1 dictates the following:
    * Opus supports all bitrates from 6 kbit/s to 510 kbit/s.
    */
    return bitrate < 6 || bitrate > 510;
}

bool i_toxav_video_bitrate_invalid(uint32_t bitrate)
{
    /* TODO: If anyone knows the answer to this one please fill it up */
    return false;
}

bool i_toxav_prepare_transmission(ToxAV* av, ToxAVCall* call)
{
    if (!av->acb.first && !av->vcb.first)
        /* It makes no sense to have CSession without callbacks */
        return false;
    
    pthread_mutex_lock(call->mutex_control);
    
    if (call->active) {
        pthread_mutex_unlock(call->mutex_control);
        LOGGER_WARNING("Call already active!\n");
        return true;
    }
    
    if (pthread_mutex_init(call->mutex_encoding_audio, NULL) != 0)
        goto MUTEX_INIT_ERROR;
    
    if (pthread_mutex_init(call->mutex_encoding_video, NULL) != 0) {
        pthread_mutex_destroy(call->mutex_encoding_audio);
        goto MUTEX_INIT_ERROR;
    }
    
    if (pthread_mutex_init(call->mutex_do, NULL) != 0) {
        pthread_mutex_destroy(call->mutex_encoding_audio);
        pthread_mutex_destroy(call->mutex_encoding_video);
        goto MUTEX_INIT_ERROR;
    }
    
    uint8_t capabilities = call->msi_call->self_capabilities;
    
    call->cs = cs_new(call->msi_call->peer_vfpsz);
    
    if ( !call->cs ) {
        LOGGER_ERROR("Error while starting Codec State!\n");
        goto FAILURE;
    }
    
    call->cs->agent = av;
    call->cs->friend_id = call->friend_id;
    
    memcpy(&call->cs->acb, &av->acb, sizeof(av->acb));
    memcpy(&call->cs->vcb, &av->vcb, sizeof(av->vcb));
    
    if (capabilities & msi_CapSAudio || capabilities & msi_CapRAudio) { /* Prepare audio sending */
        
        call->rtps[audio_index] = rtp_new(rtp_TypeAudio, av->m, call->friend_id);
        
        if ( !call->rtps[audio_index] ) {
            LOGGER_ERROR("Error while starting audio RTP session!\n");
            goto FAILURE;
        }
        
        call->rtps[audio_index]->cs = call->cs;
        
        if (cs_enable_audio_sending(call->cs, call->s_audio_b, 2) != 0) {
            LOGGER_WARNING("Failed to enable audio sending!");
            goto FAILURE;
        }
        
        if (capabilities & msi_CapRAudio) {
            if (cs_enable_audio_receiving(call->cs) != 0) {
                LOGGER_WARNING("Failed to enable audio receiving!");
                goto FAILURE;
            }
            
            rtp_register_for_receiving(call->rtps[audio_index]);
        }
    }
    
    if (capabilities & msi_CapSVideo || capabilities & msi_CapRVideo) { /* Prepare video rtp */
        call->rtps[video_index] = rtp_new(rtp_TypeVideo, av->m, call->friend_id);
        
        if ( !call->rtps[video_index] ) {
            LOGGER_ERROR("Error while starting video RTP session!\n");
            goto FAILURE;
        }
        
        call->rtps[video_index]->cs = call->cs;
        
        if (cs_enable_video_sending(call->cs, call->s_video_b) != 0) {
            LOGGER_WARNING("Failed to enable video sending!");
            goto FAILURE;
        }
        
        if (capabilities & msi_CapRVideo) {
            if (cs_enable_video_receiving(call->cs) != 0) {
                LOGGER_WARNING("Failed to enable video receiving!");
                goto FAILURE;
            }
                
            rtp_register_for_receiving(call->rtps[audio_index]);
        }
    }
    
    call->active = 1;
    pthread_mutex_unlock(call->mutex_control);
    return true;
    
FAILURE:
    rtp_kill(call->rtps[audio_index]);
    call->rtps[audio_index] = NULL;
    rtp_kill(call->rtps[video_index]);
    call->rtps[video_index] = NULL;
    cs_kill(call->cs);
    call->cs = NULL;
    call->active = 0;
    pthread_mutex_destroy(call->mutex_encoding_audio);
    pthread_mutex_destroy(call->mutex_encoding_video);
    pthread_mutex_destroy(call->mutex_do);
    
    pthread_mutex_unlock(call->mutex_control);
    return false;
    
MUTEX_INIT_ERROR:
    pthread_mutex_unlock(call->mutex_control);
    LOGGER_ERROR("Mutex initialization failed!\n");
    return false;
}

void i_toxav_kill_transmission(ToxAV* av, uint32_t friend_number)
{
    ToxAVCall* call = i_toxav_get_call(av, friend_number);
    if (!call)
        return;
    
    pthread_mutex_lock(call->mutex_control);
    
    if (!call->active) {
        pthread_mutex_unlock(call->mutex_control);
        return;
    }
    
    call->active = 0;
    
    pthread_mutex_lock(call->mutex_encoding_audio);
    pthread_mutex_unlock(call->mutex_encoding_audio);
    pthread_mutex_lock(call->mutex_encoding_video);
    pthread_mutex_unlock(call->mutex_encoding_video);
    pthread_mutex_lock(call->mutex_do);
    pthread_mutex_unlock(call->mutex_do);
    
    rtp_kill(call->rtps[audio_index]);
    call->rtps[audio_index] = NULL;
    rtp_kill(call->rtps[video_index]);
    call->rtps[video_index] = NULL;
    cs_kill(call->cs);
    call->cs = NULL;
    
    pthread_mutex_destroy(call->mutex_encoding_audio);
    pthread_mutex_destroy(call->mutex_encoding_video);
    pthread_mutex_destroy(call->mutex_do);
    
    pthread_mutex_unlock(call->mutex_control);
}