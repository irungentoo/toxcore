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

#include "msi.h"
#include "rtp.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define MAX_ENCODE_TIME_US ((1000 / 24) * 1000)
#define BITRATE_CHANGE_TESTING_TIME_MS 4000

typedef struct ToxAvBitrateAdapter_s {
    bool active;
    uint64_t end_time;
    uint64_t next_send;
    uint64_t next_send_interval;
    uint32_t bit_rate;
} ToxAvBitrateAdapter;

typedef struct ToxAVCall_s {
    ToxAV* av;
    
    pthread_mutex_t mutex_audio[1];
    PAIR(RTPSession *, ACSession *) audio;
    
    pthread_mutex_t mutex_video[1];
    PAIR(RTPSession *, VCSession *) video;
    
    pthread_mutex_t mutex[1];
    
    bool active;
    MSICall* msi_call;
    uint32_t friend_number;
    
    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */
    
    ToxAvBitrateAdapter aba;
    ToxAvBitrateAdapter vba;
    
    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;
    
    /** Quality control */
    uint64_t time_audio_good;
    uint32_t last_bad_audio_bit_rate;
    uint64_t time_video_good;
    uint32_t last_bad_video_bit_rate;
    
    struct ToxAVCall_s *prev;
    struct ToxAVCall_s *next;
} ToxAVCall;

struct ToxAV {
    Messenger* m;
    MSISession* msi;
    
    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall** calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t mutex[1];
    
    PAIR(toxav_call_cb *, void*) ccb; /* Call callback */
    PAIR(toxav_call_state_cb *, void *) scb; /* Call state callback */
    PAIR(toxav_audio_receive_frame_cb *, void *) acb; /* Audio frame receive callback */
    PAIR(toxav_video_receive_frame_cb *, void *) vcb; /* Video frame receive callback */
    PAIR(toxav_audio_bit_rate_status_cb *, void *) abcb; /* Audio bit rate control callback */
    PAIR(toxav_video_bit_rate_status_cb *, void *) vbcb; /* Video bit rate control callback */
    
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

bool audio_bit_rate_invalid(uint32_t bit_rate);
bool video_bit_rate_invalid(uint32_t bit_rate);
bool invoke_call_state(ToxAV* av, uint32_t friend_number, uint32_t state);
ToxAVCall* call_new(ToxAV* av, uint32_t friend_number, TOXAV_ERR_CALL* error);
ToxAVCall* call_get(ToxAV* av, uint32_t friend_number);
ToxAVCall* call_remove(ToxAVCall* call);
bool call_prepare_transmission(ToxAVCall* call);
void call_kill_transmission(ToxAVCall* call);
void ba_set(ToxAvBitrateAdapter* ba, uint32_t bit_rate);
bool ba_shoud_send_dummy(ToxAvBitrateAdapter* ba);

uint32_t toxav_version_major(void)
{
    return 0;
}
uint32_t toxav_version_minor(void)
{
    return 0;
}
uint32_t toxav_version_patch(void)
{
    return 0;
}
bool toxav_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch)
{
    (void)major;
    (void)minor;
    (void)patch;
    
    return 1;
}

ToxAV* toxav_new(Tox* tox, TOXAV_ERR_NEW* error)
{
    TOXAV_ERR_NEW rc = TOXAV_ERR_NEW_OK;
    ToxAV *av = NULL;
    
    if (tox == NULL) {
        rc = TOXAV_ERR_NEW_NULL;
        goto END;
    }
    
    if (((Messenger*)tox)->msi_packet) {
        rc = TOXAV_ERR_NEW_MULTIPLE;
        goto END;
    }
    
    av = calloc (sizeof(ToxAV), 1);
    
    if (av == NULL) {
        LOGGER_WARNING("Allocation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }
    
    if (create_recursive_mutex(av->mutex) != 0) {
        LOGGER_WARNING("Mutex creation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }
    
    av->m = (Messenger *)tox;
    av->msi = msi_new(av->m);
    
    if (av->msi == NULL) {
        pthread_mutex_destroy(av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto END;
    }
    
    av->interval = 200;
    av->msi->av = av;
    
    msi_register_callback(av->msi, callback_invite, msi_OnInvite);
    msi_register_callback(av->msi, callback_start, msi_OnStart);
    msi_register_callback(av->msi, callback_end, msi_OnEnd);
    msi_register_callback(av->msi, callback_error, msi_OnError);
    msi_register_callback(av->msi, callback_error, msi_OnPeerTimeout);
    msi_register_callback(av->msi, callback_capabilites, msi_OnCapabilities);
    
END:
    if (error)
        *error = rc;
    
    if (rc != TOXAV_ERR_NEW_OK) {
        free(av);
        av = NULL;
    }
    
    return av;
}

void toxav_kill(ToxAV* av)
{
    if (av == NULL)
        return;
    pthread_mutex_lock(av->mutex);
    
    msi_kill(av->msi);
    
    /* Msi kill will hang up all calls so just clean these calls */
    if (av->calls) {
        ToxAVCall* it = call_get(av, av->calls_head);
        while (it) {
            call_kill_transmission(it);
            it = call_remove(it); /* This will eventually free av->calls */
        }
    }
    
    pthread_mutex_unlock(av->mutex);
    pthread_mutex_destroy(av->mutex);
    free(av);
}

Tox* toxav_get_tox(const ToxAV* av)
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
    pthread_mutex_lock(av->mutex);
    if (av->calls == NULL) {
        pthread_mutex_unlock(av->mutex);
        return;
    }
    
    uint64_t start = current_time_monotonic();
    int32_t rc = 500;
    
    ToxAVCall* i = av->calls[av->calls_head];
    for (; i; i = i->next) {
        if (i->active) {
            pthread_mutex_lock(i->mutex);
            pthread_mutex_unlock(av->mutex);
            
            ac_do(i->audio.second);
            if (rtp_do(i->audio.first) < 0) {
                /* Bad transmission */
                
                uint32_t bb = i->audio_bit_rate;
                
                if (i->aba.active) {
                    bb = i->aba.bit_rate;
                    /* Stop sending dummy packets */
                    memset(&i->aba, 0, sizeof(i->aba));
                }
                
                /* Notify app */
                if (av->abcb.first)
                    av->abcb.first (av, i->friend_number, false, bb, av->abcb.second);
            } else if (i->aba.active && i->aba.end_time < current_time_monotonic()) {
                
                i->audio_bit_rate = i->aba.bit_rate;
                
                /* Notify user about the new bit rate */
                if (av->abcb.first)
                    av->abcb.first (av, i->friend_number, true, i->aba.bit_rate, av->abcb.second);
                
                /* Stop sending dummy packets */
                memset(&i->aba, 0, sizeof(i->aba));
            }
            
            vc_do(i->video.second);
            if (rtp_do(i->video.first) < 0) {
                /* Bad transmission */
                uint32_t bb = i->video_bit_rate;
                
                if (i->vba.active) {
                    bb = i->vba.bit_rate;
                    /* Stop sending dummy packets */
                    memset(&i->vba, 0, sizeof(i->vba));
                }
                
                /* Notify app */
                if (av->vbcb.first)
                    av->vbcb.first (av, i->friend_number, false, bb, av->vbcb.second);
                
            } else if (i->vba.active && i->vba.end_time < current_time_monotonic()) {
                
                i->video_bit_rate = i->vba.bit_rate;
                
                /* Notify user about the new bit rate */
                if (av->vbcb.first)
                    av->vbcb.first (av, i->friend_number, true, i->vba.bit_rate, av->vbcb.second);
                
                /* Stop sending dummy packets */
                memset(&i->vba, 0, sizeof(i->vba));
            }
            
            if (i->msi_call->self_capabilities & msi_CapRAudio && 
                i->msi_call->peer_capabilities & msi_CapSAudio)
                rc = MIN(i->audio.second->last_packet_frame_duration, rc);
            
            if (i->msi_call->self_capabilities & msi_CapRVideo && 
                i->msi_call->peer_capabilities & msi_CapSVideo)
                rc = MIN(i->video.second->lcfd, (uint32_t) rc);
            
            uint32_t fid = i->friend_number;
            
            pthread_mutex_unlock(i->mutex);
            pthread_mutex_lock(av->mutex);
            
            /* In case this call is popped from container stop iteration */
            if (call_get(av, fid) != i)
                break;
        }
    }
    pthread_mutex_unlock(av->mutex);
    
    av->interval = rc < av->dmssa ? 0 : (rc - av->dmssa);
    av->dmsst += current_time_monotonic() - start;
    
    if (++av->dmssc == 3) {
        av->dmssa = av->dmsst / 3 + 5 /* NOTE Magic Offset for precission */;
        av->dmssc = 0;
        av->dmsst = 0;
    }
}

bool toxav_call(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_CALL* error)
{
    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
      ||(video_bit_rate && video_bit_rate_invalid(video_bit_rate))
    ) {
        if (error)
            *error = TOXAV_ERR_CALL_INVALID_BIT_RATE;
        return false;
    }
    
    pthread_mutex_lock(av->mutex);
    ToxAVCall* call = call_new(av, friend_number, error);
    if (call == NULL) {
        pthread_mutex_unlock(av->mutex);
        return false;
    }
    
    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;
    
    call->previous_self_capabilities = msi_CapRAudio | msi_CapRVideo;
    
    call->previous_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_invite(av->msi, &call->msi_call, friend_number, call->previous_self_capabilities) != 0) {
        call_remove(call);
        if (error)
            *error = TOXAV_ERR_CALL_MALLOC;
        pthread_mutex_unlock(av->mutex);
        return false;
    }
    
    call->msi_call->av_call = call;
    pthread_mutex_unlock(av->mutex);
    
    return true;
}

void toxav_callback_call(ToxAV* av, toxav_call_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->ccb.first = function;
    av->ccb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_answer(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_ANSWER* error)
{
    pthread_mutex_lock(av->mutex);
    
    TOXAV_ERR_ANSWER rc = TOXAV_ERR_ANSWER_OK;
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
      ||(video_bit_rate && video_bit_rate_invalid(video_bit_rate))
    ) {
        rc = TOXAV_ERR_ANSWER_INVALID_BIT_RATE;
        goto END;
    }
    
    ToxAVCall* call = call_get(av, friend_number);
    if (call == NULL) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;
        goto END;
    }
    
    if (!call_prepare_transmission(call)) {
		rc = TOXAV_ERR_ANSWER_CODEC_INITIALIZATION;
		goto END;
	}
    
    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;
    
    call->previous_self_capabilities = msi_CapRAudio | msi_CapRVideo;
    
    call->previous_self_capabilities |= audio_bit_rate > 0 ? msi_CapSAudio : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? msi_CapSVideo : 0;
    
    if (msi_answer(call->msi_call, call->previous_self_capabilities) != 0)
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING; /* the only reason for msi_answer to fail */
    
    
END:
    pthread_mutex_unlock(av->mutex);
    
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_ANSWER_OK;
}

void toxav_callback_call_state(ToxAV* av, toxav_call_state_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->scb.first = function;
    av->scb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_call_control(ToxAV* av, uint32_t friend_number, TOXAV_CALL_CONTROL control, TOXAV_ERR_CALL_CONTROL* error)
{
    pthread_mutex_lock(av->mutex);
    TOXAV_ERR_CALL_CONTROL rc = TOXAV_ERR_CALL_CONTROL_OK;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
        goto END;
    }
    
    ToxAVCall* call = call_get(av, friend_number);
    if (call == NULL || (!call->active && control != TOXAV_CALL_CONTROL_CANCEL)) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME: {
            /* Only act if paused and had media transfer active before */
            if (call->msi_call->self_capabilities == 0 && 
                call->previous_self_capabilities ) {
                
                if (msi_change_capabilities(call->msi_call, 
                    call->previous_self_capabilities) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->audio.first);
                rtp_start_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
        
        case TOXAV_CALL_CONTROL_PAUSE: {
            /* Only act if not already paused */
            if (call->msi_call->self_capabilities) {
                call->previous_self_capabilities = call->msi_call->self_capabilities;
                
                if (msi_change_capabilities(call->msi_call, 0) == -1 ) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->audio.first);
                rtp_stop_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
        
        case TOXAV_CALL_CONTROL_CANCEL: {
            /* Hang up */
            msi_hangup(call->msi_call);
            
            /* No mather the case, terminate the call */
            call_kill_transmission(call);
            call_remove(call);
        } break;
        
        case TOXAV_CALL_CONTROL_MUTE_AUDIO: {
            if (call->msi_call->self_capabilities & msi_CapRAudio) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities ^ msi_CapRAudio) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->audio.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
        
        case TOXAV_CALL_CONTROL_UNMUTE_AUDIO: {
            if (call->msi_call->self_capabilities ^ msi_CapRAudio) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities | msi_CapRAudio) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->audio.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
        
        case TOXAV_CALL_CONTROL_HIDE_VIDEO: {
            if (call->msi_call->self_capabilities & msi_CapRVideo) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities ^ msi_CapRVideo) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_stop_receiving(call->video.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
        
        case TOXAV_CALL_CONTROL_SHOW_VIDEO: {
            if (call->msi_call->self_capabilities ^ msi_CapRVideo) {
                if (msi_change_capabilities(call->msi_call, call->
                    msi_call->self_capabilities | msi_CapRVideo) == -1) {
                    /* The only reason for this function to fail is invalid state 
                     * ( not active ) */
                    rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
                    goto END;
                }
                
                rtp_start_receiving(call->audio.first);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto END;
            }
        } break;
    }
    
END:
    pthread_mutex_unlock(av->mutex);
    
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}

void toxav_callback_audio_bit_rate_status(ToxAV* av, toxav_audio_bit_rate_status_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->abcb.first = function;
    av->abcb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_audio_bit_rate_set(ToxAV* av, uint32_t friend_number, uint32_t audio_bit_rate, bool force, TOXAV_ERR_SET_BIT_RATE* error)
{
    LOGGER_DEBUG("Setting new audio bitrate to: %d", audio_bit_rate);
    
    TOXAV_ERR_SET_BIT_RATE rc = TOXAV_ERR_SET_BIT_RATE_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SET_BIT_RATE_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate)) {
        rc = TOXAV_ERR_SET_BIT_RATE_INVALID;
        goto END;
    }
    
    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SET_BIT_RATE_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->audio_bit_rate == audio_bit_rate || (call->aba.active && call->aba.bit_rate == audio_bit_rate)) {
        pthread_mutex_unlock(av->mutex);
        goto END;
    }
    
    /* Video sending is turned off; notify peer */
    if (audio_bit_rate == 0) {
        call->audio_bit_rate = 0;
        
        msi_change_capabilities(call->msi_call, call->msi_call->
        self_capabilities ^ msi_CapSAudio);
        pthread_mutex_unlock(av->mutex);
        goto END;
    }
    
    pthread_mutex_lock(call->mutex);
    
    if (call->audio_bit_rate == 0) {
        /* The audio has been turned off before this */
        call->audio_bit_rate = audio_bit_rate;
        
        msi_change_capabilities(call->msi_call, call->
        msi_call->self_capabilities | msi_CapSAudio);
        
        if (!force && av->abcb.first) 
            av->abcb.first (av, call->friend_number, true, audio_bit_rate, av->abcb.second);
    } else {
        /* The audio was active before this */
        if (audio_bit_rate > call->audio_bit_rate && !force)
            ba_set(&call->aba, audio_bit_rate);
        else {
            /* Cancel any previous non forceful bitrate change request */
            memset(&call->aba, 0, sizeof(call->aba));
            call->audio_bit_rate = audio_bit_rate;
            
            if (!force && av->abcb.first) 
                av->abcb.first (av, call->friend_number, true, audio_bit_rate, av->abcb.second);
        }
    }
    
    pthread_mutex_unlock(call->mutex);
    pthread_mutex_unlock(av->mutex);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SET_BIT_RATE_OK;
}

void toxav_callback_video_bit_rate_status(ToxAV* av, toxav_video_bit_rate_status_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vbcb.first = function;
    av->vbcb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_video_bit_rate_set(ToxAV* av, uint32_t friend_number, uint32_t video_bit_rate, bool force, TOXAV_ERR_SET_BIT_RATE* error)
{
    LOGGER_DEBUG("Setting new video bitrate to: %d", video_bit_rate);
    
    TOXAV_ERR_SET_BIT_RATE rc = TOXAV_ERR_SET_BIT_RATE_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SET_BIT_RATE_FRIEND_NOT_FOUND;
        goto END;
    }
    
    if (video_bit_rate && video_bit_rate_invalid(video_bit_rate)) {
        rc = TOXAV_ERR_SET_BIT_RATE_INVALID;
        goto END;
    }
    
    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SET_BIT_RATE_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->video_bit_rate == video_bit_rate || (call->vba.active && call->vba.bit_rate == video_bit_rate)) {
        pthread_mutex_unlock(av->mutex);
        goto END;
    }
    
    /* Video sending is turned off; notify peer */
    if (video_bit_rate == 0) {
        call->video_bit_rate = 0;
        
        msi_change_capabilities(call->msi_call, call->msi_call->
        self_capabilities ^ msi_CapSVideo);
        pthread_mutex_unlock(av->mutex);
        goto END;
    }
    
    pthread_mutex_lock(call->mutex);
    
    if (call->video_bit_rate == 0) {
        /* The video has been turned off before this */
        call->video_bit_rate = video_bit_rate;
        
        msi_change_capabilities(call->msi_call, call->
        msi_call->self_capabilities | msi_CapSVideo);
        
        if (!force && av->vbcb.first) 
            av->vbcb.first (av, call->friend_number, true, video_bit_rate, av->vbcb.second);
    } else {
        /* The video was active before this */
        if (video_bit_rate > call->video_bit_rate && !force)
            ba_set(&call->vba, video_bit_rate);
        else {
            /* Cancel any previous non forceful bitrate change request */
            memset(&call->vba, 0, sizeof(call->vba));
            call->video_bit_rate = video_bit_rate;
            
            if (!force && av->vbcb.first) 
                av->vbcb.first (av, call->friend_number, true, video_bit_rate, av->vbcb.second);
        }
    }
    
    pthread_mutex_unlock(call->mutex);
    pthread_mutex_unlock(av->mutex);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SET_BIT_RATE_OK;
}

bool toxav_audio_send_frame(ToxAV* av, uint32_t friend_number, const int16_t* pcm, size_t sample_count, uint8_t channels, uint32_t sampling_rate, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->audio_bit_rate == 0) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_BIT_RATE_NOT_SET;
        goto END;
    }
    
    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(av->mutex);
    
    if ( pcm == NULL ) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( channels > 2 ) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto END;
    }
    
    { /* Encode and send */
        if (ac_reconfigure_encoder(call->audio.second, call->audio_bit_rate * 1000, sampling_rate, channels) != 0) {
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        uint8_t dest[sample_count + sizeof(sampling_rate)]; /* This is more than enough always */
        
        sampling_rate = htonl(sampling_rate);
        memcpy(dest, &sampling_rate, sizeof(sampling_rate));
        int vrc = opus_encode(call->audio.second->encoder, pcm, sample_count,
                              dest + sizeof(sampling_rate), sizeof(dest) - sizeof(sampling_rate));
        
        if (vrc < 0) {
            LOGGER_WARNING("Failed to encode frame %s", opus_strerror(vrc));
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        if (rtp_send_data(call->audio.first, dest, vrc + sizeof(sampling_rate), false) != 0) {
            LOGGER_WARNING("Failed to send audio packet");
            rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        }
        
        
        /* For bit rate measurement; send dummy packet */
        if (ba_shoud_send_dummy(&call->aba)) {
            sampling_rate = ntohl(sampling_rate);
            if (ac_reconfigure_test_encoder(call->audio.second, call->audio_bit_rate * 1000, sampling_rate, channels) != 0) {
                /* FIXME should the bit rate changing fail here? */
                pthread_mutex_unlock(call->mutex_audio);
                rc = TOXAV_ERR_SEND_FRAME_INVALID;
                goto END;
            }
            
            sampling_rate = htonl(sampling_rate);
            memcpy(dest, &sampling_rate, sizeof(sampling_rate));
            vrc = opus_encode(call->audio.second->test_encoder, pcm, sample_count,
                                dest + sizeof(sampling_rate), sizeof(dest) - sizeof(sampling_rate));
            
            if (vrc < 0) {
                LOGGER_WARNING("Failed to encode frame %s", opus_strerror(vrc));
                pthread_mutex_unlock(call->mutex_audio);
                rc = TOXAV_ERR_SEND_FRAME_INVALID;
                goto END;
            }
            
            if (rtp_send_data(call->audio.first, dest, vrc + sizeof(sampling_rate), true) != 0) {
                LOGGER_WARNING("Failed to send audio packet");
                rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            }
            
            if (call->aba.end_time == (uint64_t) ~0)
                call->aba.end_time = current_time_monotonic() + BITRATE_CHANGE_TESTING_TIME_MS;
        }
    }
    
    
    pthread_mutex_unlock(call->mutex_audio);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

bool toxav_video_send_frame(ToxAV* av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t* y, const uint8_t* u, const uint8_t* v, TOXAV_ERR_SEND_FRAME* error)
{
    TOXAV_ERR_SEND_FRAME rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall* call;
    
    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto END;
    }
    
    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);
    if (call == NULL || !call->active || call->msi_call->state != msi_CallActive) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto END;
    }
    
    if (call->video_bit_rate == 0) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_BIT_RATE_NOT_SET;
        goto END;
    }
    
    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(av->mutex);
    
    if ( y == NULL || u == NULL || v == NULL ) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto END;
    }
    
    if ( vc_reconfigure_encoder(call->video.second, call->video_bit_rate * 1000, width, height) != 0 ) {
        pthread_mutex_unlock(call->mutex_video);
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
        
        int vrc = vpx_codec_encode(call->video.second->encoder, &img, 
                                   call->video.second->frame_counter, 1, 0, MAX_ENCODE_TIME_US);
        
        vpx_img_free(&img);
        if ( vrc != VPX_CODEC_OK) {
            pthread_mutex_unlock(call->mutex_video);
            LOGGER_ERROR("Could not encode video frame: %s\n", vpx_codec_err_to_string(vrc));
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
    }
    
    ++call->video.second->frame_counter;
    
    { /* Split and send */
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t *pkt;
        
        vc_init_video_splitter_cycle(call->video.second);
        
        while ( (pkt = vpx_codec_get_cx_data(call->video.second->encoder, &iter)) ) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                int parts = vc_update_video_splitter_cycle(call->video.second, pkt->data.frame.buf, 
                                                           pkt->data.frame.sz);
                
                if (parts < 0) /* Should never happen though */
                    continue;
                
                uint16_t part_size;
                const uint8_t *iter;
                
                int i;
                for (i = 0; i < parts; i++) {
                    iter = vc_iterate_split_video_frame(call->video.second, &part_size);
                    
                    if (rtp_send_data(call->video.first, iter, part_size, false) < 0) {
                        pthread_mutex_unlock(call->mutex_video);
                        LOGGER_WARNING("Could not send video frame: %s\n", strerror(errno));
                        rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                        goto END;
                    }
                }
            }
        }
    }
    
    if (ba_shoud_send_dummy(&call->vba)) {
        if ( vc_reconfigure_test_encoder(call->video.second, call->vba.bit_rate * 1000, width, height) != 0 ) {
            pthread_mutex_unlock(call->mutex_video);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        /* FIXME use the same image as before */
        vpx_image_t img;
        img.w = img.h = img.d_w = img.d_h = 0;
        vpx_img_alloc(&img, VPX_IMG_FMT_VPXI420, width, height, 1);
        
        /* I420 "It comprises an NxM Y plane followed by (N/2)x(M/2) V and U planes." 
         * http://fourcc.org/yuv.php#IYUV
         */
        memcpy(img.planes[VPX_PLANE_Y], y, width * height);
        memcpy(img.planes[VPX_PLANE_U], u, (width/2) * (height/2));
        memcpy(img.planes[VPX_PLANE_V], v, (width/2) * (height/2));
        
        int vrc = vpx_codec_encode(call->video.second->test_encoder, &img, 
                                   call->video.second->test_frame_counter, 1, 0, MAX_ENCODE_TIME_US);
        
        vpx_img_free(&img);
        if ( vrc != VPX_CODEC_OK) {
            pthread_mutex_unlock(call->mutex_video);
            LOGGER_ERROR("Could not encode video frame: %s\n", vpx_codec_err_to_string(vrc));
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto END;
        }
        
        call->video.second->test_frame_counter++;
        
        vpx_codec_iter_t iter = NULL;
        const vpx_codec_cx_pkt_t *pkt;
        
        /* Send the encoded data as dummy packets */
        while ( (pkt = vpx_codec_get_cx_data(call->video.second->test_encoder, &iter)) ) {
            if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
                
                int parts = pkt->data.frame.sz / 1300;
                int i;
                for (i = 0; i < parts; i++) {
                    if (rtp_send_data(call->video.first, pkt->data.frame.buf + i * 1300, 1300, true) < 0) {
                        pthread_mutex_unlock(call->mutex_video);
                        LOGGER_WARNING("Could not send video frame: %s\n", strerror(errno));
                        rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                        goto END;
                    }
                }
                
                if (pkt->data.frame.sz % 1300) {
                    if (rtp_send_data(call->video.first, pkt->data.frame.buf + parts * 1300, pkt->data.frame.sz % 1300, true) < 0) {
                        pthread_mutex_unlock(call->mutex_video);
                        LOGGER_WARNING("Could not send video frame: %s\n", strerror(errno));
                        rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                        goto END;
                    }
                }
            }
        }
        
        if (call->vba.end_time == (uint64_t) ~0)
            call->vba.end_time = current_time_monotonic() + BITRATE_CHANGE_TESTING_TIME_MS;
    }
    
    pthread_mutex_unlock(call->mutex_video);
    
END:
    if (error)
        *error = rc;
    
    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_audio_receive_frame(ToxAV* av, toxav_audio_receive_frame_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->acb.first = function;
    av->acb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}

void toxav_callback_video_receive_frame(ToxAV* av, toxav_video_receive_frame_cb* function, void* user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vcb.first = function;
    av->vcb.second = user_data;
    pthread_mutex_unlock(av->mutex);
}


/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
int callback_invite(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    pthread_mutex_lock(toxav->mutex);
    
    ToxAVCall* av_call = call_new(toxav, call->friend_number, NULL);
    if (av_call == NULL) {
        LOGGER_WARNING("Failed to initialize call...");
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }
    
    call->av_call = av_call;
    av_call->msi_call = call;
    
    if (toxav->ccb.first)
        toxav->ccb.first(toxav, call->friend_number, call->peer_capabilities & msi_CapSAudio, 
                         call->peer_capabilities & msi_CapSVideo, toxav->ccb.second);
    else {
        /* No handler to capture the call request, send failure */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }
    
    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

int callback_start(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    pthread_mutex_lock(toxav->mutex);
    
    ToxAVCall* av_call = call_get(toxav, call->friend_number);
    
    if (av_call == NULL) {
        /* Should this ever happen? */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }
    
    if (!call_prepare_transmission(av_call)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }
    
    if (!invoke_call_state(toxav, call->friend_number, call->peer_capabilities)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }
    
    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

int callback_end(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    pthread_mutex_lock(toxav->mutex);
    
    invoke_call_state(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_FINISHED);
    
    call_kill_transmission(call->av_call);
    call_remove(call->av_call);
    
    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

int callback_error(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    pthread_mutex_lock(toxav->mutex);
    
    invoke_call_state(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_ERROR);
    
    call_kill_transmission(call->av_call);
    call_remove(call->av_call);
    
    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

int callback_capabilites(void* toxav_inst, MSICall* call)
{
    ToxAV* toxav = toxav_inst;
    pthread_mutex_lock(toxav->mutex);
    
    invoke_call_state(toxav, call->friend_number, call->peer_capabilities);
    
    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

bool audio_bit_rate_invalid(uint32_t bit_rate)
{
    /* Opus RFC 6716 section-2.1.1 dictates the following:
     * Opus supports all bit rates from 6 kbit/s to 510 kbit/s.
     */
    return bit_rate < 6 || bit_rate > 510;
}

bool video_bit_rate_invalid(uint32_t bit_rate)
{
    (void) bit_rate;
    /* TODO: If anyone knows the answer to this one please fill it up */
    return false;
}

bool invoke_call_state(ToxAV* av, uint32_t friend_number, uint32_t state)
{
    if (av->scb.first)
        av->scb.first(av, friend_number, state, av->scb.second);
    else
        return false;
    return true;
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
    call->friend_number = friend_number;
    
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
        uint32_t i = av->calls_tail + 1;
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

ToxAVCall* call_remove(ToxAVCall* call)
{
    if (call == NULL)
        return NULL;
    
    uint32_t friend_number = call->friend_number;
    ToxAV* av = call->av;
    
    ToxAVCall* prev = call->prev;
    ToxAVCall* next = call->next;
    
    free(call);
    
    if (prev)
        prev->next = next;
    else if (next)
        av->calls_head = next->friend_number;
    else goto CLEAR;
    
    if (next)
        next->prev = prev;
    else if (prev)
        av->calls_tail = prev->friend_number;
    else goto CLEAR;
    
    av->calls[friend_number] = NULL;
    return next;
    
CLEAR:
    av->calls_head = av->calls_tail = 0;
    free(av->calls);
    av->calls = NULL;
    
    return NULL;
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
    
    if (create_recursive_mutex(call->mutex_audio) != 0)
        return false;
    
    if (create_recursive_mutex(call->mutex_video) != 0)
        goto FAILURE_3;
    
    if (create_recursive_mutex(call->mutex) != 0) 
        goto FAILURE_2;
    
    
    { /* Prepare audio */
        call->audio.second = ac_new(av, call->friend_number, av->acb.first, av->acb.second);
        if (!call->audio.second) {
            LOGGER_ERROR("Failed to create audio codec session");
            goto FAILURE;
        }
        
        call->audio.first = rtp_new(rtp_TypeAudio, av->m, call->friend_number, call->audio.second, ac_queue_message);
        if (!call->audio.first) {
            LOGGER_ERROR("Failed to create audio rtp session");;
            goto FAILURE;
        }
    }
    
    { /* Prepare video */
        call->video.second = vc_new(av, call->friend_number, av->vcb.first, av->vcb.second, call->msi_call->peer_vfpsz);
        if (!call->video.second) {
            LOGGER_ERROR("Failed to create video codec session");
            goto FAILURE;
        }
        
        call->video.first = rtp_new(rtp_TypeVideo, av->m, call->friend_number, call->video.second, vc_queue_message);
        if (!call->video.first) {
            LOGGER_ERROR("Failed to create video rtp session");
            goto FAILURE;
        }
    }
    
    call->active = 1;
    return true;
    
FAILURE:
    rtp_kill(call->audio.first);
    ac_kill(call->audio.second);
    call->audio.first = NULL;
    call->audio.second = NULL;
    rtp_kill(call->video.first);
    vc_kill(call->video.second);
    call->video.first = NULL;
    call->video.second = NULL;
    pthread_mutex_destroy(call->mutex);
FAILURE_2:
    pthread_mutex_destroy(call->mutex_video);
FAILURE_3:
    pthread_mutex_destroy(call->mutex_audio);
    return false;
}

void call_kill_transmission(ToxAVCall* call)
{
    if (call == NULL || call->active == 0)
        return;
    
    call->active = 0;
    
    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(call->mutex_audio);
    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(call->mutex_video);
    pthread_mutex_lock(call->mutex);
    pthread_mutex_unlock(call->mutex);
    
    rtp_kill(call->audio.first);
    ac_kill(call->audio.second);
    call->audio.first = NULL;
    call->audio.second = NULL;
    
    rtp_kill(call->video.first);
    vc_kill(call->video.second);
    call->video.first = NULL;
    call->video.second = NULL;
    
    pthread_mutex_destroy(call->mutex_audio);
    pthread_mutex_destroy(call->mutex_video);
    pthread_mutex_destroy(call->mutex);
}

void ba_set(ToxAvBitrateAdapter* ba, uint32_t bit_rate)
{
    ba->bit_rate = bit_rate;
    ba->next_send = current_time_monotonic();
    ba->end_time = ~0;
    ba->next_send_interval = 1000;
    ba->active = true;
}

bool ba_shoud_send_dummy(ToxAvBitrateAdapter* ba)
{
    if (!ba->active || ba->next_send > current_time_monotonic())
        return false;
    
    ba->next_send_interval *= 0.8;
    ba->next_send = current_time_monotonic() + ba->next_send_interval;
    
    return true;
}