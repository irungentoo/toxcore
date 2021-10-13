/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "toxav.h"

#include "msi.h"
#include "rtp.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/util.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

// TODO(zoff99): don't hardcode this, let the application choose it
// VPX Info: Time to spend encoding, in microseconds (it's a *soft* deadline)
#define WANTED_MAX_ENCODER_FPS (40)
#define MAX_ENCODE_TIME_US (1000000 / WANTED_MAX_ENCODER_FPS) // to allow x fps

#define VIDEO_SEND_X_KEYFRAMES_FIRST 7 // force the first n frames to be keyframes!

/*
 * VPX_DL_REALTIME       (1)       deadline parameter analogous to VPx REALTIME mode.
 * VPX_DL_GOOD_QUALITY   (1000000) deadline parameter analogous to VPx GOOD QUALITY mode.
 * VPX_DL_BEST_QUALITY   (0)       deadline parameter analogous to VPx BEST QUALITY mode.
 */

typedef struct ToxAVCall_s {
    ToxAV *av;

    pthread_mutex_t mutex_audio[1];
    RTPSession *audio_rtp;
    ACSession *audio;

    pthread_mutex_t mutex_video[1];
    RTPSession *video_rtp;
    VCSession *video;

    BWController *bwc;

    bool active;
    MSICall *msi_call;
    uint32_t friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    pthread_mutex_t toxav_call_mutex[1];

    struct ToxAVCall_s *prev;
    struct ToxAVCall_s *next;
} ToxAVCall;

struct ToxAV {
    Tox *tox;
    Messenger *m;
    MSISession *msi;

    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall **calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t mutex[1];

    /* Call callback */
    toxav_call_cb *ccb;
    void *ccb_user_data;
    /* Call state callback */
    toxav_call_state_cb *scb;
    void *scb_user_data;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *acb;
    void *acb_user_data;
    /* Video frame receive callback */
    toxav_video_receive_frame_cb *vcb;
    void *vcb_user_data;
    /* Bit rate control callback */
    toxav_audio_bit_rate_cb *abcb;
    void *abcb_user_data;
    /* Bit rate control callback */
    toxav_video_bit_rate_cb *vbcb;
    void *vbcb_user_data;

    /** Decode time measures */
    int32_t dmssc; /** Measure count */
    int32_t dmsst; /** Last cycle total */
    int32_t dmssa; /** Average decoding time in ms */

    uint32_t interval; /** Calculated interval */
    Mono_Time *toxav_mono_time; /** ToxAV's own mono_time instance */
};

static void callback_bwc(BWController *bwc, uint32_t friend_number, float loss, void *user_data);

static int callback_invite(void *toxav_inst, MSICall *call);
static int callback_start(void *toxav_inst, MSICall *call);
static int callback_end(void *toxav_inst, MSICall *call);
static int callback_error(void *toxav_inst, MSICall *call);
static int callback_capabilites(void *toxav_inst, MSICall *call);

static bool audio_bit_rate_invalid(uint32_t bit_rate);
static bool video_bit_rate_invalid(uint32_t bit_rate);
static bool invoke_call_state_callback(ToxAV *av, uint32_t friend_number, uint32_t state);
static ToxAVCall *call_new(ToxAV *av, uint32_t friend_number, Toxav_Err_Call *error);
static ToxAVCall *call_get(ToxAV *av, uint32_t friend_number);
static ToxAVCall *call_remove(ToxAVCall *call);
static bool call_prepare_transmission(ToxAVCall *call);
static void call_kill_transmission(ToxAVCall *call);

ToxAV *toxav_new(Tox *tox, Toxav_Err_New *error)
{
    Toxav_Err_New rc = TOXAV_ERR_NEW_OK;
    ToxAV *av = nullptr;

    if (tox == nullptr) {
        rc = TOXAV_ERR_NEW_NULL;
        goto RETURN;
    }

    // TODO(iphydf): Don't rely on toxcore internals.
    Messenger *m;
    //!TOKSTYLE-
    m = *(Messenger **)tox;
    //!TOKSTYLE+

    if (m->msi_packet) {
        rc = TOXAV_ERR_NEW_MULTIPLE;
        goto RETURN;
    }

    av = (ToxAV *)calloc(sizeof(ToxAV), 1);

    if (av == nullptr) {
        LOGGER_WARNING(m->log, "Allocation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    if (create_recursive_mutex(av->mutex) != 0) {
        LOGGER_WARNING(m->log, "Mutex creation failed!");
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    av->tox = tox;
    av->m = m;
    av->toxav_mono_time = mono_time_new();
    av->msi = msi_new(av->m);

    if (av->msi == nullptr) {
        pthread_mutex_destroy(av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    av->interval = 200;
    av->msi->av = av;

    msi_register_callback(av->msi, callback_invite, MSI_ON_INVITE);
    msi_register_callback(av->msi, callback_start, MSI_ON_START);
    msi_register_callback(av->msi, callback_end, MSI_ON_END);
    msi_register_callback(av->msi, callback_error, MSI_ON_ERROR);
    msi_register_callback(av->msi, callback_error, MSI_ON_PEERTIMEOUT);
    msi_register_callback(av->msi, callback_capabilites, MSI_ON_CAPABILITIES);

RETURN:

    if (error) {
        *error = rc;
    }

    if (rc != TOXAV_ERR_NEW_OK) {
        free(av);
        av = nullptr;
    }

    return av;
}
void toxav_kill(ToxAV *av)
{
    if (av == nullptr) {
        return;
    }

    pthread_mutex_lock(av->mutex);

    /* To avoid possible deadlocks */
    while (av->msi && msi_kill(av->msi, av->m->log) != 0) {
        pthread_mutex_unlock(av->mutex);
        pthread_mutex_lock(av->mutex);
    }

    /* Msi kill will hang up all calls so just clean these calls */
    if (av->calls) {
        ToxAVCall *it = call_get(av, av->calls_head);

        while (it) {
            call_kill_transmission(it);
            it->msi_call = nullptr; /* msi_kill() frees the call's msi_call handle; which causes #278 */
            it = call_remove(it); /* This will eventually free av->calls */
        }
    }

    mono_time_free(av->toxav_mono_time);

    pthread_mutex_unlock(av->mutex);
    pthread_mutex_destroy(av->mutex);

    free(av);
}
Tox *toxav_get_tox(const ToxAV *av)
{
    return av->tox;
}
uint32_t toxav_iteration_interval(const ToxAV *av)
{
    /* If no call is active interval is 200 */
    return av->calls ? av->interval : 200;
}
void toxav_iterate(ToxAV *av)
{
    pthread_mutex_lock(av->mutex);

    if (av->calls == nullptr) {
        pthread_mutex_unlock(av->mutex);
        return;
    }

    uint64_t start = current_time_monotonic(av->toxav_mono_time);
    int32_t rc = 500;

    ToxAVCall *i = av->calls[av->calls_head];

    for (; i; i = i->next) {
        if (i->active) {
            pthread_mutex_lock(i->toxav_call_mutex);
            pthread_mutex_unlock(av->mutex);

            ac_iterate(i->audio);
            vc_iterate(i->video);

            if (i->msi_call->self_capabilities & MSI_CAP_R_AUDIO &&
                    i->msi_call->peer_capabilities & MSI_CAP_S_AUDIO) {
                rc = min_s32(i->audio->lp_frame_duration, rc);
            }

            if (i->msi_call->self_capabilities & MSI_CAP_R_VIDEO &&
                    i->msi_call->peer_capabilities & MSI_CAP_S_VIDEO) {
                pthread_mutex_lock(i->video->queue_mutex);
                rc = min_u32(i->video->lcfd, rc);
                pthread_mutex_unlock(i->video->queue_mutex);
            }

            uint32_t fid = i->friend_number;

            pthread_mutex_unlock(i->toxav_call_mutex);
            pthread_mutex_lock(av->mutex);

            /* In case this call is popped from container stop iteration */
            if (call_get(av, fid) != i) {
                break;
            }
        }
    }

    av->interval = rc < av->dmssa ? 0 : (rc - av->dmssa);
    av->dmsst += current_time_monotonic(av->toxav_mono_time) - start;

    if (++av->dmssc == 3) {
        av->dmssa = av->dmsst / 3 + 5; /* NOTE Magic Offset 5 for precision */
        av->dmssc = 0;
        av->dmsst = 0;
    }

    pthread_mutex_unlock(av->mutex);
}
bool toxav_call(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                Toxav_Err_Call *error)
{
    Toxav_Err_Call rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call;

    pthread_mutex_lock(av->mutex);

    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate && video_bit_rate_invalid(video_bit_rate))) {
        rc = TOXAV_ERR_CALL_INVALID_BIT_RATE;
        goto RETURN;
    }

    call = call_new(av, friend_number, &rc);

    if (call == nullptr) {
        goto RETURN;
    }

    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;

    call->previous_self_capabilities = MSI_CAP_R_AUDIO | MSI_CAP_R_VIDEO;

    call->previous_self_capabilities |= audio_bit_rate > 0 ? MSI_CAP_S_AUDIO : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? MSI_CAP_S_VIDEO : 0;

    if (msi_invite(av->msi, &call->msi_call, friend_number, call->previous_self_capabilities) != 0) {
        call_remove(call);
        rc = TOXAV_ERR_CALL_SYNC;
        goto RETURN;
    }

    call->msi_call->av_call = call;

RETURN:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_OK;
}
void toxav_callback_call(ToxAV *av, toxav_call_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->ccb = callback;
    av->ccb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_answer(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                  Toxav_Err_Answer *error)
{
    pthread_mutex_lock(av->mutex);

    Toxav_Err_Answer rc = TOXAV_ERR_ANSWER_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if ((audio_bit_rate && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate && video_bit_rate_invalid(video_bit_rate))
       ) {
        rc = TOXAV_ERR_ANSWER_INVALID_BIT_RATE;
        goto RETURN;
    }

    call = call_get(av, friend_number);

    if (call == nullptr) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;
        goto RETURN;
    }

    if (!call_prepare_transmission(call)) {
        rc = TOXAV_ERR_ANSWER_CODEC_INITIALIZATION;
        goto RETURN;
    }

    call->audio_bit_rate = audio_bit_rate;
    call->video_bit_rate = video_bit_rate;

    call->previous_self_capabilities = MSI_CAP_R_AUDIO | MSI_CAP_R_VIDEO;

    call->previous_self_capabilities |= audio_bit_rate > 0 ? MSI_CAP_S_AUDIO : 0;
    call->previous_self_capabilities |= video_bit_rate > 0 ? MSI_CAP_S_VIDEO : 0;

    if (msi_answer(call->msi_call, call->previous_self_capabilities) != 0) {
        rc = TOXAV_ERR_ANSWER_SYNC;
    }

RETURN:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_ANSWER_OK;
}
void toxav_callback_call_state(ToxAV *av, toxav_call_state_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->scb = callback;
    av->scb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_call_control(ToxAV *av, uint32_t friend_number, Toxav_Call_Control control, Toxav_Err_Call_Control *error)
{
    pthread_mutex_lock(av->mutex);
    Toxav_Err_Call_Control rc = TOXAV_ERR_CALL_CONTROL_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    call = call_get(av, friend_number);

    if (call == nullptr || (!call->active && control != TOXAV_CALL_CONTROL_CANCEL)) {
        rc = TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
        goto RETURN;
    }

    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME: {
            /* Only act if paused and had media transfer active before */
            if (call->msi_call->self_capabilities == 0 &&
                    call->previous_self_capabilities) {

                if (msi_change_capabilities(call->msi_call,
                                            call->previous_self_capabilities) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_allow_receiving(call->audio_rtp);
                rtp_allow_receiving(call->video_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_PAUSE: {
            /* Only act if not already paused */
            if (call->msi_call->self_capabilities) {
                call->previous_self_capabilities = call->msi_call->self_capabilities;

                if (msi_change_capabilities(call->msi_call, 0) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_stop_receiving(call->audio_rtp);
                rtp_stop_receiving(call->video_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_CANCEL: {
            /* Hang up */
            pthread_mutex_lock(call->toxav_call_mutex);

            if (msi_hangup(call->msi_call) != 0) {
                rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                pthread_mutex_unlock(call->toxav_call_mutex);
                goto RETURN;
            }

            call->msi_call = nullptr;
            pthread_mutex_unlock(call->toxav_call_mutex);

            /* No mather the case, terminate the call */
            call_kill_transmission(call);
            call_remove(call);
        }
        break;

        case TOXAV_CALL_CONTROL_MUTE_AUDIO: {
            if (call->msi_call->self_capabilities & MSI_CAP_R_AUDIO) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities ^ MSI_CAP_R_AUDIO) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_stop_receiving(call->audio_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_UNMUTE_AUDIO: {
            if (call->msi_call->self_capabilities ^ MSI_CAP_R_AUDIO) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | MSI_CAP_R_AUDIO) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_allow_receiving(call->audio_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_HIDE_VIDEO: {
            if (call->msi_call->self_capabilities & MSI_CAP_R_VIDEO) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities ^ MSI_CAP_R_VIDEO) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_stop_receiving(call->video_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;

        case TOXAV_CALL_CONTROL_SHOW_VIDEO: {
            if (call->msi_call->self_capabilities ^ MSI_CAP_R_VIDEO) {
                if (msi_change_capabilities(call->msi_call, call->
                                            msi_call->self_capabilities | MSI_CAP_R_VIDEO) == -1) {
                    rc = TOXAV_ERR_CALL_CONTROL_SYNC;
                    goto RETURN;
                }

                rtp_allow_receiving(call->video_rtp);
            } else {
                rc = TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
                goto RETURN;
            }
        }
        break;
    }

RETURN:
    pthread_mutex_unlock(av->mutex);

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}
bool toxav_audio_set_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate,
                              Toxav_Err_Bit_Rate_Set *error)
{
    Toxav_Err_Bit_Rate_Set rc = TOXAV_ERR_BIT_RATE_SET_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (audio_bit_rate > 0 && audio_bit_rate_invalid(audio_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_SET_INVALID_BIT_RATE;
        goto RETURN;
    }

    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);

    if (call == nullptr || !call->active || call->msi_call->state != MSI_CALL_ACTIVE) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL;
        goto RETURN;
    }

    LOGGER_DEBUG(av->m->log, "Setting new audio bitrate to: %d", audio_bit_rate);

    if (call->audio_bit_rate == audio_bit_rate) {
        LOGGER_DEBUG(av->m->log, "Audio bitrate already set to: %d", audio_bit_rate);
    } else if (audio_bit_rate == 0) {
        LOGGER_DEBUG(av->m->log, "Turned off audio sending");

        if (msi_change_capabilities(call->msi_call, call->msi_call->
                                    self_capabilities ^ MSI_CAP_S_AUDIO) != 0) {
            pthread_mutex_unlock(av->mutex);
            rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
            goto RETURN;
        }

        /* Audio sending is turned off; notify peer */
        call->audio_bit_rate = 0;
    } else {
        pthread_mutex_lock(call->toxav_call_mutex);

        if (call->audio_bit_rate == 0) {
            LOGGER_DEBUG(av->m->log, "Turned on audio sending");

            /* The audio has been turned off before this */
            if (msi_change_capabilities(call->msi_call, call->
                                        msi_call->self_capabilities | MSI_CAP_S_AUDIO) != 0) {
                pthread_mutex_unlock(call->toxav_call_mutex);
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto RETURN;
            }
        } else {
            LOGGER_DEBUG(av->m->log, "Set new audio bit rate %d", audio_bit_rate);
        }

        call->audio_bit_rate = audio_bit_rate;
        pthread_mutex_unlock(call->toxav_call_mutex);
    }

    pthread_mutex_unlock(av->mutex);
RETURN:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_BIT_RATE_SET_OK;
}
bool toxav_video_set_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t video_bit_rate,
                              Toxav_Err_Bit_Rate_Set *error)
{
    Toxav_Err_Bit_Rate_Set rc = TOXAV_ERR_BIT_RATE_SET_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (video_bit_rate > 0 && video_bit_rate_invalid(video_bit_rate)) {
        rc = TOXAV_ERR_BIT_RATE_SET_INVALID_BIT_RATE;
        goto RETURN;
    }

    pthread_mutex_lock(av->mutex);
    call = call_get(av, friend_number);

    if (call == nullptr || !call->active || call->msi_call->state != MSI_CALL_ACTIVE) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL;
        goto RETURN;
    }

    LOGGER_DEBUG(av->m->log, "Setting new video bitrate to: %d", video_bit_rate);

    if (call->video_bit_rate == video_bit_rate) {
        LOGGER_DEBUG(av->m->log, "Video bitrate already set to: %d", video_bit_rate);
    } else if (video_bit_rate == 0) {
        LOGGER_DEBUG(av->m->log, "Turned off video sending");

        /* Video sending is turned off; notify peer */
        if (msi_change_capabilities(call->msi_call, call->msi_call->
                                    self_capabilities ^ MSI_CAP_S_VIDEO) != 0) {
            pthread_mutex_unlock(av->mutex);
            rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
            goto RETURN;
        }

        call->video_bit_rate = 0;
    } else {
        pthread_mutex_lock(call->toxav_call_mutex);

        if (call->video_bit_rate == 0) {
            LOGGER_DEBUG(av->m->log, "Turned on video sending");

            /* The video has been turned off before this */
            if (msi_change_capabilities(call->msi_call, call->
                                        msi_call->self_capabilities | MSI_CAP_S_VIDEO) != 0) {
                pthread_mutex_unlock(call->toxav_call_mutex);
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto RETURN;
            }
        } else {
            LOGGER_DEBUG(av->m->log, "Set new video bit rate %d", video_bit_rate);
        }

        call->video_bit_rate = video_bit_rate;
        pthread_mutex_unlock(call->toxav_call_mutex);
    }

    pthread_mutex_unlock(av->mutex);
RETURN:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_BIT_RATE_SET_OK;
}
void toxav_callback_audio_bit_rate(ToxAV *av, toxav_audio_bit_rate_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->abcb = callback;
    av->abcb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}
void toxav_callback_video_bit_rate(ToxAV *av, toxav_video_bit_rate_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vbcb = callback;
    av->vbcb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}
bool toxav_audio_send_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm, size_t sample_count,
                            uint8_t channels, uint32_t sampling_rate, Toxav_Err_Send_Frame *error)
{
    Toxav_Err_Send_Frame rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (pthread_mutex_trylock(av->mutex) != 0) {
        rc = TOXAV_ERR_SEND_FRAME_SYNC;
        goto RETURN;
    }

    call = call_get(av, friend_number);

    if (call == nullptr || !call->active || call->msi_call->state != MSI_CALL_ACTIVE) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto RETURN;
    }

    if (call->audio_bit_rate == 0 ||
            !(call->msi_call->self_capabilities & MSI_CAP_S_AUDIO) ||
            !(call->msi_call->peer_capabilities & MSI_CAP_R_AUDIO)) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED;
        goto RETURN;
    }

    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(av->mutex);

    if (pcm == nullptr) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto RETURN;
    }

    if (channels > 2) {
        pthread_mutex_unlock(call->mutex_audio);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto RETURN;
    }

    {   /* Encode and send */
        if (ac_reconfigure_encoder(call->audio, call->audio_bit_rate * 1000, sampling_rate, channels) != 0) {
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto RETURN;
        }

        VLA(uint8_t, dest, sample_count + sizeof(sampling_rate)); /* This is more than enough always */

        sampling_rate = net_htonl(sampling_rate);
        memcpy(dest, &sampling_rate, sizeof(sampling_rate));
        int vrc = opus_encode(call->audio->encoder, pcm, sample_count,
                              dest + sizeof(sampling_rate), SIZEOF_VLA(dest) - sizeof(sampling_rate));

        if (vrc < 0) {
            LOGGER_WARNING(av->m->log, "Failed to encode frame %s", opus_strerror(vrc));
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto RETURN;
        }

        if (rtp_send_data(call->audio_rtp, dest, vrc + sizeof(sampling_rate), false, av->m->log) != 0) {
            LOGGER_WARNING(av->m->log, "Failed to send audio packet");
            rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        }
    }

    pthread_mutex_unlock(call->mutex_audio);

RETURN:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

static Toxav_Err_Send_Frame send_frames(const Logger *log, ToxAVCall *call)
{
    vpx_codec_iter_t iter = nullptr;

    for (const vpx_codec_cx_pkt_t *pkt = vpx_codec_get_cx_data(call->video->encoder, &iter);
            pkt != nullptr;
            pkt = vpx_codec_get_cx_data(call->video->encoder, &iter)) {
        if (pkt->kind != VPX_CODEC_CX_FRAME_PKT) {
            continue;
        }

        const bool is_keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0;

        // https://www.webmproject.org/docs/webm-sdk/structvpx__codec__cx__pkt.html
        // pkt->data.frame.sz -> size_t
        const uint32_t frame_length_in_bytes = pkt->data.frame.sz;

        const int res = rtp_send_data(
                            call->video_rtp,
                            (const uint8_t *)pkt->data.frame.buf,
                            frame_length_in_bytes,
                            is_keyframe,
                            log);

        LOGGER_DEBUG(log, "+ _sending_FRAME_TYPE_==%s bytes=%d frame_len=%d", is_keyframe ? "K" : ".",
                     (int)pkt->data.frame.sz, (int)frame_length_in_bytes);
        const uint8_t *const buf = (const uint8_t *)pkt->data.frame.buf;
        LOGGER_DEBUG(log, "+ _sending_FRAME_ b0=%d b1=%d", buf[0], buf[1]);

        if (res < 0) {
            LOGGER_WARNING(log, "Could not send video frame: %s", strerror(errno));
            return TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        }
    }

    return TOXAV_ERR_SEND_FRAME_OK;
}

bool toxav_video_send_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t *y,
                            const uint8_t *u, const uint8_t *v, Toxav_Err_Send_Frame *error)
{
    Toxav_Err_Send_Frame rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    int vpx_encode_flags = 0;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (pthread_mutex_trylock(av->mutex) != 0) {
        rc = TOXAV_ERR_SEND_FRAME_SYNC;
        goto RETURN;
    }

    call = call_get(av, friend_number);

    if (call == nullptr || !call->active || call->msi_call->state != MSI_CALL_ACTIVE) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;
        goto RETURN;
    }

    if (call->video_bit_rate == 0 ||
            !(call->msi_call->self_capabilities & MSI_CAP_S_VIDEO) ||
            !(call->msi_call->peer_capabilities & MSI_CAP_R_VIDEO)) {
        pthread_mutex_unlock(av->mutex);
        rc = TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED;
        goto RETURN;
    }

    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(av->mutex);

    if (y == nullptr || u == nullptr || v == nullptr) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_NULL;
        goto RETURN;
    }

    if (vc_reconfigure_encoder(call->video, call->video_bit_rate * 1000, width, height, -1) != 0) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto RETURN;
    }

    if (call->video_rtp->ssrc < VIDEO_SEND_X_KEYFRAMES_FIRST) {
        // Key frame flag for first frames
        vpx_encode_flags = VPX_EFLAG_FORCE_KF;
        LOGGER_INFO(av->m->log, "I_FRAME_FLAG:%d only-i-frame mode", call->video_rtp->ssrc);

        ++call->video_rtp->ssrc;
    } else if (call->video_rtp->ssrc == VIDEO_SEND_X_KEYFRAMES_FIRST) {
        // normal keyframe placement
        vpx_encode_flags = 0;
        LOGGER_INFO(av->m->log, "I_FRAME_FLAG:%d normal mode", call->video_rtp->ssrc);

        ++call->video_rtp->ssrc;
    }

    // we start with I-frames (full frames) and then switch to normal mode later

    {   /* Encode */
        vpx_image_t img;
        img.w = 0;
        img.h = 0;
        img.d_w = 0;
        img.d_h = 0;
        vpx_img_alloc(&img, VPX_IMG_FMT_I420, width, height, 0);

        /* I420 "It comprises an NxM Y plane followed by (N/2)x(M/2) V and U planes."
         * http://fourcc.org/yuv.php#IYUV
         */
        memcpy(img.planes[VPX_PLANE_Y], y, width * height);
        memcpy(img.planes[VPX_PLANE_U], u, (width / 2) * (height / 2));
        memcpy(img.planes[VPX_PLANE_V], v, (width / 2) * (height / 2));

        vpx_codec_err_t vrc = vpx_codec_encode(call->video->encoder, &img,
                                               call->video->frame_counter, 1, vpx_encode_flags, MAX_ENCODE_TIME_US);

        vpx_img_free(&img);

        if (vrc != VPX_CODEC_OK) {
            pthread_mutex_unlock(call->mutex_video);
            LOGGER_ERROR(av->m->log, "Could not encode video frame: %s", vpx_codec_err_to_string(vrc));
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto RETURN;
        }
    }

    ++call->video->frame_counter;

    rc = send_frames(av->m->log, call);

    pthread_mutex_unlock(call->mutex_video);

RETURN:

    if (error) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_audio_receive_frame(ToxAV *av, toxav_audio_receive_frame_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->acb = callback;
    av->acb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

void toxav_callback_video_receive_frame(ToxAV *av, toxav_video_receive_frame_cb *callback, void *user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vcb = callback;
    av->vcb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
static void callback_bwc(BWController *bwc, uint32_t friend_number, float loss, void *user_data)
{
    /* Callback which is called when the internal measure mechanism reported packet loss.
     * We report suggested lowered bitrate to an app. If app is sending both audio and video,
     * we will report lowered bitrate for video only because in that case video probably
     * takes more than 90% bandwidth. Otherwise, we report lowered bitrate on audio.
     * The application may choose to disable video totally if the stream is too bad.
     */

    ToxAVCall *call = (ToxAVCall *)user_data;
    assert(call);

    LOGGER_DEBUG(call->av->m->log, "Reported loss of %f%%", (double)loss * 100);

    /* if less than 10% data loss we do nothing! */
    if (loss < 0.1f) {
        return;
    }

    pthread_mutex_lock(call->av->mutex);

    if (call->video_bit_rate) {
        if (!call->av->vbcb) {
            pthread_mutex_unlock(call->av->mutex);
            LOGGER_WARNING(call->av->m->log, "No callback to report loss on");
            return;
        }

        call->av->vbcb(call->av, friend_number,
                       call->video_bit_rate - (call->video_bit_rate * loss),
                       call->av->vbcb_user_data);
    } else if (call->audio_bit_rate) {
        if (!call->av->abcb) {
            pthread_mutex_unlock(call->av->mutex);
            LOGGER_WARNING(call->av->m->log, "No callback to report loss on");
            return;
        }

        call->av->abcb(call->av, friend_number,
                       call->audio_bit_rate - (call->audio_bit_rate * loss),
                       call->av->abcb_user_data);
    }

    pthread_mutex_unlock(call->av->mutex);
}
static int callback_invite(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_new(toxav, call->friend_number, nullptr);

    if (av_call == nullptr) {
        LOGGER_WARNING(toxav->m->log, "Failed to initialize call...");
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    call->av_call = av_call;
    av_call->msi_call = call;

    if (toxav->ccb) {
        toxav->ccb(toxav, call->friend_number, call->peer_capabilities & MSI_CAP_S_AUDIO,
                   call->peer_capabilities & MSI_CAP_S_VIDEO, toxav->ccb_user_data);
    } else {
        /* No handler to capture the call request, send failure */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
static int callback_start(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_get(toxav, call->friend_number);

    if (av_call == nullptr) {
        /* Should this ever happen? */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!call_prepare_transmission(av_call)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!invoke_call_state_callback(toxav, call->friend_number, call->peer_capabilities)) {
        callback_error(toxav_inst, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
static int callback_end(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_FINISHED);

    if (call->av_call) {
        call_kill_transmission(call->av_call);
        call_remove(call->av_call);
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
static int callback_error(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_ERROR);

    if (call->av_call) {
        call_kill_transmission(call->av_call);
        call_remove(call->av_call);
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
static int callback_capabilites(void *toxav_inst, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)toxav_inst;
    pthread_mutex_lock(toxav->mutex);

    if (call->peer_capabilities & MSI_CAP_S_AUDIO) {
        rtp_allow_receiving(call->av_call->audio_rtp);
    } else {
        rtp_stop_receiving(call->av_call->audio_rtp);
    }

    if (call->peer_capabilities & MSI_CAP_S_VIDEO) {
        rtp_allow_receiving(call->av_call->video_rtp);
    } else {
        rtp_stop_receiving(call->av_call->video_rtp);
    }

    invoke_call_state_callback(toxav, call->friend_number, call->peer_capabilities);

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}
static bool audio_bit_rate_invalid(uint32_t bit_rate)
{
    /* Opus RFC 6716 section-2.1.1 dictates the following:
     * Opus supports all bit rates from 6 kbit/s to 510 kbit/s.
     */
    return bit_rate < 6 || bit_rate > 510;
}
static bool video_bit_rate_invalid(uint32_t bit_rate)
{
    /* https://www.webmproject.org/docs/webm-sdk/structvpx__codec__enc__cfg.html shows the following:
     * unsigned int rc_target_bitrate
     * the range of uint varies from platform to platform
     * though, uint32_t should be large enough to store bitrates,
     * we may want to prevent from passing overflowed bitrates to libvpx
     * more in detail, it's the case where bit_rate is larger than uint, but smaller than uint32_t
     */
    return bit_rate > UINT_MAX;
}
static bool invoke_call_state_callback(ToxAV *av, uint32_t friend_number, uint32_t state)
{
    if (av->scb) {
        av->scb(av, friend_number, state, av->scb_user_data);
    } else {
        return false;
    }

    return true;
}

static ToxAVCall *call_new(ToxAV *av, uint32_t friend_number, Toxav_Err_Call *error)
{
    /* Assumes mutex locked */
    Toxav_Err_Call rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call = nullptr;

    if (m_friend_exists(av->m, friend_number) == 0) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (m_get_friend_connectionstatus(av->m, friend_number) < 1) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;
        goto RETURN;
    }

    if (call_get(av, friend_number) != nullptr) {
        rc = TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;
        goto RETURN;
    }

    call = (ToxAVCall *)calloc(sizeof(ToxAVCall), 1);

    if (call == nullptr) {
        rc = TOXAV_ERR_CALL_MALLOC;
        goto RETURN;
    }

    call->av = av;
    call->friend_number = friend_number;

    if (create_recursive_mutex(call->toxav_call_mutex)) {
        free(call);
        call = nullptr;
        rc = TOXAV_ERR_CALL_MALLOC;
        goto RETURN;
    }

    if (av->calls == nullptr) { /* Creating */
        av->calls = (ToxAVCall **)calloc(sizeof(ToxAVCall *), friend_number + 1);

        if (av->calls == nullptr) {
            pthread_mutex_destroy(call->toxav_call_mutex);
            free(call);
            call = nullptr;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto RETURN;
        }

        av->calls_tail = friend_number;
        av->calls_head = friend_number;
    } else if (av->calls_tail < friend_number) { /* Appending */
        ToxAVCall **tmp = (ToxAVCall **)realloc(av->calls, sizeof(ToxAVCall *) * (friend_number + 1));

        if (tmp == nullptr) {
            pthread_mutex_destroy(call->toxav_call_mutex);
            free(call);
            call = nullptr;
            rc = TOXAV_ERR_CALL_MALLOC;
            goto RETURN;
        }

        av->calls = tmp;

        /* Set fields in between to null */
        for (uint32_t i = av->calls_tail + 1; i < friend_number; ++i) {
            av->calls[i] = nullptr;
        }

        call->prev = av->calls[av->calls_tail];
        av->calls[av->calls_tail]->next = call;

        av->calls_tail = friend_number;
    } else if (av->calls_head > friend_number) { /* Inserting at front */
        call->next = av->calls[av->calls_head];
        av->calls[av->calls_head]->prev = call;
        av->calls_head = friend_number;
    }

    av->calls[friend_number] = call;

RETURN:

    if (error) {
        *error = rc;
    }

    return call;
}

static ToxAVCall *call_get(ToxAV *av, uint32_t friend_number)
{
    /* Assumes mutex locked */
    if (av->calls == nullptr || av->calls_tail < friend_number) {
        return nullptr;
    }

    return av->calls[friend_number];
}

static ToxAVCall *call_remove(ToxAVCall *call)
{
    if (call == nullptr) {
        return nullptr;
    }

    uint32_t friend_number = call->friend_number;
    ToxAV *av = call->av;

    ToxAVCall *prev = call->prev;
    ToxAVCall *next = call->next;

    /* Set av call in msi to NULL in order to know if call if ToxAVCall is
     * removed from the msi call.
     */
    if (call->msi_call) {
        call->msi_call->av_call = nullptr;
    }

    pthread_mutex_destroy(call->toxav_call_mutex);
    free(call);

    if (prev) {
        prev->next = next;
    } else if (next) {
        av->calls_head = next->friend_number;
    } else {
        goto CLEAR;
    }

    if (next) {
        next->prev = prev;
    } else if (prev) {
        av->calls_tail = prev->friend_number;
    } else {
        goto CLEAR;
    }

    av->calls[friend_number] = nullptr;
    return next;

CLEAR:
    av->calls_head = 0;
    av->calls_tail = 0;
    free(av->calls);
    av->calls = nullptr;

    return nullptr;
}

static bool call_prepare_transmission(ToxAVCall *call)
{
    /* Assumes mutex locked */

    if (call == nullptr) {
        return false;
    }

    ToxAV *av = call->av;

    if (!av->acb && !av->vcb) {
        /* It makes no sense to have CSession without callbacks */
        return false;
    }

    if (call->active) {
        LOGGER_WARNING(av->m->log, "Call already active!");
        return true;
    }

    if (create_recursive_mutex(call->mutex_audio) != 0) {
        return false;
    }

    if (create_recursive_mutex(call->mutex_video) != 0) {
        goto FAILURE_2;
    }

    /* Prepare bwc */
    call->bwc = bwc_new(av->m, av->tox, call->friend_number, callback_bwc, call, av->toxav_mono_time);

    {   /* Prepare audio */
        call->audio = ac_new(av->toxav_mono_time, av->m->log, av, call->friend_number, av->acb, av->acb_user_data);

        if (!call->audio) {
            LOGGER_ERROR(av->m->log, "Failed to create audio codec session");
            goto FAILURE;
        }

        call->audio_rtp = rtp_new(RTP_TYPE_AUDIO, av->m, av->tox, call->friend_number, call->bwc,
                                  call->audio, ac_queue_message);

        if (!call->audio_rtp) {
            LOGGER_ERROR(av->m->log, "Failed to create audio rtp session");
            goto FAILURE;
        }
    }
    {   /* Prepare video */
        call->video = vc_new(av->toxav_mono_time, av->m->log, av, call->friend_number, av->vcb, av->vcb_user_data);

        if (!call->video) {
            LOGGER_ERROR(av->m->log, "Failed to create video codec session");
            goto FAILURE;
        }

        call->video_rtp = rtp_new(RTP_TYPE_VIDEO, av->m, av->tox, call->friend_number, call->bwc,
                                  call->video, vc_queue_message);

        if (!call->video_rtp) {
            LOGGER_ERROR(av->m->log, "Failed to create video rtp session");
            goto FAILURE;
        }
    }

    call->active = 1;
    return true;

FAILURE:
    bwc_kill(call->bwc);
    rtp_kill(call->audio_rtp);
    ac_kill(call->audio);
    call->audio_rtp = nullptr;
    call->audio = nullptr;
    rtp_kill(call->video_rtp);
    vc_kill(call->video);
    call->video_rtp = nullptr;
    call->video = nullptr;
    pthread_mutex_destroy(call->mutex_video);
FAILURE_2:
    pthread_mutex_destroy(call->mutex_audio);
    return false;
}

static void call_kill_transmission(ToxAVCall *call)
{
    if (call == nullptr || call->active == 0) {
        return;
    }

    call->active = 0;

    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(call->mutex_audio);
    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(call->mutex_video);
    pthread_mutex_lock(call->toxav_call_mutex);
    pthread_mutex_unlock(call->toxav_call_mutex);

    bwc_kill(call->bwc);

    rtp_kill(call->audio_rtp);
    ac_kill(call->audio);
    call->audio_rtp = nullptr;
    call->audio = nullptr;

    rtp_kill(call->video_rtp);
    vc_kill(call->video);
    call->video_rtp = nullptr;
    call->video = nullptr;

    pthread_mutex_destroy(call->mutex_audio);
    pthread_mutex_destroy(call->mutex_video);
}
