/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "toxav.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "audio.h"
#include "bwcontroller.h"
#include "msi.h"
#include "rtp.h"
#include "video.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/network.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "../toxcore/tox_struct.h"  // IWYU pragma: keep
#include "../toxcore/util.h"

#define VIDEO_SEND_X_KEYFRAMES_FIRST 7 // force the first n frames to be keyframes!

// iteration interval that is used when no call is active
#define IDLE_ITERATION_INTERVAL_MS 1000

typedef struct ToxAVCall ToxAVCall;

static ToxAVCall *_Nullable call_get(ToxAV *_Nonnull av, uint32_t friend_number);
static RTPSession *_Nullable rtp_session_get(ToxAVCall *_Nullable call, int payload_type);
static BWController *_Nullable bwc_controller_get(const ToxAVCall *_Nullable call);

struct ToxAVCall {
    ToxAV *_Nonnull av;

    pthread_mutex_t mutex_audio[1];
    RTPSession *_Nullable audio_rtp;
    ACSession *_Nullable audio;

    pthread_mutex_t mutex_video[1];
    RTPSession *_Nullable video_rtp;
    VCSession *_Nullable video;

    BWController *_Nullable bwc;

    bool active;
    MSICall *_Nullable msi_call;
    Tox_Friend_Number friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    toxav_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;

    toxav_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable vcb_user_data;

    pthread_mutex_t toxav_call_mutex[1];

    struct ToxAVCall *_Nullable prev;
    struct ToxAVCall *_Nullable next;
};

/** Decode time statistics */
typedef struct DecodeTimeStats {
    /** Measure count */
    int32_t count;
    /** Last cycle total */
    int32_t total;
    /** Average decoding time in ms */
    int32_t average;

    /** Calculated iteration interval */
    uint32_t interval;
} DecodeTimeStats;

struct ToxAV {
    const struct Memory *_Nonnull mem;
    Logger *_Nonnull log;
    Tox *_Nonnull tox;
    MSISession *_Nonnull msi;

    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall *_Nullable *_Nullable calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t *_Nonnull mutex;

    /* Call callback */
    toxav_call_cb *_Nullable ccb;
    void *_Nullable ccb_user_data;
    /* Call state callback */
    toxav_call_state_cb *_Nullable scb;
    void *_Nullable scb_user_data;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;
    /* Video frame receive callback */
    toxav_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable vcb_user_data;
    /* Bit rate control callback */
    toxav_audio_bit_rate_cb *_Nullable abcb;
    void *_Nullable abcb_user_data;
    /* Bit rate control callback */
    toxav_video_bit_rate_cb *_Nullable vbcb;
    void *_Nullable vbcb_user_data;

    /* keep track of decode times for audio and video */
    DecodeTimeStats audio_stats;
    DecodeTimeStats video_stats;

    Mono_Time *_Nonnull toxav_mono_time; // ToxAV's own mono_time instance
};

static void callback_bwc(BWController *_Nonnull bwc, Tox_Friend_Number friend_number, float loss, void *_Nonnull user_data);

static int msi_send_packet(void *_Nonnull user_data, uint32_t friend_number, const uint8_t *_Nonnull data, size_t length)
{
    Tox *tox = (Tox *)user_data;
    const size_t length_new = length + 1;
    VLA(uint8_t, data_new, length_new);
    data_new[0] = PACKET_ID_MSI;
    memcpy(data_new + 1, data, length);

    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossless_packet(tox, friend_number, data_new, length_new, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK ? 0 : -1;
}

static void handle_msi_packet(Tox *_Nonnull tox, uint32_t friend_number, const uint8_t *_Nonnull data, size_t length,
                              void *_Nullable user_data)
{
    ToxAV *toxav = (ToxAV *)tox_get_av_object(tox);

    if (toxav == nullptr) {
        return;
    }

    if (length < 2) {
        LOGGER_ERROR(toxav->log, "MSI packet is less than 2 bytes in size");
        return;
    }

    msi_handle_packet(toxav->msi, toxav->log, friend_number, data + 1, length - 1);
}

static int rtp_send_packet(void *_Nonnull user_data, const uint8_t *_Nonnull data, uint16_t length)
{
    ToxAVCall *call = (ToxAVCall *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossy_packet(call->av->tox, call->friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK ? 0 : -1;
}

static void rtp_add_recv(void *_Nullable user_data, uint32_t bytes)
{
    BWController *bwc = (BWController *)user_data;
    bwc_add_recv(bwc, bytes);
}

static void rtp_add_lost(void *_Nullable user_data, uint32_t bytes)
{
    BWController *bwc = (BWController *)user_data;
    bwc_add_lost(bwc, bytes);
}

static void handle_rtp_packet(Tox *_Nonnull tox, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length, void *_Nullable user_data)
{
    ToxAV *toxav = (ToxAV *)tox_get_av_object(tox);

    if (toxav == nullptr) {
        return;
    }

    ToxAVCall *call = call_get(toxav, friend_number);

    if (call == nullptr) {
        return;
    }

    RTPSession *session = rtp_session_get(call, data[0]);

    if (session == nullptr) {
        return;
    }

    if (!rtp_session_is_receiving_active(session)) {
        return;
    }

    rtp_receive_packet(session, data, length);
}

static void handle_bwc_packet(Tox *_Nonnull tox, uint32_t friend_number, const uint8_t *_Nonnull data, size_t length, void *_Nullable user_data)
{
    ToxAV *toxav = (ToxAV *)tox_get_av_object(tox);

    if (toxav == nullptr) {
        return;
    }

    const ToxAVCall *call = call_get(toxav, friend_number);

    if (call == nullptr) {
        return;
    }

    BWController *bwc = bwc_controller_get(call);

    if (bwc == nullptr) {
        return;
    }

    bwc_handle_packet(bwc, data, length);
}

static void handle_audio_frame(uint32_t friend_number, const int16_t *_Nonnull pcm, size_t sample_count, uint8_t channels,
                               uint32_t sampling_rate, void *_Nullable user_data)
{
    ToxAVCall *call = (ToxAVCall *)user_data;
    pthread_mutex_lock(call->toxav_call_mutex);
    toxav_audio_receive_frame_cb *acb = call->acb;
    void *acb_user_data = call->acb_user_data;
    pthread_mutex_unlock(call->toxav_call_mutex);

    if (acb != nullptr) {
        acb(call->av, friend_number, pcm, sample_count, channels, sampling_rate, acb_user_data);
    }
}

static void handle_video_frame(uint32_t friend_number, uint16_t width, uint16_t height,
                               const uint8_t *_Nonnull y, const uint8_t *_Nonnull u, const uint8_t *_Nonnull v,
                               int32_t ystride, int32_t ustride, int32_t vstride,
                               void *_Nullable user_data)
{
    ToxAVCall *call = (ToxAVCall *)user_data;
    pthread_mutex_lock(call->toxav_call_mutex);
    toxav_video_receive_frame_cb *vcb = call->vcb;
    void *vcb_user_data = call->vcb_user_data;
    pthread_mutex_unlock(call->toxav_call_mutex);

    if (vcb != nullptr) {
        vcb(call->av, friend_number, width, height, y, u, v, ystride, ustride, vstride, vcb_user_data);
    }
}

static int callback_invite(void *_Nonnull object, MSICall *_Nonnull call);
static int callback_start(void *_Nonnull object, MSICall *_Nonnull call);
static int callback_end(void *_Nonnull object, MSICall *_Nonnull call);
static int callback_error(void *_Nonnull object, MSICall *_Nonnull call);
static int callback_capabilities(void *_Nonnull object, MSICall *_Nonnull call);

static bool audio_bit_rate_invalid(uint32_t bit_rate);
static bool video_bit_rate_invalid(uint32_t bit_rate);
static bool invoke_call_state_callback(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t state);
static ToxAVCall *_Nullable call_new(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, Toxav_Err_Call *_Nullable error);
static ToxAVCall *_Nullable call_remove(ToxAVCall *_Nullable call);
static bool call_prepare_transmission(ToxAVCall *_Nullable call);
static void call_kill_transmission(ToxAVCall *_Nullable call);

static ToxAVCall *call_get(ToxAV *av, uint32_t friend_number)
{
    if (av == nullptr) {
        return nullptr;
    }

    /* Assumes mutex locked */
    if (av->calls == nullptr || av->calls_tail < friend_number) {
        return nullptr;
    }

    return av->calls[friend_number];
}

static RTPSession *rtp_session_get(ToxAVCall *call, int payload_type)
{
    if (call == nullptr) {
        return nullptr;
    }

    if (payload_type == RTP_TYPE_VIDEO) {
        return call->video_rtp;
    } else {
        return call->audio_rtp;
    }
}

static BWController *bwc_controller_get(const ToxAVCall *call)
{
    if (call == nullptr) {
        return nullptr;
    }

    return call->bwc;
}

/**
 * @brief initialize d with default values
 * @param d struct to be initialized, must not be nullptr
 */
static void init_decode_time_stats(DecodeTimeStats *_Nonnull d)
{
    assert(d != nullptr);
    d->count = 0;
    d->total = 0;
    d->average = 0;
    d->interval = IDLE_ITERATION_INTERVAL_MS;
}

ToxAV *_Nullable toxav_new(Tox *_Nonnull tox, Toxav_Err_New *_Nullable error)
{
    const MSICallbacks callbacks = {
        callback_invite,
        callback_start,
        callback_end,
        callback_error,
        callback_error, // peertimeout
        callback_capabilities,
    };

    Toxav_Err_New rc = TOXAV_ERR_NEW_OK;
    ToxAV *av = nullptr;

    if (tox == nullptr) {
        rc = TOXAV_ERR_NEW_NULL;
        goto RETURN;
    }

    av = (ToxAV *)calloc(1, sizeof(ToxAV));

    if (av == nullptr) {
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    av->mutex = (pthread_mutex_t *)mem_alloc(tox->sys.mem, sizeof(pthread_mutex_t));
    if (av->mutex == nullptr) {
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    if (create_recursive_mutex(av->mutex) != 0) {
        mem_delete(tox->sys.mem, av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    av->mem = tox->sys.mem;
    av->log = tox->m->log;
    av->tox = tox;

    av->msi = msi_new(av->log, msi_send_packet, av->tox, &callbacks, av);

    tox_callback_friend_lossy_packet_per_pktid(av->tox, handle_rtp_packet, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, handle_rtp_packet, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, handle_bwc_packet, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(av->tox, handle_msi_packet, PACKET_ID_MSI);

    av->toxav_mono_time = mono_time_new(tox->sys.mem, nullptr, nullptr);

    if (av->msi == nullptr) {
        tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, RTP_TYPE_AUDIO);
        tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, RTP_TYPE_VIDEO);
        tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, BWC_PACKET_ID);
        tox_callback_friend_lossless_packet_per_pktid(av->tox, nullptr, PACKET_ID_MSI);

        mono_time_free(tox->sys.mem, av->toxav_mono_time);

        pthread_mutex_destroy(av->mutex);
        mem_delete(tox->sys.mem, av->mutex);
        rc = TOXAV_ERR_NEW_MALLOC;
        goto RETURN;
    }

    init_decode_time_stats(&av->audio_stats);
    init_decode_time_stats(&av->video_stats);

    // save ToxAV object into toxcore
    tox_set_av_object(av->tox, av);

RETURN:

    if (error != nullptr) {
        *error = rc;
    }

    if (rc != TOXAV_ERR_NEW_OK) {
        if (av != nullptr) {
            free(av);
            av = nullptr;
        }
    }

    return av;
}

void toxav_kill(ToxAV *_Nullable av)
{
    if (av == nullptr) {
        return;
    }

    pthread_mutex_lock(av->mutex);

    // unregister callbacks
    for (uint8_t i = PACKET_ID_RANGE_LOSSY_AV_START; i <= PACKET_ID_RANGE_LOSSY_AV_END; ++i) {
        tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, i);
    }

    tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, nullptr, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(av->tox, nullptr, PACKET_ID_MSI);

    /* To avoid possible deadlocks */
    while (av->msi != nullptr && msi_kill(av->log, av->msi) != 0) {
        pthread_mutex_unlock(av->mutex);
        pthread_mutex_lock(av->mutex);
    }

    /* Msi kill will hang up all calls so just clean these calls */
    if (av->calls != nullptr) {
        ToxAVCall *it = call_get(av, av->calls_head);

        while (it != nullptr) {
            call_kill_transmission(it);
            it->msi_call = nullptr; /* msi_kill() frees the call's msi_call handle; which causes #278 */
            it = call_remove(it); /* This will eventually free av->calls */
        }
    }

    mono_time_free(av->tox->sys.mem, av->toxav_mono_time);

    pthread_mutex_unlock(av->mutex);
    pthread_mutex_destroy(av->mutex);
    mem_delete(av->tox->sys.mem, av->mutex);

    // set ToxAV object to NULL in toxcore, to signal ToxAV has been shutdown
    tox_set_av_object(av->tox, nullptr);

    free(av);
}

Tox *_Nonnull toxav_get_tox(const ToxAV *_Nonnull av)
{
    Tox *tox;
    pthread_mutex_lock(av->mutex);
    tox = av->tox;
    pthread_mutex_unlock(av->mutex);
    return tox;
}

uint32_t toxav_audio_iteration_interval(const ToxAV *_Nonnull av)
{
    return av->calls != nullptr ? av->audio_stats.interval : IDLE_ITERATION_INTERVAL_MS;
}

uint32_t toxav_video_iteration_interval(const ToxAV *_Nonnull av)
{
    return av->calls != nullptr ? av->video_stats.interval : IDLE_ITERATION_INTERVAL_MS;
}

uint32_t toxav_iteration_interval(const ToxAV *_Nonnull av)
{
    return min_u32(toxav_audio_iteration_interval(av),
                   toxav_video_iteration_interval(av));
}

/**
 * @brief calc_interval Calculates the needed iteration interval based on previous decode times
 * @param mono_time Mono_Time struct to work on
 * @param stats Statistics to update
 * @param frame_time the duration of the current frame in ms
 * @param start_time the timestamp when decoding of this frame started
 */
static void calc_interval(const Mono_Time *_Nonnull mono_time, DecodeTimeStats *_Nonnull stats, int32_t frame_time, uint64_t start_time)
{
    stats->interval = frame_time < stats->average ? 0 : (frame_time - stats->average);
    stats->total += current_time_monotonic(mono_time) - start_time;

    if (++stats->count == 3) {
        /* NOTE: Magic Offset for precision */
        stats->average = stats->total / 3 + 5;
        stats->count = 0;
        stats->total = 0;
    }
}

/**
 * @brief common iterator function for audio and video calls
 * @param av pointer to ToxAV structure of current instance
 * @param audio if true, iterate audio, video else
 */
static void iterate_common(ToxAV *_Nonnull av, bool audio)
{
    pthread_mutex_lock(av->mutex);

    if (av->calls == nullptr) {
        pthread_mutex_unlock(av->mutex);
        return;
    }

    const Mono_Time *mono_time = av->toxav_mono_time;
    const uint64_t start = current_time_monotonic(mono_time);
    int32_t frame_time = IDLE_ITERATION_INTERVAL_MS;

    for (ToxAVCall *i = av->calls[av->calls_head]; i != nullptr; i = i->next) {
        if (!i->active) {
            continue;
        }

        pthread_mutex_lock(i->toxav_call_mutex);
        pthread_mutex_unlock(av->mutex);

        const uint32_t fid = i->friend_number;
        Tox_Err_Friend_Query f_con_query_error;
        const bool is_offline = tox_friend_get_connection_status(av->tox, fid, &f_con_query_error) == TOX_CONNECTION_NONE;

        if (is_offline) {
            MSISession *session = i->msi_call->session;
            pthread_mutex_unlock(i->toxav_call_mutex);
            msi_call_timeout(session, av->log, fid);
            pthread_mutex_lock(av->mutex);
            break;
        }

        if (audio) {
            ac_iterate(i->audio);

            if ((i->msi_call->self_capabilities & MSI_CAP_R_AUDIO) != 0 &&
                    (i->msi_call->peer_capabilities & MSI_CAP_S_AUDIO) != 0) {
                frame_time = min_s32(ac_get_lp_frame_duration(i->audio), frame_time);
            }
        } else {
            vc_iterate(i->video);

            if ((i->msi_call->self_capabilities & MSI_CAP_R_VIDEO) != 0 &&
                    (i->msi_call->peer_capabilities & MSI_CAP_S_VIDEO) != 0) {
                pthread_mutex_lock(vc_get_queue_mutex(i->video));
                frame_time = min_s32(vc_get_lcfd(i->video), frame_time);
                pthread_mutex_unlock(vc_get_queue_mutex(i->video));
            }
        }

        pthread_mutex_unlock(i->toxav_call_mutex);
        pthread_mutex_lock(av->mutex);

        /* In case this call is popped from container stop iteration */
        if (call_get(av, fid) != i) {
            break;
        }
    }

    DecodeTimeStats *stats = audio ? &av->audio_stats : &av->video_stats;
    calc_interval(mono_time, stats, frame_time, start);

    pthread_mutex_unlock(av->mutex);
}

void toxav_audio_iterate(ToxAV *_Nonnull av)
{
    iterate_common(av, true);
}

void toxav_video_iterate(ToxAV *_Nonnull av)
{
    iterate_common(av, false);
}

void toxav_iterate(ToxAV *_Nonnull av)
{
    toxav_audio_iterate(av);
    toxav_video_iterate(av);
}

bool toxav_call(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                Toxav_Err_Call *_Nullable error)
{
    Toxav_Err_Call rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call;

    pthread_mutex_lock(av->mutex);

    if ((audio_bit_rate != 0 && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate != 0 && video_bit_rate_invalid(video_bit_rate))) {
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

    if (msi_invite(av->log, av->msi, &call->msi_call, friend_number, call->previous_self_capabilities) != 0) {
        call_remove(call);
        rc = TOXAV_ERR_CALL_SYNC;
        goto RETURN;
    }

    call->msi_call->user_data = call;

RETURN:
    pthread_mutex_unlock(av->mutex);

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_OK;
}

void toxav_callback_call(ToxAV *_Nonnull av, toxav_call_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->ccb = callback;
    av->ccb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_answer(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                  Toxav_Err_Answer *_Nullable error)
{
    pthread_mutex_lock(av->mutex);

    Toxav_Err_Answer rc = TOXAV_ERR_ANSWER_OK;
    ToxAVCall *call;

    if (!tox_friend_exists(av->tox, friend_number)) {
        rc = TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if ((audio_bit_rate != 0 && audio_bit_rate_invalid(audio_bit_rate))
            || (video_bit_rate != 0 && video_bit_rate_invalid(video_bit_rate))
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

    if (msi_answer(av->log, call->msi_call, call->previous_self_capabilities) != 0) {
        rc = TOXAV_ERR_ANSWER_SYNC;
    }

RETURN:
    pthread_mutex_unlock(av->mutex);

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_ANSWER_OK;
}

void toxav_callback_call_state(ToxAV *_Nonnull av, toxav_call_state_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->scb = callback;
    av->scb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

static Toxav_Err_Call_Control call_control_handle_resume(const ToxAVCall *_Nonnull call)
{
    /* Only act if paused and had media transfer active before */
    if (call->msi_call->self_capabilities != 0 || call->previous_self_capabilities == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    if (msi_change_capabilities(call->av->log, call->msi_call,
                                call->previous_self_capabilities) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    rtp_allow_receiving_mark(call->audio_rtp);
    rtp_allow_receiving_mark(call->video_rtp);

    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_pause(ToxAVCall *_Nonnull call)
{
    /* Only act if not already paused */
    if (call->msi_call->self_capabilities == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    call->previous_self_capabilities = call->msi_call->self_capabilities;

    if (msi_change_capabilities(call->av->log, call->msi_call, 0) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    rtp_stop_receiving_mark(call->audio_rtp);
    rtp_stop_receiving_mark(call->video_rtp);

    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_cancel(ToxAVCall *_Nonnull call)
{
    /* Hang up */
    pthread_mutex_lock(call->toxav_call_mutex);

    if (msi_hangup(call->av->log, call->msi_call) != 0) {
        pthread_mutex_unlock(call->toxav_call_mutex);
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    call->msi_call = nullptr;
    pthread_mutex_unlock(call->toxav_call_mutex);

    /* No matter the case, terminate the call */
    call_kill_transmission(call);
    call_remove(call);

    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_mute_audio(const ToxAVCall *_Nonnull call)
{
    if ((call->msi_call->self_capabilities & MSI_CAP_R_AUDIO) == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    if (msi_change_capabilities(call->av->log, call->msi_call, call->
                                msi_call->self_capabilities ^ MSI_CAP_R_AUDIO) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;

    }

    rtp_stop_receiving_mark(call->audio_rtp);
    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_unmute_audio(const ToxAVCall *_Nonnull call)
{
    if ((call->msi_call->self_capabilities ^ MSI_CAP_R_AUDIO) == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    if (msi_change_capabilities(call->av->log, call->msi_call, call->
                                msi_call->self_capabilities | MSI_CAP_R_AUDIO) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    rtp_allow_receiving_mark(call->audio_rtp);
    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_hide_video(const ToxAVCall *_Nonnull call)
{
    if ((call->msi_call->self_capabilities & MSI_CAP_R_VIDEO) == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    if (msi_change_capabilities(call->av->log, call->msi_call, call->
                                msi_call->self_capabilities ^ MSI_CAP_R_VIDEO) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    rtp_stop_receiving_mark(call->video_rtp);
    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle_show_video(const ToxAVCall *_Nonnull call)
{
    if ((call->msi_call->self_capabilities ^ MSI_CAP_R_VIDEO) == 0) {
        return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    if (msi_change_capabilities(call->av->log, call->msi_call, call->
                                msi_call->self_capabilities | MSI_CAP_R_VIDEO) == -1) {
        return TOXAV_ERR_CALL_CONTROL_SYNC;
    }

    rtp_allow_receiving_mark(call->video_rtp);
    return TOXAV_ERR_CALL_CONTROL_OK;
}
static Toxav_Err_Call_Control call_control_handle(ToxAVCall *_Nonnull call, Toxav_Call_Control control)
{
    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME:
            return call_control_handle_resume(call);

        case TOXAV_CALL_CONTROL_PAUSE:
            return call_control_handle_pause(call);

        case TOXAV_CALL_CONTROL_CANCEL:
            return call_control_handle_cancel(call);

        case TOXAV_CALL_CONTROL_MUTE_AUDIO:
            return call_control_handle_mute_audio(call);

        case TOXAV_CALL_CONTROL_UNMUTE_AUDIO:
            return call_control_handle_unmute_audio(call);

        case TOXAV_CALL_CONTROL_HIDE_VIDEO:
            return call_control_handle_hide_video(call);

        case TOXAV_CALL_CONTROL_SHOW_VIDEO:
            return call_control_handle_show_video(call);
    }

    return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
}
static Toxav_Err_Call_Control call_control(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, Toxav_Call_Control control)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        return TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND;
    }

    ToxAVCall *call = call_get(av, friend_number);

    if (call == nullptr || (!call->active && control != TOXAV_CALL_CONTROL_CANCEL)) {
        return TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;
    }

    return call_control_handle(call, control);
}
bool toxav_call_control(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, Toxav_Call_Control control, Toxav_Err_Call_Control *_Nullable error)
{
    pthread_mutex_lock(av->mutex);

    const Toxav_Err_Call_Control rc = call_control(av, friend_number, control);

    pthread_mutex_unlock(av->mutex);

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_CALL_CONTROL_OK;
}

bool toxav_audio_set_bit_rate(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t bit_rate,
                              Toxav_Err_Bit_Rate_Set *_Nullable error)
{
    Toxav_Err_Bit_Rate_Set rc = TOXAV_ERR_BIT_RATE_SET_OK;
    ToxAVCall *call;

    if (!tox_friend_exists(av->tox, friend_number)) {
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (bit_rate > 0 && audio_bit_rate_invalid(bit_rate)) {
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

    LOGGER_DEBUG(av->log, "Setting new audio bitrate to: %u", bit_rate);

    if (call->audio_bit_rate == bit_rate) {
        LOGGER_DEBUG(av->log, "Audio bitrate already set to: %u", bit_rate);
    } else if (bit_rate == 0) {
        LOGGER_DEBUG(av->log, "Turned off audio sending");

        if (msi_change_capabilities(av->log, call->msi_call, call->msi_call->
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
            LOGGER_DEBUG(av->log, "Turned on audio sending");

            /* The audio has been turned off before this */
            if (msi_change_capabilities(av->log, call->msi_call, call->
                                        msi_call->self_capabilities | MSI_CAP_S_AUDIO) != 0) {
                pthread_mutex_unlock(call->toxav_call_mutex);
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto RETURN;
            }
        } else {
            LOGGER_DEBUG(av->log, "Set new audio bit rate %u", bit_rate);
        }

        call->audio_bit_rate = bit_rate;
        pthread_mutex_unlock(call->toxav_call_mutex);
    }

    pthread_mutex_unlock(av->mutex);
RETURN:

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_BIT_RATE_SET_OK;
}

bool toxav_video_set_bit_rate(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t bit_rate,
                              Toxav_Err_Bit_Rate_Set *_Nullable error)
{
    Toxav_Err_Bit_Rate_Set rc = TOXAV_ERR_BIT_RATE_SET_OK;
    ToxAVCall *call;

    if (!tox_friend_exists(av->tox, friend_number)) {
        rc = TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    if (bit_rate > 0 && video_bit_rate_invalid(bit_rate)) {
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

    LOGGER_DEBUG(av->log, "Setting new video bitrate to: %u", bit_rate);

    if (call->video_bit_rate == bit_rate) {
        LOGGER_DEBUG(av->log, "Video bitrate already set to: %u", bit_rate);
    } else if (bit_rate == 0) {
        LOGGER_DEBUG(av->log, "Turned off video sending");

        /* Video sending is turned off; notify peer */
        if (msi_change_capabilities(av->log, call->msi_call, call->msi_call->
                                    self_capabilities ^ MSI_CAP_S_VIDEO) != 0) {
            pthread_mutex_unlock(av->mutex);
            rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
            goto RETURN;
        }

        call->video_bit_rate = 0;
    } else {
        pthread_mutex_lock(call->toxav_call_mutex);

        if (call->video_bit_rate == 0) {
            LOGGER_DEBUG(av->log, "Turned on video sending");

            /* The video has been turned off before this */
            if (msi_change_capabilities(av->log, call->msi_call, call->
                                        msi_call->self_capabilities | MSI_CAP_S_VIDEO) != 0) {
                pthread_mutex_unlock(call->toxav_call_mutex);
                pthread_mutex_unlock(av->mutex);
                rc = TOXAV_ERR_BIT_RATE_SET_SYNC;
                goto RETURN;
            }
        } else {
            LOGGER_DEBUG(av->log, "Set new video bit rate %u", bit_rate);
        }

        call->video_bit_rate = bit_rate;
        pthread_mutex_unlock(call->toxav_call_mutex);
    }

    pthread_mutex_unlock(av->mutex);
RETURN:

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_BIT_RATE_SET_OK;
}

void toxav_callback_audio_bit_rate(ToxAV *_Nonnull av, toxav_audio_bit_rate_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->abcb = callback;
    av->abcb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

void toxav_callback_video_bit_rate(ToxAV *_Nonnull av, toxav_video_bit_rate_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vbcb = callback;
    av->vbcb_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
}

bool toxav_audio_send_frame(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const int16_t *_Nullable pcm, size_t sample_count,
                            uint8_t channels, uint32_t sampling_rate, Toxav_Err_Send_Frame *_Nullable error)
{
    Toxav_Err_Send_Frame rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    if (!tox_friend_exists(av->tox, friend_number)) {
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
            (call->msi_call->self_capabilities & MSI_CAP_S_AUDIO) == 0 ||
            (call->msi_call->peer_capabilities & MSI_CAP_R_AUDIO) == 0) {
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

        /* This is more than enough always */
        const uint16_t dest_size = sample_count + sizeof(sampling_rate);
        VLA(uint8_t, dest, dest_size);

        sampling_rate = net_htonl(sampling_rate);
        memcpy(dest, &sampling_rate, sizeof(sampling_rate));
        const int vrc = ac_encode(call->audio, pcm, sample_count,
                                  dest + sizeof(sampling_rate), dest_size - sizeof(sampling_rate));

        if (vrc < 0) {
            pthread_mutex_unlock(call->mutex_audio);
            rc = TOXAV_ERR_SEND_FRAME_INVALID;
            goto RETURN;
        }

        if (rtp_send_data(av->log, call->audio_rtp, dest, vrc + sizeof(sampling_rate), false) != 0) {
            LOGGER_WARNING(av->log, "Failed to send audio packet");
            rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        }
    }

    pthread_mutex_unlock(call->mutex_audio);

RETURN:

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

static Toxav_Err_Send_Frame send_frames(const ToxAV *_Nonnull av, ToxAVCall *_Nonnull call)
{
    uint8_t *data;
    uint32_t size;
    bool is_keyframe;

    while (vc_get_cx_data(call->video, &data, &size, &is_keyframe) != 0) {
        const int res = rtp_send_data(
                            av->log,
                            call->video_rtp,
                            data,
                            size,
                            is_keyframe);

        if (res < 0) {
            Net_Strerror error_str;
            LOGGER_WARNING(av->log, "Could not send video frame: %s", net_strerror(net_error(), &error_str));
            return TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        }
    }

    return TOXAV_ERR_SEND_FRAME_OK;
}

bool toxav_video_send_frame(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint16_t width, uint16_t height,
                            const uint8_t *_Nullable y, const uint8_t *_Nullable u, const uint8_t *_Nullable v, Toxav_Err_Send_Frame *_Nullable error)
{
    Toxav_Err_Send_Frame rc = TOXAV_ERR_SEND_FRAME_OK;
    ToxAVCall *call;

    int video_encode_flags = 0;

    if (!tox_friend_exists(av->tox, friend_number)) {
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
            (call->msi_call->self_capabilities & MSI_CAP_S_VIDEO) == 0 ||
            (call->msi_call->peer_capabilities & MSI_CAP_R_VIDEO) == 0) {
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

    if (vc_reconfigure_encoder(call->video, call->video_bit_rate, width, height, -1) != 0) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto RETURN;
    }

    // we start with I-frames (full frames) and then switch to normal mode later
    if (rtp_session_get_ssrc(call->video_rtp) < VIDEO_SEND_X_KEYFRAMES_FIRST) {
        // Key frame flag for first frames
        video_encode_flags = VC_EFLAG_FORCE_KF;
        LOGGER_DEBUG(av->log, "I_FRAME_FLAG:%u only-i-frame mode", rtp_session_get_ssrc(call->video_rtp));

        rtp_session_set_ssrc(call->video_rtp, rtp_session_get_ssrc(call->video_rtp) + 1);
    } else if (rtp_session_get_ssrc(call->video_rtp) == VIDEO_SEND_X_KEYFRAMES_FIRST) {
        // normal keyframe placement
        video_encode_flags = VC_EFLAG_NONE;
        LOGGER_DEBUG(av->log, "I_FRAME_FLAG:%u normal mode", rtp_session_get_ssrc(call->video_rtp));

        rtp_session_set_ssrc(call->video_rtp, rtp_session_get_ssrc(call->video_rtp) + 1);
    }

    if (vc_encode(call->video, width, height, y, u, v, video_encode_flags) != 0) {
        pthread_mutex_unlock(call->mutex_video);
        rc = TOXAV_ERR_SEND_FRAME_INVALID;
        goto RETURN;
    }

    vc_increment_frame_counter(call->video);

    rc = send_frames(av, call);

    pthread_mutex_unlock(call->mutex_video);

RETURN:

    if (error != nullptr) {
        *error = rc;
    }

    return rc == TOXAV_ERR_SEND_FRAME_OK;
}

void toxav_callback_audio_receive_frame(ToxAV *_Nonnull av, toxav_audio_receive_frame_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->acb = callback;
    av->acb_user_data = user_data;

    if (av->calls != nullptr) {
        for (ToxAVCall *i = av->calls[av->calls_head]; i != nullptr; i = i->next) {
            pthread_mutex_lock(i->toxav_call_mutex);
            i->acb = callback;
            i->acb_user_data = user_data;
            pthread_mutex_unlock(i->toxav_call_mutex);
        }
    }

    pthread_mutex_unlock(av->mutex);
}

void toxav_callback_video_receive_frame(ToxAV *_Nonnull av, toxav_video_receive_frame_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->vcb = callback;
    av->vcb_user_data = user_data;

    if (av->calls != nullptr) {
        for (ToxAVCall *i = av->calls[av->calls_head]; i != nullptr; i = i->next) {
            pthread_mutex_lock(i->toxav_call_mutex);
            i->vcb = callback;
            i->vcb_user_data = user_data;
            pthread_mutex_unlock(i->toxav_call_mutex);
        }
    }

    pthread_mutex_unlock(av->mutex);
}

/*******************************************************************************
 *
 * :: Internal
 *
 ******************************************************************************/
static void callback_bwc(BWController *bwc, Tox_Friend_Number friend_number, float loss, void *user_data)
{
    /* Callback which is called when the internal measure mechanism reported packet loss.
     * We report suggested lowered bitrate to an app. If app is sending both audio and video,
     * we will report lowered bitrate for video only because in that case video probably
     * takes more than 90% bandwidth. Otherwise, we report lowered bitrate on audio.
     * The application may choose to disable video totally if the stream is too bad.
     */

    ToxAVCall *call = (ToxAVCall *)user_data;
    assert(call != nullptr);

    LOGGER_DEBUG(call->av->log, "Reported loss of %f%%", (double)loss * 100);

    /* if less than 10% data loss we do nothing! */
    if (loss < 0.1F) {
        return;
    }

    pthread_mutex_lock(call->av->mutex);

    if (call->video_bit_rate != 0) {
        if (call->av->vbcb == nullptr) {
            pthread_mutex_unlock(call->av->mutex);
            LOGGER_WARNING(call->av->log, "No callback to report loss on");
            return;
        }

        call->av->vbcb(call->av, friend_number,
                       call->video_bit_rate - (call->video_bit_rate * loss),
                       call->av->vbcb_user_data);
    } else if (call->audio_bit_rate != 0) {
        if (call->av->abcb == nullptr) {
            pthread_mutex_unlock(call->av->mutex);
            LOGGER_WARNING(call->av->log, "No callback to report loss on");
            return;
        }

        call->av->abcb(call->av, friend_number,
                       call->audio_bit_rate - (call->audio_bit_rate * loss),
                       call->av->abcb_user_data);
    }

    pthread_mutex_unlock(call->av->mutex);
}

static int callback_invite(void *object, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)object;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_new(toxav, call->friend_number, nullptr);

    if (av_call == nullptr) {
        LOGGER_WARNING(toxav->log, "Failed to initialize call...");
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    call->user_data = av_call;
    av_call->msi_call = call;

    if (toxav->ccb != nullptr) {
        toxav->ccb(toxav, call->friend_number, (call->peer_capabilities & MSI_CAP_S_AUDIO) != 0,
                   (call->peer_capabilities & MSI_CAP_S_VIDEO) != 0, toxav->ccb_user_data);
    } else {
        /* No handler to capture the call request, send failure */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

static void handle_call_error(ToxAV *_Nonnull toxav, MSICall *_Nonnull call)
{
    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_ERROR);

    if (call->user_data != nullptr) {
        call_kill_transmission((ToxAVCall *)call->user_data);
        call_remove((ToxAVCall *)call->user_data);
    }
}

static int callback_start(void *object, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)object;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = call_get(toxav, call->friend_number);

    if (av_call == nullptr) {
        /* Should this ever happen? */
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!call_prepare_transmission(av_call)) {
        handle_call_error(toxav, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    if (!invoke_call_state_callback(toxav, call->friend_number, call->peer_capabilities)) {
        handle_call_error(toxav, call);
        pthread_mutex_unlock(toxav->mutex);
        return -1;
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

static int callback_end(void *object, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)object;
    pthread_mutex_lock(toxav->mutex);

    invoke_call_state_callback(toxav, call->friend_number, TOXAV_FRIEND_CALL_STATE_FINISHED);

    if (call->user_data != nullptr) {
        call_kill_transmission((ToxAVCall *)call->user_data);
        call_remove((ToxAVCall *)call->user_data);
    }

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

static int callback_error(void *object, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)object;
    pthread_mutex_lock(toxav->mutex);

    handle_call_error(toxav, call);

    pthread_mutex_unlock(toxav->mutex);
    return 0;
}

static int callback_capabilities(void *object, MSICall *call)
{
    ToxAV *toxav = (ToxAV *)object;
    pthread_mutex_lock(toxav->mutex);

    ToxAVCall *av_call = (ToxAVCall *)call->user_data;

    if ((call->peer_capabilities & MSI_CAP_S_AUDIO) != 0) {
        rtp_allow_receiving_mark(av_call->audio_rtp);
    } else {
        rtp_stop_receiving_mark(av_call->audio_rtp);
    }

    if ((call->peer_capabilities & MSI_CAP_S_VIDEO) != 0) {
        rtp_allow_receiving_mark(av_call->video_rtp);
    } else {
        rtp_stop_receiving_mark(av_call->video_rtp);
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
    /* Cap the target rate to 1000 Mbps to avoid some integer overflows in
     * target bandwidth calculations.
     * https://github.com/webmproject/libvpx/blob/027bbee30a0103b99d86327b48d29567fed11688/vp8/vp8_cx_iface.c#L350-L352
     */
    return bit_rate > 1000000;
}

static bool invoke_call_state_callback(ToxAV *av, Tox_Friend_Number friend_number, uint32_t state)
{
    if (av->scb != nullptr) {
        av->scb(av, friend_number, state, av->scb_user_data);
    } else {
        return false;
    }

    return true;
}

static ToxAVCall *call_new(ToxAV *av, Tox_Friend_Number friend_number, Toxav_Err_Call *error)
{
    /* Assumes mutex locked */
    Toxav_Err_Call rc = TOXAV_ERR_CALL_OK;
    ToxAVCall *call = nullptr;

    Tox_Err_Friend_Query f_con_query_error;
    Tox_Connection f_con_status = TOX_CONNECTION_NONE;

    if (!tox_friend_exists(av->tox, friend_number)) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_FOUND;
        goto RETURN;
    }

    f_con_status = tox_friend_get_connection_status(av->tox, friend_number, &f_con_query_error);

    if (f_con_status == TOX_CONNECTION_NONE) {
        rc = TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;
        goto RETURN;
    }

    if (call_get(av, friend_number) != nullptr) {
        rc = TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;
        goto RETURN;
    }

    call = (ToxAVCall *)calloc(1, sizeof(ToxAVCall));

    if (call == nullptr) {
        rc = TOXAV_ERR_CALL_MALLOC;
        goto RETURN;
    }

    call->av = av;
    call->friend_number = friend_number;

    if (create_recursive_mutex(call->toxav_call_mutex) != 0) {
        free(call);
        call = nullptr;
        rc = TOXAV_ERR_CALL_MALLOC;
        goto RETURN;
    }

    if (av->calls == nullptr) { /* Creating */
        av->calls = (ToxAVCall **)calloc(friend_number + 1, sizeof(ToxAVCall *));

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
        ToxAVCall **tmp = (ToxAVCall **)realloc(av->calls, (friend_number + 1) * sizeof(ToxAVCall *));

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

    if (error != nullptr) {
        *error = rc;
    }

    return call;
}

static ToxAVCall *call_remove(ToxAVCall *call)
{
    if (call == nullptr) {
        return nullptr;
    }

    const uint32_t friend_number = call->friend_number;
    ToxAV *av = call->av;

    ToxAVCall *prev = call->prev;
    ToxAVCall *next = call->next;

    /* Set av call in msi to NULL in order to know if call if ToxAVCall is
     * removed from the msi call.
     */
    if (call->msi_call != nullptr) {
        call->msi_call->user_data = nullptr;
    }

    pthread_mutex_destroy(call->toxav_call_mutex);
    free(call);

    if (prev != nullptr) {
        prev->next = next;
    } else if (next != nullptr) {
        av->calls_head = next->friend_number;
    } else {
        goto CLEAR;
    }

    if (next != nullptr) {
        next->prev = prev;
    } else if (prev != nullptr) {
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

    if (av->acb == nullptr && av->vcb == nullptr) {
        /* It makes no sense to have CSession without callbacks */
        return false;
    }

    if (call->active) {
        LOGGER_WARNING(av->log, "Call already active!");
        return true;
    }

    if (create_recursive_mutex(call->mutex_audio) != 0) {
        return false;
    }

    if (create_recursive_mutex(call->mutex_video) != 0) {
        goto FAILURE_2;
    }

    /* Prepare bwc */
    call->bwc = bwc_new(av->log, call->friend_number, callback_bwc, call, rtp_send_packet, call, av->toxav_mono_time);

    { /* Prepare audio */
        call->acb = av->acb;
        call->acb_user_data = av->acb_user_data;
        call->audio = ac_new(av->toxav_mono_time, av->log, call->friend_number, handle_audio_frame, call);

        if (call->audio == nullptr) {
            LOGGER_ERROR(av->log, "Failed to create audio codec session");
            goto FAILURE;
        }

        call->audio_rtp = rtp_new(av->log, RTP_TYPE_AUDIO, av->toxav_mono_time,
                                  rtp_send_packet, call,
                                  rtp_add_recv, rtp_add_lost, call->bwc,
                                  call->audio, ac_queue_message);

        if (call->audio_rtp == nullptr) {
            LOGGER_ERROR(av->log, "Failed to create audio rtp session");
            goto FAILURE;
        }
    }
    { /* Prepare video */
        call->vcb = av->vcb;
        call->vcb_user_data = av->vcb_user_data;
        call->video = vc_new(av->mem, av->log, av->toxav_mono_time, call->friend_number, handle_video_frame, call);

        if (call->video == nullptr) {
            LOGGER_ERROR(av->log, "Failed to create video codec session");
            goto FAILURE;
        }

        call->video_rtp = rtp_new(av->log, RTP_TYPE_VIDEO, av->toxav_mono_time,
                                  rtp_send_packet, call,
                                  rtp_add_recv, rtp_add_lost, call->bwc,
                                  call->video, vc_queue_message);

        if (call->video_rtp == nullptr) {
            LOGGER_ERROR(av->log, "Failed to create video rtp session");
            goto FAILURE;
        }
    }

    call->active = true;
    return true;

FAILURE:
    bwc_kill(call->bwc);
    rtp_kill(av->log, call->audio_rtp);
    ac_kill(call->audio);
    call->audio_rtp = nullptr;
    call->audio = nullptr;
    rtp_kill(av->log, call->video_rtp);
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
    if (call == nullptr || !call->active) {
        return;
    }

    call->active = false;

    pthread_mutex_lock(call->mutex_audio);
    pthread_mutex_unlock(call->mutex_audio);
    pthread_mutex_lock(call->mutex_video);
    pthread_mutex_unlock(call->mutex_video);
    pthread_mutex_lock(call->toxav_call_mutex);
    pthread_mutex_unlock(call->toxav_call_mutex);

    bwc_kill(call->bwc);

    const ToxAV *av = call->av;

    rtp_kill(av->log, call->audio_rtp);
    ac_kill(call->audio);
    call->audio_rtp = nullptr;
    call->audio = nullptr;

    rtp_kill(av->log, call->video_rtp);
    vc_kill(call->video);
    call->video_rtp = nullptr;
    call->video = nullptr;

    pthread_mutex_destroy(call->mutex_audio);
    pthread_mutex_destroy(call->mutex_video);
}
