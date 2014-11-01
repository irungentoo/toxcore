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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */


#define _GNU_SOURCE /* implicit declaration warning */

#include "codec.h"
#include "msi.h"

#include "../toxcore/logger.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Assume 24 fps*/
#define MAX_ENCODE_TIME_US ((1000 / 24) * 1000)

/* call index invalid: true if invalid */
#define cii(c_idx, session) (c_idx < 0 || c_idx >= session->max_calls)


const ToxAvCSettings av_DefaultSettings = {
    TypeAudio,

    500,
    1280,
    720,

    64000,
    20,
    48000,
    1
};

const uint32_t av_jbufdc = 3;
const uint32_t av_VADd = 40;


static const uint8_t audio_index = 0, video_index = 1;

typedef struct _CallSpecific {
    RTPSession *crtps[2]; /** Audio is first and video is second */
    CodecState *cs;/** Each call have its own encoders and decoders.
                     * You can, but don't have to, reuse encoders for
                     * multiple calls. If you choose to reuse encoders,
                     * make sure to also reuse encoded payload for every call.
                     * Decoders have to be unique for each call.
                     */
                     
    _Bool call_active;
    pthread_mutex_t mutex;
} CallSpecific;

struct _ToxAv {
    Messenger *messenger;
    MSISession *msi_session; /** Main msi session */
    CallSpecific *calls; /** Per-call params */
    uint32_t max_calls;
};


static const MSICSettings *msicsettings_cast (const ToxAvCSettings *from)
{
    assert(sizeof(MSICSettings) == sizeof(ToxAvCSettings));
    return (const MSICSettings *) from;
}

static const ToxAvCSettings* toxavcsettings_cast (const MSICSettings *from)
{    
    assert(sizeof(MSICSettings) == sizeof(ToxAvCSettings));
    return (const ToxAvCSettings *) from;
    
}


ToxAv *toxav_new( Tox *messenger, int32_t max_calls)
{
    ToxAv *av = calloc ( sizeof(ToxAv), 1);

    if (av == NULL) {
        LOGGER_WARNING("Allocation failed!");
        return NULL;
    }

    av->messenger = (Messenger *)messenger;
    av->msi_session = msi_init_session(av->messenger, max_calls);
    av->msi_session->agent_handler = av;
    av->calls = calloc(sizeof(CallSpecific), max_calls);
    av->max_calls = max_calls;

    return av;
}

void toxav_kill ( ToxAv *av )
{
    uint32_t i;

    for (i = 0; i < av->max_calls; i ++) {
        if ( av->calls[i].crtps[audio_index] )
            rtp_terminate_session(av->calls[i].crtps[audio_index], av->msi_session->messenger_handle);


        if ( av->calls[i].crtps[video_index] )
            rtp_terminate_session(av->calls[i].crtps[video_index], av->msi_session->messenger_handle);

        if ( av->calls[i].cs ) cs_terminate_session(av->calls[i].cs);
    }

    msi_terminate_session(av->msi_session);

    free(av->calls);
    free(av);
}

void toxav_do(ToxAv* av)
{
    msi_do(av->msi_session);
}

void toxav_register_callstate_callback ( ToxAv *av, 
                                                ToxAVCallback callback, 
                                                ToxAvCallbackID id, 
                                                void *userdata )
{
    msi_register_callback(av->msi_session, (MSICallbackType)callback, (MSICallbackID) id, userdata);
}

int toxav_call (ToxAv *av, 
                int32_t *call_index, 
                int user, 
                const ToxAvCSettings *csettings, 
                int ringing_seconds )
{
    return msi_invite(av->msi_session, call_index, msicsettings_cast(csettings), ringing_seconds * 1000, user);
}

int toxav_hangup ( ToxAv *av, int32_t call_index )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_active ) {
        return ErrorInvalidState;
    }

    return msi_hangup(av->msi_session, call_index);
}

int toxav_answer ( ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_answer(av->msi_session, call_index, msicsettings_cast(csettings));
}

int toxav_reject ( ToxAv *av, int32_t call_index, const char *reason )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_reject(av->msi_session, call_index, reason);
}

int toxav_cancel ( ToxAv *av, int32_t call_index, int peer_id, const char *reason )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_inviting ) {
        return ErrorInvalidState;
    }

    return msi_cancel(av->msi_session, call_index, peer_id, reason);
}

int toxav_change_settings(ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings)
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    return msi_change_csettings(av->msi_session, call_index, msicsettings_cast(csettings));
}

int toxav_stop_call ( ToxAv *av, int32_t call_index )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    return msi_stopcall(av->msi_session, call_index);
}

int toxav_prepare_transmission ( ToxAv *av, 
                                 int32_t call_index,
                                 uint32_t jbuf_capacity, 
                                 uint32_t VAD_treshold,
                                 int support_video )
{
    if ( !av->msi_session || cii(call_index, av->msi_session) ||
            !av->msi_session->calls[call_index] || !av->msi_session->calls[call_index]->csettings_peer ||
            av->calls[call_index].call_active) {
        LOGGER_ERROR("Error while starting RTP session: invalid call!\n");
        return ErrorInternal;
    }

    CallSpecific *call = &av->calls[call_index];
    
    if ( pthread_mutex_init(&call->mutex, NULL) != 0 ) {
        LOGGER_WARNING("Failed to init call mutex!");
        return ErrorInternal;
    }
    
    const ToxAvCSettings* c_peer = toxavcsettings_cast
    (&av->msi_session->calls[call_index]->csettings_peer[0]);
    const ToxAvCSettings* c_self = toxavcsettings_cast
    (&av->msi_session->calls[call_index]->csettings_local);
    
    LOGGER_DEBUG(
        "Type: %u \n"
        "Video bitrate: %u \n"
        "Video height: %u \n"
        "Video width: %u \n"
        "Audio bitrate: %u \n"
        "Audio framedur: %u \n"
        "Audio sample rate: %u \n"
        "Audio channels: %u \n",
        c_peer->call_type,
        c_peer->video_bitrate,
        c_peer->max_video_height,
        c_peer->max_video_width,
        c_peer->audio_bitrate,
        c_peer->audio_frame_duration,
        c_peer->audio_sample_rate,
        c_peer->audio_channels );
    
    if ( !(call->cs = cs_init_session(c_self, c_peer, VAD_treshold, jbuf_capacity, support_video)) ){
        pthread_mutex_destroy(&call->mutex);
        LOGGER_ERROR("Error while starting Codec State!\n");
        return ErrorInternal;
    }
    
    call->crtps[audio_index] =
        rtp_init_session(type_audio, av->messenger, av->msi_session->calls[call_index]->peers[0]);

    if ( !call->crtps[audio_index] ) {
        LOGGER_ERROR("Error while starting audio RTP session!\n");
        return ErrorInternal;
    }
    
    call->crtps[audio_index]->cs = call->cs;

    if ( support_video ) {
        call->crtps[video_index] =
            rtp_init_session(type_video, av->messenger, av->msi_session->calls[call_index]->peers[0]);

        if ( !call->crtps[video_index] ) {
            LOGGER_ERROR("Error while starting video RTP session!\n");
            goto error;
        }
        
        call->crtps[video_index]->cs = call->cs;
    }

    call->call_active = 1;
    return ErrorNone;
error:
    rtp_terminate_session(call->crtps[audio_index], av->messenger);
    rtp_terminate_session(call->crtps[video_index], av->messenger);
    cs_terminate_session(call->cs);
    pthread_mutex_destroy(&call->mutex);
    memset(call, 0, sizeof(CallSpecific));
    
    return ErrorInternal;
}

int toxav_kill_transmission ( ToxAv *av, int32_t call_index )
{
    if (cii(call_index, av->msi_session)) {
        LOGGER_WARNING("Invalid call index: %d", call_index);
        return ErrorNoCall;
    }

    CallSpecific *call = &av->calls[call_index];

    pthread_mutex_lock(&call->mutex);

    if (!call->call_active) {
        pthread_mutex_unlock(&call->mutex);
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }

    rtp_terminate_session(call->crtps[audio_index], av->messenger); call->crtps[audio_index] = NULL;
    rtp_terminate_session(call->crtps[video_index], av->messenger); call->crtps[video_index] = NULL;
    cs_terminate_session(call->cs); call->cs = NULL;
    
    call->call_active = 0;

    pthread_mutex_unlock(&call->mutex);
    pthread_mutex_destroy(&call->mutex);
    
    return ErrorNone;
}

static int toxav_send_rtp_payload(ToxAv *av, 
                                  CallSpecific *call, 
                                  ToxAvCallType type, 
                                  const uint8_t *payload,
                                  unsigned int length)
{
    if (call->crtps[type - TypeAudio]) {
        
        /* Audio */
        if (type == TypeAudio) 
            return rtp_send_msg(call->crtps[audio_index], av->messenger, payload, length);
        
        /* Video */
        int parts = cs_split_video_payload(call->cs, payload, length);
        if (parts == -1) return ErrorInternal;
        
        int i; uint16_t part_size;
        for (i = 0; i < parts; i++) {
            if (rtp_send_msg(call->crtps[video_index], av->messenger,
                cs_get_split_video_frame(call->cs, &part_size), part_size) != 0) 
                return ErrorInternal;
        }
        
        return ErrorNone;
        
    } else return ErrorNoRtpSession;
}

int toxav_prepare_video_frame ( ToxAv *av, 
                                int32_t call_index, 
                                uint8_t *dest, 
                                int dest_max, 
                                vpx_image_t *input)
{
    if (cii(call_index, av->msi_session)) {
        LOGGER_WARNING("Invalid call index: %d", call_index);
        return ErrorNoCall;
    }
    
    
    CallSpecific *call = &av->calls[call_index];
    pthread_mutex_lock(&call->mutex);
    
    if (!call->call_active) {
        pthread_mutex_unlock(&call->mutex);
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }
    
    if (cs_reconfigure_video_encoder_resolution(call->cs, input->d_w, input->d_h) != 0) {
        pthread_mutex_unlock(&call->mutex);
        return ErrorInternal;
    }
    
    int rc = vpx_codec_encode(&call->cs->v_encoder, input, call->cs->frame_counter, 1, 0, MAX_ENCODE_TIME_US);
    
    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Could not encode video frame: %s\n", vpx_codec_err_to_string(rc));
        pthread_mutex_unlock(&call->mutex);
        return ErrorInternal;
    }
    
    ++call->cs->frame_counter;
    
    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    int copied = 0;
    
    while ( (pkt = vpx_codec_get_cx_data(&call->cs->v_encoder, &iter)) ) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            if ( copied + pkt->data.frame.sz > dest_max ) {
                pthread_mutex_unlock(&call->mutex);
                return ErrorPacketTooLarge;
            }
            
            memcpy(dest + copied, pkt->data.frame.buf, pkt->data.frame.sz);
            copied += pkt->data.frame.sz;
        }
    }
    
    pthread_mutex_unlock(&call->mutex);
    return copied;
}

int toxav_send_video ( ToxAv *av, int32_t call_index, const uint8_t *frame, unsigned int frame_size)
{

    if (cii(call_index, av->msi_session)) {
        LOGGER_WARNING("Invalid call index: %d", call_index);
        return ErrorNoCall;
    }

    CallSpecific *call = &av->calls[call_index];
    pthread_mutex_lock(&call->mutex);


    if (!call->call_active) {
        pthread_mutex_unlock(&call->mutex);
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }

    int rc = toxav_send_rtp_payload(av, call, TypeVideo, frame, frame_size);
    pthread_mutex_unlock(&call->mutex);

    return rc;
}

int toxav_recv_video ( ToxAv* av, int32_t call_index, vpx_image_t** output, uint16_t max_images, int32_t wait)
{
    
    if (cii(call_index, av->msi_session) || !av->calls[call_index].call_active) {
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }
    
    /* If CodecSession gets terminated while waiting this function returns -1 */
    return cs_recv_decoded_video(av->calls[call_index].cs, output, max_images, wait);
}

int toxav_prepare_audio_frame ( ToxAv *av, 
                                int32_t call_index, 
                                uint8_t *dest, 
                                int dest_max, 
                                const int16_t *frame,
                                int frame_size)
{
    if (cii(call_index, av->msi_session) || !av->calls[call_index].call_active) {
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }
    
    CallSpecific *call = &av->calls[call_index];
    pthread_mutex_lock(&call->mutex);
    
    
    if (!call->call_active) {
        pthread_mutex_unlock(&call->mutex);
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }
    
    int32_t rc = opus_encode(call->cs->audio_encoder, frame, frame_size, dest, dest_max);
    pthread_mutex_unlock(&call->mutex);
    
    if (rc < 0) {
        LOGGER_ERROR("Failed to encode payload: %s\n", opus_strerror(rc));
        return ErrorInternal;
    }
    
    return rc;
}

int toxav_send_audio ( ToxAv *av, int32_t call_index, const uint8_t *data, unsigned int size)
{
    if (size > MAX_CRYPTO_DATA_SIZE)
        return ErrorInternal;

    if (cii(call_index, av->msi_session) || !av->calls[call_index].call_active) {
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }

    CallSpecific *call = &av->calls[call_index];
    pthread_mutex_lock(&call->mutex);


    if (!call->call_active) {
        pthread_mutex_unlock(&call->mutex);
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }

    int rc = toxav_send_rtp_payload(av, call, TypeAudio, data, size);
    pthread_mutex_unlock(&call->mutex);

    return rc;
}

int toxav_recv_audio(ToxAv* av, int32_t call_index, int16_t* dest, uint16_t max_size, int32_t wait)
{
    
    if (cii(call_index, av->msi_session) || !av->calls[call_index].call_active) {
        LOGGER_WARNING("Action on inactive call: %d", call_index);
        return ErrorNoCall;
    }
    
    /* If CodecSession gets terminated while waiting this function returns -1 */
    return cs_recv_decoded_audio(av->calls[call_index].cs, dest, max_size, wait);
}

int toxav_get_peer_csettings ( ToxAv *av, int32_t call_index, int peer, ToxAvCSettings *dest )
{
    if ( peer < 0 || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index]
            || av->msi_session->calls[call_index]->peer_count <= peer )
        return ErrorInternal;

    *dest = *toxavcsettings_cast(&av->msi_session->calls[call_index]->csettings_peer[peer]);
    return ErrorNone;
}

int toxav_get_peer_id ( ToxAv *av, int32_t call_index, int peer )
{
    if ( peer < 0 || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index]
            || av->msi_session->calls[call_index]->peer_count <= peer )
        return ErrorInternal;

    return av->msi_session->calls[call_index]->peers[peer];
}

ToxAvCallState toxav_get_call_state(ToxAv *av, int32_t call_index)
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] )
        return av_CallNonExistant;

    return av->msi_session->calls[call_index]->state;

}

int toxav_capability_supported ( ToxAv *av, int32_t call_index, ToxAvCapabilities capability )
{
    return av->calls[call_index].cs ? av->calls[call_index].cs->capabilities & (CsCapabilities) capability : 0;
    /* 0 is error here */
}

Tox *toxav_get_tox(ToxAv *av)
{
    return (Tox *)av->messenger;
}

int toxav_has_activity(ToxAv *av, 
                       int32_t call_index, 
                       int16_t *PCM, 
                       uint16_t frame_size, 
                       float ref_energy)
{
    if ( !av->calls[call_index].cs ) return ErrorInvalidCodecState;

    return cs_calculate_energy_VAD(av->calls[call_index].cs, PCM, frame_size, ref_energy);
}