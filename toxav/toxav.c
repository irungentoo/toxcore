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

#include "rtp.h"
#include "codec.h"
#include "msi.h"
#include "toxav.h"

#include "../toxcore/logger.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Assume 60 fps*/
#define MAX_ENCODE_TIME_US ((1000 / 24) * 1000)

#define MAX_VIDEOFRAME_SIZE 0x40000 /* 256KiB */
#define VIDEOFRAME_PIECE_SIZE 0x500 /* 1.25 KiB*/
#define VIDEOFRAME_HEADER_SIZE 0x2


#define inline__ inline __attribute__((always_inline))

/* call index invalid: true if invalid */
#define cii(c_idx, session) (c_idx < 0 || c_idx >= session->max_calls)

static const uint8_t audio_index = 0, video_index = 1;

typedef struct _CallSpecific {
    RTPSession *crtps[2]; /** Audio is first and video is second */
    CodecState *cs;/** Each call have its own encoders and decoders.
                     * You can, but don't have to, reuse encoders for
                     * multiple calls. If you choose to reuse encoders,
                     * make sure to also reuse encoded payload for every call.
                     * Decoders have to be unique for each call. FIXME: Now add refcounted encoders and
                     * reuse them really.
                     */
    JitterBuffer *j_buf; /** Jitter buffer for audio */

    uint32_t frame_limit; /* largest address written to in frame_buf for current input frame*/
    uint8_t frame_id, frame_outid; /* id of input and output video frame */
    void *frame_buf; /* buffer for split video payloads */

    _Bool call_active;
    pthread_mutex_t mutex;
} CallSpecific;


struct _ToxAv {
    Messenger *messenger;
    MSISession *msi_session; /** Main msi session */
    CallSpecific *calls; /** Per-call params */

    void (*audio_callback)(ToxAv *, int32_t, int16_t *, int);
    void (*video_callback)(ToxAv *, int32_t, vpx_image_t *);

    uint32_t max_calls;
};

const ToxAvCodecSettings av_DefaultSettings = {
    500,
    800,
    600,

    64000,
    20,
    48000,
    1,
    600,

    6
};


/**
 * @brief Start new A/V session. There can only be one session at the time. If you register more
 *        it will result in undefined behaviour.
 *
 * @param messenger The messenger handle.
 * @param userdata The agent handling A/V session (i.e. phone).
 * @param video_width Width of video frame.
 * @param video_height Height of video frame.
 * @return ToxAv*
 * @retval NULL On error.
 */
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

/**
 * @brief Remove A/V session.
 *
 * @param av Handler.
 * @return void
 */
void toxav_kill ( ToxAv *av )
{
    int i = 0;

    for (; i < av->max_calls; i ++) {
        if ( av->calls[i].crtps[audio_index] )
            rtp_terminate_session(av->calls[i].crtps[audio_index], av->msi_session->messenger_handle);


        if ( av->calls[i].crtps[video_index] )
            rtp_terminate_session(av->calls[i].crtps[video_index], av->msi_session->messenger_handle);



        if ( av->calls[i].j_buf ) terminate_queue(av->calls[i].j_buf);

        if ( av->calls[i].cs ) codec_terminate_session(av->calls[i].cs);
    }

    msi_terminate_session(av->msi_session);

    free(av->calls);
    free(av);
}

/**
 * @brief Register callback for call state.
 *
 * @param av Handler.
 * @param callback The callback
 * @param id One of the ToxAvCallbackID values
 * @return void
 */
void toxav_register_callstate_callback ( ToxAv* av, ToxAVCallback callback, ToxAvCallbackID id, void* userdata )
{
    msi_register_callback(av->msi_session, (MSICallbackType)callback, (MSICallbackID) id, userdata);
}

/**
 * @brief Register callback for recieving audio data
 *
 * @param callback The callback
 * @return void
 */
void toxav_register_audio_recv_callback (ToxAv *av, void (*callback)(ToxAv *, int32_t, int16_t *, int))
{
    av->audio_callback = callback;
}

/**
 * @brief Register callback for recieving video data
 *
 * @param callback The callback
 * @return void
 */
void toxav_register_video_recv_callback (ToxAv *av, void (*callback)(ToxAv *, int32_t, vpx_image_t *))
{
    av->video_callback = callback;
}

/**
 * @brief Call user. Use its friend_id.
 *
 * @param av Handler.
 * @param user The user.
 * @param call_type Call type.
 * @param ringing_seconds Ringing timeout.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_call (ToxAv *av, int32_t *call_index, int user, ToxAvCallType call_type, int ringing_seconds )
{
    return msi_invite(av->msi_session, call_index, call_type, ringing_seconds * 1000, user);
}

/**
 * @brief Hangup active call.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
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

/**
 * @brief Answer incomming call.
 *
 * @param av Handler.
 * @param call_type Answer with...
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_answer ( ToxAv *av, int32_t call_index, ToxAvCallType call_type )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_answer(av->msi_session, call_index, call_type);
}

/**
 * @brief Reject incomming call.
 *
 * @param av Handler.
 * @param reason Optional reason. Set NULL if none.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_reject ( ToxAv *av, int32_t call_index, const char *reason )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->calls[call_index]->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_reject(av->msi_session, call_index, (const uint8_t *) reason);
}

/**
 * @brief Cancel outgoing request.
 *
 * @param av Handler.
 * @param reason Optional reason.
 * @param peer_id peer friend_id
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
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

/**
 * @brief Notify peer that we are changing call type
 *
 * @param av Handler.
 * @return int
 * @param call_type Change to...
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_change_type(ToxAv* av, int32_t call_index, ToxAvCallType call_type)
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }
    
    return msi_change_type(av->msi_session, call_index, call_type);
}

/**
 * @brief Terminate transmission. Note that transmission will be terminated without informing remote peer.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_stop_call ( ToxAv *av, int32_t call_index )
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        return ErrorNoCall;
    }

    return msi_stopcall(av->msi_session, call_index);
}

/**
 * @brief Must be call before any RTP transmission occurs.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_prepare_transmission ( ToxAv *av, int32_t call_index, ToxAvCodecSettings *codec_settings, int support_video )
{
    if ( !av->msi_session || cii(call_index, av->msi_session) ||
            !av->msi_session->calls[call_index] || av->calls[call_index].call_active) {
        LOGGER_ERROR("Error while starting RTP session: invalid call!\n");
        return ErrorInternal;
    }

    CallSpecific *call = &av->calls[call_index];

    call->crtps[audio_index] =
        rtp_init_session(type_audio, av->messenger, av->msi_session->calls[call_index]->peers[0]);


    if ( !call->crtps[audio_index] ) {
        LOGGER_ERROR("Error while starting audio RTP session!\n");
        return ErrorInternal;
    }

    call->crtps[audio_index]->call_index = call_index;
    call->crtps[audio_index]->av = av;

    if ( support_video ) {
        call->crtps[video_index] =
            rtp_init_session(type_video, av->messenger, av->msi_session->calls[call_index]->peers[0]);

        if ( !call->crtps[video_index] ) {
            LOGGER_ERROR("Error while starting video RTP session!\n");
            goto error;
        }

        call->crtps[video_index]->call_index = call_index;
        call->crtps[video_index]->av = av;

        call->frame_limit = 0;
        call->frame_id = 0;
        call->frame_outid = 0;

        call->frame_buf = calloc(MAX_VIDEOFRAME_SIZE, 1);

        if (!call->frame_buf) {
            LOGGER_WARNING("Frame buffer allocation failed!");
            goto error;
        }

    }

    if ( !(call->j_buf = create_queue(codec_settings->jbuf_capacity)) ) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        goto error;
    }

    if ( (call->cs = codec_init_session(codec_settings->audio_bitrate,
                                        codec_settings->audio_frame_duration,
                                        codec_settings->audio_sample_rate,
                                        codec_settings->audio_channels,
                                        codec_settings->audio_VAD_tolerance,
                                        codec_settings->max_video_width,
                                        codec_settings->max_video_height,
                                        codec_settings->video_bitrate) )) {

        if ( pthread_mutex_init(&call->mutex, NULL) != 0 ) goto error;

        call->call_active = 1;

        return ErrorNone;
    }

error:
    rtp_terminate_session(call->crtps[audio_index], av->messenger);
    rtp_terminate_session(call->crtps[video_index], av->messenger);
    free(call->frame_buf);
    terminate_queue(call->j_buf);
    codec_terminate_session(call->cs);

    return ErrorInternal;
}

/**
 * @brief Call this at the end of the transmission.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
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


    call->call_active = 0;

    rtp_terminate_session(call->crtps[audio_index], av->messenger);
    call->crtps[audio_index] = NULL;
    rtp_terminate_session(call->crtps[video_index], av->messenger);
    call->crtps[video_index] = NULL;
    terminate_queue(call->j_buf);
    call->j_buf = NULL;
    codec_terminate_session(call->cs);
    call->cs = NULL;

    pthread_mutex_unlock(&call->mutex);
    pthread_mutex_destroy(&call->mutex);

    return ErrorNone;
}


/**
 * @brief Send RTP payload.
 *
 * @param av Handler.
 * @param type Type of payload.
 * @param payload The payload.
 * @param length Size of it.
 * @return int
 * @retval 0 Success.
 * @retval -1 Failure.
 */
inline__ int toxav_send_rtp_payload ( ToxAv *av, int32_t call_index, ToxAvCallType type, const uint8_t *payload,
                                      unsigned int length )
{
    CallSpecific *call = &av->calls[call_index];

    if (call->crtps[type - TypeAudio]) {

        if (type == TypeAudio) {
            return rtp_send_msg(call->crtps[type - TypeAudio], av->messenger, payload, length);
        } else {
            if (length == 0 || length > MAX_VIDEOFRAME_SIZE) {
                LOGGER_ERROR("Invalid video frame size: %u\n", length);
                return ErrorInternal;
            }

            /* number of pieces - 1*/
            uint8_t numparts = (length - 1) / VIDEOFRAME_PIECE_SIZE;

            uint8_t load[2 + VIDEOFRAME_PIECE_SIZE];
            load[0] = call->frame_outid++;
            load[1] = 0;

            int i;

            for (i = 0; i < numparts; i++) {
                memcpy(load + VIDEOFRAME_HEADER_SIZE, payload, VIDEOFRAME_PIECE_SIZE);
                payload += VIDEOFRAME_PIECE_SIZE;

                if (rtp_send_msg(call->crtps[type - TypeAudio], av->messenger,
                                 load, VIDEOFRAME_HEADER_SIZE + VIDEOFRAME_PIECE_SIZE) != 0) {

                    return ErrorInternal;
                }

                load[1]++;
            }

            /* remainder = length % VIDEOFRAME_PIECE_SIZE, VIDEOFRAME_PIECE_SIZE if = 0 */
            length = ((length - 1) % VIDEOFRAME_PIECE_SIZE) + 1;
            memcpy(load + VIDEOFRAME_HEADER_SIZE, payload, length);

            return rtp_send_msg(call->crtps[type - TypeAudio], av->messenger, load, VIDEOFRAME_HEADER_SIZE + length);
        }
    } else {
        return ErrorNoRtpSession;
    }
}

/**
 * @brief Encode and send video packet.
 *
 * @param av Handler.
 * @param input The packet.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
inline__ int toxav_send_video ( ToxAv *av, int32_t call_index, const uint8_t *frame, int frame_size)
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

    int rc = toxav_send_rtp_payload(av, call_index, TypeVideo, frame, frame_size);
    pthread_mutex_unlock(&call->mutex);

    return rc;
}

/**
 * @brief Encode video frame
 *
 * @param av Handler
 * @param dest Where to
 * @param dest_max Max size
 * @param input What to encode
 * @return int
 * @retval ToxAvError On error.
 * @retval >0 On success
 */
inline__ int toxav_prepare_video_frame(ToxAv *av, int32_t call_index, uint8_t *dest, int dest_max, vpx_image_t *input)
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

    if (reconfigure_video_encoder_resolution(call->cs, input->d_w, input->d_h) != 0) {
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

/**
 * @brief Send audio frame.
 *
 * @param av Handler.
 * @param frame The frame (raw 16 bit signed pcm with AUDIO_CHANNELS channels audio.)
 * @param frame_size Its size in number of frames/samples (one frame/sample is 16 bits or 2 bytes)
 *                   frame size should be AUDIO_FRAME_SIZE.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
inline__ int toxav_send_audio ( ToxAv *av, int32_t call_index, const uint8_t *frame, int frame_size)
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

    int rc = toxav_send_rtp_payload(av, call_index, TypeAudio, frame, frame_size);
    pthread_mutex_unlock(&call->mutex);

    return rc;
}

/**
 * @brief Encode audio frame
 *
 * @param av Handler
 * @param dest dest
 * @param dest_max Max dest size
 * @param frame The frame
 * @param frame_size The frame size
 * @return int
 * @retval ToxAvError On error.
 * @retval >0 On success
 */
inline__ int toxav_prepare_audio_frame ( ToxAv *av, int32_t call_index, uint8_t *dest, int dest_max,
        const int16_t *frame, int frame_size)
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

/**
 * @brief Get peer transmission type. It can either be audio or video.
 *
 * @param av Handler.
 * @param peer The peer
 * @return int
 * @retval ToxAvCallType On success.
 * @retval ToxAvError On error.
 */
int toxav_get_peer_transmission_type ( ToxAv *av, int32_t call_index, int peer )
{
    if ( peer < 0 || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index]
            || av->msi_session->calls[call_index]->peer_count <= peer )
        return ErrorInternal;

    return av->msi_session->calls[call_index]->type_peer[peer];
}

/**
 * @brief Get id of peer participating in conversation
 *
 * @param av Handler
 * @param peer peer index
 * @return int
 * @retval ToxAvError No peer id
 */
int toxav_get_peer_id ( ToxAv *av, int32_t call_index, int peer )
{
    if ( peer < 0 || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index]
            || av->msi_session->calls[call_index]->peer_count <= peer )
        return ErrorInternal;

    return av->msi_session->calls[call_index]->peers[peer];
}

/**
 * @brief Get id of peer participating in conversation
 *
 * @param av Handler
 * @param peer peer index
 * @return int
 * @retval ToxAvError No peer id
 */
ToxAvCallState toxav_get_call_state(ToxAv *av, int32_t call_index)
{
    if ( cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] )
        return av_CallNonExistant;

    return av->msi_session->calls[call_index]->state;

}

/**
 * @brief Is certain capability supported
 *
 * @param av Handler
 * @return int
 * @retval 1 Yes.
 * @retval 0 No.
 */
inline__ int toxav_capability_supported ( ToxAv *av, int32_t call_index, ToxAvCapabilities capability )
{
    return av->calls[call_index].cs ? av->calls[call_index].cs->capabilities & (Capabilities) capability : 0;
    /* 0 is error here */
}

inline__ Tox *toxav_get_tox(ToxAv *av)
{
    return (Tox *)av->messenger;
}

int toxav_has_activity(ToxAv *av, int32_t call_index, int16_t *PCM, uint16_t frame_size, float ref_energy)
{
    if ( !av->calls[call_index].cs ) return ErrorInvalidCodecState;

    return energy_VAD(av->calls[call_index].cs, PCM, frame_size, ref_energy);
}

void toxav_handle_packet(RTPSession *_session, RTPMessage *_msg)
{
    ToxAv *av = _session->av;
    int32_t call_index = _session->call_index;
    CallSpecific *call = &av->calls[call_index];

    if (!call->call_active) return;
    
    if (_session->payload_type == type_audio % 128) {
        queue(call->j_buf, _msg);

        int success = 0, dec_size;
        int frame_size = 960;
        int16_t dest[frame_size];

        while ((_msg = dequeue(call->j_buf, &success)) || success == 2) {
            if (success == 2) {
                dec_size = opus_decode(call->cs->audio_decoder, NULL, 0, dest, frame_size, 1);
            } else {
                dec_size = opus_decode(call->cs->audio_decoder, _msg->data, _msg->length, dest, frame_size, 0);
                rtp_free_msg(NULL, _msg);
            }

            if (dec_size < 0) {
                LOGGER_WARNING("Decoding error: %s", opus_strerror(dec_size));
                continue;
            }

            if ( av->audio_callback )
                av->audio_callback(av, call_index, dest, frame_size);
            else 
                LOGGER_WARNING("Audio packet dropped due to missing callback!");
        }
    } else {
        uint8_t *packet = _msg->data;
        int recved_size = _msg->length;

        if (recved_size < VIDEOFRAME_HEADER_SIZE) {
            goto end;
        }

        uint8_t i = packet[0] - call->frame_id;

        if (i == 0) {
            /* piece of current frame */
        } else if (i > 0 && i < 128) {
            /* recieved a piece of a frame ahead, flush current frame and start reading this new frame */
            int rc = vpx_codec_decode(&call->cs->v_decoder, call->frame_buf, call->frame_limit, NULL, 0);
            call->frame_id = packet[0];
            memset(call->frame_buf, 0, call->frame_limit);
            call->frame_limit = 0;

            if (rc != VPX_CODEC_OK) {
                LOGGER_ERROR("Error decoding video: %u %s\n", i, vpx_codec_err_to_string(rc));
            }
        } else {
            /* old packet, dont read */
            LOGGER_DEBUG("Old packet: %u\n", i);
            goto end;
        }

        if (packet[1] > (MAX_VIDEOFRAME_SIZE - VIDEOFRAME_PIECE_SIZE + 1) /
                VIDEOFRAME_PIECE_SIZE) { //TODO, fix this check? not sure
            /* packet out of buffer range */
            goto end;
        }

        LOGGER_DEBUG("Video Packet: %u %u\n", packet[0], packet[1]);
        memcpy(call->frame_buf + packet[1] * VIDEOFRAME_PIECE_SIZE, packet + VIDEOFRAME_HEADER_SIZE,
               recved_size - VIDEOFRAME_HEADER_SIZE);
        uint32_t limit = packet[1] * VIDEOFRAME_PIECE_SIZE + recved_size - VIDEOFRAME_HEADER_SIZE;

        if (limit > call->frame_limit) {
            call->frame_limit = limit;
            LOGGER_DEBUG("Limit: %u\n", call->frame_limit);
        }

end:;
        vpx_codec_iter_t iter = NULL;
        vpx_image_t *img;
        img = vpx_codec_get_frame(&call->cs->v_decoder, &iter);

        if (img && av->video_callback) {
            av->video_callback(av, call_index, img);
        } else
            LOGGER_WARNING("Video packet dropped due to missing callback or no image!");

        rtp_free_msg(NULL, _msg);
    }
}
