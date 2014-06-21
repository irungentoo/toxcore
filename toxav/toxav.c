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
#define MAX_ENCODE_TIME_US ((1000 / 60) * 1000)


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
} CallSpecific;


struct _ToxAv {
    Messenger *messenger;
    MSISession *msi_session; /** Main msi session */
    CallSpecific *calls; /** Per-call params */
    uint32_t max_calls;
};

const ToxAvCodecSettings av_DefaultSettings = {
    1000000,
    800,
    600,

    64000,
    20,
    48000,
    1,
    600,
    
    10
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
    msi_terminate_session(av->msi_session);

    int i = 0;

    for (; i < av->max_calls; i ++) {
        if ( av->calls[i].crtps[audio_index] )
            rtp_terminate_session(av->calls[i].crtps[audio_index], av->msi_session->messenger_handle);


        if ( av->calls[i].crtps[video_index] )
            rtp_terminate_session(av->calls[i].crtps[video_index], av->msi_session->messenger_handle);



        if ( av->calls[i].j_buf ) terminate_queue(av->calls[i].j_buf);

        if ( av->calls[i].cs ) codec_terminate_session(av->calls[i].cs);
    }

    free(av->calls);
    free(av);
}

/**
 * @brief Register callback for call state.
 *
 * @param callback The callback
 * @param id One of the ToxAvCallbackID values
 * @return void
 */
void toxav_register_callstate_callback ( ToxAVCallback callback, ToxAvCallbackID id, void *userdata )
{
    msi_register_callback((MSICallback)callback, (MSICallbackID) id, userdata);
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

    return msi_cancel(av->msi_session, call_index, peer_id, reason);
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
    if ( !av->msi_session || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index] ) {
        LOGGER_ERROR("Error while starting audio RTP session: invalid call!\n");
        return ErrorInternal;
    }

    CallSpecific *call = &av->calls[call_index];

    call->crtps[audio_index] =
        rtp_init_session(
            type_audio,
            av->messenger,
            av->msi_session->calls[call_index]->peers[0],
            av->msi_session->calls[call_index]->key_peer,
            av->msi_session->calls[call_index]->key_local,
            av->msi_session->calls[call_index]->nonce_peer,
            av->msi_session->calls[call_index]->nonce_local);


    if ( !call->crtps[audio_index] ) {
        LOGGER_ERROR("Error while starting audio RTP session!\n");
        return ErrorStartingAudioRtp;
    }


    if ( support_video ) {
        call->crtps[video_index] =
            rtp_init_session (
                type_video,
                av->messenger,
                av->msi_session->calls[call_index]->peers[0],
                av->msi_session->calls[call_index]->key_peer,
                av->msi_session->calls[call_index]->key_local,
                av->msi_session->calls[call_index]->nonce_peer,
                av->msi_session->calls[call_index]->nonce_local);


        if ( !call->crtps[video_index] ) {
            LOGGER_ERROR("Error while starting video RTP session!\n");
            return ErrorStartingVideoRtp;
        }
    }

    if ( !(call->j_buf = create_queue(codec_settings->jbuf_capacity)) ) return ErrorInternal;

    call->cs = codec_init_session(codec_settings->audio_bitrate,
                                  codec_settings->audio_frame_duration,
                                  codec_settings->audio_sample_rate,
                                  codec_settings->audio_channels,
                                  codec_settings->audio_VAD_tolerance,
                                  codec_settings->video_width,
                                  codec_settings->video_height,
                                  codec_settings->video_bitrate);

    return call->cs ? ErrorNone : ErrorInternal;
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
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    CallSpecific *call = &av->calls[call_index];

    if ( call->crtps[audio_index] && -1 == rtp_terminate_session(call->crtps[audio_index], av->messenger) ) {
        LOGGER_ERROR("Error while terminating audio RTP session!\n");
        return ErrorTerminatingAudioRtp;
    }

    if ( call->crtps[video_index] && -1 == rtp_terminate_session(call->crtps[video_index], av->messenger) ) {
        LOGGER_ERROR("Error while terminating video RTP session!\n");
        return ErrorTerminatingVideoRtp;
    }

    call->crtps[audio_index] = NULL;
    call->crtps[video_index] = NULL;

    if ( call->j_buf ) {
        terminate_queue(call->j_buf);
        call->j_buf = NULL;
        LOGGER_DEBUG("Terminated j queue");
    } else LOGGER_DEBUG("No j queue");

    if ( call->cs ) {
        codec_terminate_session(call->cs);
        call->cs = NULL;
        LOGGER_DEBUG("Terminated codec session");
    } else LOGGER_DEBUG("No codec session");

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
                                      uint16_t length )
{
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    if ( av->calls[call_index].crtps[type - TypeAudio] )
        return rtp_send_msg ( av->calls[call_index].crtps[type - TypeAudio], av->msi_session->messenger_handle, payload,
                              length );
    else return -1;
}

/**
 * @brief Receive RTP payload.
 *
 * @param av Handler.
 * @param type Type of the payload.
 * @param dest Storage.
 * @return int
 * @retval ToxAvError On Error.
 * @retval >=0 Size of received payload.
 */
inline__ int toxav_recv_rtp_payload ( ToxAv *av, int32_t call_index, ToxAvCallType type, uint8_t *dest )
{
    if ( !dest ) return ErrorInternal;

    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    CallSpecific *call = &av->calls[call_index];

    if ( !call->crtps[type - TypeAudio] ) return ErrorNoRtpSession;

    RTPMessage *message;

    if ( type == TypeAudio ) {

        do {
            message = rtp_recv_msg(call->crtps[audio_index]);

            if (message) {
                /* push the packet into the queue */
                queue(call->j_buf, message);
            }
        } while (message);

        int success = 0;
        message = dequeue(call->j_buf, &success);

        if ( success == 2) return ErrorAudioPacketLost;
    } else {
        message = rtp_recv_msg(call->crtps[video_index]);
    }

    if ( message ) {
        memcpy(dest, message->data, message->length);

        int length = message->length;

        rtp_free_msg(NULL, message);

        return length;
    }

    return 0;
}

/**
 * @brief Receive decoded video packet.
 *
 * @param av Handler.
 * @param output Storage.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On Error.
 */
inline__ int toxav_recv_video ( ToxAv *av, int32_t call_index, vpx_image_t **output)
{
    if ( !output ) return ErrorInternal;

    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    uint8_t packet [RTP_PAYLOAD_SIZE];
    int recved_size = 0;
    int rc;
    CallSpecific *call = &av->calls[call_index];

    do {
        recved_size = toxav_recv_rtp_payload(av, call_index, TypeVideo, packet);

        if (recved_size > 0 && ( rc = vpx_codec_decode(&call->cs->v_decoder, packet, recved_size, NULL, 0) ) != VPX_CODEC_OK) {
            LOGGER_ERROR("Error decoding video: %s\n", vpx_codec_err_to_string(rc));
            return ErrorInternal;
        }

    } while (recved_size > 0);

    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;
    img = vpx_codec_get_frame(&call->cs->v_decoder, &iter);

    *output = img;
    return 0;
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
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    return toxav_send_rtp_payload(av, call_index, TypeVideo, frame, frame_size);
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
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    CallSpecific *call = &av->calls[call_index];

    int rc = vpx_codec_encode(&call->cs->v_encoder, input, call->cs->frame_counter, 1, 0, MAX_ENCODE_TIME_US);

    if ( rc != VPX_CODEC_OK) {
        LOGGER_ERROR("Could not encode video frame: %s\n", vpx_codec_err_to_string(rc));
        return ErrorInternal;
    }

    ++call->cs->frame_counter;

    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    int copied = 0;

    while ( (pkt = vpx_codec_get_cx_data(&call->cs->v_encoder, &iter)) ) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            if ( copied + pkt->data.frame.sz > dest_max ) return ErrorPacketTooLarge;

            memcpy(dest + copied, pkt->data.frame.buf, pkt->data.frame.sz);
            copied += pkt->data.frame.sz;
        }
    }

    return copied;
}

/**
 * @brief Receive decoded audio frame.
 *
 * @param av Handler.
 * @param frame_size The size of dest in frames/samples (one frame/sample is 16 bits or 2 bytes
 *                   and corresponds to one sample of audio.)
 * @param dest Destination of the raw audio (16 bit signed pcm with AUDIO_CHANNELS channels).
 *             Make sure it has enough space for frame_size frames/samples.
 * @return int
 * @retval >=0 Size of received data in frames/samples.
 * @retval ToxAvError On error.
 */
inline__ int toxav_recv_audio ( ToxAv *av, int32_t call_index, int frame_size, int16_t *dest )
{
    if ( !dest ) return ErrorInternal;

    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    CallSpecific *call = &av->calls[call_index];

    uint8_t packet [RTP_PAYLOAD_SIZE];

    int recved_size = toxav_recv_rtp_payload(av, call_index, TypeAudio, packet);

    if ( recved_size == ErrorAudioPacketLost ) {
        int dec_size = opus_decode(call->cs->audio_decoder, NULL, 0, dest, frame_size, 1);

        if ( dec_size < 0 ) {
            LOGGER_WARNING("Decoding error: %s", opus_strerror(dec_size));
            return ErrorInternal;
        } else return dec_size;

    } else if ( recved_size ) {
        int dec_size = opus_decode(call->cs->audio_decoder, packet, recved_size, dest, frame_size, 0);

        if ( dec_size < 0 ) {
            LOGGER_WARNING("Decoding error: %s", opus_strerror(dec_size));
            return ErrorInternal;
        } else return dec_size;
    } else {
        return 0; /* Nothing received */
    }
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
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    return toxav_send_rtp_payload(av, call_index, TypeAudio, frame, frame_size);
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
    if (cii(call_index, av->msi_session)) return ErrorNoCall;

    int32_t rc = opus_encode(av->calls[call_index].cs->audio_encoder, frame, frame_size, dest, dest_max);

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
    assert(av->msi_session);

    if ( peer < 0 || cii(call_index, av->msi_session) || !av->msi_session->calls[call_index]
            || av->msi_session->calls[call_index]->peer_count <= peer )
        return ErrorInternal;

    return av->msi_session->calls[call_index]->peers[peer];
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

/**
 * @brief Set queue limit
 *
 * @param av Handler
 * @param call_index index
 * @param limit the limit
 * @return void
 */
inline__ int toxav_set_audio_queue_limit(ToxAv *av, int32_t call_index, uint64_t limit)
{
    if ( av->calls[call_index].crtps[audio_index] )
        rtp_queue_adjust_limit(av->calls[call_index].crtps[audio_index], limit);
    else
        return ErrorNoRtpSession;

    return ErrorNone;
}

/**
 * @brief Set queue limit
 *
 * @param av Handler
 * @param call_index index
 * @param limit the limit
 * @return void
 */
inline__ int toxav_set_video_queue_limit(ToxAv *av, int32_t call_index, uint64_t limit)
{
    if ( av->calls[call_index].crtps[video_index] )
        rtp_queue_adjust_limit(av->calls[call_index].crtps[video_index], limit);
    else
        return ErrorNoRtpSession;

    return ErrorNone;
}

inline__ Tox *toxav_get_tox(ToxAv *av)
{
    return (Tox *)av->messenger;
}

int toxav_has_activity(ToxAv* av, int32_t call_index, int16_t* PCM, uint16_t frame_size, float ref_energy)
{
    if ( !av->calls[call_index].cs ) return ErrorInvalidCodecState;
    return energy_VAD(av->calls[call_index].cs, PCM, frame_size, ref_energy);
}