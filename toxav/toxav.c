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
 *   Report bugs/suggestions at #tox-dev @ freenode.net:6667
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "media.h"
#include "rtp.h"
#include "msi.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "toxav.h"

/* Default video bitrate in bytes/s */
#define VIDEO_BITRATE   (10*1000*100)

/* Default audio bitrate in bits/s */
#define AUDIO_BITRATE   64000

/* Assume 60 fps*/
#define MAX_ENCODE_TIME_US ((1000 / 60) * 1000)


#define inline__ inline __attribute__((always_inline))

static const uint8_t audio_index = 0, video_index = 1;


typedef enum {
    ts_closing,
    ts_running,
    ts_closed

} ThreadState;

typedef struct _ToxAv {
    Messenger *messenger;

    MSISession *msi_session; /** Main msi session */

    RTPSession *rtp_sessions[2]; /* Audio is first and video is second */

    struct jitter_buffer *j_buf;
    CodecState *cs;

    void *agent_handler;
} ToxAv;

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
ToxAv *toxav_new( Tox *messenger, void *userdata, uint16_t video_width, uint16_t video_height)
{
    ToxAv *av = calloc ( sizeof(ToxAv), 1);

    if (av == NULL)
        return NULL;

    av->messenger = (Messenger *)messenger;

    av->msi_session = msi_init_session(av->messenger);
    av->msi_session->agent_handler = av;

    av->rtp_sessions[0] = av->rtp_sessions [1] = NULL;

    /* NOTE: This should be user defined or? */
    av->j_buf = create_queue(20);

    av->cs = codec_init_session(AUDIO_BITRATE, AUDIO_FRAME_DURATION, AUDIO_SAMPLE_RATE, AUDIO_CHANNELS, video_width,
                                video_height, VIDEO_BITRATE);

    av->agent_handler = userdata;

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

    if ( av->rtp_sessions[audio_index] ) {
        rtp_terminate_session(av->rtp_sessions[audio_index], av->msi_session->messenger_handle);
    }

    if ( av->rtp_sessions[video_index] ) {
        rtp_terminate_session(av->rtp_sessions[video_index], av->msi_session->messenger_handle);
    }

    codec_terminate_session(av->cs);

    free(av);
}

/**
 * @brief Register callback for call state.
 *
 * @param callback The callback
 * @param id One of the ToxAvCallbackID values
 * @return void
 */
void toxav_register_callstate_callback ( ToxAVCallback callback, ToxAvCallbackID id )
{
    msi_register_callback((MSICallback)callback, (MSICallbackID) id);
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
int toxav_call (ToxAv *av, int user, ToxAvCallType call_type, int ringing_seconds )
{
    if ( av->msi_session->call ) {
        return ErrorAlreadyInCall;
    }

    return msi_invite(av->msi_session, call_type, ringing_seconds * 1000, user);
}

/**
 * @brief Hangup active call.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_hangup ( ToxAv *av )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->call->state != call_active ) {
        return ErrorInvalidState;
    }

    return msi_hangup(av->msi_session);
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
int toxav_answer ( ToxAv *av, ToxAvCallType call_type )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->call->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_answer(av->msi_session, call_type);
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
int toxav_reject ( ToxAv *av, const char *reason )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    if ( av->msi_session->call->state != call_starting ) {
        return ErrorInvalidState;
    }

    return msi_reject(av->msi_session, (const uint8_t *) reason);
}

/**
 * @brief Cancel outgoing request.
 *
 * @param av Handler.
 * @param reason Optional reason.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_cancel ( ToxAv *av, const char *reason )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    return msi_cancel(av->msi_session, 0, (const uint8_t *)reason);
}

/**
 * @brief Terminate transmission. Note that transmission will be terminated without informing remote peer.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_stop_call ( ToxAv *av )
{
    if ( !av->msi_session->call ) {
        return ErrorNoCall;
    }

    return msi_stopcall(av->msi_session);
}

/**
 * @brief Must be call before any RTP transmission occurs.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_prepare_transmission ( ToxAv *av )
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

/**
 * @brief Call this at the end of the transmission.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_kill_transmission ( ToxAv *av )
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
inline__ int toxav_send_rtp_payload ( ToxAv *av, ToxAvCallType type, const uint8_t *payload, uint16_t length )
{
    if ( av->rtp_sessions[type - TypeAudio] )
        return rtp_send_msg ( av->rtp_sessions[type - TypeAudio], av->msi_session->messenger_handle, payload, length );
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
inline__ int toxav_recv_rtp_payload ( ToxAv *av, ToxAvCallType type, uint8_t *dest )
{
    if ( !dest ) return ErrorInternal;

    if ( !av->rtp_sessions[type - TypeAudio] ) return ErrorNoRtpSession;

    RTPMessage *message;

    if ( type == TypeAudio ) {

        do {
            message = rtp_recv_msg(av->rtp_sessions[audio_index]);

            if (message) {
                /* push the packet into the queue */
                queue(av->j_buf, message);
            }
        } while (message);

        int success = 0;
        message = dequeue(av->j_buf, &success);

        if ( success == 2) return ErrorAudioPacketLost;
    } else {
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

/**
 * @brief Receive decoded video packet.
 *
 * @param av Handler.
 * @param output Storage.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On Error.
 */
inline__ int toxav_recv_video ( ToxAv *av, vpx_image_t **output)
{
    if ( !output ) return ErrorInternal;

    uint8_t packet [RTP_PAYLOAD_SIZE];
    int recved_size = 0;

    do {
        recved_size = toxav_recv_rtp_payload(av, TypeVideo, packet);

        if (recved_size > 0) {
            printf("decode: %s\n", vpx_codec_err_to_string(vpx_codec_decode(&av->cs->v_decoder, packet, recved_size, NULL, 0)));
        }
    } while (recved_size > 0);

    vpx_codec_iter_t iter = NULL;
    vpx_image_t *img;
    img = vpx_codec_get_frame(&av->cs->v_decoder, &iter);

    if (img == NULL)
        return ErrorInternal;

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
inline__ int toxav_send_video ( ToxAv *av, vpx_image_t *input)
{
    if (vpx_codec_encode(&av->cs->v_encoder, input, av->cs->frame_counter, 1, 0, MAX_ENCODE_TIME_US) != VPX_CODEC_OK) {
        printf("could not encode video frame\n");
        return ErrorInternal;
    }

    ++av->cs->frame_counter;

    vpx_codec_iter_t iter = NULL;
    const vpx_codec_cx_pkt_t *pkt;
    int sent = 0;

    while ( (pkt = vpx_codec_get_cx_data(&av->cs->v_encoder, &iter)) ) {
        if (pkt->kind == VPX_CODEC_CX_FRAME_PKT) {
            if (toxav_send_rtp_payload(av, TypeVideo, pkt->data.frame.buf, pkt->data.frame.sz) != -1)
                ++sent;
        }
    }

    if (sent > 0)
        return 0;

    return ErrorInternal;
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
inline__ int toxav_recv_audio ( ToxAv *av, int frame_size, int16_t *dest )
{
    if ( !dest ) return ErrorInternal;

    uint8_t packet [RTP_PAYLOAD_SIZE];

    int recved_size = toxav_recv_rtp_payload(av, TypeAudio, packet);

    if ( recved_size == ErrorAudioPacketLost ) {
        printf("Lost packet\n");
        return opus_decode(av->cs->audio_decoder, NULL, 0, dest, frame_size, 1);
    } else if ( recved_size ) {
        return opus_decode(av->cs->audio_decoder, packet, recved_size, dest, frame_size, 0);
    } else {
        return 0; /* Nothing received */
    }
}

/**
 * @brief Encode and send audio frame.
 *
 * @param av Handler.
 * @param frame The frame (raw 16 bit signed pcm with AUDIO_CHANNELS channels audio.)
 * @param frame_size Its size in number of frames/samples (one frame/sample is 16 bits or 2 bytes)
 *                   frame size should be AUDIO_FRAME_SIZE.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
inline__ int toxav_send_audio ( ToxAv *av, const int16_t *frame, int frame_size)
{
    uint8_t temp_data[RTP_PAYLOAD_SIZE];
    int32_t ret = opus_encode(av->cs->audio_encoder, frame, frame_size, temp_data, sizeof(temp_data));

    if (ret <= 0)
        return ErrorInternal;

    return toxav_send_rtp_payload(av, TypeAudio, temp_data, ret);
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
int toxav_get_peer_transmission_type ( ToxAv *av, int peer )
{
    assert(av->msi_session);

    if ( peer < 0 || !av->msi_session->call || av->msi_session->call->peer_count <= peer )
        return ErrorInternal;

    return av->msi_session->call->type_peer[peer];
}

/**
 * @brief Get reference to an object that is handling av session.
 *
 * @param av Handler.
 * @return void*
 */
void *toxav_get_agent_handler ( ToxAv *av )
{
    return av->agent_handler;
}
