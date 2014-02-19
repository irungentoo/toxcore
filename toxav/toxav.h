/**  toxav.h
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


#ifndef __TOXAV
#define __TOXAV
#include <inttypes.h>

/* vpx_image_t */
#include <vpx/vpx_image.h>

typedef void *( *ToxAVCallback ) ( void *arg );
typedef struct _ToxAv ToxAv;

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

#define RTP_PAYLOAD_SIZE 65535

/* Number of audio channels. */
#define AUDIO_CHANNELS 1

/* Audio frame duration in miliseconds */
#define AUDIO_FRAME_DURATION    20

/* Audio sample rate recommended to be 48kHz for Opus */
#define AUDIO_SAMPLE_RATE   48000

/* The amount of samples in one audio frame */
#define AUDIO_FRAME_SIZE    (AUDIO_SAMPLE_RATE*AUDIO_FRAME_DURATION/1000)


/**
 * @brief Callbacks ids that handle the call states.
 */
typedef enum {
    /* Requests */
    OnInvite,
    OnStart,
    OnCancel,
    OnReject,
    OnEnd,

    /* Responses */
    OnRinging,
    OnStarting,
    OnEnding,

    /* Protocol */
    OnError,
    OnRequestTimeout

} ToxAvCallbackID;


/**
 * @brief Call type identifier.
 */
typedef enum {
    TypeAudio = 70,
    TypeVideo
} ToxAvCallType;


/**
 * @brief Error indicators.
 *
 */
typedef enum {
    ErrorNone = 0,
    ErrorInternal = -1, /* Internal error */
    ErrorAlreadyInCall = -2, /* Already has an active call */
    ErrorNoCall = -3, /* Trying to perform call action while not in a call */
    ErrorInvalidState = -4, /* Trying to perform call action while in invalid state*/
    ErrorNoRtpSession = -5, /* Trying to perform rtp action on invalid session */
    ErrorAudioPacketLost = -6, /* Indicating packet loss */
    ErrorStartingAudioRtp = -7, /* Error in toxav_prepare_transmission() */
    ErrorStartingVideoRtp = -8 , /* Error in toxav_prepare_transmission() */
    ErrorNoTransmission = -9, /* Returned in toxav_kill_transmission() */
    ErrorTerminatingAudioRtp = -10, /* Returned in toxav_kill_transmission() */
    ErrorTerminatingVideoRtp = -11, /* Returned in toxav_kill_transmission() */

} ToxAvError;


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
ToxAv *toxav_new(Tox *messenger, void *userdata, uint16_t video_width, uint16_t video_height);

/**
 * @brief Remove A/V session.
 *
 * @param av Handler.
 * @return void
 */
void toxav_kill(ToxAv *av);

/**
 * @brief Register callback for call state.
 *
 * @param callback The callback
 * @param id One of the ToxAvCallbackID values
 * @return void
 */
void toxav_register_callstate_callback (ToxAVCallback callback, ToxAvCallbackID id);

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
int toxav_call(ToxAv *av, int user, ToxAvCallType call_type, int ringing_seconds);

/**
 * @brief Hangup active call.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_hangup(ToxAv *av);

/**
 * @brief Answer incomming call.
 *
 * @param av Handler.
 * @param call_type Answer with...
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_answer(ToxAv *av, ToxAvCallType call_type );

/**
 * @brief Reject incomming call.
 *
 * @param av Handler.
 * @param reason Optional reason. Set NULL if none.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_reject(ToxAv *av, const char *reason);

/**
 * @brief Cancel outgoing request.
 *
 * @param av Handler.
 * @param reason Optional reason.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_cancel(ToxAv *av, const char *reason);

/**
 * @brief Terminate transmission. Note that transmission will be terminated without informing remote peer.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_stop_call(ToxAv *av);

/**
 * @brief Must be call before any RTP transmission occurs.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_prepare_transmission(ToxAv *av);

/**
 * @brief Call this at the end of the transmission.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_kill_transmission(ToxAv *av);

/**
 * @brief Receive decoded video packet.
 *
 * @param av Handler.
 * @param output Storage.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On Error.
 */
int toxav_recv_video ( ToxAv *av, vpx_image_t **output);

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
int toxav_recv_audio( ToxAv *av, int frame_size, int16_t *dest );

/**
 * @brief Encode and send video packet.
 *
 * @param av Handler.
 * @param input The packet.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_send_video ( ToxAv *av, vpx_image_t *input);

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
int toxav_send_audio ( ToxAv *av, const int16_t *frame, int frame_size);

/**
 * @brief Get peer transmission type. It can either be audio or video.
 *
 * @param av Handler.
 * @param peer The peer
 * @return int
 * @retval ToxAvCallType On success.
 * @retval ToxAvError On error.
 */
int toxav_get_peer_transmission_type ( ToxAv *av, int peer );

/**
 * @brief Get reference to an object that is handling av session.
 *
 * @param av Handler.
 * @return void*
 */
void *toxav_get_agent_handler ( ToxAv *av );

#endif /* __TOXAV */