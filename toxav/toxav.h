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
 */


#ifndef __TOXAV
#define __TOXAV
#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* vpx_image_t */
#include <vpx/vpx_image.h>

typedef void ( *ToxAVCallback ) ( void *agent, int32_t call_idx, void *arg );
typedef struct _ToxAv ToxAv;

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

#define RTP_PAYLOAD_SIZE 65535


/**
 * @brief Callbacks ids that handle the call states.
 */
typedef enum {
    /* Requests */
    av_OnInvite,
    av_OnStart,
    av_OnCancel,
    av_OnReject,
    av_OnEnd,

    /* Responses */
    av_OnRinging,
    av_OnStarting,
    av_OnEnding,

    /* Protocol */
    av_OnRequestTimeout,
    av_OnPeerTimeout,
    av_OnMediaChange
} ToxAvCallbackID;


/**
 * @brief Call type identifier.
 */
typedef enum {
    TypeAudio = 192,
    TypeVideo
} ToxAvCallType;


typedef enum {
    av_CallNonExistant = -1,
    av_CallInviting, /* when sending call invite */
    av_CallStarting, /* when getting call invite */
    av_CallActive,
    av_CallHold,
    av_CallHanged_up
} ToxAvCallState;

/**
 * @brief Error indicators.
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
    ErrorTerminatingAudioRtp = -9, /* Returned in toxav_kill_transmission() */
    ErrorTerminatingVideoRtp = -10, /* Returned in toxav_kill_transmission() */
    ErrorPacketTooLarge = -11, /* Buffer exceeds size while encoding */
    ErrorInvalidCodecState = -12, /* Codec state not initialized */

} ToxAvError;


/**
 * @brief Locally supported capabilities.
 */
typedef enum {
    AudioEncoding = 1 << 0,
    AudioDecoding = 1 << 1,
    VideoEncoding = 1 << 2,
    VideoDecoding = 1 << 3
} ToxAvCapabilities;


/**
 * @brief Encoding settings.
 */
typedef struct _ToxAvCodecSettings {
    ToxAvCallType call_type;

    uint32_t video_bitrate; /* In kbits/s */
    uint16_t max_video_width; /* In px */
    uint16_t max_video_height; /* In px */

    uint32_t audio_bitrate; /* In bits/s */
    uint16_t audio_frame_duration; /* In ms */
    uint32_t audio_sample_rate; /* In Hz */
    uint32_t audio_channels;
} ToxAvCSettings;

extern const ToxAvCSettings av_DefaultSettings;
extern const uint32_t av_jbufdc; /* Jitter buffer default capacity */
extern const uint32_t av_VADd; /* VAD default treshold */

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
ToxAv *toxav_new(Tox *messenger, int32_t max_calls);

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
 * @param av Handler.
 * @param callback The callback
 * @param id One of the ToxAvCallbackID values
 * @return void
 */
void toxav_register_callstate_callback (ToxAv *av, ToxAVCallback callback, ToxAvCallbackID id, void *userdata);

/**
 * @brief Register callback for recieving audio data
 *
 * @param av Handler.
 * @param callback The callback
 * @return void
 */
void toxav_register_audio_recv_callback (ToxAv *av, void (*callback)(ToxAv *, int32_t, int16_t *, int, void *),
        void *user_data);

/**
 * @brief Register callback for recieving video data
 *
 * @param av Handler.
 * @param callback The callback
 * @return void
 */
void toxav_register_video_recv_callback (ToxAv *av, void (*callback)(ToxAv *, int32_t, vpx_image_t *, void *),
        void *user_data);

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
int toxav_call(ToxAv *av, int32_t *call_index, int user, const ToxAvCSettings *csettings, int ringing_seconds);

/**
 * @brief Hangup active call.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_hangup(ToxAv *av, int32_t call_index);

/**
 * @brief Answer incomming call.
 *
 * @param av Handler.
 * @param call_type Answer with...
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_answer(ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings );

/**
 * @brief Reject incomming call.
 *
 * @param av Handler.
 * @param reason Optional reason. Set NULL if none.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_reject(ToxAv *av, int32_t call_index, const char *reason);

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
int toxav_cancel(ToxAv *av, int32_t call_index, int peer_id, const char *reason);

/**
 * @brief Notify peer that we are changing call settings
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_change_settings(ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings);

/**
 * @brief Terminate transmission. Note that transmission will be terminated without informing remote peer.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_stop_call(ToxAv *av, int32_t call_index);

/**
 * @brief Must be call before any RTP transmission occurs.
 *
 * @param av Handler.
 * @param support_video Is video supported ? 1 : 0
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_prepare_transmission(ToxAv *av, int32_t call_index, uint32_t jbuf_size, uint32_t VAD_treshold,
                               int support_video);

/**
 * @brief Call this at the end of the transmission.
 *
 * @param av Handler.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_kill_transmission(ToxAv *av, int32_t call_index);

/**
 * @brief Encode and send video packet.
 *
 * @param av Handler.
 * @param frame The encoded frame.
 * @param frame_size The size of the encoded frame.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_send_video ( ToxAv *av, int32_t call_index, const uint8_t *frame, unsigned int frame_size);

/**
 * @brief Send audio frame.
 *
 * @param av Handler.
 * @param data The audio data encoded with toxav_prepare_audio_frame().
 * @param size Its size in number of bytes.
 * @return int
 * @retval 0 Success.
 * @retval ToxAvError On error.
 */
int toxav_send_audio ( ToxAv *av, int32_t call_index, const uint8_t *frame, unsigned int size);

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
int toxav_prepare_video_frame ( ToxAv *av, int32_t call_index, uint8_t *dest, int dest_max, vpx_image_t *input );

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
int toxav_prepare_audio_frame ( ToxAv *av, int32_t call_index, uint8_t *dest, int dest_max, const int16_t *frame,
                                int frame_size);

/**
 * @brief Get peer transmission type. It can either be audio or video.
 *
 * @param av Handler.
 * @param peer The peer
 * @return int
 * @retval ToxAvCallType On success.
 * @retval ToxAvError On error.
 */
int toxav_get_peer_csettings ( ToxAv *av, int32_t call_index, int peer, ToxAvCSettings *dest );

/**
 * @brief Get id of peer participating in conversation
 *
 * @param av Handler
 * @param peer peer index
 * @return int
 * @retval ToxAvError No peer id
 */
int toxav_get_peer_id ( ToxAv *av, int32_t call_index, int peer );

/**
 * @brief Get current call state
 *
 * @param av Handler
 * @param call_index What call
 * @return int
 * @retval ToxAvCallState State id
 */
ToxAvCallState toxav_get_call_state ( ToxAv *av, int32_t call_index );
/**
 * @brief Is certain capability supported
 *
 * @param av Handler
 * @return int
 * @retval 1 Yes.
 * @retval 0 No.
 */
int toxav_capability_supported ( ToxAv *av, int32_t call_index, ToxAvCapabilities capability );


Tox *toxav_get_tox(ToxAv *av);

int toxav_has_activity ( ToxAv *av, int32_t call_index, int16_t *PCM, uint16_t frame_size, float ref_energy );

#ifdef __cplusplus
}
#endif

#endif /* __TOXAV */
