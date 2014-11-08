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
 * Callbacks ids that handle the call states.
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
 * Call type identifier.
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
 * Error indicators.
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
 * Locally supported capabilities.
 */
typedef enum {
    AudioEncoding = 1 << 0,
    AudioDecoding = 1 << 1,
    VideoEncoding = 1 << 2,
    VideoDecoding = 1 << 3
} ToxAvCapabilities;


/**
 * Encoding settings.
 */
typedef struct _ToxAvCSettings {
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
 * Start new A/V session. There can only be one session at the time.
 */
ToxAv *toxav_new(Tox *messenger, int32_t max_calls);

/**
 * Remove A/V session.
 */
void toxav_kill(ToxAv *av);

/**
 * Main loop for the session. Best called right after tox_do();
 */
void toxav_do(ToxAv *av);

/**
 * Register callback for call state.
 */
void toxav_register_callstate_callback (ToxAv *av, 
                                        ToxAVCallback callback, 
                                        ToxAvCallbackID id, 
                                        void *userdata);

/**
 * Call user. Use its friend_id.
 */
int toxav_call(ToxAv *av, 
               int32_t *call_index, 
               int friend_id,
               const ToxAvCSettings *csettings, 
               int ringing_seconds);

/**
 * Hangup active call.
 */
int toxav_hangup(ToxAv *av, int32_t call_index);

/**
 * Answer incoming call. Pass the csettings that you will use.
 */
int toxav_answer(ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings );

/**
 * Reject incoming call.
 */
int toxav_reject(ToxAv *av, int32_t call_index, const char *reason);

/**
 * Cancel outgoing request.
 */
int toxav_cancel(ToxAv *av, int32_t call_index, int peer_id, const char *reason);

/**
 * Notify peer that we are changing codec settings.
 */
int toxav_change_settings(ToxAv *av, int32_t call_index, const ToxAvCSettings *csettings);

/**
 * Terminate transmission. Note that transmission will be 
 * terminated without informing remote peer. Usually called when we can't inform peer.
 */
int toxav_stop_call(ToxAv *av, int32_t call_index);

/**
 * Allocates transmission data. Must be call before calling toxav_prepare_* and toxav_send_*.
 */
int toxav_prepare_transmission(ToxAv *av, 
                               int32_t call_index, 
                               uint32_t jbuf_size, 
                               uint32_t VAD_treshold,
                               int support_video);

/**
 * Clears transmission data. Call this at the end of the transmission.
 */
int toxav_kill_transmission(ToxAv *av, int32_t call_index);

/**
 * Encode video frame.
 */
int toxav_prepare_video_frame ( ToxAv *av, 
                                int32_t call_index, 
                                uint8_t *dest, 
                                int dest_max, 
                                vpx_image_t *input);

/**
 * Send encoded video packet.
 */
int toxav_send_video ( ToxAv *av, int32_t call_index, const uint8_t *frame, uint32_t frame_size);

/**
 * Recv video payload. You can either poll (wait == 0), wait some time 
 * (wait == -1 forever or wait == x for x ms) . Returns -1 on error else amount of images recved.
 * NOTE: make sure do deallocate 'output' images since they are allocated internally (no need for this on error)
 */
int toxav_recv_video ( ToxAv *av, int32_t call_index, vpx_image_t **output, uint16_t max_images, int32_t wait);

/**
 * Encode audio frame.
 */
int toxav_prepare_audio_frame ( ToxAv *av, 
                                int32_t call_index, 
                                uint8_t *dest, 
                                int dest_max, 
                                const int16_t *frame,
                                int frame_size);

/**
 * Send encoded audio frame.
 */
int toxav_send_audio ( ToxAv *av, int32_t call_index, const uint8_t *frame, unsigned int size);

/**
 * Recv audio payload. You can either poll (wait == 0), wait some time 
 * (wait == -1 forever or wait == x for x ms). Returns: -1 on error, else size recved.
 */
int toxav_recv_audio ( ToxAv *av, int32_t call_index, int16_t* dest, uint16_t max_size, int32_t wait);

/**
 * Get codec settings from the peer. These were exchanged during call initialization
 * or when peer send us new csettings.
 */
int toxav_get_peer_csettings ( ToxAv *av, int32_t call_index, int peer, ToxAvCSettings *dest );

/**
 * Get friend id of peer participating in conversation.
 */
int toxav_get_peer_id ( ToxAv *av, int32_t call_index, int peer );

/**
 * Get current call state.
 */
ToxAvCallState toxav_get_call_state ( ToxAv *av, int32_t call_index );

/**
 * Is certain capability supported. Used to determine if encoding/decoding is ready.
 */
int toxav_capability_supported ( ToxAv *av, int32_t call_index, ToxAvCapabilities capability );

/**
 * Returns tox reference.
 */
Tox *toxav_get_tox (ToxAv *av);

/**
 * Check if there is activity in the PCM data.
 * Activity is present if the calculated PCM energy is > ref_energy.
 * Returns bool.
 */
int toxav_has_activity ( ToxAv *av, 
                         int32_t call_index, 
                         int16_t *PCM, 
                         uint16_t frame_size, 
                         float ref_energy );

#ifdef __cplusplus
}
#endif

#endif /* __TOXAV */
