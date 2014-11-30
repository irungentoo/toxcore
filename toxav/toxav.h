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

typedef struct _ToxAv ToxAv;

/* vpx_image_t */
#include <vpx/vpx_image.h>

typedef void ( *ToxAVCallback ) ( void *agent, int32_t call_idx, void *arg );
typedef void ( *ToxAvAudioCallback ) (void *agent, int32_t call_idx, const int16_t *PCM, uint16_t size, void *data);
typedef void ( *ToxAvVideoCallback ) (void *agent, int32_t call_idx, const vpx_image_t *img, void *data);

#ifndef __TOX_DEFINED__
#define __TOX_DEFINED__
typedef struct Tox Tox;
#endif

#define RTP_PAYLOAD_SIZE 65535


/**
 * Callbacks ids that handle the call states.
 */
typedef enum {
    av_OnInvite, /* Incoming call */
    av_OnRinging, /* When peer is ready to accept/reject the call */
    av_OnStart, /* Call (RTP transmission) started */
    av_OnCancel, /* The side that initiated call canceled invite */
    av_OnReject, /* The side that was invited rejected the call */
    av_OnEnd, /* Call that was active ended */
    av_OnRequestTimeout, /* When the requested action didn't get response in specified time */
    av_OnPeerTimeout, /* Peer timed out; stop the call */
    av_OnPeerCSChange, /* Peer changing Csettings. Prepare for changed AV */
    av_OnSelfCSChange /* Csettings change confirmation. Once triggered peer is ready to recv changed AV */
} ToxAvCallbackID;


/**
 * Call type identifier.
 */
typedef enum {
    av_TypeAudio = 192,
    av_TypeVideo
} ToxAvCallType;


typedef enum {
    av_CallNonExistent = -1,
    av_CallInviting, /* when sending call invite */
    av_CallStarting, /* when getting call invite */
    av_CallActive,
    av_CallHold,
    av_CallHungUp
} ToxAvCallState;

/**
 * Error indicators. Values under -20 are reserved for toxcore.
 */
typedef enum {
    av_ErrorNone = 0,
    av_ErrorUnknown = -1, /* Unknown error */
    av_ErrorNoCall = -20, /* Trying to perform call action while not in a call */
    av_ErrorInvalidState = -21, /* Trying to perform call action while in invalid state*/
    av_ErrorAlreadyInCallWithPeer = -22, /* Trying to call peer when already in a call with peer */
    av_ErrorReachedCallLimit = -23, /* Cannot handle more calls */
    av_ErrorInitializingCodecs = -30, /* Failed creating CSSession */
    av_ErrorSettingVideoResolution = -31, /* Error setting resolution */
    av_ErrorSettingVideoBitrate = -32, /* Error setting bitrate */
    av_ErrorSplittingVideoPayload = -33, /* Error splitting video payload */
    av_ErrorEncodingVideo = -34, /* vpx_codec_encode failed */
    av_ErrorEncodingAudio = -35, /* opus_encode failed */
    av_ErrorSendingPayload = -40, /* Sending lossy packet failed */
    av_ErrorCreatingRtpSessions = -41, /* One of the rtp sessions failed to initialize */
    av_ErrorNoRtpSession = -50, /* Trying to perform rtp action on invalid session */
    av_ErrorInvalidCodecState = -51, /* Codec state not initialized */
    av_ErrorPacketTooLarge = -52, /* Split packet exceeds it's limit */
} ToxAvError;


/**
 * Locally supported capabilities.
 */
typedef enum {
    av_AudioEncoding = 1 << 0,
    av_AudioDecoding = 1 << 1,
    av_VideoEncoding = 1 << 2,
    av_VideoDecoding = 1 << 3
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

/**
 * Start new A/V session. There can only be one session at the time.
 */
ToxAv *toxav_new(Tox *messenger, int32_t max_calls);

/**
 * Remove A/V session.
 */
void toxav_kill(ToxAv *av);

/**
 * Returns the interval in milliseconds when the next toxav_do() should be called.
 * If no call is active at the moment returns 200.
 */
uint32_t toxav_do_interval(ToxAv *av);

/**
 * Main loop for the session. Best called right after tox_do();
 */
void toxav_do(ToxAv *av);

/**
 * Register callback for call state.
 */
void toxav_register_callstate_callback (ToxAv *av, ToxAVCallback cb, ToxAvCallbackID id, void *userdata);

/**
 * Register callback for audio data.
 */
void toxav_register_audio_callback (ToxAv *av, ToxAvAudioCallback cb, void *userdata);

/**
 * Register callback for video data.
 */
void toxav_register_video_callback (ToxAv *av, ToxAvVideoCallback cb, void *userdata);

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
 * Also, it must be called when call is started
 */
int toxav_prepare_transmission(ToxAv *av, int32_t call_index, int support_video);

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
 * Returns number of active calls or -1 on error.
 */
int toxav_get_active_count (ToxAv *av);

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 *
 * Audio data callback format:
 *   audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 */
int toxav_add_av_groupchat(Tox *tox, void (*audio_callback)(Tox *, int, int, const int16_t *, unsigned int, uint8_t,
                           unsigned int, void *), void *userdata);

/* Join a AV group (you need to have been invited first.)
 *
 * returns group number on success
 * returns -1 on failure.
 *
 * Audio data callback format (same as the one for toxav_add_av_groupchat()):
 *   audio_callback(Tox *tox, int groupnumber, int peernumber, const int16_t *pcm, unsigned int samples, uint8_t channels, unsigned int sample_rate, void *userdata)
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 */
int toxav_join_av_groupchat(Tox *tox, int32_t friendnumber, const uint8_t *data, uint16_t length,
                            void (*audio_callback)(Tox *, int, int, const int16_t *, unsigned int, uint8_t, unsigned int, void *), void *userdata);

/* Send audio to the group chat.
 *
 * return 0 on success.
 * return -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to (samples * channels * sizeof(int16_t)).
 *
 * Valid number of samples are ((sample rate) * (audio length (Valid ones are: 2.5, 5, 10, 20, 40 or 60 ms)) / 1000)
 * Valid number of channels are 1 or 2.
 * Valid sample rates are 8000, 12000, 16000, 24000, or 48000.
 *
 * Recommended values are: samples = 960, channels = 1, sample_rate = 48000
 */
int toxav_group_send_audio(Tox *tox, int groupnumber, const int16_t *pcm, unsigned int samples, uint8_t channels,
                           unsigned int sample_rate);

#ifdef __cplusplus
}
#endif

#endif /* __TOXAV */
