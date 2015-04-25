/**  toxav.h
 * 
 *   Copyright (C) 2013-2015 Tox project All Rights Reserved.
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

#ifndef TOXAV_H
#define TOXAV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif
/** \page av Public audio/video API for Tox clients.
 * 
 * Unlike the Core API, this API is fully thread-safe. The library will ensure
 * the proper synchronisation of parallel calls.
 */
/**
 * The type of the Tox Audio/Video subsystem object.
 */
typedef struct toxAV ToxAV;
#ifndef TOX_DEFINED
#define TOX_DEFINED
/**
 * The type of a Tox instance. Repeated here so this file does not have a direct
 * dependency on the Core interface.
 */
typedef struct Tox Tox;
#endif
/*******************************************************************************
 * 
 * :: Creation and destruction
 *
 ******************************************************************************/
typedef enum TOXAV_ERR_NEW {
    TOXAV_ERR_NEW_OK,
    TOXAV_ERR_NEW_NULL,
    /**
     * Memory allocation failure while trying to allocate structures required for
     * the A/V session.
     */
    TOXAV_ERR_NEW_MALLOC,
    /**
     * Attempted to create a second session for the same Tox instance.
     */
    TOXAV_ERR_NEW_MULTIPLE
} TOXAV_ERR_NEW;
/**
 * Start new A/V session. There can only be only one session per Tox instance.
 */
ToxAV *toxav_new(Tox *tox, TOXAV_ERR_NEW *error);
/**
 * Releases all resources associated with the A/V session.
 *
 * If any calls were ongoing, these will be forcibly terminated without
 * notifying peers. After calling this function, no other functions may be
 * called and the av pointer becomes invalid.
 */
void toxav_kill(ToxAV *av);
/**
 * Returns the Tox instance the A/V object was created for.
 */
Tox *toxav_get_tox(ToxAV *av);
/*******************************************************************************
 * 
 * :: A/V event loop
 *
 ******************************************************************************/
/**
 * Returns the interval in milliseconds when the next toxav_iterate call should
 * be. If no call is active at the moment, this function returns 200.
 */
uint32_t toxav_iteration_interval(ToxAV const *av);
/**
 * Main loop for the session. This function needs to be called in intervals of
 * toxav_iteration_interval() milliseconds. It is best called in the same loop
 * as tox_iteration.
 */
void toxav_iterate(ToxAV *av);
/*******************************************************************************
 * 
 * :: Call setup
 *
 ******************************************************************************/
typedef enum TOXAV_ERR_CALL {
    TOXAV_ERR_CALL_OK,
    /**
     * A resource allocation error occurred while trying to create the structures
     * required for the call.
     */
    TOXAV_ERR_CALL_MALLOC,
    /**
     * The friend number did not designate a valid friend.
     */
    TOXAV_ERR_CALL_FRIEND_NOT_FOUND,
    /**
     * The friend was valid, but not currently connected.
     */
    TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED,
    /**
     * Attempted to call a friend while already in an audio or video call with
     * them.
     */
    TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL,
    /**
     * Audio or video bit rate is invalid.
     */
    TOXAV_ERR_CALL_INVALID_BIT_RATE
} TOXAV_ERR_CALL;
/**
 * Call a friend. This will start ringing the friend.
 *
 * It is the client's responsibility to stop ringing after a certain timeout,
 * if such behaviour is desired. If the client does not stop ringing, the A/V
 * library will not stop until the friend is disconnected.
 *
 * @param friend_number The friend number of the friend that should be called.
 * @param audio_bit_rate Audio bit rate in Kb/sec. Set this to 0 to disable
 * audio sending.
 * @param video_bit_rate Video bit rate in Kb/sec. Set this to 0 to disable
 * video sending.
 */
bool toxav_call(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_CALL *error);
/**
 * The function type for the `call` callback.
 */
typedef void toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data);
/**
 * Set the callback for the `call` event. Pass NULL to unset.
 *
 * This event is triggered when a call is received from a friend.
 */
void toxav_callback_call(ToxAV *av, toxav_call_cb *function, void *user_data);
typedef enum TOXAV_ERR_ANSWER {
    TOXAV_ERR_ANSWER_OK,
    /**
     * A resource allocation error occurred while trying to create the structures
     * required for the call.
     */
    TOXAV_ERR_ANSWER_MALLOC,
    /**
     * The friend number did not designate a valid friend.
     */
    TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND,
    /**
     * The friend was valid, but they are not currently trying to initiate a call.
     * This is also returned if this client is already in a call with the friend.
     */
    TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING,
    /**
     * Audio or video bit rate is invalid.
     */
    TOXAV_ERR_ANSWER_INVALID_BIT_RATE
} TOXAV_ERR_ANSWER;
/**
 * Accept an incoming call.
 *
 * If an allocation error occurs while answering a call, both participants will
 * receive TOXAV_CALL_STATE_ERROR and the call will end.
 *
 * @param friend_number The friend number of the friend that is calling.
 * @param audio_bit_rate Audio bit rate in Kb/sec. Set this to 0 to disable
 * audio sending.
 * @param video_bit_rate Video bit rate in Kb/sec. Set this to 0 to disable
 * video sending.
 */
bool toxav_answer(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate, TOXAV_ERR_ANSWER *error);
/*******************************************************************************
 * 
 * :: Call state graph
 *
 ******************************************************************************/
typedef enum TOXAV_CALL_STATE {
    /**
     * Not sending nor receiving anything, meaning, one of the sides requested pause.
     * The call will be resumed once the side that initiated pause resumes it.
     */
    TOXAV_CALL_STATE_PAUSED = 0,
    /**
     * The flag that marks that friend is sending audio.
     */
    TOXAV_CALL_STATE_SENDING_A = 1,
    /**
     * The flag that marks that friend is sending video.
     */
    TOXAV_CALL_STATE_SENDING_V = 2,
    /**
     * The flag that marks that friend is receiving audio.
     */
    TOXAV_CALL_STATE_RECEIVING_A = 4,
    /**
     * The flag that marks that friend is receiving video.
     */
    TOXAV_CALL_STATE_RECEIVING_V = 8,
    /**
     * The call has finished. This is the final state after which no more state
     * transitions can occur for the call.
     */
    TOXAV_CALL_STATE_END = 16,
    /**
     * Set by the AV core if an error occurred on the remote end.
     */
    TOXAV_CALL_STATE_ERROR = 32768
} TOXAV_CALL_STATE;
/**
 * The function type for the `call_state` callback.
 *
 * @param friend_number The friend number for which the call state changed.
 * @param state The new call state.
 */
typedef void toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data);
/**
 * Set the callback for the `call_state` event. Pass NULL to unset.
 *
 * This event is triggered when a call state transition occurs.
 */
void toxav_callback_call_state(ToxAV *av, toxav_call_state_cb *function, void *user_data);
/*******************************************************************************
 * 
 * :: Call control
 *
 ******************************************************************************/
typedef enum TOXAV_CALL_CONTROL {
    /**
     * Resume a previously paused call. Only valid if the pause was caused by this
     * client, if not, this control is ignored. Not valid before the call is accepted.
     */
    TOXAV_CALL_CONTROL_RESUME,
    /**
     * Put a call on hold. Not valid before the call is accepted.
     */
    TOXAV_CALL_CONTROL_PAUSE,
    /**
     * Reject a call if it was not answered, yet. Cancel a call after it was
     * answered.
     */
    TOXAV_CALL_CONTROL_CANCEL,
    /**
     * Request that the friend stops sending audio. Regardless of the friend's
     * compliance, this will cause the `receive_audio_frame` event to stop being
     * triggered on receiving an audio frame from the friend. If the audio was
     * already muted, calling this control will notify client to start sending
     * audio again.
     */
    TOXAV_CALL_CONTROL_TOGGLE_MUTE_AUDIO,
    /**
     * Request that the friend stops sending video. Regardless of the friend's
     * compliance, this will cause the `receive_video_frame` event to stop being
     * triggered on receiving an video frame from the friend. If the video was
     * already muted, calling this control will notify client to start sending
     * video again.
     */
    TOXAV_CALL_CONTROL_TOGGLE_MUTE_VIDEO,
} TOXAV_CALL_CONTROL;
typedef enum TOXAV_ERR_CALL_CONTROL {
    TOXAV_ERR_CALL_CONTROL_OK,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND,
    /**
     * This client is currently not in a call with the friend. Before the call is
     * answered, only CANCEL is a valid control.
     */
    TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL,
    /**
     * Attempted to resume a call that was not paused.
     */
    TOXAV_ERR_CALL_CONTROL_NOT_PAUSED,
    /**
     * Attempted to resume a call that was paused by the other party. Also set if
     * the client attempted to send a system-only control.
     */
    TOXAV_ERR_CALL_CONTROL_DENIED,
    /**
     * The call was already paused on this client. It is valid to pause if the
     * other party paused the call. The call will resume after both parties sent
     * the RESUME control.
     */
    TOXAV_ERR_CALL_CONTROL_ALREADY_PAUSED,
    /**
     * Tried to unmute a call that was not already muted.
     */
    TOXAV_ERR_CALL_CONTROL_NOT_MUTED
} TOXAV_ERR_CALL_CONTROL;
/**
 * Sends a call control command to a friend.
 *
 * @param friend_number The friend number of the friend this client is in a call
 * with.
 * @param control The control command to send.
 *
 * @return true on success.
 */
bool toxav_call_control(ToxAV *av, uint32_t friend_number, TOXAV_CALL_CONTROL control, TOXAV_ERR_CALL_CONTROL *error);
/*******************************************************************************
 * 
 * :: Controlling bit rates
 *
 ******************************************************************************/
typedef enum TOXAV_ERR_BIT_RATE {
    TOXAV_ERR_BIT_RATE_OK,
    /**
     * The bit rate passed was not one of the supported values.
     */
    TOXAV_ERR_BIT_RATE_INVALID,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOXAV_ERR_BIT_RATE_FRIEND_NOT_FOUND,
    /**
     * This client is currently not in a call with the friend.
     */
    TOXAV_ERR_BIT_RATE_FRIEND_NOT_IN_CALL
} TOXAV_ERR_BIT_RATE;
/**
 * The function type for the `audio_bitrate_control` callback.
 * 
 * @param friend_number The friend number of the friend for which to set the
 * audio bit rate.
 * @param good Is the stream good enough to keep the said bitrate. Upon failed
 * non forceful bit rate setup this will be set to false and 'bit_rate'
 * will be set to the bit rate that failed, otherwise 'good' will be set to
 * true with 'bit_rate' set to new bit rate. If the stream becomes bad, 
 * the 'good' wil be set to false with 'bit_rate' set to the current bit rate.
 * This callback will never be called when the stream is good.
 * @param bit_rate The bit rate in Kb/sec.
 */
typedef void toxav_audio_bitrate_control_cb(ToxAV *av, uint32_t friend_number, bool good, uint32_t bit_rate, void *user_data);
/**
 * Set the callback for the `audio_bitrate_control` event. Pass NULL to unset.
 */
void toxav_callback_audio_bitrate_control(ToxAV *av, toxav_audio_bitrate_control_cb *function, void *user_data);
/**
 * Set the audio bit rate to be used in subsequent audio frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 * audio bit rate.
 * @param audio_bit_rate The new audio bit rate in Kb/sec. Set to 0 to disable
 * audio sending.
 *
 * @see toxav_call for the valid bit rates.
 */
bool toxav_set_audio_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, bool force, TOXAV_ERR_BIT_RATE *error);
/**
 * The function type for the `video_bitrate_control` callback.
 * 
 * @param friend_number The friend number of the friend for which to set the
 * video bit rate.
 * @param good Is the stream good enough to keep the said bitrate. Upon failed
 * non forceful bit rate setup this will be set to false and 'bit_rate'
 * will be set to the bit rate that failed, otherwise 'good' will be set to
 * true with 'bit_rate' set to new bit rate. If the stream becomes bad, 
 * the 'good' wil be set to false with 'bit_rate' set to the current bit rate.
 * This callback will never be called when the stream is good.
 * @param bit_rate The bit rate in Kb/sec.
 */
typedef void toxav_video_bitrate_control_cb(ToxAV *av, uint32_t friend_number, bool good, uint32_t bit_rate, void *user_data);
/**
 * Set the callback for the `video_bitrate_control` event. Pass NULL to unset.
 */
void toxav_callback_video_bitrate_control(ToxAV *av, toxav_video_bitrate_control_cb *function, void *user_data);
/**
 * Set the video bit rate to be used in subsequent video frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 * video bit rate.
 * @param video_bit_rate The new video bit rate in Kb/sec. Set to 0 to disable
 * video sending.
 *
 * @see toxav_call for the valid bit rates.
 */
bool toxav_set_video_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t video_bit_rate, bool force, TOXAV_ERR_BIT_RATE *error);
/*******************************************************************************
 * 
 * :: A/V sending
 *
 ******************************************************************************/
/**
 * Common error codes for the send_*_frame functions.
 */
typedef enum TOXAV_ERR_SEND_FRAME {
    TOXAV_ERR_SEND_FRAME_OK,
    /**
     * In case of video, one of Y, U, or V was NULL. In case of audio, the samples
     * data pointer was NULL.
     */
    TOXAV_ERR_SEND_FRAME_NULL,
    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND,
    /**
     * This client is currently not in a call with the friend.
     */
    TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL,
    /**
     * No video frame had been requested through the `video_frame_request` event,
     * but the client tried to send one, anyway.
     */
    TOXAV_ERR_SEND_FRAME_NOT_REQUESTED,
    /**
     * One of the frame parameters was invalid. E.g. the resolution may be too
     * small or too large, or the audio sampling rate may be unsupported.
     */
    TOXAV_ERR_SEND_FRAME_INVALID,
	/**
     * Failed to push frame through rtp interface.
     */
	TOXAV_ERR_SEND_FRAME_RTP_FAILED
} TOXAV_ERR_SEND_FRAME;
/**
 * Send a video frame to a friend.
 *
 * This is called in response to receiving the `video_frame_request` event.
 *
 * Y - plane should be of size: height * width
 * U - plane should be of size: (height/2) * (width/2)
 * V - plane should be of size: (height/2) * (width/2)
 *
 * @param friend_number The friend number of the friend to which to send a video
 * frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y Y (Luminance) plane data.
 * @param u U (Chroma) plane data.
 * @param v V (Chroma) plane data.
 */
bool toxav_send_video_frame(ToxAV *av, uint32_t friend_number,
                            uint16_t width, uint16_t height,
                            uint8_t const *y, uint8_t const *u, uint8_t const *v,
                            TOXAV_ERR_SEND_FRAME *error);
/**
 * Send an audio frame to a friend.
 *
 * This is called in response to receiving the `audio_frame_request` event.
 *
 * The expected format of the PCM data is: [s1c1][s1c2][...][s2c1][s2c2][...]...
 * Meaning: sample 1 for channel 1, sample 1 for channel 2, ...
 * For mono audio, this has no meaning, every sample is subsequent. For stereo,
 * this means the expected format is LRLRLR... with samples for left and right
 * alternating.
 *
 * @param friend_number The friend number of the friend to which to send an
 * audio frame.
 * @param pcm An array of audio samples. The size of this array must be
 * sample_count * channels.
 * @param sample_count Number of samples in this frame. Valid numbers here are
 * ((sample rate) * (audio length) / 1000), where audio length can be
 * 2.5, 5, 10, 20, 40 or 60 millseconds.
 * @param channels Number of audio channels. Must be at least 1 for mono.
 * For voice over IP, more than 2 channels (stereo) typically doesn't make
 * sense, but up to 255 channels are supported.
 * @param sampling_rate Audio sampling rate used in this frame. Valid sampling
 * rates are 8000, 12000, 16000, 24000, or 48000.
 */
bool toxav_send_audio_frame(ToxAV *av, uint32_t friend_number,
                            int16_t const *pcm,
                            size_t sample_count,
                            uint8_t channels,
                            uint32_t sampling_rate,
                            TOXAV_ERR_SEND_FRAME *error);
/*******************************************************************************
 * 
 * :: A/V receiving
 *
 ******************************************************************************/
/**
 * The function type for the `receive_video_frame` callback.
 *
 * @param friend_number The friend number of the friend who sent a video frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y 
 * @param u 
 * @param v Plane data.
 *          The size of plane data is derived from width and height where
 *          Y = width * height, U = (width/2) * (height/2) and V = (width/2) * (height/2).
 * @param ystride
 * @param ustride
 * @param vstride Strides data.
 */
typedef void toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
                                          uint16_t width, uint16_t height,
                                          uint8_t const *y, uint8_t const *u, uint8_t const *v, 
                                          int32_t ystride, int32_t ustride, int32_t vstride,
                                          void *user_data);
/**
 * Set the callback for the `receive_video_frame` event. Pass NULL to unset.
 */
void toxav_callback_receive_video_frame(ToxAV *av, toxav_receive_video_frame_cb *function, void *user_data);
/**
 * The function type for the `receive_audio_frame` callback.
 *
 * @param friend_number The friend number of the friend who sent an audio frame.
 * @param pcm An array of audio samples (sample_count * channels elements).
 * @param sample_count The number of audio samples per channel in the PCM array.
 * @param channels Number of audio channels.
 * @param sampling_rate Sampling rate used in this frame.
 *
 * @see toxav_send_audio_frame for the audio format.
 */
typedef void toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
                                          int16_t const *pcm,
                                          size_t sample_count,
                                          uint8_t channels,
                                          uint32_t sampling_rate,
                                          void *user_data);
/**
 * Set the callback for the `receive_audio_frame` event. Pass NULL to unset.
 */
void toxav_callback_receive_audio_frame(ToxAV *av, toxav_receive_audio_frame_cb *function, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* TOXAV_H */
