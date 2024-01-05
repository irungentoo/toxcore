/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/** @file
 * @brief Public audio/video API for Tox clients.
 *
 * This API can handle multiple calls. Each call has its state, in very rare
 * occasions the library can change the state of the call without apps knowledge.
 *
 * @section av_events Events and callbacks
 *
 * As in Core API, events are handled by callbacks. One callback can be
 * registered per event. All events have a callback function type named
 * `toxav_{event}_cb` and a function to register it named `toxav_callback_{event}`.
 * Passing a NULL callback will result in no callback being registered for that
 * event. Only one callback per event can be registered, so if a client needs
 * multiple event listeners, it needs to implement the dispatch functionality
 * itself. Unlike Core API, lack of some event handlers will cause the the
 * library to drop calls before they are started. Hanging up call from a
 * callback causes undefined behaviour.
 *
 * @section av_threading Threading implications
 *
 * Only toxav_iterate is thread-safe, all other functions must run from the
 * tox thread.
 *
 * Important exceptions are the `*_iterate` and `*_iterate_interval`
 * functions. You have to choose either the single thread or the multi thread
 * functions and read their documentation.
 *
 * A common way to run ToxAV (multiple or single instance) is to have a thread,
 * separate from tox instance thread, running a simple toxav_iterate loop,
 * sleeping for `toxav_iteration_interval * milliseconds` on each iteration.
 *
 * An important thing to note is that events are triggered from both tox and
 * toxav thread (see above). Audio and video receive frame events are triggered
 * from toxav thread while all the other events are triggered from tox thread.
 *
 * Tox thread has priority with mutex mechanisms. Any api function can
 * fail if mutexes are held by tox thread in which case they will set SYNC
 * error code.
 *
 * @subsection av_multi_threading Separate audio and video threads
 *
 * ToxAV supports either a single thread for audio and video or decoding and
 * encoding them in separate threads. You have to choose one mode and can not
 * mix function calls to those different modes.
 *
 * For best results use the multi-threaded mode and run the audio thread with
 * higher priority than the video thread. This prioritizes audio over video.
 */
#ifndef C_TOXCORE_TOXAV_TOXAV_H
#define C_TOXCORE_TOXAV_TOXAV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * External Tox type.
 */
#ifndef APIGEN_IGNORE
#ifndef TOX_DEFINED
#define TOX_DEFINED
typedef struct Tox Tox;
#endif /* !TOX_DEFINED */
#endif /* !APIGEN_IGNORE */

/**
 * @brief The ToxAV instance type.
 *
 * Each ToxAV instance can be bound to only one Tox instance, and Tox instance
 * can have only one ToxAV instance. One must make sure to close ToxAV instance
 * prior closing Tox instance otherwise undefined behaviour occurs. Upon
 * closing of ToxAV instance, all active calls will be forcibly terminated
 * without notifying peers.
 */
typedef struct ToxAV ToxAV;


/** @{
 * @brief Creation and destruction
 */

typedef enum Toxav_Err_New {

    /**
     * The function returned successfully.
     */
    TOXAV_ERR_NEW_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOXAV_ERR_NEW_NULL,

    /**
     * Memory allocation failure while trying to allocate structures required for
     * the A/V session.
     */
    TOXAV_ERR_NEW_MALLOC,

    /**
     * Attempted to create a second session for the same Tox instance.
     */
    TOXAV_ERR_NEW_MULTIPLE,

} Toxav_Err_New;


/**
 * Start new A/V session. There can only be only one session per Tox instance.
 */
ToxAV *toxav_new(Tox *tox, Toxav_Err_New *error);

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
Tox *toxav_get_tox(const ToxAV *av);

/** @} */


/** @{
 * @brief A/V event loop, single thread
 */

/**
 * Returns the interval in milliseconds when the next toxav_iterate call should
 * be. If no call is active at the moment, this function returns 200.
 * This function MUST be called from the same thread as toxav_iterate.
 */
uint32_t toxav_iteration_interval(const ToxAV *av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `toxav_iteration_interval()` milliseconds. It is best called in the separate
 * thread from tox_iterate.
 */
void toxav_iterate(ToxAV *av);

/** @} */


/** @{
 * @brief A/V event loop, multiple threads
 */

/**
 * Returns the interval in milliseconds when the next toxav_audio_iterate call
 * should be. If no call is active at the moment, this function returns 200.
 * This function MUST be called from the same thread as toxav_audio_iterate.
 */
uint32_t toxav_audio_iteration_interval(const ToxAV *av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `toxav_audio_iteration_interval()` milliseconds. It is best called in a
 * separate thread from tox_iterate and toxav_video_iterate. The thread calling
 * this function should have higher priority than the one calling
 * toxav_video_iterate to prioritize audio over video.
 */
void toxav_audio_iterate(ToxAV *av);

/**
 * Returns the interval in milliseconds when the next toxav_video_iterate call
 * should be. If no call is active at the moment, this function returns 200.
 * This function MUST be called from the same thread as toxav_video_iterate.
 */
uint32_t toxav_video_iteration_interval(const ToxAV *av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `toxav_video_iteration_interval()` milliseconds. It is best called in a
 * separate thread from tox_iterate and toxav_audio_iterate. The thread calling
 * this function should have lower priority than the one calling
 * toxav_audio_iterate to prioritize audio over video.
 */
void toxav_video_iterate(ToxAV *av);

/** @} */


/** @{
 * @brief Call setup
 */

typedef enum Toxav_Err_Call {

    /**
     * The function returned successfully.
     */
    TOXAV_ERR_CALL_OK,

    /**
     * A resource allocation error occurred while trying to create the structures
     * required for the call.
     */
    TOXAV_ERR_CALL_MALLOC,

    /**
     * Synchronization error occurred.
     */
    TOXAV_ERR_CALL_SYNC,

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
    TOXAV_ERR_CALL_INVALID_BIT_RATE,

} Toxav_Err_Call;


/**
 * Call a friend. This will start ringing the friend.
 *
 * It is the client's responsibility to stop ringing after a certain timeout,
 * if such behaviour is desired. If the client does not stop ringing, the
 * library will not stop until the friend is disconnected. Audio and video
 * receiving are both enabled by default.
 *
 * @param friend_number The friend number of the friend that should be called.
 * @param audio_bit_rate Audio bit rate in Kb/sec. Set this to 0 to disable
 * audio sending.
 * @param video_bit_rate Video bit rate in Kb/sec. Set this to 0 to disable
 * video sending.
 */
bool toxav_call(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                Toxav_Err_Call *error);

/**
 * The function type for the call callback.
 *
 * @param friend_number The friend number from which the call is incoming.
 * @param audio_enabled True if friend is sending audio.
 * @param video_enabled True if friend is sending video.
 */
typedef void toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data);


/**
 * Set the callback for the `call` event. Pass NULL to unset.
 *
 */
void toxav_callback_call(ToxAV *av, toxav_call_cb *callback, void *user_data);

typedef enum Toxav_Err_Answer {

    /**
     * The function returned successfully.
     */
    TOXAV_ERR_ANSWER_OK,

    /**
     * Synchronization error occurred.
     */
    TOXAV_ERR_ANSWER_SYNC,

    /**
     * Failed to initialize codecs for call session. Note that codec initiation
     * will fail if there is no receive callback registered for either audio or
     * video.
     */
    TOXAV_ERR_ANSWER_CODEC_INITIALIZATION,

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
    TOXAV_ERR_ANSWER_INVALID_BIT_RATE,

} Toxav_Err_Answer;


/**
 * Accept an incoming call.
 *
 * If answering fails for any reason, the call will still be pending and it is
 * possible to try and answer it later. Audio and video receiving are both
 * enabled by default.
 *
 * @param friend_number The friend number of the friend that is calling.
 * @param audio_bit_rate Audio bit rate in Kb/sec. Set this to 0 to disable
 * audio sending.
 * @param video_bit_rate Video bit rate in Kb/sec. Set this to 0 to disable
 * video sending.
 */
bool toxav_answer(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                  Toxav_Err_Answer *error);

/** @} */


/** @{
 * @brief Call state graph
 */

enum Toxav_Friend_Call_State {

    /**
     * The empty bit mask. None of the bits specified below are set.
     */
    TOXAV_FRIEND_CALL_STATE_NONE = 0,

    /**
     * Set by the AV core if an error occurred on the remote end or if friend
     * timed out. This is the final state after which no more state
     * transitions can occur for the call. This call state will never be triggered
     * in combination with other call states.
     */
    TOXAV_FRIEND_CALL_STATE_ERROR = 1,

    /**
     * The call has finished. This is the final state after which no more state
     * transitions can occur for the call. This call state will never be
     * triggered in combination with other call states.
     */
    TOXAV_FRIEND_CALL_STATE_FINISHED = 2,

    /**
     * The flag that marks that friend is sending audio.
     */
    TOXAV_FRIEND_CALL_STATE_SENDING_A = 4,

    /**
     * The flag that marks that friend is sending video.
     */
    TOXAV_FRIEND_CALL_STATE_SENDING_V = 8,

    /**
     * The flag that marks that friend is receiving audio.
     */
    TOXAV_FRIEND_CALL_STATE_ACCEPTING_A = 16,

    /**
     * The flag that marks that friend is receiving video.
     */
    TOXAV_FRIEND_CALL_STATE_ACCEPTING_V = 32,

};


/**
 * The function type for the call_state callback.
 *
 * @param friend_number The friend number for which the call state changed.
 * @param state The bitmask of the new call state which is guaranteed to be
 * different than the previous state. The state is set to 0 when the call is
 * paused. The bitmask represents all the activities currently performed by the
 * friend.
 */
typedef void toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data);


/**
 * Set the callback for the `call_state` event. Pass NULL to unset.
 *
 */
void toxav_callback_call_state(ToxAV *av, toxav_call_state_cb *callback, void *user_data);

/** @} */


/** @{
 * @brief Call control
 */

typedef enum Toxav_Call_Control {

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
     * compliance, this will cause the audio_receive_frame event to stop being
     * triggered on receiving an audio frame from the friend.
     */
    TOXAV_CALL_CONTROL_MUTE_AUDIO,

    /**
     * Calling this control will notify client to start sending audio again.
     */
    TOXAV_CALL_CONTROL_UNMUTE_AUDIO,

    /**
     * Request that the friend stops sending video. Regardless of the friend's
     * compliance, this will cause the video_receive_frame event to stop being
     * triggered on receiving a video frame from the friend.
     */
    TOXAV_CALL_CONTROL_HIDE_VIDEO,

    /**
     * Calling this control will notify client to start sending video again.
     */
    TOXAV_CALL_CONTROL_SHOW_VIDEO,

} Toxav_Call_Control;


typedef enum Toxav_Err_Call_Control {

    /**
     * The function returned successfully.
     */
    TOXAV_ERR_CALL_CONTROL_OK,

    /**
     * Synchronization error occurred.
     */
    TOXAV_ERR_CALL_CONTROL_SYNC,

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
     * Happens if user tried to pause an already paused call or if trying to
     * resume a call that is not paused.
     */
    TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION,

} Toxav_Err_Call_Control;


/**
 * Sends a call control command to a friend.
 *
 * @param friend_number The friend number of the friend this client is in a call
 * with.
 * @param control The control command to send.
 *
 * @return true on success.
 */
bool toxav_call_control(ToxAV *av, uint32_t friend_number, Toxav_Call_Control control, Toxav_Err_Call_Control *error);

/** @} */


/** @{
 * @brief Controlling bit rates
 */

typedef enum Toxav_Err_Bit_Rate_Set {

    /**
     * The function returned successfully.
     */
    TOXAV_ERR_BIT_RATE_SET_OK,

    /**
     * Synchronization error occurred.
     */
    TOXAV_ERR_BIT_RATE_SET_SYNC,

    /**
     * The bit rate passed was not one of the supported values.
     */
    TOXAV_ERR_BIT_RATE_SET_INVALID_BIT_RATE,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND,

    /**
     * This client is currently not in a call with the friend.
     */
    TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL,

} Toxav_Err_Bit_Rate_Set;

/** @} */



/** @{
 * @brief A/V sending
 */

typedef enum Toxav_Err_Send_Frame {

    /**
     * The function returned successfully.
     */
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
     * Synchronization error occurred.
     */
    TOXAV_ERR_SEND_FRAME_SYNC,

    /**
     * One of the frame parameters was invalid. E.g. the resolution may be too
     * small or too large, or the audio sampling rate may be unsupported.
     */
    TOXAV_ERR_SEND_FRAME_INVALID,

    /**
     * Either friend turned off audio or video receiving or we turned off sending
     * for the said payload.
     */
    TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED,

    /**
     * Failed to push frame through rtp interface.
     */
    TOXAV_ERR_SEND_FRAME_RTP_FAILED,

} Toxav_Err_Send_Frame;


/**
 * Send an audio frame to a friend.
 *
 * The expected format of the PCM data is: `[s1c1][s1c2][...][s2c1][s2c2][...]...`
 * Meaning: sample 1 for channel 1, sample 1 for channel 2, ...
 * For mono audio, this has no meaning, every sample is subsequent. For stereo,
 * this means the expected format is LRLRLR... with samples for left and right
 * alternating.
 *
 * @param friend_number The friend number of the friend to which to send an
 *   audio frame.
 * @param pcm An array of audio samples. The size of this array must be
 *   `sample_count * channels`.
 * @param sample_count Number of samples in this frame. Valid numbers here are
 *   `((sample rate) * (audio length) / 1000)`, where audio length can be
 *   2.5, 5, 10, 20, 40 or 60 millseconds.
 * @param channels Number of audio channels. Supported values are 1 and 2.
 * @param sampling_rate Audio sampling rate used in this frame. Valid sampling
 * rates are 8000, 12000, 16000, 24000, or 48000.
 */
bool toxav_audio_send_frame(ToxAV *av, uint32_t friend_number, const int16_t pcm[], size_t sample_count,
                            uint8_t channels, uint32_t sampling_rate, Toxav_Err_Send_Frame *error);

/**
 * Set the bit rate to be used in subsequent video frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 * bit rate.
 * @param bit_rate The new audio bit rate in Kb/sec. Set to 0 to disable.
 *
 * @return true on success.
 */
bool toxav_audio_set_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t bit_rate, Toxav_Err_Bit_Rate_Set *error);

/**
 * The function type for the audio_bit_rate callback. The event is triggered
 * when the network becomes too saturated for current bit rates at which
 * point core suggests new bit rates.
 *
 * @param friend_number The friend number of the friend for which to set the
 * bit rate.
 * @param audio_bit_rate Suggested maximum audio bit rate in Kb/sec.
 */
typedef void toxav_audio_bit_rate_cb(ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, void *user_data);


/**
 * Set the callback for the `audio_bit_rate` event. Pass NULL to unset.
 *
 */
void toxav_callback_audio_bit_rate(ToxAV *av, toxav_audio_bit_rate_cb *callback, void *user_data);

/**
 * Send a video frame to a friend.
 *
 * Y - plane should be of size: `height * width`
 * U - plane should be of size: `(height/2) * (width/2)`
 * V - plane should be of size: `(height/2) * (width/2)`
 *
 * @param friend_number The friend number of the friend to which to send a video
 * frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y Y (Luminance) plane data.
 * @param u U (Chroma) plane data.
 * @param v V (Chroma) plane data.
 */
bool toxav_video_send_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height, const uint8_t y[],
                            const uint8_t u[], const uint8_t v[], Toxav_Err_Send_Frame *error);

/**
 * Set the bit rate to be used in subsequent video frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 * bit rate.
 * @param bit_rate The new video bit rate in Kb/sec. Set to 0 to disable.
 *
 * @return true on success.
 */
bool toxav_video_set_bit_rate(ToxAV *av, uint32_t friend_number, uint32_t bit_rate, Toxav_Err_Bit_Rate_Set *error);

/**
 * The function type for the video_bit_rate callback. The event is triggered
 * when the network becomes too saturated for current bit rates at which
 * point core suggests new bit rates.
 *
 * @param friend_number The friend number of the friend for which to set the
 * bit rate.
 * @param video_bit_rate Suggested maximum video bit rate in Kb/sec.
 */
typedef void toxav_video_bit_rate_cb(ToxAV *av, uint32_t friend_number, uint32_t video_bit_rate, void *user_data);


/**
 * Set the callback for the `video_bit_rate` event. Pass NULL to unset.
 *
 */
void toxav_callback_video_bit_rate(ToxAV *av, toxav_video_bit_rate_cb *callback, void *user_data);

/** @} */


/** @{
 * @brief A/V receiving
 */

/**
 * The function type for the audio_receive_frame callback. The callback can be
 * called multiple times per single iteration depending on the amount of queued
 * frames in the buffer. The received format is the same as in send function.
 *
 * @param friend_number The friend number of the friend who sent an audio frame.
 * @param pcm An array of audio samples (`sample_count * channels` elements).
 * @param sample_count The number of audio samples per channel in the PCM array.
 * @param channels Number of audio channels.
 * @param sampling_rate Sampling rate used in this frame.
 *
 */
typedef void toxav_audio_receive_frame_cb(ToxAV *av, uint32_t friend_number, const int16_t pcm[], size_t sample_count,
        uint8_t channels, uint32_t sampling_rate, void *user_data);


/**
 * Set the callback for the `audio_receive_frame` event. Pass NULL to unset.
 *
 */
void toxav_callback_audio_receive_frame(ToxAV *av, toxav_audio_receive_frame_cb *callback, void *user_data);

/**
 * The function type for the video_receive_frame callback.
 *
 * The size of plane data is derived from width and height as documented
 * below.
 *
 * Strides represent padding for each plane that may or may not be present.
 * You must handle strides in your image processing code. Strides are
 * negative if the image is bottom-up hence why you MUST `abs()` it when
 * calculating plane buffer size.
 *
 * @param friend_number The friend number of the friend who sent a video frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y Luminosity plane. `Size = MAX(width, abs(ystride)) * height`.
 * @param u U chroma plane. `Size = MAX(width/2, abs(ustride)) * (height/2)`.
 * @param v V chroma plane. `Size = MAX(width/2, abs(vstride)) * (height/2)`.
 *
 * @param ystride Luminosity plane stride.
 * @param ustride U chroma plane stride.
 * @param vstride V chroma plane stride.
 */
typedef void toxav_video_receive_frame_cb(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
        const uint8_t y[], const uint8_t u[], const uint8_t v[], int32_t ystride, int32_t ustride, int32_t vstride,
        void *user_data);


/**
 * Set the callback for the `video_receive_frame` event. Pass NULL to unset.
 *
 */
void toxav_callback_video_receive_frame(ToxAV *av, toxav_video_receive_frame_cb *callback, void *user_data);

#ifndef APIGEN_IGNORE

/***
 * NOTE Compatibility with old toxav group calls. TODO(iphydf): remove
 *
 * TODO(iphydf): Use proper new API guidelines for these. E.g. don't use inline
 * function types, don't have per-callback userdata, especially don't have one
 * userdata per group.
 */

// TODO(iphydf): Use this better typed one instead of the void-pointer one below.
typedef void toxav_group_audio_cb(Tox *tox, uint32_t groupnumber, uint32_t peernumber, const int16_t pcm[],
                                  uint32_t samples, uint8_t channels, uint32_t sample_rate, void *user_data);

typedef void toxav_audio_data_cb(void *tox, uint32_t groupnumber, uint32_t peernumber, const int16_t pcm[],
                                 uint32_t samples, uint8_t channels, uint32_t sample_rate, void *userdata);

/** @brief Create a new toxav group.
 *
 * @return group number on success.
 * @retval -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to `samples * channels * sizeof(int16_t)`.
 */
int32_t toxav_add_av_groupchat(Tox *tox, toxav_audio_data_cb *audio_callback, void *userdata);

/** @brief Join a AV group (you need to have been invited first).
 *
 * @return group number on success.
 * @retval -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to `samples * channels * sizeof(int16_t)`.
 */
int32_t toxav_join_av_groupchat(
        Tox *tox, uint32_t friendnumber, const uint8_t data[], uint16_t length,
        toxav_audio_data_cb *audio_callback, void *userdata);

/** @brief Send audio to the group chat.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to `samples * channels * sizeof(int16_t)`.
 *
 * Valid number of samples are `(sample rate) * (audio length) / 1000`
 *   (Valid values for audio length are: 2.5, 5, 10, 20, 40 or 60 ms)
 * Valid number of channels are 1 or 2.
 * Valid sample rates are 8000, 12000, 16000, 24000, or 48000.
 *
 * Recommended values are: samples = 960, channels = 1, sample_rate = 48000
 */
int32_t toxav_group_send_audio(
        Tox *tox, uint32_t groupnumber, const int16_t pcm[], uint32_t samples, uint8_t channels,
        uint32_t sample_rate);

/** @brief Enable A/V in a groupchat.
 *
 * A/V must be enabled on a groupchat for audio to be sent to it and for
 * received audio to be handled.
 *
 * An A/V group created with `toxav_add_av_groupchat` or `toxav_join_av_groupchat`
 * will start with A/V enabled.
 *
 * An A/V group loaded from a savefile will start with A/V disabled.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 *
 * Note that total size of pcm in bytes is equal to `samples * channels * sizeof(int16_t)`.
 */
int32_t toxav_groupchat_enable_av(
        Tox *tox, uint32_t groupnumber,
        toxav_audio_data_cb *audio_callback, void *userdata);

/** @brief Disable A/V in a groupchat.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int32_t toxav_groupchat_disable_av(Tox *tox, uint32_t groupnumber);

/** @brief Return whether A/V is enabled in the groupchat. */
bool toxav_groupchat_av_enabled(Tox *tox, uint32_t groupnumber);

#endif /* !APIGEN_IGNORE */

/** @} */

#ifdef __cplusplus
}
#endif

//!TOKSTYLE-
#ifndef DOXYGEN_IGNORE

typedef Toxav_Err_Call TOXAV_ERR_CALL;
typedef Toxav_Err_New TOXAV_ERR_NEW;
typedef Toxav_Err_Answer TOXAV_ERR_ANSWER;
typedef Toxav_Err_Call_Control TOXAV_ERR_CALL_CONTROL;
typedef Toxav_Err_Bit_Rate_Set TOXAV_ERR_BIT_RATE_SET;
typedef Toxav_Err_Send_Frame TOXAV_ERR_SEND_FRAME;
typedef Toxav_Call_Control TOXAV_CALL_CONTROL;
typedef enum Toxav_Friend_Call_State TOXAV_FRIEND_CALL_STATE;

#endif
//!TOKSTYLE+

#endif // C_TOXCORE_TOXAV_TOXAV_H
