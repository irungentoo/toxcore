/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "audio.h"

#include <assert.h>
#include <opus.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "rtp.h"

#include "../toxcore/attributes.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/util.h"


struct ACSession {
    Mono_Time *_Nonnull mono_time;
    const Logger *_Nonnull log;

    /* encoding */
    OpusEncoder *_Nullable encoder;
    uint32_t le_sample_rate; /* Last encoder sample rate */
    uint8_t le_channel_count; /* Last encoder channel count */
    uint32_t le_bit_rate; /* Last encoder bit rate */

    /* decoding */
    OpusDecoder *_Nullable decoder;
    uint8_t lp_channel_count; /* Last packet channel count */
    uint32_t lp_sampling_rate; /* Last packet sample rate */
    uint32_t lp_frame_duration; /* Last packet frame duration */
    uint32_t ld_sample_rate; /* Last decoder sample rate */
    uint8_t ld_channel_count; /* Last decoder channel count */
    uint64_t ldrts; /* Last decoder reconfiguration time stamp */
    void *_Nullable j_buf;

    pthread_mutex_t queue_mutex[1];

    int16_t *_Nullable decode_buffer;

    uint32_t friend_number;
    /* Audio frame receive callback */
    ac_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable user_data;
};


static struct JitterBuffer *_Nullable jbuf_new(uint32_t capacity);
static void jbuf_clear(struct JitterBuffer *_Nonnull q);
static void jbuf_free(struct JitterBuffer *_Nullable q);
static int jbuf_write(const Logger *_Nonnull log, struct JitterBuffer *_Nonnull q, struct RTPMessage *_Nonnull m);
static struct RTPMessage *_Nullable jbuf_read(struct JitterBuffer *_Nonnull q, int32_t *_Nonnull success);
static OpusEncoder *_Nullable create_audio_encoder(const Logger *_Nonnull log, uint32_t bit_rate, uint32_t sampling_rate,
        uint8_t channel_count);
static bool reconfigure_audio_encoder(const Logger *_Nonnull log, OpusEncoder *_Nonnull *_Nonnull e, uint32_t new_br, uint32_t new_sr,
                                      uint8_t new_ch, uint32_t *_Nonnull old_br, uint32_t *_Nonnull old_sr, uint8_t *_Nonnull old_ch);
static bool reconfigure_audio_decoder(ACSession *_Nonnull ac, uint32_t sampling_rate, uint8_t channels);



ACSession *ac_new(Mono_Time *mono_time, const Logger *log, uint32_t friend_number,
                  ac_audio_receive_frame_cb *cb, void *user_data)
{
    ACSession *ac = (ACSession *)calloc(1, sizeof(ACSession));

    if (ac == nullptr) {
        LOGGER_WARNING(log, "Allocation failed! Application might misbehave!");
        return nullptr;
    }

    if (create_recursive_mutex(ac->queue_mutex) != 0) {
        LOGGER_WARNING(log, "Failed to create recursive mutex!");
        free(ac);
        return nullptr;
    }

    int status;
    ac->decoder = opus_decoder_create(AUDIO_DECODER_START_SAMPLE_RATE, AUDIO_DECODER_START_CHANNEL_COUNT, &status);

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while starting audio decoder: %s", opus_strerror(status));
        goto BASE_CLEANUP;
    }

    ac->j_buf = jbuf_new(AUDIO_JITTERBUFFER_COUNT);

    if (ac->j_buf == nullptr) {
        LOGGER_WARNING(log, "Jitter buffer creaton failed!");
        opus_decoder_destroy(ac->decoder);
        goto BASE_CLEANUP;
    }

    ac->mono_time = mono_time;
    ac->log = log;

    ac->decode_buffer = (int16_t *)malloc(AUDIO_MAX_BUFFER_SIZE_PCM16 * AUDIO_MAX_CHANNEL_COUNT * sizeof(int16_t));

    if (ac->decode_buffer == nullptr) {
        LOGGER_ERROR(log, "Failed to allocate memory for audio buffer");
        goto DECODER_CLEANUP;
    }

    /* Initialize encoders with default values */
    ac->encoder = create_audio_encoder(log, AUDIO_START_BITRATE, AUDIO_START_SAMPLE_RATE, AUDIO_START_CHANNEL_COUNT);

    if (ac->encoder == nullptr) {
        goto DECODER_CLEANUP;
    }

    ac->le_bit_rate = AUDIO_START_BITRATE;
    ac->le_sample_rate = AUDIO_START_SAMPLE_RATE;
    ac->le_channel_count = AUDIO_START_CHANNEL_COUNT;

    ac->ld_channel_count = AUDIO_DECODER_START_CHANNEL_COUNT;
    ac->ld_sample_rate = AUDIO_DECODER_START_SAMPLE_RATE;
    ac->ldrts = 0; /* Make it possible to reconfigure straight away */

    /* These need to be set in order to properly
     * do error correction with opus */
    ac->lp_frame_duration = AUDIO_MAX_FRAME_DURATION_MS;
    ac->lp_sampling_rate = AUDIO_DECODER_START_SAMPLE_RATE;
    ac->lp_channel_count = AUDIO_DECODER_START_CHANNEL_COUNT;

    ac->friend_number = friend_number;
    ac->acb = cb;
    ac->user_data = user_data;

    return ac;

DECODER_CLEANUP:
    free(ac->decode_buffer);
    opus_decoder_destroy(ac->decoder);
    jbuf_free((struct JitterBuffer *)ac->j_buf);
BASE_CLEANUP:
    pthread_mutex_destroy(ac->queue_mutex);
    free(ac);
    return nullptr;
}

void ac_kill(ACSession *ac)
{
    if (ac == nullptr) {
        return;
    }

    opus_encoder_destroy(ac->encoder);
    opus_decoder_destroy(ac->decoder);
    jbuf_free((struct JitterBuffer *)ac->j_buf);
    free(ac->decode_buffer);

    pthread_mutex_destroy(ac->queue_mutex);

    LOGGER_DEBUG(ac->log, "Terminated audio handler: %p", (void *)ac);
    free(ac);
}

void ac_iterate(ACSession *ac)
{
    if (ac == nullptr) {
        return;
    }

    /* TODO: fix this and jitter buffering */

    int rc = 0;

    pthread_mutex_lock(ac->queue_mutex);

    while (true) {
        struct JitterBuffer *const j_buf = (struct JitterBuffer *)ac->j_buf;
        struct RTPMessage *msg = jbuf_read(j_buf, &rc);

        if (msg == nullptr && rc != 2) {
            break;
        }

        pthread_mutex_unlock(ac->queue_mutex);

        if (rc == 2) {
            /* Packet Loss Concealment (PLC) */
            LOGGER_DEBUG(ac->log, "OPUS correction");

            /* Use safe defaults or last known good values */
            const uint32_t sampling_rate = ac->lp_sampling_rate;
            const uint32_t frame_duration = ac->lp_frame_duration;

            if (sampling_rate == 0 || sampling_rate > AUDIO_MAX_SAMPLE_RATE || frame_duration > AUDIO_MAX_FRAME_DURATION_MS) {
                LOGGER_WARNING(ac->log, "Invalid PLC parameters: sr %u, dur %u", sampling_rate, frame_duration);
            } else {
                const int fs = (sampling_rate * frame_duration) / 1000;
                rc = opus_decode(ac->decoder, nullptr, 0, ac->decode_buffer, fs, 1);
            }
        } else {
            const uint8_t *msg_data = rtp_message_data(msg);
            const uint32_t msg_length = rtp_message_len(msg);

            if (msg_length <= 4) {
                LOGGER_WARNING(ac->log, "Packet too short: %u", msg_length);
                free(msg);
                pthread_mutex_lock(ac->queue_mutex);
                continue;
            }

            /* Pick up sampling rate from packet */
            uint32_t sampling_rate;
            memcpy(&sampling_rate, msg_data, 4);
            sampling_rate = net_ntohl(sampling_rate);

            const int channels = opus_packet_get_nb_channels(msg_data + 4);

            if (channels < 1 || channels > AUDIO_MAX_CHANNEL_COUNT ||
                    sampling_rate == 0 || sampling_rate > AUDIO_MAX_SAMPLE_RATE) {
                LOGGER_WARNING(ac->log, "Invalid packet parameters: sr %u, cc %d", sampling_rate, channels);
                free(msg);
                pthread_mutex_lock(ac->queue_mutex);
                continue;
            }

            /** NOTE: even though OPUS supports decoding mono frames with stereo decoder and vice versa,
              * it didn't work quite well.
              */
            if (!reconfigure_audio_decoder(ac, sampling_rate, (uint8_t)channels)) {
                LOGGER_WARNING(ac->log, "Failed to reconfigure decoder!");
                free(msg);
                pthread_mutex_lock(ac->queue_mutex);
                continue;
            }

            ac->lp_sampling_rate = sampling_rate;
            ac->lp_channel_count = (uint8_t)channels;

            /*
             * frame_size = opus_decode(dec, packet, len, decoded, max_size, 0);
             *   where
             * packet is the byte array containing the compressed data
             * len is the exact number of bytes contained in the packet
             * decoded is the decoded audio data in opus_int16 (or float for opus_decode_float())
             * max_size is the max duration of the frame in samples (per channel) that can fit
             * into the decoded_frame array
             */
            rc = opus_decode(ac->decoder, msg_data + 4, msg_length - 4, ac->decode_buffer, AUDIO_MAX_BUFFER_SIZE_PCM16, 0);
            free(msg);
        }

        if (rc < 0) {
            LOGGER_WARNING(ac->log, "Decoding error: %s", opus_strerror(rc));
        } else if (ac->acb != nullptr && ac->lp_sampling_rate != 0) {
            ac->lp_frame_duration = (rc * 1000) / ac->lp_sampling_rate;

            ac->acb(ac->friend_number, ac->decode_buffer, (size_t)rc, ac->lp_channel_count,
                    ac->lp_sampling_rate, ac->user_data);
        }

        pthread_mutex_lock(ac->queue_mutex);
    }

    pthread_mutex_unlock(ac->queue_mutex);
}

int ac_queue_message(const Mono_Time *mono_time, void *cs, struct RTPMessage *msg)
{
    ACSession *ac = (ACSession *)cs;

    if (ac == nullptr || msg == nullptr) {
        free(msg);
        return -1;
    }

    if ((rtp_message_pt(msg) & 0x7f) == (RTP_TYPE_AUDIO + 2) % 128) {
        LOGGER_WARNING(ac->log, "Got dummy!");
        free(msg);
        return 0;
    }

    if ((rtp_message_pt(msg) & 0x7f) != RTP_TYPE_AUDIO % 128) {
        LOGGER_WARNING(ac->log, "Invalid payload type!");
        free(msg);
        return -1;
    }

    pthread_mutex_lock(ac->queue_mutex);
    const int rc = jbuf_write(ac->log, (struct JitterBuffer *)ac->j_buf, msg);
    pthread_mutex_unlock(ac->queue_mutex);

    if (rc == -1) {
        LOGGER_WARNING(ac->log, "Could not queue the message!");
        free(msg);
        return -1;
    }

    return 0;
}

int ac_reconfigure_encoder(ACSession *ac, uint32_t bit_rate, uint32_t sampling_rate, uint8_t channels)
{
    if (ac == nullptr || !reconfigure_audio_encoder(
                ac->log, &ac->encoder, bit_rate,
                sampling_rate, channels,
                &ac->le_bit_rate,
                &ac->le_sample_rate,
                &ac->le_channel_count)) {
        return -1;
    }

    return 0;
}

uint32_t ac_get_lp_frame_duration(const ACSession *ac)
{
    return ac->lp_frame_duration;
}

int ac_encode(ACSession *ac, const int16_t *pcm, size_t sample_count, uint8_t *dest, size_t dest_max)
{
    const int vrc = opus_encode(ac->encoder, pcm, (int)sample_count, dest, (int)dest_max);

    if (vrc < 0) {
        LOGGER_WARNING(ac->log, "Failed to encode frame %s", opus_strerror(vrc));
    }

    return vrc;
}

struct JitterBuffer {
    struct RTPMessage *_Nullable *_Nonnull queue;
    uint32_t size;
    uint32_t capacity;
    uint16_t bottom;
    uint16_t top;
};

static struct JitterBuffer *jbuf_new(uint32_t capacity)
{
    unsigned int size = 1;

    while (size <= (capacity * 4)) {
        size *= 2;
    }

    struct JitterBuffer *q = (struct JitterBuffer *)calloc(1, sizeof(struct JitterBuffer));

    if (q == nullptr) {
        return nullptr;
    }

    q->queue = (struct RTPMessage **)calloc(size, sizeof(struct RTPMessage *));

    if (q->queue == nullptr) {
        free(q);
        return nullptr;
    }

    q->size = size;
    q->capacity = capacity;
    return q;
}

static void jbuf_clear(struct JitterBuffer *q)
{
    while (q->bottom != q->top) {
        free(q->queue[q->bottom % q->size]);
        q->queue[q->bottom % q->size] = nullptr;
        ++q->bottom;
    }
}

static void jbuf_free(struct JitterBuffer *q)
{
    if (q == nullptr) {
        return;
    }

    jbuf_clear(q);
    free(q->queue);
    free(q);
}

/*
 * if -1 is returned the RTPMessage m needs to be free'd by the caller
 * if  0 is returned the RTPMessage m is stored in the ringbuffer and must NOT be freed by the caller
 */
static int jbuf_write(const Logger *log, struct JitterBuffer *q, struct RTPMessage *m)
{
    const uint16_t sequnum = rtp_message_sequnum(m);

    const unsigned int num = sequnum % q->size;

    const int16_t diff = (int16_t)(sequnum - q->bottom);

    if (diff < 0) {
        return -1;
    }

    if (diff > (int32_t)q->size) {
        LOGGER_DEBUG(log, "Clearing filled jitter buffer: %p", (void *)q);

        jbuf_clear(q);
        q->bottom = sequnum - q->capacity;
        q->queue[num] = m;
        q->top = sequnum + 1;
        return 0;
    }

    if (q->queue[num] != nullptr) {
        return -1;
    }

    q->queue[num] = m;

    if ((sequnum - q->bottom) >= (q->top - q->bottom)) {
        q->top = sequnum + 1;
    }

    return 0;
}

static struct RTPMessage *jbuf_read(struct JitterBuffer *q, int32_t *success)
{
    if (q->top == q->bottom) {
        *success = 0;
        return nullptr;
    }

    const unsigned int num = q->bottom % q->size;

    if (q->queue[num] != nullptr) {
        struct RTPMessage *ret = q->queue[num];
        q->queue[num] = nullptr;
        ++q->bottom;
        *success = 1;
        return ret;
    }

    if ((uint16_t)(q->top - q->bottom) > q->capacity) {
        ++q->bottom;
        *success = 2;
        return nullptr;
    }

    *success = 0;
    return nullptr;
}
static OpusEncoder *create_audio_encoder(const Logger *log, uint32_t bit_rate, uint32_t sampling_rate,
        uint8_t channel_count)
{
    int status = OPUS_OK;
    /*
     * OPUS_APPLICATION_VOIP Process signal for improved speech intelligibility
     * OPUS_APPLICATION_AUDIO Favor faithfulness to the original input
     * OPUS_APPLICATION_RESTRICTED_LOWDELAY Configure the minimum possible coding delay
     */
    OpusEncoder *rc = opus_encoder_create(sampling_rate, channel_count, OPUS_APPLICATION_VOIP, &status);

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while starting audio encoder: %s", opus_strerror(status));
        return nullptr;
    }

    /*
     * Rates from 500 to 512000 bits per second are meaningful as well as the special
     * values OPUS_BITRATE_AUTO and OPUS_BITRATE_MAX. The value OPUS_BITRATE_MAX can
     * be used to cause the codec to use as much rate as it can, which is useful for
     * controlling the rate by adjusting the output buffer size.
     *
     * Parameters:
     *   `[in]`    `x`   `opus_int32`: bitrate in bits per second.
     */
    status = opus_encoder_ctl(rc, OPUS_SET_BITRATE(bit_rate));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /*
     * The libopus library defaults to VBR, which is unsafe in any VoIP environment
     * (see for example doi:10.1109/SP.2011.34). Switching to CBR very slightly
     * decreases audio quality at lower bitrates.
     *
     * Parameters:
     *  `[in]`    `x`   `opus_int32`: Whether to use VBR mode, 1 (VBR) is default
     */
    status = opus_encoder_ctl(rc, OPUS_SET_VBR(0));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /*
     * Configures the encoder's use of inband forward error correction.
     * Note:
     *   This is only applicable to the LPC layer
     * Parameters:
     *   `[in]`    `x`   `int`: FEC flag, 0 (disabled) is default
     */
    /* Enable in-band forward error correction in codec */
    status = opus_encoder_ctl(rc, OPUS_SET_INBAND_FEC(1));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /*
     * Configures the encoder's expected packet loss percentage.
     * Higher values with trigger progressively more loss resistant behavior in
     * the encoder at the expense of quality at a given bitrate in the lossless case,
     * but greater quality under loss.
     * Parameters:
     *     `[in]`    `x`   `int`: Loss percentage in the range 0-100, inclusive.
     */
    /* Make codec resistant to up to 10% packet loss
     * NOTE This could also be adjusted on the fly, rather than hard-coded,
     *      with feedback from the receiving client.
     */
    status = opus_encoder_ctl(rc, OPUS_SET_PACKET_LOSS_PERC(AUDIO_OPUS_PACKET_LOSS_PERC));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /*
     * Configures the encoder's computational complexity.
     *
     * The supported range is 0-10 inclusive with 10 representing the highest complexity.
     * The default value is 10.
     *
     * Parameters:
     *   `[in]`    `x`   `int`: 0-10, inclusive
     */
    /* Set algorithm to the highest complexity, maximizing compression */
    status = opus_encoder_ctl(rc, OPUS_SET_COMPLEXITY(AUDIO_OPUS_COMPLEXITY));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    return rc;

FAILURE:
    opus_encoder_destroy(rc);
    return nullptr;
}

static bool reconfigure_audio_encoder(const Logger *log, OpusEncoder **e, uint32_t new_br, uint32_t new_sr,
                                      uint8_t new_ch, uint32_t *old_br, uint32_t *old_sr, uint8_t *old_ch)
{
    /* Values are checked in toxav.c */
    if (*old_sr != new_sr || *old_ch != new_ch) {
        OpusEncoder *new_encoder = create_audio_encoder(log, new_br, new_sr, new_ch);

        if (new_encoder == nullptr) {
            return false;
        }

        opus_encoder_destroy(*e);
        *e = new_encoder;
    } else if (*old_br == new_br) {
        return true; /* Nothing changed */
    }

    const int status = opus_encoder_ctl(*e, OPUS_SET_BITRATE(new_br));

    if (status != OPUS_OK) {
        LOGGER_ERROR(log, "Error while setting encoder ctl: %s", opus_strerror(status));
        return false;
    }

    *old_br = new_br;
    *old_sr = new_sr;
    *old_ch = new_ch;

    LOGGER_DEBUG(log, "Reconfigured audio encoder br: %u sr: %u cc:%d", new_br, new_sr, new_ch);
    return true;
}

static bool reconfigure_audio_decoder(ACSession *ac, uint32_t sampling_rate, uint8_t channels)
{
    if (sampling_rate != ac->ld_sample_rate || channels != ac->ld_channel_count) {
        if (current_time_monotonic(ac->mono_time) - ac->ldrts < 500) {
            return false;
        }

        int status;
        OpusDecoder *new_dec = opus_decoder_create(sampling_rate, channels, &status);

        if (status != OPUS_OK) {
            LOGGER_ERROR(ac->log, "Error while starting audio decoder(%u %u): %s", sampling_rate, channels, opus_strerror(status));
            return false;
        }

        ac->ld_sample_rate = sampling_rate;
        ac->ld_channel_count = channels;
        ac->ldrts = current_time_monotonic(ac->mono_time);

        opus_decoder_destroy(ac->decoder);
        ac->decoder = new_dec;

        LOGGER_DEBUG(ac->log, "Reconfigured audio decoder sr: %u cc: %u", sampling_rate, channels);
    }

    return true;
}
