/**  audio.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>

#include "audio.h"
#include "rtp.h"

#include "../toxcore/logger.h"

static struct JitterBuffer *jbuf_new(uint32_t capacity);
static void jbuf_clear(struct JitterBuffer *q);
static void jbuf_free(struct JitterBuffer *q);
static int jbuf_write(struct JitterBuffer *q, struct RTPMessage *m);
static struct RTPMessage *jbuf_read(struct JitterBuffer *q, int32_t *success);
OpusEncoder *create_audio_encoder (int32_t bit_rate, int32_t sampling_rate, int32_t channel_count);
bool reconfigure_audio_encoder(OpusEncoder **e, int32_t new_br, int32_t new_sr, uint8_t new_ch,
                               int32_t *old_br, int32_t *old_sr, int32_t *old_ch);
bool reconfigure_audio_decoder(ACSession *ac, int32_t sampling_rate, int8_t channels);



ACSession *ac_new(ToxAV *av, uint32_t friend_number, toxav_audio_receive_frame_cb *cb, void *cb_data)
{
    ACSession *ac = calloc(sizeof(ACSession), 1);

    if (!ac) {
        LOGGER_WARNING("Allocation failed! Application might misbehave!");
        return NULL;
    }

    if (create_recursive_mutex(ac->queue_mutex) != 0) {
        LOGGER_WARNING("Failed to create recursive mutex!");
        free(ac);
        return NULL;
    }

    int status;
    ac->decoder = opus_decoder_create(48000, 2, &status);

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while starting audio decoder: %s", opus_strerror(status));
        goto BASE_CLEANUP;
    }

    if (!(ac->j_buf = jbuf_new(3))) {
        LOGGER_WARNING("Jitter buffer creaton failed!");
        opus_decoder_destroy(ac->decoder);
        goto BASE_CLEANUP;
    }

    /* Initialize encoders with default values */
    ac->encoder = create_audio_encoder(48000, 48000, 2);

    if (ac->encoder == NULL)
        goto DECODER_CLEANUP;

    ac->le_bit_rate = 48000;
    ac->le_sample_rate = 48000;
    ac->le_channel_count = 2;

    ac->ld_channel_count = 2;
    ac->ld_sample_rate = 48000;
    ac->ldrts = 0; /* Make it possible to reconfigure straight away */

    /* These need to be set in order to properly
     * do error correction with opus */
    ac->lp_frame_duration = 120;
    ac->lp_sampling_rate = 48000;
    ac->lp_channel_count = 1;

    ac->av = av;
    ac->friend_number = friend_number;
    ac->acb.first = cb;
    ac->acb.second = cb_data;

    return ac;

DECODER_CLEANUP:
    opus_decoder_destroy(ac->decoder);
    jbuf_free(ac->j_buf);
BASE_CLEANUP:
    pthread_mutex_destroy(ac->queue_mutex);
    free(ac);
    return NULL;
}
void ac_kill(ACSession *ac)
{
    if (!ac)
        return;

    opus_encoder_destroy(ac->encoder);
    opus_decoder_destroy(ac->decoder);
    jbuf_free(ac->j_buf);

    pthread_mutex_destroy(ac->queue_mutex);

    LOGGER_DEBUG("Terminated audio handler: %p", ac);
    free(ac);
}
void ac_iterate(ACSession *ac)
{
    if (!ac)
        return;

    /* TODO fix this and jitter buffering */

    /* Enough space for the maximum frame size (120 ms 48 KHz stereo audio) */
    int16_t tmp[5760 * 2];

    struct RTPMessage *msg;
    int rc = 0;

    pthread_mutex_lock(ac->queue_mutex);

    while ((msg = jbuf_read(ac->j_buf, &rc)) || rc == 2) {
        pthread_mutex_unlock(ac->queue_mutex);

        if (rc == 2) {
            LOGGER_DEBUG("OPUS correction");
            int fs = (ac->lp_sampling_rate * ac->lp_frame_duration) / 1000;
            rc = opus_decode(ac->decoder, NULL, 0, tmp, fs, 1);
        } else {
            /* Get values from packet and decode. */
            /* NOTE: This didn't work very well
            rc = convert_bw_to_sampling_rate(opus_packet_get_bandwidth(msg->data));
            if (rc != -1) {
                cs->last_packet_sampling_rate = rc;
            } else {
                LOGGER_WARNING("Failed to load packet values!");
                rtp_free_msg(msg);
                continue;
            }*/


            /* Pick up sampling rate from packet */
            memcpy(&ac->lp_sampling_rate, msg->data, 4);
            ac->lp_sampling_rate = ntohl(ac->lp_sampling_rate);

            ac->lp_channel_count = opus_packet_get_nb_channels(msg->data + 4);

            /** NOTE: even though OPUS supports decoding mono frames with stereo decoder and vice versa,
              * it didn't work quite well.
              */
            if (!reconfigure_audio_decoder(ac, ac->lp_sampling_rate, ac->lp_channel_count)) {
                LOGGER_WARNING("Failed to reconfigure decoder!");
                free(msg);
                continue;
            }

            rc = opus_decode(ac->decoder, msg->data + 4, msg->len - 4, tmp, 5760, 0);
            free(msg);
        }

        if (rc < 0) {
            LOGGER_WARNING("Decoding error: %s", opus_strerror(rc));
        } else if (ac->acb.first) {
            ac->lp_frame_duration = (rc * 1000) / ac->lp_sampling_rate;

            ac->acb.first(ac->av, ac->friend_number, tmp, rc, ac->lp_channel_count,
                          ac->lp_sampling_rate, ac->acb.second);
        }

        return;
    }

    pthread_mutex_unlock(ac->queue_mutex);
}
int ac_queue_message(void *acp, struct RTPMessage *msg)
{
    if (!acp || !msg)
        return -1;

    if ((msg->header.pt & 0x7f) == (rtp_TypeAudio + 2) % 128) {
        LOGGER_WARNING("Got dummy!");
        free(msg);
        return 0;
    }

    if ((msg->header.pt & 0x7f) != rtp_TypeAudio % 128) {
        LOGGER_WARNING("Invalid payload type!");
        free(msg);
        return -1;
    }

    ACSession *ac = acp;

    pthread_mutex_lock(ac->queue_mutex);
    int rc = jbuf_write(ac->j_buf, msg);
    pthread_mutex_unlock(ac->queue_mutex);

    if (rc == -1) {
        LOGGER_WARNING("Could not queue the message!");
        free(msg);
        return -1;
    }

    return 0;
}
int ac_reconfigure_encoder(ACSession *ac, int32_t bit_rate, int32_t sampling_rate, uint8_t channels)
{
    if (!ac || !reconfigure_audio_encoder(&ac->encoder, bit_rate,
                                          sampling_rate, channels,
                                          &ac->le_bit_rate,
                                          &ac->le_sample_rate,
                                          &ac->le_channel_count))
        return -1;

    return 0;
}



struct JitterBuffer {
    struct RTPMessage **queue;
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

    struct JitterBuffer *q;

    if (!(q = calloc(sizeof(struct JitterBuffer), 1))) return NULL;

    if (!(q->queue = calloc(sizeof(struct RTPMessage *), size))) {
        free(q);
        return NULL;
    }

    q->size = size;
    q->capacity = capacity;
    return q;
}
static void jbuf_clear(struct JitterBuffer *q)
{
    for (; q->bottom != q->top; ++q->bottom) {
        if (q->queue[q->bottom % q->size]) {
            free(q->queue[q->bottom % q->size]);
            q->queue[q->bottom % q->size] = NULL;
        }
    }
}
static void jbuf_free(struct JitterBuffer *q)
{
    if (!q) return;

    jbuf_clear(q);
    free(q->queue);
    free(q);
}
static int jbuf_write(struct JitterBuffer *q, struct RTPMessage *m)
{
    uint16_t sequnum = m->header.sequnum;

    unsigned int num = sequnum % q->size;

    if ((uint32_t)(sequnum - q->bottom) > q->size) {
        LOGGER_DEBUG("Clearing filled jitter buffer: %p", q);

        jbuf_clear(q);
        q->bottom = sequnum - q->capacity;
        q->queue[num] = m;
        q->top = sequnum + 1;
        return 0;
    }

    if (q->queue[num])
        return -1;

    q->queue[num] = m;

    if ((sequnum - q->bottom) >= (q->top - q->bottom))
        q->top = sequnum + 1;

    return 0;
}
static struct RTPMessage *jbuf_read(struct JitterBuffer *q, int32_t *success)
{
    if (q->top == q->bottom) {
        *success = 0;
        return NULL;
    }

    unsigned int num = q->bottom % q->size;

    if (q->queue[num]) {
        struct RTPMessage *ret = q->queue[num];
        q->queue[num] = NULL;
        ++q->bottom;
        *success = 1;
        return ret;
    }

    if ((uint32_t)(q->top - q->bottom) > q->capacity) {
        ++q->bottom;
        *success = 2;
        return NULL;
    }

    *success = 0;
    return NULL;
}
OpusEncoder *create_audio_encoder (int32_t bit_rate, int32_t sampling_rate, int32_t channel_count)
{
    int status = OPUS_OK;
    OpusEncoder *rc = opus_encoder_create(sampling_rate, channel_count, OPUS_APPLICATION_VOIP, &status);

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(status));
        return NULL;
    }

    status = opus_encoder_ctl(rc, OPUS_SET_BITRATE(bit_rate));

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /* Enable in-band forward error correction in codec */
    status = opus_encoder_ctl(rc, OPUS_SET_INBAND_FEC(1));

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /* Make codec resistant to up to 10% packet loss
     * NOTE This could also be adjusted on the fly, rather than hard-coded,
     *      with feedback from the receiving client.
     */
    status = opus_encoder_ctl(rc, OPUS_SET_PACKET_LOSS_PERC(10));

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    /* Set algorithm to the highest complexity, maximizing compression */
    status = opus_encoder_ctl(rc, OPUS_SET_COMPLEXITY(10));

    if (status != OPUS_OK) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
        goto FAILURE;
    }

    return rc;

FAILURE:
    opus_encoder_destroy(rc);
    return NULL;
}
bool reconfigure_audio_encoder(OpusEncoder **e, int32_t new_br, int32_t new_sr, uint8_t new_ch,
                               int32_t *old_br, int32_t *old_sr, int32_t *old_ch)
{
    /* Values are checked in toxav.c */
    if (*old_sr != new_sr || *old_ch != new_ch) {
        OpusEncoder *new_encoder = create_audio_encoder(new_br, new_sr, new_ch);

        if (new_encoder == NULL)
            return false;

        opus_encoder_destroy(*e);
        *e = new_encoder;
    } else if (*old_br == new_br)
        return true; /* Nothing changed */
    else {
        int status = opus_encoder_ctl(*e, OPUS_SET_BITRATE(new_br));

        if (status != OPUS_OK) {
            LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(status));
            return false;
        }
    }

    *old_br = new_br;
    *old_sr = new_sr;
    *old_ch = new_ch;

    LOGGER_DEBUG ("Reconfigured audio encoder br: %d sr: %d cc:%d", new_br, new_sr, new_ch);
    return true;
}
bool reconfigure_audio_decoder(ACSession *ac, int32_t sampling_rate, int8_t channels)
{
    if (sampling_rate != ac->ld_sample_rate || channels != ac->ld_channel_count) {
        if (current_time_monotonic() - ac->ldrts < 500)
            return false;

        int status;
        OpusDecoder *new_dec = opus_decoder_create(sampling_rate, channels, &status);

        if (status != OPUS_OK) {
            LOGGER_ERROR("Error while starting audio decoder(%d %d): %s", sampling_rate, channels, opus_strerror(status));
            return false;
        }

        ac->ld_sample_rate = sampling_rate;
        ac->ld_channel_count = channels;
        ac->ldrts = current_time_monotonic();

        opus_decoder_destroy(ac->decoder);
        ac->decoder = new_dec;

        LOGGER_DEBUG("Reconfigured audio decoder sr: %d cc: %d", sampling_rate, channels);
    }

    return true;
}
