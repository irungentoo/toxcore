/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "video.h"

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vpx_image.h>

#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ring_buffer.h"
#include "rtp.h"

#include "../toxcore/attributes.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/util.h"

struct VCSession {
    /* encoding */
    vpx_codec_ctx_t encoder[1];
    uint32_t frame_counter;

    vpx_image_t raw_encoder_frame;
    bool raw_encoder_frame_allocated;

    /* decoding */
    vpx_codec_ctx_t decoder[1];
    struct RingBuffer *_Nonnull vbuf_raw; /* Un-decoded data */

    uint64_t linfts; /* Last received frame time stamp */
    uint32_t lcfd; /* Last calculated frame duration for incoming video payload */

    uint32_t friend_number;

    /* Video frame receive callback */
    vc_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable user_data;

    pthread_mutex_t *_Nonnull queue_mutex;
    const Logger *_Nonnull log;
    const Memory *_Nonnull mem;

    vpx_codec_iter_t iter;
};

/**
 * Codec control function to set encoder internal speed settings. Changes in
 * this value influences, among others, the encoder's selection of motion
 * estimation methods. Values greater than 0 will increase encoder speed at the
 * expense of quality.
 *
 * Note Valid range for VP8: `-16..16`
 */
#define VP8E_SET_CPUUSED_VALUE 16

/**
 * Initialize encoder with this value.
 *
 * Target bandwidth to use for this stream, in kilobits per second.
 */
#define VIDEO_BITRATE_INITIAL_VALUE 5000
#define VIDEO_DECODE_BUFFER_SIZE 5 // this buffer has normally max. 1 entry

/**
 * Security limits to prevent resource exhaustion.
 */
#define VIDEO_MAX_FRAME_SIZE (10 * 1024 * 1024)
#define VIDEO_MAX_RESOLUTION_LIMIT 4096

static vpx_codec_iface_t *_Nonnull video_codec_decoder_interface(void)
{
    return vpx_codec_vp8_dx();
}
static vpx_codec_iface_t *_Nonnull video_codec_encoder_interface(void)
{
    return vpx_codec_vp8_cx();
}

#define VIDEO_CODEC_DECODER_MAX_WIDTH  800 // its a dummy value, because the struct needs a value there
#define VIDEO_CODEC_DECODER_MAX_HEIGHT 600 // its a dummy value, because the struct needs a value there

#define VPX_MAX_DIST_START 40

#define VPX_MAX_ENCODER_THREADS 4
#define VPX_MAX_DECODER_THREADS 4
#define VIDEO_VP8_DECODER_POST_PROCESSING_ENABLED 0

static vpx_codec_err_t vc_init_encoder_cfg(const Logger *_Nonnull log, vpx_codec_enc_cfg_t *_Nonnull cfg,
        int16_t kf_max_dist)
{
    const vpx_codec_err_t rc = vpx_codec_enc_config_default(video_codec_encoder_interface(), cfg, 0);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "vc_init_encoder_cfg:Failed to get config: %s", vpx_codec_err_to_string(rc));
        return rc;
    }

    /* Target bandwidth to use for this stream, in kilobits per second */
    cfg->rc_target_bitrate = VIDEO_BITRATE_INITIAL_VALUE;
    cfg->g_w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    cfg->g_h = VIDEO_CODEC_DECODER_MAX_HEIGHT;
    cfg->g_pass = VPX_RC_ONE_PASS;
    cfg->g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT | VPX_ERROR_RESILIENT_PARTITIONS;
    cfg->g_lag_in_frames = 0;

    /* Allow lagged encoding
     *
     * If set, this value allows the encoder to consume a number of input
     * frames before producing output frames. This allows the encoder to
     * base decisions for the current frame on future frames. This does
     * increase the latency of the encoding pipeline, so it is not appropriate
     * in all situations (ex: realtime encoding).
     *
     * Note that this is a maximum value -- the encoder may produce frames
     * sooner than the given limit. Set this value to 0 to disable this
     * feature.
     */
    cfg->kf_min_dist = 0;
    cfg->kf_mode = VPX_KF_AUTO; // Encoder determines optimal placement automatically
    cfg->rc_end_usage = VPX_VBR; // what quality mode?

    /*
     * VPX_VBR    Variable Bit Rate (VBR) mode
     * VPX_CBR    Constant Bit Rate (CBR) mode
     * VPX_CQ     Constrained Quality (CQ) mode -> give codec a hint that we may be on low bandwidth connection
     * VPX_Q    Constant Quality (Q) mode
     */
    if (kf_max_dist > 1) {
        cfg->kf_max_dist = kf_max_dist; // a full frame every x frames minimum (can be more often, codec decides automatically)
        LOGGER_DEBUG(log, "kf_max_dist=%u (1)", cfg->kf_max_dist);
    } else {
        cfg->kf_max_dist = VPX_MAX_DIST_START;
        LOGGER_DEBUG(log, "kf_max_dist=%u (2)", cfg->kf_max_dist);
    }

    cfg->g_threads = VPX_MAX_ENCODER_THREADS; // Maximum number of threads to use
    /* TODO: set these to something reasonable */
    // cfg->g_timebase.num = 1;
    // cfg->g_timebase.den = 60; // 60 fps
    cfg->rc_resize_allowed = 1; // allow encoder to resize to smaller resolution
    cfg->rc_resize_up_thresh = 40;
    cfg->rc_resize_down_thresh = 5;

    /* TODO: make quality setting an API call, but start with normal quality */
#if 0
    /* Highest-resolution encoder settings */
    cfg->rc_dropframe_thresh = 0;
    cfg->rc_resize_allowed = 0;
    cfg->rc_min_quantizer = 2;
    cfg->rc_max_quantizer = 56;
    cfg->rc_undershoot_pct = 100;
    cfg->rc_overshoot_pct = 15;
    cfg->rc_buf_initial_sz = 500;
    cfg->rc_buf_optimal_sz = 600;
    cfg->rc_buf_sz = 1000;
#endif /* 0 */

    return VPX_CODEC_OK;
}

VCSession *vc_new(const Memory *mem, const Logger *log, const Mono_Time *mono_time, uint32_t friend_number,
                  vc_video_receive_frame_cb *cb, void *user_data)
{
    if (mono_time == nullptr) {
        return nullptr;
    }

    VCSession *vc = (VCSession *)calloc(1, sizeof(VCSession));
    vpx_codec_err_t rc;

    if (vc == nullptr) {
        LOGGER_ERROR(log, "Allocation failed! Application might misbehave!");
        return nullptr;
    }

    vc->mem = mem;

    vc->queue_mutex = (pthread_mutex_t *)mem_alloc(mem, sizeof(pthread_mutex_t));
    if (vc->queue_mutex == nullptr) {
        LOGGER_ERROR(log, "Allocation failed! Application might misbehave!");
        free(vc);
        return nullptr;
    }

    if (create_recursive_mutex(vc->queue_mutex) != 0) {
        LOGGER_ERROR(log, "Failed to create recursive mutex!");
        mem_delete(mem, vc->queue_mutex);
        free(vc);
        return nullptr;
    }

    const int cpu_used_value = VP8E_SET_CPUUSED_VALUE;

    vc->vbuf_raw = rb_new(VIDEO_DECODE_BUFFER_SIZE);

    if (vc->vbuf_raw == nullptr) {
        LOGGER_ERROR(log, "Failed to create ring buffer!");
        goto BASE_CLEANUP;
    }

    /*
     * VPX_CODEC_USE_FRAME_THREADING
     *    Enable frame-based multi-threading
     *
     * VPX_CODEC_USE_ERROR_CONCEALMENT
     *    Conceal errors in decoded frames
     */
    vpx_codec_dec_cfg_t  dec_cfg;
    dec_cfg.threads = VPX_MAX_DECODER_THREADS; // Maximum number of threads to use
    dec_cfg.w = VIDEO_CODEC_DECODER_MAX_WIDTH;
    dec_cfg.h = VIDEO_CODEC_DECODER_MAX_HEIGHT;

    LOGGER_DEBUG(log, "Using VP8 codec for decoder (0)");
    rc = vpx_codec_dec_init(vc->decoder, video_codec_decoder_interface(), &dec_cfg,
                            VPX_CODEC_USE_FRAME_THREADING | VPX_CODEC_USE_POSTPROC);

    if (rc == VPX_CODEC_INCAPABLE) {
        LOGGER_WARNING(log, "Codec incapable of requested features, trying without postproc (0)");
        rc = vpx_codec_dec_init(vc->decoder, video_codec_decoder_interface(), &dec_cfg, VPX_CODEC_USE_FRAME_THREADING);
    }

    if (rc == VPX_CODEC_INCAPABLE) {
        LOGGER_WARNING(log, "Threading not supported by this decoder, trying without (0)");
        rc = vpx_codec_dec_init(vc->decoder, video_codec_decoder_interface(), &dec_cfg, 0);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Init video_decoder failed (rc=%d): %s", (int)rc, vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP;
    }

    if (VIDEO_VP8_DECODER_POST_PROCESSING_ENABLED == 1) {
        vp8_postproc_cfg_t pp = {VP8_DEBLOCK, 1, 0};
        const vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(log, "Failed to turn on postproc");
        } else {
            LOGGER_DEBUG(log, "turn on postproc: OK");
        }
    } else {
        vp8_postproc_cfg_t pp = {0, 0, 0};
        const vpx_codec_err_t cc_res = vpx_codec_control(vc->decoder, VP8_SET_POSTPROC, &pp);

        if (cc_res != VPX_CODEC_OK) {
            LOGGER_WARNING(log, "Failed to turn OFF postproc");
        } else {
            LOGGER_DEBUG(log, "Disable postproc: OK");
        }
    }

    /* Set encoder to some initial values
     */
    vpx_codec_enc_cfg_t cfg;
    rc = vc_init_encoder_cfg(log, &cfg, 1);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to initialize encoder config (rc=%d): %s", (int)rc, vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }

    LOGGER_DEBUG(log, "Using VP8 codec for encoder (0.1)");
    rc = vpx_codec_enc_init(vc->encoder, video_codec_encoder_interface(), &cfg, VPX_CODEC_USE_FRAME_THREADING);

    if (rc == VPX_CODEC_INCAPABLE) {
        LOGGER_WARNING(log, "Threading not supported by this encoder, trying without (0.1)");
        rc = vpx_codec_enc_init(vc->encoder, video_codec_encoder_interface(), &cfg, 0);
    }

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to initialize encoder (rc=%d): %s", (int)rc, vpx_codec_err_to_string(rc));
        goto BASE_CLEANUP_1;
    }

    rc = vpx_codec_control(vc->encoder, VP8E_SET_CPUUSED, cpu_used_value);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    }

    /*
     * VPX_CTRL_USE_TYPE(VP8E_SET_NOISE_SENSITIVITY, unsigned int)
     * control function to set noise sensitivity
     *   0: off, 1: OnYOnly, 2: OnYUV, 3: OnYUVAggressive, 4: Adaptive
     */
#if 0
    rc = vpx_codec_control(vc->encoder, VP8E_SET_NOISE_SENSITIVITY, 2);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
        vpx_codec_destroy(vc->encoder);
        goto BASE_CLEANUP_1;
    }

#endif /* 0 */

    vc->linfts = current_time_monotonic(mono_time);
    vc->lcfd = 60;
    vc->vcb = cb;
    vc->user_data = user_data;
    vc->friend_number = friend_number;
    vc->log = log;
    return vc;

BASE_CLEANUP_1:
    vpx_codec_destroy(vc->decoder);
BASE_CLEANUP:
    pthread_mutex_destroy(vc->queue_mutex);
    mem_delete(vc->mem, vc->queue_mutex);
    rb_kill(vc->vbuf_raw);
    free(vc);

    return nullptr;
}

void vc_kill(VCSession *vc)
{
    if (vc == nullptr) {
        return;
    }

    if (vc->raw_encoder_frame_allocated) {
        vpx_img_free(&vc->raw_encoder_frame);
    }

    vpx_codec_destroy(vc->encoder);
    vpx_codec_destroy(vc->decoder);
    void *p;

    while (rb_read(vc->vbuf_raw, &p)) {
        free(p);
    }

    rb_kill(vc->vbuf_raw);
    pthread_mutex_destroy(vc->queue_mutex);
    mem_delete(vc->mem, vc->queue_mutex);
    LOGGER_DEBUG(vc->log, "Terminated video handler: %p", (void *)vc);
    free(vc);
}

void vc_iterate(VCSession *vc)
{
    if (vc == nullptr) {
        return;
    }

    pthread_mutex_lock(vc->queue_mutex);

    struct RTPMessage *p;

    if (!rb_read(vc->vbuf_raw, (void **)&p)) {
        LOGGER_TRACE(vc->log, "no Video frame data available");
        pthread_mutex_unlock(vc->queue_mutex);
        return;
    }

    const uint16_t log_rb_size = rb_size(vc->vbuf_raw);
    pthread_mutex_unlock(vc->queue_mutex);

    uint32_t full_data_len;

    if ((rtp_message_flags(p) & RTP_LARGE_FRAME) != 0) {
        full_data_len = rtp_message_data_length_full(p);
        LOGGER_DEBUG(vc->log, "vc_iterate:001:full_data_len=%u", full_data_len);
    } else {
        full_data_len = rtp_message_len(p);
        LOGGER_DEBUG(vc->log, "vc_iterate:002");
    }

    /* Security check: Ensure the reported full data length does not exceed the actual buffer size.
     * rtp_message_len(p) returns the actual allocated payload size.
     */
    if (full_data_len > rtp_message_len(p)) {
        LOGGER_ERROR(vc->log, "vc_iterate: Malicious packet detected! Lying length: %u actual: %u",
                     full_data_len, (uint32_t)rtp_message_len(p));
        free(p);
        return;
    }

    LOGGER_DEBUG(vc->log, "vc_iterate: rb_read p->len=%u", full_data_len);
    LOGGER_DEBUG(vc->log, "vc_iterate: rb_read rb size=%d", (int)log_rb_size);
    const vpx_codec_err_t rc = vpx_codec_decode(vc->decoder, rtp_message_data(p), full_data_len, nullptr, 0);
    free(p);

    if (rc != VPX_CODEC_OK) {
        LOGGER_ERROR(vc->log, "Error decoding video: %d %s", (int)rc, vpx_codec_err_to_string(rc));
        return;
    }

    /* Play decoded images */
    vpx_codec_iter_t iter = nullptr;

    for (vpx_image_t *dest = vpx_codec_get_frame(vc->decoder, &iter);
            dest != nullptr;
            dest = vpx_codec_get_frame(vc->decoder, &iter)) {
        if (vc->vcb != nullptr) {
            vc->vcb(vc->friend_number, dest->d_w, dest->d_h,
                    dest->planes[0], dest->planes[1], dest->planes[2],
                    dest->stride[0], dest->stride[1], dest->stride[2], vc->user_data);
        }
    }
}

int vc_queue_message(const Mono_Time *mono_time, void *cs, struct RTPMessage *msg)
{
    VCSession *vc = (VCSession *)cs;

    /* This function is called with complete messages
     * they have already been assembled.
     * this function gets called from handle_rtp_packet()
     */
    if (vc == nullptr || msg == nullptr) {
        free(msg);

        return -1;
    }

    if (rtp_message_pt(msg) == (RTP_TYPE_VIDEO + 2) % 128) {
        LOGGER_WARNING(vc->log, "Got dummy!");
        free(msg);
        return 0;
    }

    if (rtp_message_pt(msg) != RTP_TYPE_VIDEO % 128) {
        LOGGER_WARNING(vc->log, "Invalid payload type! pt=%d", (int)rtp_message_pt(msg));
        free(msg);
        return -1;
    }

    /* Security check: Sanitize message size to prevent memory exhaustion */
    if (rtp_message_data_length_full(msg) > VIDEO_MAX_FRAME_SIZE) {
        LOGGER_ERROR(vc->log, "Message too large! size=%u", (uint32_t)rtp_message_data_length_full(msg));
        free(msg);
        return -1;
    }

    pthread_mutex_lock(vc->queue_mutex);

    if ((rtp_message_flags(msg) & RTP_LARGE_FRAME) != 0 && rtp_message_pt(msg) == RTP_TYPE_VIDEO % 128) {
        LOGGER_DEBUG(vc->log, "rb_write msg->len=%d b0=%d b1=%d", (int)rtp_message_len(msg), (int)rtp_message_data(msg)[0], (int)rtp_message_data(msg)[1]);
    }

    free(rb_write(vc->vbuf_raw, msg));

    /* Calculate time it took for peer to send us this frame */
    const uint32_t t_lcfd = current_time_monotonic(mono_time) - vc->linfts;
    vc->lcfd = t_lcfd > 100 ? vc->lcfd : t_lcfd;
    vc->linfts = current_time_monotonic(mono_time);
    pthread_mutex_unlock(vc->queue_mutex);
    return 0;
}

int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist)
{
    if (vc == nullptr) {
        return -1;
    }

    /* Security check: Sanitize resolution to prevent resource exhaustion */
    if (width == 0 || height == 0 || width > VIDEO_MAX_RESOLUTION_LIMIT || height > VIDEO_MAX_RESOLUTION_LIMIT) {
        LOGGER_ERROR(vc->log, "Invalid resolution requested: %ux%u", (uint32_t)width, (uint32_t)height);
        return -1;
    }

    vpx_codec_enc_cfg_t cfg2 = *vc->encoder->config.enc;

    if (cfg2.rc_target_bitrate == bit_rate && cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1) {
        return 0; /* Nothing changed */
    }

    if (cfg2.g_w == width && cfg2.g_h == height && kf_max_dist == -1) {
        /* Only bit rate changed */
        LOGGER_INFO(vc->log, "bitrate change from: %u to: %u", (uint32_t)cfg2.rc_target_bitrate, (uint32_t)bit_rate);
        cfg2.rc_target_bitrate = bit_rate;
        const vpx_codec_err_t rc = vpx_codec_enc_config_set(vc->encoder, &cfg2);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            return -1;
        }
    } else {
        /* Resolution is changed, must reinitialize encoder since libvpx v1.4 doesn't support
         * reconfiguring encoder to use resolutions greater than initially set.
         */
        LOGGER_DEBUG(vc->log, "Have to reinitialize vpx encoder on session %p", (void *)vc);
        vpx_codec_enc_cfg_t  cfg;
        vpx_codec_err_t rc = vc_init_encoder_cfg(vc->log, &cfg, kf_max_dist);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to initialize encoder config: %s", vpx_codec_err_to_string(rc));
            return -1;
        }

        cfg.rc_target_bitrate = bit_rate;
        cfg.g_w = width;
        cfg.g_h = height;

        /* Atomic reconfiguration: Initialize new encoder first */
        vpx_codec_ctx_t new_encoder;
        LOGGER_DEBUG(vc->log, "Using VP8 codec for encoder");
        rc = vpx_codec_enc_init(&new_encoder, video_codec_encoder_interface(), &cfg, VPX_CODEC_USE_FRAME_THREADING);

        if (rc == VPX_CODEC_INCAPABLE) {
            LOGGER_WARNING(vc->log, "Threading not supported by this encoder, trying without");
            rc = vpx_codec_enc_init(&new_encoder, video_codec_encoder_interface(), &cfg, 0);
        }

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to initialize encoder: %s", vpx_codec_err_to_string(rc));
            return -1;
        }

        const int cpu_used_value = VP8E_SET_CPUUSED_VALUE;

        rc = vpx_codec_control(&new_encoder, VP8E_SET_CPUUSED, cpu_used_value);

        if (rc != VPX_CODEC_OK) {
            LOGGER_ERROR(vc->log, "Failed to set encoder control setting: %s", vpx_codec_err_to_string(rc));
            vpx_codec_destroy(&new_encoder);
            return -1;
        }

        /* Swap only on success */
        vpx_codec_destroy(vc->encoder);
        *vc->encoder = new_encoder;
        return 0;
    }

    return 0;
}

int vc_encode(VCSession *vc, uint16_t width, uint16_t height, const uint8_t *y,
              const uint8_t *u, const uint8_t *v, int encode_flags)
{
    if (vc->raw_encoder_frame_allocated && (vc->raw_encoder_frame.d_w != width || vc->raw_encoder_frame.d_h != height)) {
        vpx_img_free(&vc->raw_encoder_frame);
        vc->raw_encoder_frame_allocated = false;
    }

    if (!vc->raw_encoder_frame_allocated) {
        if (vpx_img_alloc(&vc->raw_encoder_frame, VPX_IMG_FMT_I420, width, height, 1) == nullptr) {
            LOGGER_ERROR(vc->log, "Could not allocate image for frame");
            return -1;
        }

        vc->raw_encoder_frame_allocated = true;
    }

    vpx_image_t *img = &vc->raw_encoder_frame;

    memcpy(img->planes[VPX_PLANE_Y], y, (size_t)width * height);
    memcpy(img->planes[VPX_PLANE_U], u, ((size_t)width / 2) * (height / 2));
    memcpy(img->planes[VPX_PLANE_V], v, ((size_t)width / 2) * (height / 2));

    int vpx_flags = 0;

    if ((encode_flags & VC_EFLAG_FORCE_KF) != 0) {
        vpx_flags |= VPX_EFLAG_FORCE_KF;
    }

    const vpx_codec_err_t vrc = vpx_codec_encode(vc->encoder, img,
                                vc->frame_counter, 1, vpx_flags, VPX_DL_REALTIME);

    if (vrc != VPX_CODEC_OK) {
        LOGGER_ERROR(vc->log, "Could not encode video frame: %s", vpx_codec_err_to_string(vrc));
        return -1;
    }

    vc->iter = nullptr;
    return 0;
}

int vc_get_cx_data(VCSession *vc, uint8_t **data, uint32_t *size, bool *is_keyframe)
{
    const vpx_codec_cx_pkt_t *pkt = vpx_codec_get_cx_data(vc->encoder, &vc->iter);

    while (pkt != nullptr && pkt->kind != VPX_CODEC_CX_FRAME_PKT) {
        pkt = vpx_codec_get_cx_data(vc->encoder, &vc->iter);
    }

    if (pkt == nullptr) {
        return 0;
    }

    *data = (uint8_t *)pkt->data.frame.buf;
    *size = (uint32_t)pkt->data.frame.sz;
    *is_keyframe = (pkt->data.frame.flags & VPX_FRAME_IS_KEY) != 0;

    return 1;
}

uint32_t vc_get_lcfd(const VCSession *vc)
{
    uint32_t lcfd;
    pthread_mutex_lock(vc->queue_mutex);
    lcfd = vc->lcfd;
    pthread_mutex_unlock(vc->queue_mutex);
    return lcfd;
}

pthread_mutex_t *vc_get_queue_mutex(VCSession *vc)
{
    return vc->queue_mutex;
}

void vc_increment_frame_counter(VCSession *vc)
{
    ++vc->frame_counter;
}
