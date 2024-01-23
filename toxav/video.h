/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_VIDEO_H
#define C_TOXCORE_TOXAV_VIDEO_H

#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <vpx/vpx_image.h>

#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>

#include <pthread.h>

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"
#include "ring_buffer.h"
#include "rtp.h"

typedef struct VCSession {
    /* encoding */
    vpx_codec_ctx_t encoder[1];
    uint32_t frame_counter;

    /* decoding */
    vpx_codec_ctx_t decoder[1];
    struct RingBuffer *vbuf_raw; /* Un-decoded data */

    uint64_t linfts; /* Last received frame time stamp */
    uint32_t lcfd; /* Last calculated frame duration for incoming video payload */

    const Logger *log;
    ToxAV *av;
    uint32_t friend_number;

    /* Video frame receive callback */
    toxav_video_receive_frame_cb *vcb;
    void *vcb_user_data;

    pthread_mutex_t queue_mutex[1];
} VCSession;

VCSession *vc_new(Mono_Time *mono_time, const Logger *log, ToxAV *av, uint32_t friend_number,
                  toxav_video_receive_frame_cb *cb, void *cb_data);
void vc_kill(VCSession *vc);
void vc_iterate(VCSession *vc);
int vc_queue_message(Mono_Time *mono_time, void *cs, struct RTPMessage *msg);
int vc_reconfigure_encoder(VCSession *vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist);

#endif /* C_TOXCORE_TOXAV_VIDEO_H */
