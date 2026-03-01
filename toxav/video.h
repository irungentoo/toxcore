/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_VIDEO_H
#define C_TOXCORE_TOXAV_VIDEO_H

#include <pthread.h>
#include <stdint.h>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void vc_video_receive_frame_cb(uint32_t friend_number, uint16_t width, uint16_t height,
                                       const uint8_t *_Nonnull y, const uint8_t *_Nonnull u, const uint8_t *_Nonnull v,
                                       int32_t ystride, int32_t ustride, int32_t vstride,
                                       void *_Nullable user_data);

typedef struct VCSession VCSession;

#define VC_EFLAG_NONE 0
#define VC_EFLAG_FORCE_KF (1 << 0)

struct RTPMessage;

VCSession *_Nullable vc_new(const Memory *_Nonnull mem, const Logger *_Nonnull log, const Mono_Time *_Nonnull mono_time, uint32_t friend_number,
                            vc_video_receive_frame_cb *_Nullable cb, void *_Nullable user_data);
void vc_kill(VCSession *_Nullable vc);
void vc_iterate(VCSession *_Nullable vc);

int vc_queue_message(const Mono_Time *_Nonnull mono_time, void *_Nullable cs, struct RTPMessage *_Nullable msg);
int vc_reconfigure_encoder(VCSession *_Nullable vc, uint32_t bit_rate, uint16_t width, uint16_t height, int16_t kf_max_dist);

int vc_encode(VCSession *_Nonnull vc, uint16_t width, uint16_t height, const uint8_t *_Nonnull y,
              const uint8_t *_Nonnull u, const uint8_t *_Nonnull v, int encode_flags);

int vc_get_cx_data(VCSession *_Nonnull vc, uint8_t *_Nonnull *_Nonnull data, uint32_t *_Nonnull size, bool *_Nonnull is_keyframe);
uint32_t vc_get_lcfd(const VCSession *_Nonnull vc);
pthread_mutex_t *_Nonnull vc_get_queue_mutex(VCSession *_Nonnull vc);
void vc_increment_frame_counter(VCSession *_Nonnull vc);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_VIDEO_H */
