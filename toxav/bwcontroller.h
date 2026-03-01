/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_BWCONTROLLER_H
#define C_TOXCORE_TOXAV_BWCONTROLLER_H

#include <stddef.h>
#include <stdint.h>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BWC_PACKET_ID 196

typedef struct BWController BWController;

typedef void bwc_loss_report_cb(BWController *_Nonnull bwc, uint32_t friend_number, float loss, void *_Nullable user_data);

typedef int bwc_send_packet_cb(void *_Nullable user_data, const uint8_t *_Nonnull data, uint16_t length);

BWController *_Nullable bwc_new(const Logger *_Nonnull log, uint32_t friendnumber,
                                bwc_loss_report_cb *_Nullable mcb, void *_Nullable mcb_user_data,
                                bwc_send_packet_cb *_Nullable send_packet, void *_Nullable send_packet_user_data,
                                Mono_Time *_Nonnull bwc_mono_time);

void bwc_kill(BWController *_Nullable bwc);

void bwc_add_lost(BWController *_Nullable bwc, uint32_t bytes_lost);
void bwc_add_recv(BWController *_Nullable bwc, uint32_t recv_bytes);

void bwc_handle_packet(BWController *_Nullable bwc, const uint8_t *_Nonnull data, size_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_BWCONTROLLER_H */
