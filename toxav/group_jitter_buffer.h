/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_GROUP_JITTER_BUFFER_H
#define C_TOXCORE_TOXAV_GROUP_JITTER_BUFFER_H

#include <stdint.h>

#include "../toxcore/attributes.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Group_Audio_Packet {
    uint16_t sequnum;
    uint16_t length;
    uint8_t *_Nonnull data;
} Group_Audio_Packet;

void group_audio_packet_free(Group_Audio_Packet *_Nullable pk);

/** Jitter buffer for the audio packets of a conference peer. */
typedef struct Group_JitterBuffer Group_JitterBuffer;

Group_JitterBuffer *_Nullable group_jbuf_new(unsigned int capacity);
void group_jbuf_kill(Group_JitterBuffer *_Nullable q);

/** @retval 0 if packet was queued
 * @retval -1 if it wasn't.
 */
int group_jbuf_write(Group_JitterBuffer *_Nonnull q, const Mono_Time *_Nonnull mono_time, Group_Audio_Packet *_Nonnull pk);

/**
 * success is:
 * - 0 when there is nothing to dequeue
 * - 1 when there's a good packet
 * - 2 when there's a lost packet
 */
Group_Audio_Packet *_Nullable group_jbuf_read(Group_JitterBuffer *_Nonnull q, int *_Nonnull success);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_GROUP_JITTER_BUFFER_H */
