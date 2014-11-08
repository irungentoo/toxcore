/**  groupav.h
 *
 *   Copyright (C) 2014 Tox project All Rights Reserved.
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "group.h"
#include "../toxcore/logger.h"

typedef struct {
    uint16_t sequnum;
    uint16_t length;
    uint8_t data[];
} Group_Audio_Packet;

typedef struct {
    Group_Audio_Packet **queue;
    uint32_t size;
    uint32_t capacity;
    uint16_t bottom;
    uint16_t top;
} Group_JitterBuffer;

static Group_JitterBuffer *create_queue(unsigned int capacity)
{
    unsigned int size = 1;

    while (size <= capacity) {
        size *= 2;
    }

    Group_JitterBuffer *q;

    if ( !(q = calloc(sizeof(Group_JitterBuffer), 1)) ) return NULL;

    if (!(q->queue = calloc(sizeof(Group_Audio_Packet *), size))) {
        free(q);
        return NULL;
    }

    q->size = size;
    q->capacity = capacity;
    return q;
}

static void clear_queue(Group_JitterBuffer *q)
{
    for (; q->bottom != q->top; ++q->bottom) {
        if (q->queue[q->bottom % q->size]) {
            free(q->queue[q->bottom % q->size]);
            q->queue[q->bottom % q->size] = NULL;
        }
    }
}

static void terminate_queue(Group_JitterBuffer *q)
{
    if (!q) return;

    clear_queue(q);
    free(q->queue);
    free(q);
}

static void queue(Group_JitterBuffer *q, Group_Audio_Packet *pk)
{
    uint16_t sequnum = pk->sequnum;

    unsigned int num = sequnum % q->size;

    if ((uint32_t)(sequnum - q->bottom) > q->size) {
        clear_queue(q);
        q->bottom = sequnum;
        q->queue[num] = pk;
        q->top = sequnum + 1;
        return;
    }

    if (q->queue[num])
        return;

    q->queue[num] = pk;

    if ((sequnum - q->bottom) >= (q->top - q->bottom))
        q->top = sequnum + 1;
}

/* success is 0 when there is nothing to dequeue, 1 when there's a good packet, 2 when there's a lost packet */
static Group_Audio_Packet *dequeue(Group_JitterBuffer *q, int *success)
{
    if (q->top == q->bottom) {
        *success = 0;
        return NULL;
    }

    unsigned int num = q->bottom % q->size;

    if (q->queue[num]) {
        Group_Audio_Packet *ret = q->queue[num];
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


typedef struct {
    OpusEncoder *audio_encoder;

    unsigned int audio_channels, audio_sample_rate, audio_bitrate;
} Group_AV;

typedef struct {
    Group_JitterBuffer *buffer;

    OpusDecoder *audio_decoder;
} Group_Peer_AV;

static void kill_group_av(Group_AV *group_av)
{
    opus_encoder_destroy(group_av->audio_encoder);
    free(group_av);
}

static Group_AV *new_group_av(unsigned int audio_channels, unsigned int audio_sample_rate, unsigned int audio_bitrate)
{
    Group_AV *group_av = calloc(1, sizeof(Group_AV));

    int rc = OPUS_OK;
    group_av->audio_encoder = opus_encoder_create(audio_sample_rate, audio_channels, OPUS_APPLICATION_AUDIO, &rc);

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while starting audio encoder: %s", opus_strerror(rc));
        free(group_av);
        return NULL;
    }

    rc = opus_encoder_ctl(group_av->audio_encoder, OPUS_SET_BITRATE(audio_bitrate));

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        opus_encoder_destroy(group_av->audio_encoder);
        free(group_av);
        return NULL;
    }

    rc = opus_encoder_ctl(group_av->audio_encoder, OPUS_SET_COMPLEXITY(10));

    if ( rc != OPUS_OK ) {
        LOGGER_ERROR("Error while setting encoder ctl: %s", opus_strerror(rc));
        opus_encoder_destroy(group_av->audio_encoder);
        free(group_av);
        return NULL;
    }

    group_av->audio_channels = audio_channels;
    group_av->audio_sample_rate = audio_sample_rate;
    group_av->audio_bitrate = audio_bitrate;
    return 0;
}

static void group_av_peer_new(void *object, int groupnumber, int friendgroupnumber)
{


}

static void group_av_peer_delete(void *object, int groupnumber, int friendgroupnumber, void *peer_object)
{


}

static int groupchat_enable_av(Group_Chats *g_c, int groupnumber)
{
    Group_AV *group_av = new_group_av(1, 48000, 64000); //TODO: Use variables instead.

    if (group_av == NULL) {
        return -1;
    }

    if (group_set_object(g_c, groupnumber, group_av) == -1
            || callback_groupchat_peer_new(g_c, groupnumber, group_av_peer_new) == -1
            || callback_groupchat_peer_delete(g_c, groupnumber, group_av_peer_delete) == -1) {
        kill_group_av(group_av);
        return -1;
    }

    return 0;
}

/* Create a new toxav group.
 *
 * return group number on success.
 * return -1 on failure.
 */
int add_av_groupchat(Group_Chats *g_c)
{
    int groupnumber = add_groupchat(g_c);

    if (groupnumber == -1) {
        return -1;
    }

    if (groupchat_enable_av(g_c, groupnumber) == -1) {
        del_groupchat(g_c, groupnumber);
        return -1;
    }

    return groupnumber;
}


