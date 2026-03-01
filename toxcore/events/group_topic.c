/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_event.h"
#include "../tox_events.h"
#include "../tox_struct.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Group_Topic {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *_Nullable topic;
    uint32_t topic_length;
};

static void tox_event_group_topic_set_group_number(Tox_Event_Group_Topic *_Nonnull group_topic, uint32_t group_number)
{
    assert(group_topic != nullptr);
    group_topic->group_number = group_number;
}
uint32_t tox_event_group_topic_get_group_number(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->group_number;
}

static void tox_event_group_topic_set_peer_id(Tox_Event_Group_Topic *_Nonnull group_topic, uint32_t peer_id)
{
    assert(group_topic != nullptr);
    group_topic->peer_id = peer_id;
}
uint32_t tox_event_group_topic_get_peer_id(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->peer_id;
}

static bool tox_event_group_topic_set_topic(Tox_Event_Group_Topic *_Nonnull group_topic,
        const Memory *_Nonnull mem, const uint8_t *_Nullable topic, uint32_t topic_length)
{
    assert(group_topic != nullptr);
    if (group_topic->topic != nullptr) {
        mem_delete(mem, group_topic->topic);
        group_topic->topic = nullptr;
        group_topic->topic_length = 0;
    }

    if (topic == nullptr) {
        assert(topic_length == 0);
        return true;
    }

    if (topic_length == 0) {
        group_topic->topic = nullptr;
        group_topic->topic_length = 0;
        return true;
    }

    uint8_t *topic_copy = (uint8_t *)mem_balloc(mem, topic_length);

    if (topic_copy == nullptr) {
        return false;
    }

    memcpy(topic_copy, topic, topic_length);
    group_topic->topic = topic_copy;
    group_topic->topic_length = topic_length;
    return true;
}
uint32_t tox_event_group_topic_get_topic_length(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->topic_length;
}
const uint8_t *tox_event_group_topic_get_topic(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->topic;
}

static void tox_event_group_topic_construct(Tox_Event_Group_Topic *_Nonnull group_topic)
{
    *group_topic = (Tox_Event_Group_Topic) {
        0
    };
}
static void tox_event_group_topic_destruct(Tox_Event_Group_Topic *_Nonnull group_topic, const Memory *_Nonnull mem)
{
    mem_delete(mem, group_topic->topic);
}

bool tox_event_group_topic_pack(
    const Tox_Event_Group_Topic *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->topic, event->topic_length);
}

static bool tox_event_group_topic_unpack_into(Tox_Event_Group_Topic *_Nonnull event, Bin_Unpack *_Nonnull bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && bin_unpack_bin(bu, &event->topic, &event->topic_length);
}

/*****************************************************
 *
 * :: new/free/add/get/size/unpack
 *
 *****************************************************/

const Tox_Event_Group_Topic *tox_event_get_group_topic(const Tox_Event *event)
{
    return event->type == TOX_EVENT_GROUP_TOPIC ? event->data.group_topic : nullptr;
}

Tox_Event_Group_Topic *tox_event_group_topic_new(const Memory *mem)
{
    Tox_Event_Group_Topic *const group_topic =
        (Tox_Event_Group_Topic *)mem_alloc(mem, sizeof(Tox_Event_Group_Topic));

    if (group_topic == nullptr) {
        return nullptr;
    }

    tox_event_group_topic_construct(group_topic);
    return group_topic;
}

void tox_event_group_topic_free(Tox_Event_Group_Topic *group_topic, const Memory *mem)
{
    if (group_topic != nullptr) {
        tox_event_group_topic_destruct(group_topic, mem);
    }
    mem_delete(mem, group_topic);
}

static Tox_Event_Group_Topic *_Nullable tox_events_add_group_topic(Tox_Events *_Nonnull events, const Memory *_Nonnull mem)
{
    Tox_Event_Group_Topic *const group_topic = tox_event_group_topic_new(mem);

    if (group_topic == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_TOPIC;
    event.data.group_topic = group_topic;

    if (!tox_events_add(events, &event)) {
        tox_event_group_topic_free(group_topic, mem);
        return nullptr;
    }
    return group_topic;
}

bool tox_event_group_topic_unpack(
    Tox_Event_Group_Topic **event, Bin_Unpack *bu, const Memory *mem)
{
    assert(event != nullptr);
    assert(*event == nullptr);
    *event = tox_event_group_topic_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_group_topic_unpack_into(*event, bu);
}

static Tox_Event_Group_Topic *_Nullable tox_event_group_topic_alloc(Tox_Events_State *_Nonnull state)
{
    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Group_Topic *group_topic = tox_events_add_group_topic(state->events, state->mem);

    if (group_topic == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return group_topic;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_group_topic(
    Tox *_Nonnull tox,
    uint32_t group_number,
    uint32_t peer_id,
    const uint8_t *_Nullable topic, size_t topic_length,
    void *_Nullable user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    Tox_Event_Group_Topic *group_topic = tox_event_group_topic_alloc(state);

    if (group_topic == nullptr) {
        return;
    }

    tox_event_group_topic_set_group_number(group_topic, group_number);
    tox_event_group_topic_set_peer_id(group_topic, peer_id);
    if (!tox_event_group_topic_set_topic(group_topic, state->mem, topic, topic_length)) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }
}

void tox_events_handle_group_topic_dispatch(Tox *tox, const Tox_Event_Group_Topic *event, void *user_data)
{
    if (tox->group_topic_callback == nullptr) {
        return;
    }

    tox_unlock(tox);
    tox->group_topic_callback(tox, event->group_number, event->peer_id, event->topic, event->topic_length, user_data);
    tox_lock(tox);
}
