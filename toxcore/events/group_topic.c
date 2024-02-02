/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../mem.h"
#include "../tox.h"
#include "../tox_events.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Group_Topic {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *topic;
    uint32_t topic_length;
};

non_null()
static void tox_event_group_topic_set_group_number(Tox_Event_Group_Topic *group_topic,
        uint32_t group_number)
{
    assert(group_topic != nullptr);
    group_topic->group_number = group_number;
}
uint32_t tox_event_group_topic_get_group_number(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->group_number;
}

non_null()
static void tox_event_group_topic_set_peer_id(Tox_Event_Group_Topic *group_topic,
        uint32_t peer_id)
{
    assert(group_topic != nullptr);
    group_topic->peer_id = peer_id;
}
uint32_t tox_event_group_topic_get_peer_id(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->peer_id;
}

non_null(1) nullable(2)
static bool tox_event_group_topic_set_topic(Tox_Event_Group_Topic *group_topic,
        const uint8_t *topic, uint32_t topic_length)
{
    assert(group_topic != nullptr);

    if (group_topic->topic != nullptr) {
        free(group_topic->topic);
        group_topic->topic = nullptr;
        group_topic->topic_length = 0;
    }

    if (topic == nullptr) {
        assert(topic_length == 0);
        return true;
    }

    uint8_t *topic_copy = (uint8_t *)malloc(topic_length);

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

non_null()
static void tox_event_group_topic_construct(Tox_Event_Group_Topic *group_topic)
{
    *group_topic = (Tox_Event_Group_Topic) {
        0
    };
}
non_null()
static void tox_event_group_topic_destruct(Tox_Event_Group_Topic *group_topic, const Memory *mem)
{
    free(group_topic->topic);
}

bool tox_event_group_topic_pack(
    const Tox_Event_Group_Topic *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->topic, event->topic_length);
}

non_null()
static bool tox_event_group_topic_unpack_into(
    Tox_Event_Group_Topic *event, Bin_Unpack *bu)
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

non_null()
static Tox_Event_Group_Topic *tox_events_add_group_topic(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Group_Topic *const group_topic = tox_event_group_topic_new(mem);

    if (group_topic == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_GROUP_TOPIC;
    event.data.group_topic = group_topic;

    tox_events_add(events, &event);
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

non_null()
static Tox_Event_Group_Topic *tox_event_group_topic_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

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
    Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *topic, size_t length,
    void *user_data)
{
    Tox_Event_Group_Topic *group_topic = tox_event_group_topic_alloc(user_data);

    if (group_topic == nullptr) {
        return;
    }

    tox_event_group_topic_set_group_number(group_topic, group_number);
    tox_event_group_topic_set_peer_id(group_topic, peer_id);
    tox_event_group_topic_set_topic(group_topic, topic, length);
}
