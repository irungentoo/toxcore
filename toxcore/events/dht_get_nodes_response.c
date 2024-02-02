/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
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
#include "../tox_events.h"
#include "../tox_private.h"

/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/

struct Tox_Event_Dht_Get_Nodes_Response {
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    uint8_t *ip;
    uint32_t ip_length;
    uint16_t port;
};

non_null()
static bool tox_event_dht_get_nodes_response_set_public_key(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE])
{
    memcpy(dht_get_nodes_response->public_key, public_key, TOX_PUBLIC_KEY_SIZE);
    return true;
}
const uint8_t *tox_event_dht_get_nodes_response_get_public_key(const Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response)
{
    return dht_get_nodes_response->public_key;
}

non_null()
static bool tox_event_dht_get_nodes_response_set_ip(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response,
        const char *ip, uint32_t ip_length, const Memory *mem)
{
    if (dht_get_nodes_response->ip != nullptr) {
        mem_delete(mem, dht_get_nodes_response->ip);
        dht_get_nodes_response->ip = nullptr;
        dht_get_nodes_response->ip_length = 0;
    }

    uint8_t *ip_tmp = (uint8_t *)mem_balloc(mem, ip_length);

    if (ip_tmp == nullptr) {
        return false;
    }

    memcpy(ip_tmp, ip, ip_length);
    dht_get_nodes_response->ip = ip_tmp;
    dht_get_nodes_response->ip_length = ip_length;
    return true;
}
uint32_t tox_event_dht_get_nodes_response_get_ip_length(const Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response)
{
    return dht_get_nodes_response->ip_length;
}
const uint8_t *tox_event_dht_get_nodes_response_get_ip(const Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response)
{
    return dht_get_nodes_response->ip;
}

non_null()
static bool tox_event_dht_get_nodes_response_set_port(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response, uint16_t port)
{
    dht_get_nodes_response->port = port;
    return true;
}
uint16_t tox_event_dht_get_nodes_response_get_port(const Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response)
{
    return dht_get_nodes_response->port;
}

non_null()
static void tox_event_dht_get_nodes_response_construct(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response)
{
    *dht_get_nodes_response = (Tox_Event_Dht_Get_Nodes_Response) {
        {
            0
        }
    };
}
non_null()
static void tox_event_dht_get_nodes_response_destruct(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response, const Memory *mem)
{
    mem_delete(mem, dht_get_nodes_response->ip);
}

bool tox_event_dht_get_nodes_response_pack(
    const Tox_Event_Dht_Get_Nodes_Response *event, Bin_Pack *bp)
{
    return bin_pack_array(bp, 3)
           && bin_pack_bin(bp, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_pack_bin(bp, event->ip, event->ip_length)
           && bin_pack_u16(bp, event->port);
}

non_null()
static bool tox_event_dht_get_nodes_response_unpack_into(
    Tox_Event_Dht_Get_Nodes_Response *event, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_bin_fixed(bu, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_unpack_bin(bu, &event->ip, &event->ip_length)
           && bin_unpack_u16(bu, &event->port);
}

const Tox_Event_Dht_Get_Nodes_Response *tox_event_get_dht_get_nodes_response(
    const Tox_Event *event)
{
    return event->type == TOX_EVENT_DHT_GET_NODES_RESPONSE ? event->data.dht_get_nodes_response : nullptr;
}

Tox_Event_Dht_Get_Nodes_Response *tox_event_dht_get_nodes_response_new(const Memory *mem)
{
    Tox_Event_Dht_Get_Nodes_Response *const dht_get_nodes_response =
        (Tox_Event_Dht_Get_Nodes_Response *)mem_alloc(mem, sizeof(Tox_Event_Dht_Get_Nodes_Response));

    if (dht_get_nodes_response == nullptr) {
        return nullptr;
    }

    tox_event_dht_get_nodes_response_construct(dht_get_nodes_response);
    return dht_get_nodes_response;
}

void tox_event_dht_get_nodes_response_free(Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response, const Memory *mem)
{
    if (dht_get_nodes_response != nullptr) {
        tox_event_dht_get_nodes_response_destruct(dht_get_nodes_response, mem);
    }
    mem_delete(mem, dht_get_nodes_response);
}

non_null()
static Tox_Event_Dht_Get_Nodes_Response *tox_events_add_dht_get_nodes_response(Tox_Events *events, const Memory *mem)
{
    Tox_Event_Dht_Get_Nodes_Response *const dht_get_nodes_response = tox_event_dht_get_nodes_response_new(mem);

    if (dht_get_nodes_response == nullptr) {
        return nullptr;
    }

    Tox_Event event;
    event.type = TOX_EVENT_DHT_GET_NODES_RESPONSE;
    event.data.dht_get_nodes_response = dht_get_nodes_response;

    tox_events_add(events, &event);
    return dht_get_nodes_response;
}

bool tox_event_dht_get_nodes_response_unpack(
    Tox_Event_Dht_Get_Nodes_Response **event, Bin_Unpack *bu, const Memory *mem)
{
    *event = tox_event_dht_get_nodes_response_new(mem);

    if (*event == nullptr) {
        return false;
    }

    return tox_event_dht_get_nodes_response_unpack_into(*event, bu);
}

non_null()
static Tox_Event_Dht_Get_Nodes_Response *tox_event_dht_get_nodes_response_alloc(void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return nullptr;
    }

    Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response = tox_events_add_dht_get_nodes_response(state->events, state->mem);

    if (dht_get_nodes_response == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return nullptr;
    }

    return dht_get_nodes_response;
}

/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_dht_get_nodes_response(
    Tox *tox, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE],
    const char *ip, uint16_t port, void *user_data)
{
    Tox_Event_Dht_Get_Nodes_Response *dht_get_nodes_response = tox_event_dht_get_nodes_response_alloc(user_data);

    if (dht_get_nodes_response == nullptr) {
        return;
    }

    const size_t ip_length = strlen(ip);
    if (ip_length >= UINT32_MAX) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_dht_get_nodes_response_set_public_key(dht_get_nodes_response, public_key);
    tox_event_dht_get_nodes_response_set_ip(dht_get_nodes_response, ip, ip_length + 1, sys->mem);
    tox_event_dht_get_nodes_response_set_port(dht_get_nodes_response, port);
}
