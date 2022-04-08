/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#include "group_announce.h"

#include <stdlib.h>
#include <string.h>

#include "LAN_discovery.h"
#include "ccompat.h"
#include "mono_time.h"
#include "util.h"

/**
 * Removes `announces` from `gc_announces_list`.
 */
non_null()
static void remove_announces(GC_Announces_List *gc_announces_list, GC_Announces *announces)
{
    if (announces == nullptr || gc_announces_list == nullptr) {
        return;
    }

    if (announces->prev_announce != nullptr) {
        announces->prev_announce->next_announce = announces->next_announce;
    } else {
        gc_announces_list->root_announces = announces->next_announce;
    }

    if (announces->next_announce != nullptr) {
        announces->next_announce->prev_announce = announces->prev_announce;
    }

    free(announces);
}

/**
 * Returns the announce designated by `chat_id`.
 * Returns null if no announce is found.
 */
non_null()
static GC_Announces *get_announces_by_chat_id(const GC_Announces_List *gc_announces_list,  const uint8_t *chat_id)
{
    GC_Announces *announces = gc_announces_list->root_announces;

    while (announces != nullptr) {
        if (memcmp(announces->chat_id, chat_id, CHAT_ID_SIZE) == 0) {
            return announces;
        }

        announces = announces->next_announce;
    }

    return nullptr;
}

int gca_get_announces(const GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                      const uint8_t *chat_id, const uint8_t *except_public_key)
{
    if (gc_announces == nullptr || gc_announces_list == nullptr || chat_id == nullptr || max_nodes == 0
            || except_public_key == nullptr) {
        return -1;
    }

    const GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, chat_id);

    if (announces == nullptr) {
        return 0;
    }

    uint16_t added_count = 0;

    for (size_t i = 0; i < announces->index && i < GCA_MAX_SAVED_ANNOUNCES_PER_GC && added_count < max_nodes; ++i) {
        const size_t index = i % GCA_MAX_SAVED_ANNOUNCES_PER_GC;

        if (memcmp(except_public_key, &announces->peer_announces[index].base_announce.peer_public_key,
                   ENC_PUBLIC_KEY_SIZE) == 0) {
            continue;
        }

        bool already_added = false;

        for (size_t j = 0; j < added_count; ++j) {
            if (memcmp(&gc_announces[j].peer_public_key, &announces->peer_announces[index].base_announce.peer_public_key,
                       ENC_PUBLIC_KEY_SIZE) == 0) {
                already_added = true;
                break;
            }
        }

        if (!already_added) {
            gc_announces[added_count] = announces->peer_announces[index].base_announce;
            ++added_count;
        }
    }

    return added_count;
}

uint16_t gca_pack_announces_list_size(uint16_t count)
{
    return count * GCA_ANNOUNCE_MAX_SIZE;
}

int gca_pack_announce(const Logger *log, uint8_t *data, uint16_t length, const GC_Announce *announce)
{
    if (length < GCA_ANNOUNCE_MAX_SIZE) {
        LOGGER_ERROR(log, "Invalid announce length: %u", length);
        return -1;
    }

    if (data == nullptr) {
        LOGGER_ERROR(log, "data is null");
        return -1;
    }

    if (announce == nullptr) {
        LOGGER_ERROR(log, "announce is null");
        return -1;
    }

    uint16_t offset = 0;
    memcpy(data + offset, announce->peer_public_key, ENC_PUBLIC_KEY_SIZE);
    offset += ENC_PUBLIC_KEY_SIZE;

    data[offset] = announce->ip_port_is_set ? 1 : 0;
    ++offset;

    data[offset] = announce->tcp_relays_count;
    ++offset;

    if (!announce->ip_port_is_set && announce->tcp_relays_count == 0) {
        LOGGER_ERROR(log, "Failed to pack announce: no valid ip_port or tcp relay");
        return -1;
    }

    if (announce->ip_port_is_set) {
        const int ip_port_length = pack_ip_port(log, data + offset, length - offset, &announce->ip_port);

        if (ip_port_length == -1) {
            LOGGER_ERROR(log, "Failed to pack ip_port");
            return -1;
        }

        offset += ip_port_length;
    }

    const int nodes_length = pack_nodes(log, data + offset, length - offset, announce->tcp_relays,
                                        announce->tcp_relays_count);

    if (nodes_length == -1) {
        LOGGER_ERROR(log, "Failed to pack TCP nodes");
        return -1;
    }

    return nodes_length + offset;
}

/**
 * Unpacks `announce` into `data` buffer of size `length`.
 *
 * Returns the size of the unpacked data on success.
 * Returns -1 on failure.
 */
non_null()
static int gca_unpack_announce(const Logger *log, const uint8_t *data, uint16_t length, GC_Announce *announce)
{
    if (length < ENC_PUBLIC_KEY_SIZE + 2) {
        LOGGER_ERROR(log, "Invalid announce length: %u", length);
        return -1;
    }

    if (data == nullptr) {
        LOGGER_ERROR(log, "data is null");
        return -1;
    }

    if (announce == nullptr) {
        LOGGER_ERROR(log, "announce is null");
        return -1;
    }

    uint16_t offset = 0;
    memcpy(announce->peer_public_key, data + offset, ENC_PUBLIC_KEY_SIZE);
    offset += ENC_PUBLIC_KEY_SIZE;

    announce->ip_port_is_set = data[offset] == 1;
    ++offset;

    announce->tcp_relays_count = data[offset];
    ++offset;

    if (announce->tcp_relays_count > GCA_MAX_ANNOUNCED_TCP_RELAYS) {
        return -1;
    }

    if (announce->ip_port_is_set) {
        if (length - offset == 0) {
            return -1;
        }

        const int ip_port_length = unpack_ip_port(&announce->ip_port, data + offset, length - offset, false);

        if (ip_port_length == -1) {
            LOGGER_ERROR(log, "Failed to unpack ip_port");
            return -1;
        }

        offset += ip_port_length;
    }

    uint16_t nodes_length;
    const int nodes_count = unpack_nodes(announce->tcp_relays, announce->tcp_relays_count, &nodes_length,
                                         data + offset, length - offset, true);

    if (nodes_count != announce->tcp_relays_count) {
        LOGGER_ERROR(log, "Failed to unpack TCP nodes");
        return -1;
    }

    return offset + nodes_length;
}

int gca_pack_public_announce(const Logger *log, uint8_t *data, uint16_t length,
                             const GC_Public_Announce *public_announce)
{
    if (public_announce == nullptr || data == nullptr || length < CHAT_ID_SIZE) {
        return -1;
    }

    memcpy(data, public_announce->chat_public_key, CHAT_ID_SIZE);

    const int packed_size = gca_pack_announce(log, data + CHAT_ID_SIZE, length - CHAT_ID_SIZE,
                            &public_announce->base_announce);

    if (packed_size < 0) {
        LOGGER_ERROR(log, "Failed to pack public group announce");
        return -1;
    }

    return packed_size + CHAT_ID_SIZE;
}

int gca_unpack_public_announce(const Logger *log, const uint8_t *data, uint16_t length,
                               GC_Public_Announce *public_announce)
{
    if (length < CHAT_ID_SIZE) {
        LOGGER_ERROR(log, "invalid public announce length: %u", length);
        return -1;
    }

    if (data == nullptr) {
        LOGGER_ERROR(log, "data is null");
        return -1;
    }

    if (public_announce == nullptr) {
        LOGGER_ERROR(log, "public_announce is null");
        return -1;
    }

    memcpy(public_announce->chat_public_key, data, CHAT_ID_SIZE);

    const int base_announce_size = gca_unpack_announce(log, data + ENC_PUBLIC_KEY_SIZE, length - ENC_PUBLIC_KEY_SIZE,
                                   &public_announce->base_announce);

    if (base_announce_size == -1) {
        LOGGER_ERROR(log, "Failed to unpack group announce");
        return -1;
    }

    return base_announce_size + CHAT_ID_SIZE;
}

int gca_pack_announces_list(const Logger *log, uint8_t *data, uint16_t length, const GC_Announce *announces,
                            uint8_t announces_count, size_t *processed)
{
    if (data == nullptr) {
        LOGGER_ERROR(log, "data is null");
        return -1;
    }

    if (announces == nullptr) {
        LOGGER_ERROR(log, "announces is null");
        return -1;
    }

    uint16_t offset = 0;

    for (size_t i = 0; i < announces_count; ++i) {
        const int packed_length = gca_pack_announce(log, data + offset, length - offset, &announces[i]);

        if (packed_length < 0) {
            LOGGER_ERROR(log, "Failed to pack group announce");
            return -1;
        }

        offset += packed_length;
    }

    if (processed != nullptr) {
        *processed = offset;
    }

    return announces_count;
}

int gca_unpack_announces_list(const Logger *log, const uint8_t *data, uint16_t length, GC_Announce *announces,
                              uint8_t max_count)
{
    if (data == nullptr) {
        LOGGER_ERROR(log, "data is null");
        return -1;
    }

    if (announces == nullptr) {
        LOGGER_ERROR(log, "announces is null");
        return -1;
    }

    uint16_t offset = 0;
    int announces_count = 0;

    for (size_t i = 0; i < max_count && length > offset; ++i) {
        const int unpacked_length = gca_unpack_announce(log, data + offset, length - offset, &announces[i]);

        if (unpacked_length == -1) {
            LOGGER_WARNING(log, "Failed to unpack group announce: %d %d", length, offset);
            return -1;
        }

        offset += unpacked_length;
        ++announces_count;
    }

    return announces_count;
}

GC_Peer_Announce *gca_add_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list,
                                   const GC_Public_Announce *public_announce)
{
    if (gc_announces_list == nullptr || public_announce == nullptr) {
        return nullptr;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, public_announce->chat_public_key);

    // No entry for this chat_id exists so we create one
    if (announces == nullptr) {
        announces = (GC_Announces *)calloc(1, sizeof(GC_Announces));

        if (announces == nullptr) {
            return nullptr;
        }

        announces->index = 0;
        announces->prev_announce = nullptr;

        if (gc_announces_list->root_announces != nullptr) {
            gc_announces_list->root_announces->prev_announce = announces;
        }

        announces->next_announce = gc_announces_list->root_announces;
        gc_announces_list->root_announces = announces;
        memcpy(announces->chat_id, public_announce->chat_public_key, CHAT_ID_SIZE);
    }

    const uint64_t cur_time = mono_time_get(mono_time);

    announces->last_announce_received_timestamp = cur_time;

    const uint64_t index = announces->index % GCA_MAX_SAVED_ANNOUNCES_PER_GC;

    GC_Peer_Announce *gc_peer_announce = &announces->peer_announces[index];

    gc_peer_announce->base_announce = public_announce->base_announce;

    gc_peer_announce->timestamp = cur_time;

    ++announces->index;

    return gc_peer_announce;
}

bool gca_is_valid_announce(const GC_Announce *announce)
{
    if (announce == nullptr) {
        return false;
    }

    return announce->tcp_relays_count > 0 || announce->ip_port_is_set;
}

GC_Announces_List *new_gca_list(void)
{
    GC_Announces_List *announces_list = (GC_Announces_List *)calloc(1, sizeof(GC_Announces_List));
    return announces_list;
}

void kill_gca(GC_Announces_List *announces_list)
{
    if (announces_list == nullptr) {
        return;
    }

    GC_Announces *root = announces_list->root_announces;

    while (root != nullptr) {
        GC_Announces *next = root->next_announce;
        free(root);
        root = next;
    }

    free(announces_list);
}

/* How long we save a peer's announce before we consider it stale and remove it. */
#define GCA_ANNOUNCE_SAVE_TIMEOUT 30

/* How often we run do_gca() */
#define GCA_DO_GCA_TIMEOUT 1

void do_gca(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list)
{
    if (gc_announces_list == nullptr) {
        return;
    }

    if (!mono_time_is_timeout(mono_time, gc_announces_list->last_timeout_check, GCA_DO_GCA_TIMEOUT)) {
        return;
    }

    gc_announces_list->last_timeout_check = mono_time_get(mono_time);

    GC_Announces *announces = gc_announces_list->root_announces;

    while (announces != nullptr) {
        if (mono_time_is_timeout(mono_time, announces->last_announce_received_timestamp, GCA_ANNOUNCE_SAVE_TIMEOUT)) {
            GC_Announces *to_delete = announces;
            announces = announces->next_announce;
            remove_announces(gc_announces_list, to_delete);
            continue;
        }

        announces = announces->next_announce;
    }
}

void cleanup_gca(GC_Announces_List *gc_announces_list, const uint8_t *chat_id)
{
    if (gc_announces_list == nullptr || chat_id == nullptr) {
        return;
    }

    GC_Announces *announces = get_announces_by_chat_id(gc_announces_list, chat_id);

    if (announces != nullptr) {
        remove_announces(gc_announces_list, announces);
    }
}
