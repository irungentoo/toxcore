/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2026 The TokTok team.
 */

/**
 * Functions for the network profile.
 */

#include "net_profile.h"

#include <stdint.h>

#include "attributes.h"
#include "logger.h"
#include "mem.h"

#include "ccompat.h"

#define NETPROF_TCP_DATA_PACKET_ID 0x10

typedef struct Net_Profile {
    uint64_t packets_recv[NET_PROF_MAX_PACKET_IDS];
    uint64_t packets_sent[NET_PROF_MAX_PACKET_IDS];

    uint64_t total_packets_recv;
    uint64_t total_packets_sent;

    uint64_t bytes_recv[NET_PROF_MAX_PACKET_IDS];
    uint64_t bytes_sent[NET_PROF_MAX_PACKET_IDS];

    uint64_t total_bytes_recv;
    uint64_t total_bytes_sent;
} Net_Profile;

/** Returns the number of sent or received packets for all ID's between `start_id` and `end_id`. */
static uint64_t netprof_get_packet_count_id_range(const Net_Profile *_Nullable profile, uint8_t start_id, uint8_t end_id,
        Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    const uint64_t *arr = dir == PACKET_DIRECTION_SEND ? profile->packets_sent : profile->packets_recv;
    uint64_t count = 0;

    for (size_t i = start_id; i <= end_id; ++i) {
        count += arr[i];
    }

    return count;
}

/** Returns the number of sent or received bytes for all ID's between `start_id` and `end_id`. */
static uint64_t netprof_get_bytes_id_range(const Net_Profile *_Nullable profile, uint8_t start_id, uint8_t end_id,
        Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    const uint64_t *arr = dir == PACKET_DIRECTION_SEND ? profile->bytes_sent : profile->bytes_recv;
    uint64_t bytes = 0;

    for (size_t i = start_id; i <= end_id; ++i) {
        bytes += arr[i];
    }

    return bytes;
}

void netprof_record_packet(Net_Profile *profile, uint8_t id, size_t length, Packet_Direction dir)
{
    if (profile == nullptr) {
        return;
    }

    if (dir == PACKET_DIRECTION_SEND) {
        ++profile->total_packets_sent;
        ++profile->packets_sent[id];

        profile->total_bytes_sent += length;
        profile->bytes_sent[id] += length;
    } else {
        ++profile->total_packets_recv;
        ++profile->packets_recv[id];

        profile->total_bytes_recv += length;
        profile->bytes_recv[id] += length;
    }
}

uint64_t netprof_get_packet_count_id(const Net_Profile *profile, uint8_t id, Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    // Special case - TCP data packets can have any ID between 0x10 and 0xff
    if (id == NETPROF_TCP_DATA_PACKET_ID) {
        return netprof_get_packet_count_id_range(profile, id, UINT8_MAX, dir);
    }

    return dir == PACKET_DIRECTION_SEND ? profile->packets_sent[id] : profile->packets_recv[id];
}

uint64_t netprof_get_packet_count_total(const Net_Profile *profile, Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    return dir == PACKET_DIRECTION_SEND ? profile->total_packets_sent : profile->total_packets_recv;
}

uint64_t netprof_get_bytes_id(const Net_Profile *profile, uint8_t id, Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    // Special case - TCP data packets can have any ID between 0x10 and 0xff
    if (id == NETPROF_TCP_DATA_PACKET_ID) {
        return netprof_get_bytes_id_range(profile, id, 0xff, dir);
    }

    return dir == PACKET_DIRECTION_SEND ? profile->bytes_sent[id] : profile->bytes_recv[id];
}

uint64_t netprof_get_bytes_total(const Net_Profile *profile, Packet_Direction dir)
{
    if (profile == nullptr) {
        return 0;
    }

    return dir == PACKET_DIRECTION_SEND ? profile->total_bytes_sent : profile->total_bytes_recv;
}

Net_Profile *netprof_new(const Logger *log, const Memory *mem)
{
    Net_Profile *np = (Net_Profile *)mem_alloc(mem, sizeof(Net_Profile));

    if (np == nullptr) {
        LOGGER_ERROR(log, "failed to allocate memory for net profiler");
        return nullptr;
    }

    return np;
}

void netprof_kill(const Memory *mem, Net_Profile *net_profile)
{
    if (net_profile != nullptr) {
        mem_delete(mem, net_profile);
    }
}
