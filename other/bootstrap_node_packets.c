/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Special bootstrap node only packets.
 *
 * Include it in your bootstrap node and use: bootstrap_set_callbacks() to enable.
 */
#include "bootstrap_node_packets.h"

#include <string.h>

#include "../toxcore/network.h"

#define INFO_REQUEST_PACKET_LENGTH 78

static uint32_t bootstrap_version;
static uint8_t bootstrap_motd[MAX_MOTD_LENGTH];
static uint16_t bootstrap_motd_length;

/* To request this packet just send a packet of length INFO_REQUEST_PACKET_LENGTH
 * with the first byte being BOOTSTRAP_INFO_PACKET_ID
 */
static int handle_info_request(void *object, const IP_Port *source, const uint8_t *packet, uint16_t length,
                               void *userdata)
{
    if (length != INFO_REQUEST_PACKET_LENGTH) {
        return 1;
    }

    const Networking_Core *nc = (const Networking_Core *)object;

    uint8_t data[1 + sizeof(bootstrap_version) + MAX_MOTD_LENGTH];
    data[0] = BOOTSTRAP_INFO_PACKET_ID;
    memcpy(data + 1, &bootstrap_version, sizeof(bootstrap_version));
    const uint16_t len = 1 + sizeof(bootstrap_version) + bootstrap_motd_length;
    memcpy(data + 1 + sizeof(bootstrap_version), bootstrap_motd, bootstrap_motd_length);

    if (sendpacket(nc, source, data, len) == len) {
        return 0;
    }

    return 1;
}

int bootstrap_set_callbacks(Networking_Core *net, uint32_t version, const uint8_t *motd, uint16_t motd_length)
{
    if (motd_length > MAX_MOTD_LENGTH) {
        return -1;
    }

    bootstrap_version = net_htonl(version);
    memcpy(bootstrap_motd, motd, motd_length);
    bootstrap_motd_length = motd_length;

    networking_registerhandler(net, BOOTSTRAP_INFO_PACKET_ID, &handle_info_request, net);
    return 0;
}
