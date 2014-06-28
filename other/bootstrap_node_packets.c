/* bootstrap_node_packets.c
 *
 * Special bootstrap node only packets.
 *
 * Include it in your bootstrap node and use: bootstrap_set_callbacks() to enable.
 *
 *  Copyright (C) 2013 Tox project All Rights Reserved.
 *
 *  This file is part of Tox.
 *
 *  Tox is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Tox is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define MAX_MOTD_LENGTH 256 /* I recommend you use a maximum of 96 bytes. The hard maximum is this though. */

#define INFO_REQUEST_PACKET_LENGTH 78

static uint32_t bootstrap_version;
static uint8_t bootstrap_motd[MAX_MOTD_LENGTH];
static uint16_t bootstrap_motd_length;

/* To request this packet just send a packet of length INFO_REQUEST_PACKET_LENGTH
 * with the first byte being BOOTSTRAP_INFO_PACKET_ID
 */
static int handle_info_request(void *object, IP_Port source, const uint8_t *packet, uint32_t length)
{
    if (length != INFO_REQUEST_PACKET_LENGTH)
        return 1;

    uint8_t data[1 + sizeof(bootstrap_version) + MAX_MOTD_LENGTH];
    data[0] = BOOTSTRAP_INFO_PACKET_ID;
    memcpy(data + 1, &bootstrap_version, sizeof(bootstrap_version));
    uint16_t len = 1 + sizeof(bootstrap_version) + bootstrap_motd_length;
    memcpy(data + 1 + sizeof(bootstrap_version), bootstrap_motd, bootstrap_motd_length);

    if (sendpacket(object, source, data, len) == len)
        return 0;

    return 1;
}

int bootstrap_set_callbacks(Networking_Core *net, uint32_t version, uint8_t *motd, uint16_t motd_length)
{
    if (motd_length > MAX_MOTD_LENGTH)
        return -1;

    bootstrap_version = htonl(version);
    memcpy(bootstrap_motd, motd, motd_length);
    bootstrap_motd_length = motd_length;

    networking_registerhandler(net, BOOTSTRAP_INFO_PACKET_ID, &handle_info_request, net);
    return 0;
}
