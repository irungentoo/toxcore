/* connection.c
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

#include "connection.h"

void process_connection()
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;
    while (receivepacket(&ip_port, data, &length) != -1) {
#ifdef DEBUG
        /* if(rand() % 3 != 1) //simulate packet loss */
        /* { */
        if (DHT_handlepacket(data, length, ip_port) && LosslessUDP_handlepacket(data, length, ip_port) &&
            friendreq_handlepacket(data, length, ip_port) && LANdiscovery_handlepacket(data, length, ip_port))
            /* if packet is discarded */
            printf("Received unhandled packet with length: %u\n", length);
        else
            printf("Received handled packet with length: %u\n", length);
        /* } */
        printf("Status: %u %u %u\n",friendlist[0].status ,is_cryptoconnected(friendlist[0].crypt_connection_id),  friendlist[0].crypt_connection_id);
#else
        DHT_handlepacket(data, length, ip_port);
        LosslessUDP_handlepacket(data, length, ip_port);
        friendreq_handlepacket(data, length, ip_port);
        LANdiscovery_handlepacket(data, length, ip_port);
#endif

    }
}

/*  process incoming data from friend
 * returns 1 if processed or 0 if not */
int received_friend_packet(int friendId, int connectionId)
{
    int len;
    uint8_t temp[MAX_DATA_SIZE];

    len = read_cryptpacket(connectionId, temp);
    if (len > 0) {
        switch (temp[0]) {
            case PACKET_ID_NICKNAME: friend_change_nickname(friendId, temp + 1, len - 1); break;
            case PACKET_ID_USERSTATUS: friend_change_userstate(friendId, temp + 1, len - 1); break;
            case PACKET_ID_MESSAGE: message_received(friendId, temp + 1, len); break;
        }
    } else {
        if (is_cryptoconnected(connectionId) == 4) { /* if the connection timed out, kill it */
            crypto_kill(connectionId);
            friend_disconnect(friendId);
        }
        return 1;
    }
    return 0;
}


int send_friend_packet(int friendId, int packetType, uint8_t *message, uint32_t length)
{
    if (length >= MAX_DATA_SIZE) {
        /* this does not mean the maximum message length is MAX_DATA_SIZE - 1, it is actually 17 bytes less. */
        return 0;
    }

    int cryptConnectionId = get_friend_connection_id(friendId);
    uint8_t temp[MAX_DATA_SIZE];
    temp[0] = packetType;
    memcpy(temp + 1, message, length);
    return write_cryptpacket(cryptConnectionId, temp, length + 1);
}
