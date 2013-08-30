/*  LAN_discovery.c
 *
 *  LAN discovery implementation.
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

#include "LAN_discovery.h"

#define MAX_INTERFACES 16

#ifdef __linux
/* Get the first working broadcast address that's not from "lo".
 *  returns higher than 0 on success.
 *  returns 0 on error.
 */
static uint32_t get_broadcast(void)
{
    /* Not sure how many platforms this will run on,
     * so it's wrapped in __linux for now.
     */
    struct sockaddr_in *sock_holder = NULL;
    struct ifreq i_faces[MAX_INTERFACES];
    struct ifconf ifconf;
    int count = 0;
    int sock = 0;
    int i = 0;

    /* Configure ifconf for the ioctl call. */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("[!] get_broadcast: socket() error");
        return 0;
    }

    memset(i_faces, 0, sizeof(struct ifreq) * MAX_INTERFACES);

    ifconf.ifc_buf = (char *)i_faces;
    ifconf.ifc_len = sizeof(i_faces);
    count = ifconf.ifc_len / sizeof(struct ifreq);

    if (ioctl(sock, SIOCGIFCONF, &ifconf) < 0) {
        perror("get_broadcast: ioctl() error");
        return 0;
    }

    for (i = 0; i < count; i++) {
        /* Skip the loopback interface, as it's useless. */
        if (strcmp(i_faces[i].ifr_name, "lo") != 0) {
            if (ioctl(sock, SIOCGIFBRDADDR, &i_faces[i]) < 0) {
                perror("[!] get_broadcast: ioctl error");
                return 0;
            }

            /* Just to clarify where we're getting the values from. */
            sock_holder = (struct sockaddr_in *)&i_faces[i].ifr_broadaddr;
            break;
        }
    }

    close(sock);

    if (sock_holder == NULL) {
        perror("[!] no broadcast device found");
        return 0;
    }

    return sock_holder->sin_addr.s_addr;
}
#endif

/* Return the broadcast ip. */
static IP broadcast_ip(void)
{
    IP ip;
#ifdef __linux
    ip.uint32 = get_broadcast();

    if (ip.uint32 == 0)
        ip.uint32 = ~0; /* Error occured, but try anyway? */

#else
    ip.uint32 = ~0;
#endif
    return ip;
}

/* return 0 if ip is a LAN ip.
 * return -1 if it is not.
 */
static int LAN_ip(IP ip)
{
    if (ip.uint8[0] == 127) /* Loopback. */
        return 0;

    if (ip.uint8[0] == 10) /* 10.0.0.0 to 10.255.255.255 range. */
        return 0;

    if (ip.uint8[0] == 172 && ip.uint8[1] >= 16 && ip.uint8[1] <= 31) /* 172.16.0.0 to 172.31.255.255 range. */
        return 0;

    if (ip.uint8[0] == 192 && ip.uint8[1] == 168) /* 192.168.0.0 to 192.168.255.255 range. */
        return 0;

    if (ip.uint8[0] == 169 && ip.uint8[1] == 254 && ip.uint8[2] != 0
            && ip.uint8[2] != 255)/* 169.254.1.0 to 169.254.254.255 range. */
        return 0;

    return -1;
}

static int handle_LANdiscovery(void *object, IP_Port source, uint8_t *packet, uint32_t length)
{
    DHT *dht = object;

    if (LAN_ip(source.ip) == -1)
        return 1;

    if (length != crypto_box_PUBLICKEYBYTES + 1)
        return 1;

    DHT_bootstrap(dht, source, packet + 1);
    return 0;
}


int send_LANdiscovery(uint16_t port, Net_Crypto *c)
{
    uint8_t data[crypto_box_PUBLICKEYBYTES + 1];
    data[0] = NET_PACKET_LAN_DISCOVERY;
    memcpy(data + 1, c->self_public_key, crypto_box_PUBLICKEYBYTES);
    IP_Port ip_port = {{broadcast_ip(), port}};
    return sendpacket(c->lossless_udp->net->sock, ip_port, data, 1 + crypto_box_PUBLICKEYBYTES);
}


void LANdiscovery_init(DHT *dht)
{
    networking_registerhandler(dht->c->lossless_udp->net, NET_PACKET_LAN_DISCOVERY, &handle_LANdiscovery, dht);
}
