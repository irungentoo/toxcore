/* network.h
 *
 * Functions for the core networking.
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

#include "network.h"

/*  return current UNIX time in microseconds (us). */
uint64_t current_time(void)
{
    uint64_t time;
#ifdef WIN32
    /* This probably works fine */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    time = ft.dwHighDateTime;
    time <<= 32;
    time |= ft.dwLowDateTime;
    time -= 116444736000000000UL;
    return time / 10;
#else
    struct timeval a;
    gettimeofday(&a, NULL);
    time = 1000000UL * a.tv_sec + a.tv_usec;
    return time;
#endif
}

/*  return a random number.
 * NOTE: This function should probably not be used where cryptographic randomness is absolutely necessary.
 */
uint32_t random_int(void)
{
#ifndef VANILLA_NACL
    /* NOTE: this function comes from libsodium. */
    return randombytes_random();
#else
    return random();
#endif
}

/* Basic network functions:
 * Function to send packet(data) of length length to ip_port.
 */
#ifdef WIN32
int sendpacket(unsigned int sock, IP_Port ip_port, uint8_t *data, uint32_t length)
#else
int sendpacket(int sock, IP_Port ip_port, uint8_t *data, uint32_t length)
#endif
{
    ADDR addr = {AF_INET, ip_port.port, ip_port.ip, {0}};
    return sendto(sock, (char *) data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
}

/* Function to receive data
 *  ip and port of sender is put into ip_port.
 *  Packet data is put into data.
 *  Packet length is put into length.
 *  Dump all empty packets.
 */
#ifdef WIN32
static int receivepacket(unsigned int sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
#else
static int receivepacket(int sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
#endif
{
    ADDR addr;
#ifdef WIN32
    int addrlen = sizeof(addr);
#else
    uint32_t addrlen = sizeof(addr);
#endif
    (*(int32_t *)length) = recvfrom(sock, (char *) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

    if (*(int32_t *)length <= 0)
        return -1; /* Nothing received or empty packet. */

    ip_port->ip = addr.ip;
    ip_port->port = addr.port;
    return 0;
}

void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object)
{
    net->packethandlers[byte].function = cb;
    net->packethandlers[byte].object = object;
}

void networking_poll(Networking_Core *net)
{
    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (receivepacket(net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) continue;

        if (!(net->packethandlers[data[0]].function)) continue;

        net->packethandlers[data[0]].function(net->packethandlers[data[0]].object, ip_port, data, length);
    }
}

uint8_t at_startup_ran;
static int at_startup(void)
{
    if (at_startup_ran != 0)
        return 0;

#ifdef WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        return -1;

#else
    srandom((uint32_t)current_time());
#endif
    srand((uint32_t)current_time());
    at_startup_ran = 1;
    return 0;
}

/* TODO: Put this somewhere
static void at_shutdown(void)
{
#ifdef WIN32
    WSACleanup();
#endif
}
*/

/* Initialize networking.
 * Bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 *  return Networking_Core object if no problems
 *  return NULL if there are problems.
 */
Networking_Core *new_networking(IP ip, uint16_t port)
{
    if (at_startup() != 0)
        return NULL;

    /* Initialize our socket. */
    Networking_Core *temp = calloc(1, sizeof(Networking_Core));

    if (temp == NULL)
        return NULL;

    temp->sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    /* Check for socket error. */
#ifdef WIN32

    if (temp->sock == INVALID_SOCKET) { /* MSDN recommends this. */
        free(temp);
        return NULL;
    }

#else

    if (temp->sock < 0) {
        free(temp);
        return NULL;
    }

#endif

    /* Functions to increase the size of the send and receive UDP buffers.
     * NOTE: Uncomment if necessary.
     */
    /*
    int n = 1024 * 1024 * 2;
    if(setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char*)&n, sizeof(n)) == -1)
    {
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char*)&n, sizeof(n)) == -1)
        return -1;
    */

    /* Enable broadcast on socket. */
    int broadcast = 1;
    setsockopt(temp->sock, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));

    /* Set socket nonblocking. */
#ifdef WIN32
    /* I think this works for Windows. */
    u_long mode = 1;
    /* ioctl(sock, FIONBIO, &mode); */
    ioctlsocket(temp->sock, FIONBIO, &mode);
#else
    fcntl(temp->sock, F_SETFL, O_NONBLOCK, 1);
#endif

    /* Bind our socket to port PORT and address 0.0.0.0 */
    ADDR addr = {AF_INET, htons(port), ip, {0}};
    bind(temp->sock, (struct sockaddr *)&addr, sizeof(addr));
    return temp;
}

/* Function to cleanup networking stuff. */
void kill_networking(Networking_Core *net)
{
#ifdef WIN32
    closesocket(net->sock);
#else
    close(net->sock);
#endif
    free(net);
    return;
}
