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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
int sendpacket(Networking_Core *net, IP_Port ip_port, uint8_t *data, uint32_t length)
{
    ADDR addr = {AF_INET, ip_port.port, ip_port.ip, {0}};
    return sendto(net->sock, (char *) data, length, 0, (struct sockaddr *)&addr, sizeof(addr));
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
Networking_Core *new_networking(IP4 ip, uint16_t port)
{
    if (at_startup() != 0)
        return NULL;

    /* Initialize our socket. */
    Networking_Core *temp = calloc(1, sizeof(Networking_Core));

    if (temp == NULL)
        return NULL;

    temp->family = AF_INET;
    temp->sock = socket(temp->family, SOCK_DGRAM, IPPROTO_UDP);

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
    ADDR addr = {temp->family, htons(port), ip, {0}};
    if (!bind(temp->sock, (struct sockaddr *)&addr, sizeof(addr)))
        temp->port = port;

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

/* ipany_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 */
/* there would be INET6_ADDRSTRLEN, but it might be too short for the error message */
static char addresstext[96];
const char *ipany_ntoa(IPAny *ip)
{
    if (ip) {
        if (ip->family == AF_INET) {
            addresstext[0] = 0;
            struct in_addr *addr = (struct in_addr *)&ip->ip4;
            inet_ntop(ip->family, addr, addresstext, sizeof(addresstext));
        }
        else if (ip->family == AF_INET6) {
            addresstext[0] = '[';
            struct in6_addr *addr = (struct in6_addr *)&ip->ip6;
            inet_ntop(ip->family, addr, &addresstext[1], sizeof(addresstext) - 3);
            size_t len = strlen(addresstext);
            addresstext[len] = ']';
            addresstext[len + 1] = 0;
        }
        else
            snprintf(addresstext, sizeof(addresstext), "(IP invalid, family %u)", ip->family);
    }
    else
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");

    addresstext[INET6_ADDRSTRLEN + 2] = 0;
    return addresstext;
};

/*
 * addr_parse_ip
 *  directly parses the input into an IP structure
 *  tries IPv4 first, then IPv6
 *
 * input
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * output
 *  IP: family and the value is set on success
 *
 * returns 1 on success, 0 on failure
 */

int addr_parse_ip(const char *address, IPAny *to)
{
    struct in_addr addr4;
    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->family = AF_INET;
        to->ip4.in_addr = addr4;
        return 1;
    };

    struct in6_addr addr6;
    if (1 == inet_pton(AF_INET6, address, &addr6)) {
        to->family = AF_INET6;
        to->ip6 = addr6;
        return 1;
    };

    return 0;
};

/*
 * addr_resolve():
 *  uses getaddrinfo to resolve an address into an IP address
 *  uses the first IPv4/IPv6 addresses returned by getaddrinfo
 *
 * input
 *  address: a hostname (or something parseable to an IP address)
 *  ip: ip.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *
 * returns in ip a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was AF_UNSPEC and both available
 * returns 0 on failure
 */

int addr_resolve(const char *address, IPAny *ip)
{
    struct addrinfo *server = NULL;
    struct addrinfo *walker = NULL;
    struct addrinfo  hints;
    int              rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = ip->family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

#ifdef __WIN32__
    WSADATA wsa_data;

    /* CLEANUP: really not the best place to put this */
    rc = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (rc != 0) {
        return 0;
    }

#endif

    rc = getaddrinfo(address, NULL, &hints, &server);
    // Lookup failed.
    if (rc != 0) {
#ifdef __WIN32__
        WSACleanup();
#endif
        return 0;
    }

    IP4 ip4;
    memset(&ip4, 0, sizeof(ip4));
    IP6 ip6;
    memset(&ip6, 0, sizeof(ip6));

    walker = server;
    while (walker && (rc != 3)) {
        if (ip->family != AF_UNSPEC) {
            if (walker->ai_family == ip->family) {
                if (ip->family == AF_INET) {
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in)) {
                        struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                        ip->ip4.in_addr = addr->sin_addr;
                        rc = 3;
                    }
                }
                else if (ip->family == AF_INET6) {
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                        ip->ip6 = addr->sin6_addr;
                        rc = 3;
                    }
                }
            }
        }
        else {
            if (walker->ai_family == AF_INET) {
                if (walker->ai_addrlen == sizeof(struct sockaddr_in)) {
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    ip4.in_addr = addr->sin_addr;
                    rc |= 1;
                }
            }
            else if (walker->ai_family == AF_INET6) {
                if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                    struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                    ip6 = addr->sin6_addr;
                    rc |= 2;
                }
            }
        }

        walker = walker->ai_next;
    }

    if (ip->family == AF_UNSPEC) {
        if (rc & 2) {
            ip->family = AF_INET6;
            ip->ip6 = ip6;
        }
        else if (rc & 1) {
            ip->family = AF_INET;
            ip->ip4 = ip4;
        }
        else
            rc = 0;
    }

    
    freeaddrinfo(server);
#ifdef __WIN32__
    WSACleanup();
#endif
    return rc;
}

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 * to->family MUST be set (AF_UNSPEC, AF_INET, AF_INET6)
 * returns 1 on success, 0 on failure
 */
int addr_resolve_or_parse_ip(const char *address, IPAny *to)
{
    if (!addr_resolve(address, to))
        if (!addr_parse_ip(address, to))
            return 0;

    return 1;
};
