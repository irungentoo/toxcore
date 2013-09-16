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
#include "util.h"

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
 */
uint32_t random_int(void)
{
#ifndef VANILLA_NACL
    /* NOTE: this function comes from libsodium. */
    return randombytes_random();
#else
    uint32_t randnum;
    randombytes((uint8_t *)&randnum , sizeof(randnum));
    return randnum;
#endif
}

#ifdef LOGGING
static void loglogdata(char *message, uint8_t *buffer, size_t buflen, IP_Port *ip_port, ssize_t res);
#endif

/* Basic network functions:
 * Function to send packet(data) of length length to ip_port.
 */
int sendpacket(Networking_Core *net, IP_Port ip_port, uint8_t *data, uint32_t length)
{
#ifdef TOX_ENABLE_IPV6

    /* socket AF_INET, but target IP NOT: can't send */
    if ((net->family == AF_INET) && (ip_port.ip.family != AF_INET))
        return -1;

#endif

    struct sockaddr_storage addr;
    size_t addrsize = 0;

#ifdef TOX_ENABLE_IPV6

    if (ip_port.ip.family == AF_INET) {
        if (net->family == AF_INET6) {
            /* must convert to IPV4-in-IPV6 address */
            addrsize = sizeof(struct sockaddr_in6);
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
            addr6->sin6_family = AF_INET6;
            addr6->sin6_port = ip_port.port;

            /* there should be a macro for this in a standards compliant
             * environment, not found */
            IP6 ip6;

            ip6.uint32[0] = 0;
            ip6.uint32[1] = 0;
            ip6.uint32[2] = htonl(0xFFFF);
            ip6.uint32[3] = ip_port.ip.ip4.uint32;
            addr6->sin6_addr = ip6.in6_addr;

            addr6->sin6_flowinfo = 0;
            addr6->sin6_scope_id = 0;
        } else {
            IP4 ip4 = ip_port.ip.ip4;
#else
    IP4 ip4 = ip_port.ip;
#endif
            addrsize = sizeof(struct sockaddr_in);
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
            addr4->sin_family = AF_INET;
            addr4->sin_addr = ip4.in_addr;
            addr4->sin_port = ip_port.port;
#ifdef TOX_ENABLE_IPV6
        }
    } else if (ip_port.ip.family == AF_INET6)
    {
        addrsize = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = ip_port.port;
        addr6->sin6_addr = ip_port.ip.ip6.in6_addr;

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
    } else
    {
        /* unknown address type*/
        return -1;
    }

#endif

    int res = sendto(net->sock, (char *) data, length, 0, (struct sockaddr *)&addr, addrsize);
#ifdef LOGGING
    loglogdata("O=>", data, length, &ip_port, res);
#endif
    return res;
}

/* Function to receive data
 *  ip and port of sender is put into ip_port.
 *  Packet data is put into data.
 *  Packet length is put into length.
 *  Dump all empty packets.
 */
static int receivepacket(sock_t sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
{
    struct sockaddr_storage addr;
#ifdef WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif
    *length = 0;
    int fail_or_len = recvfrom(sock, (char *) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

    if (fail_or_len <= 0) {
#ifdef LOGGING

        if ((fail_or_len < 0) && (errno != EWOULDBLOCK)) {
            sprintf(logbuffer, "Unexpected error reading from socket: %u, %s\n", errno, strerror(errno));
            loglog(logbuffer);
        }

#endif
        return -1; /* Nothing received or empty packet. */
    }

    *length = (uint32_t)fail_or_len;

#ifdef TOX_ENABLE_IPV6

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        ip_port->ip.family = addr_in->sin_family;
        ip_port->ip.ip4.in_addr = addr_in->sin_addr;
        ip_port->port = addr_in->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        ip_port->ip.family = addr_in6->sin6_family;
        ip_port->ip.ip6.in6_addr = addr_in6->sin6_addr;
        ip_port->port = addr_in6->sin6_port;
    } else
        return -1;

#else

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        ip_port->ip.in_addr = addr_in->sin_addr;
        ip_port->port = addr_in->sin_port;
    } else
        return -1;

#endif

#ifdef LOGGING
    loglogdata("=>O", data, MAX_UDP_PACKET_SIZE, ip_port, *length);
#endif

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

        if (!(net->packethandlers[data[0]].function)) {
#ifdef LOGGING
            sprintf(logbuffer, "[%02u] -- Packet has no handler.\n", data[0]);
            loglog(logbuffer);
#endif
            continue;
        }

        net->packethandlers[data[0]].function(net->packethandlers[data[0]].object, ip_port, data, length);
    }
}


uint8_t at_startup_ran = 0;
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
#ifdef TOX_ENABLE_IPV6

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (ip.family != AF_INET && ip.family != AF_INET6) {
        fprintf(stderr, "Invalid address family: %u\n", ip.family);
        return NULL;
    }

#endif

    if (at_startup() != 0)
        return NULL;

    Networking_Core *temp = calloc(1, sizeof(Networking_Core));

    if (temp == NULL)
        return NULL;

#ifdef TOX_ENABLE_IPV6
    temp->family = ip.family;
#else
    temp->family = AF_INET;
#endif
    temp->port = 0;

    /* Initialize our socket. */
    /* add log message what we're creating */
    temp->sock = socket(temp->family, SOCK_DGRAM, IPPROTO_UDP);

    /* Check for socket error. */
#ifdef WIN32

    if (temp->sock == INVALID_SOCKET) { /* MSDN recommends this. */
        free(temp);
        return NULL;
    }

#else

    if (temp->sock < 0) {
        fprintf(stderr, "Failed to get a socket?! %u, %s\n", errno, strerror(errno));
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

    /* Enable broadcast on socket */
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

#ifdef LOGGING
    loginit(ntohs(port));
#endif

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    uint16_t *portptr = NULL;
    struct sockaddr_storage addr;
    size_t addrsize;
#ifdef TOX_ENABLE_IPV6

    if (temp->family == AF_INET) {
        IP4 ip4 = ip.ip4;
#else
    IP4 ip4 = ip;
#endif
        addrsize = sizeof(struct sockaddr_in);
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = 0;
        addr4->sin_addr = ip4.in_addr;

        portptr = &addr4->sin_port;
#ifdef TOX_ENABLE_IPV6
    } else if (temp->family == AF_INET6)
    {
        addrsize = sizeof(struct sockaddr_in6);
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = 0;
        addr6->sin6_addr = ip.ip6.in6_addr;

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;

        portptr = &addr6->sin6_port;
    } else
        return NULL;

    if (ip.family == AF_INET6)
    {
        char ipv6only = 0;
#ifdef LOGGING
        int res =
#endif
            setsockopt(temp->sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&ipv6only, sizeof(ipv6only));
#ifdef LOGGING

        if (res < 0) {
            sprintf(logbuffer,
                    "Failed to enable dual-stack on IPv6 socket, won't be able to receive from/send to IPv4 addresses. (%u, %s)\n",
                    errno, strerror(errno));
            loglog(logbuffer);
        } else
            loglog("Embedded IPv4 addresses enabled successfully.\n");

#endif

        /* multicast local nodes */
        struct ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;
#ifdef LOGGING
        res =
#endif
            setsockopt(temp->sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
#ifdef LOGGING

        if (res < 0) {
            sprintf(logbuffer, "Failed to activate local multicast membership. (%u, %s)\n",
                    errno, strerror(errno));
            loglog(logbuffer);
        } else
            loglog("Local multicast group FF02::1 joined successfully.\n");

#endif
    }

#endif

    /* a hanging program or a different user might block the standard port;
     * as long as it isn't a parameter coming from the commandline,
     * try a few ports after it, to see if we can find a "free" one
     *
     * if we go on without binding, the first sendto() automatically binds to
     * a free port chosen by the system (i.e. anything from 1024 to 65535)
     *
     * returning NULL after bind fails has both advantages and disadvantages:
     * advantage:
     *   we can rely on getting the port in the range 33445..33450, which
     *   enables us to tell joe user to open their firewall to a small range
     *
     * disadvantage:
     *   some clients might not test return of tox_new(), blindly assuming that
     *   it worked ok (which it did previously without a successful bind)
     */
    uint16_t port_to_try = port;
    *portptr = htons(port_to_try);
    int tries, res;

    for (tries = TOX_PORTRANGE_FROM; tries <= TOX_PORTRANGE_TO; tries++)
    {
        res = bind(temp->sock, (struct sockaddr *)&addr, addrsize);

        if (!res) {
            temp->port = *portptr;
#ifdef LOGGING
            sprintf(logbuffer, "Bound successfully to %s:%u.\n", ip_ntoa(&ip), ntohs(temp->port));
            loglog(logbuffer);
#endif

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            if (tries > 0)
                errno = 0;

            return temp;
        }

        port_to_try++;

        if (port_to_try > TOX_PORTRANGE_TO)
            port_to_try = TOX_PORTRANGE_FROM;

        *portptr = htons(port_to_try);
    }

    fprintf(stderr, "Failed to bind socket: %u, %s (IP/Port: %s:%u\n", errno,
            strerror(errno), ip_ntoa(&ip), port);
    kill_networking(temp);
    return NULL;
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

/* ip_equal
 *  compares two IPAny structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ip_equal(IP *a, IP *b)
{
    if (!a || !b)
        return 0;

#ifdef TOX_ENABLE_IPV6

    /* same family */
    if (a->family == b->family) {
        if (a->family == AF_INET)
            return (a->ip4.in_addr.s_addr == b->ip4.in_addr.s_addr);
        else if (a->family == AF_INET6)
            return IN6_ARE_ADDR_EQUAL(&a->ip6.in6_addr, &b->ip6.in6_addr);
        else
            return 0;
    }

    /* different family: check on the IPv6 one if it is the IPv4 one embedded */
    if ((a->family == AF_INET) && (b->family == AF_INET6)) {
        if (IN6_IS_ADDR_V4MAPPED(&b->ip6.in6_addr))
            return (a->ip4.in_addr.s_addr == b->ip6.uint32[3]);
    } else if ((a->family == AF_INET6)  && (b->family == AF_INET)) {
        if (IN6_IS_ADDR_V4MAPPED(&a->ip6.in6_addr))
            return (a->ip6.uint32[3] == b->ip4.in_addr.s_addr);
    }

    return 0;
#else
    return (a->uint32 == b->uint32);
#endif
};

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(IP_Port *a, IP_Port *b)
{
    if (!a || !b)
        return 0;

    if (!a->port || (a->port != b->port))
        return 0;

    return ip_equal(&a->ip, &b->ip);
};

/* nulls out ip */
void ip_reset(IP *ip)
{
    if (!ip)
        return;

#ifdef TOX_ENABLE_IPV6
    memset(ip, 0, sizeof(IP));
#else
    ip->uint32 = 0;
#endif
};

/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, uint8_t ipv6enabled)
{
    if (!ip)
        return;

#ifdef TOX_ENABLE_IPV6
    memset(ip, 0, sizeof(IP));
    ip->family = ipv6enabled ? AF_INET6 : AF_INET;
#else
    ip->uint32 = 0;
#endif
};

/* checks if ip is valid */
int ip_isset(IP *ip)
{
    if (!ip)
        return 0;

#ifdef TOX_ENABLE_IPV6
    return (ip->family != 0);
#else
    return (ip->uint32 != 0);
#endif
};

/* checks if ip is valid */
int ipport_isset(IP_Port *ipport)
{
    if (!ipport)
        return 0;

    if (!ipport->port)
        return 0;

    return ip_isset(&ipport->ip);
};

/* copies an ip structure (careful about direction!) */
void ip_copy(IP *target, IP *source)
{
    if (!source || !target)
        return;

    memcpy(target, source, sizeof(IP));
};

/* copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port *target, IP_Port *source)
{
    if (!source || !target)
        return;

    memcpy(target, source, sizeof(IP_Port));
};

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 */
/* there would be INET6_ADDRSTRLEN, but it might be too short for the error message */
static char addresstext[96];
const char *ip_ntoa(IP *ip)
{
    if (ip) {
#ifdef TOX_ENABLE_IPV6

        if (ip->family == AF_INET) {
            addresstext[0] = 0;
            struct in_addr *addr = (struct in_addr *)&ip->ip4;
            inet_ntop(ip->family, addr, addresstext, sizeof(addresstext));
        } else if (ip->family == AF_INET6) {
            addresstext[0] = '[';
            struct in6_addr *addr = (struct in6_addr *)&ip->ip6;
            inet_ntop(ip->family, addr, &addresstext[1], sizeof(addresstext) - 3);
            size_t len = strlen(addresstext);
            addresstext[len] = ']';
            addresstext[len + 1] = 0;
        } else
            snprintf(addresstext, sizeof(addresstext), "(IP invalid, family %u)", ip->family);

#else
        addresstext[0] = 0;
        struct in_addr *addr = (struct in_addr *)&ip;
        inet_ntop(AF_INET, addr, addresstext, sizeof(addresstext));
#endif
    } else
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");

    /* brute force protection against lacking termination */
    addresstext[sizeof(addresstext) - 1] = 0;
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

int addr_parse_ip(const char *address, IP *to)
{
    if (!address || !to)
        return 0;

#ifdef TOX_ENABLE_IPV6
    struct in_addr addr4;

    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->family = AF_INET;
        to->ip4.in_addr = addr4;
        return 1;
    };

    struct in6_addr addr6;

    if (1 == inet_pton(AF_INET6, address, &addr6)) {
        to->family = AF_INET6;
        to->ip6.in6_addr = addr6;
        return 1;
    };

#else
    struct in_addr addr4;

    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->in_addr = addr4;
        return 1;
    };

#endif

    return 0;
};

/*
 * addr_resolve():
 *  uses getaddrinfo to resolve an address into an IP address
 *  uses the first IPv4/IPv6 addresses returned by getaddrinfo
 *
 * input
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in *to a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was AF_UNSPEC and both available
 * returns in *extra an IPv4 address, if family was AF_UNSPEC and *to is AF_INET6
 * returns 0 on failure
 */

int addr_resolve(const char *address, IP *to, IP *extra)
{
    if (!address || !to)
        return 0;

    sa_family_t family;
#ifdef TOX_ENABLE_IPV6
    family = to->family;
#else
    family = AF_INET;
#endif

    struct addrinfo *server = NULL;
    struct addrinfo *walker = NULL;
    struct addrinfo  hints;
    int              rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    if (at_startup() != 0)
        return 0;

    rc = getaddrinfo(address, NULL, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

#ifdef TOX_ENABLE_IPV6
    IP4 ip4;
    memset(&ip4, 0, sizeof(ip4));
    IP6 ip6;
    memset(&ip6, 0, sizeof(ip6));
#endif

    for (walker = server; (walker != NULL) && (rc != 3); walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET:
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
#ifdef TOX_ENABLE_IPV6
                    to->ip4.in_addr = addr->sin_addr;
#else
                    to->in_addr = addr->sin_addr;
#endif
                    rc = 3;
                }

#ifdef TOX_ENABLE_IPV6
                else if (!(rc & 1)) { /* AF_UNSPEC requested, store away */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    ip4.in_addr = addr->sin_addr;
                    rc |= 1;
                }

#endif
                break; /* switch */
#ifdef TOX_ENABLE_IPV6

            case AF_INET6:
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                        to->ip6.in6_addr = addr->sin6_addr;
                        rc = 3;
                    }
                } else if (!(rc & 2)) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)walker->ai_addr;
                        ip6.in6_addr = addr->sin6_addr;
                        rc |= 2;
                    }
                }

                break; /* switch */
#endif
        }
    }

#ifdef TOX_ENABLE_IPV6

    if (to->family == AF_UNSPEC) {
        if (rc & 2) {
            to->family = AF_INET6;
            to->ip6 = ip6;

            if ((rc & 1) && (extra != NULL)) {
                extra->family = AF_INET;
                extra->ip4 = ip4;
            }
        } else if (rc & 1) {
            to->family = AF_INET;
            to->ip4 = ip4;
        } else
            rc = 0;
    }

#endif


    freeaddrinfo(server);
    return rc;
}

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 *  returns in *tro a matching address (IPv6 or IPv4)
 *  returns in *extra, if not NULL, an IPv4 address, if to->family was AF_UNSPEC
 *  returns 1 on success
 *  returns 0 on failure
 */
int addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra)
{
    if (!addr_resolve(address, to, extra))
        if (!addr_parse_ip(address, to))
            return 0;

    return 1;
};

#ifdef LOGGING
static void loglogdata(char *message, uint8_t *buffer, size_t buflen, IP_Port *ip_port, ssize_t res)
{
    if (res < 0)
        snprintf(logbuffer, sizeof(logbuffer), "[%2u] %s %3u%c %s:%u (%u: %s) | %04x%04x\n",
                 buffer[0], message, buflen < 999 ? buflen : 999, 'E',
                 ip_ntoa(&ip_port->ip), ntohs(ip_port->port), errno,
                 strerror(errno), buflen > 4 ? ntohl(*(uint32_t *)&buffer[1]) : 0,
                 buflen > 7 ? ntohl(*(uint32_t *)(&buffer[5])) : 0);
    else if ((res > 0) && ((size_t)res <= buflen))
        snprintf(logbuffer, sizeof(logbuffer), "[%2u] %s %3u%c %s:%u (%u: %s) | %04x%04x\n",
                 buffer[0], message, res < 999 ? res : 999, (size_t)res < buflen ? '<' : '=',
                 ip_ntoa(&ip_port->ip), ntohs(ip_port->port), 0,
                 "OK", buflen > 4 ? ntohl(*(uint32_t *)&buffer[1]) : 0,
                 buflen > 7 ? ntohl(*(uint32_t *)(&buffer[5])) : 0);
    else /* empty or overwrite */
        snprintf(logbuffer, sizeof(logbuffer), "[%2u] %s %u%c%u %s:%u (%u: %s) | %04x%04x\n",
                 buffer[0], message, res, !res ? '!' : '>', buflen,
                 ip_ntoa(&ip_port->ip), ntohs(ip_port->port), 0,
                 "OK", buflen > 4 ? ntohl(*(uint32_t *)&buffer[1]) : 0,
                 buflen > 7 ? ntohl(*(uint32_t *)(&buffer[5])) : 0);

    logbuffer[sizeof(logbuffer) - 1] = 0;
    loglog(logbuffer);
}
#endif
