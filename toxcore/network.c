/* network.c
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

#if (_WIN32_WINNT >= _WIN32_WINNT_WINXP)
#define _WIN32_WINNT  0x501
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "logger.h"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <errno.h>
#endif

#ifdef __APPLE__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#include "network.h"
#include "util.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

static const char *inet_ntop(sa_family_t family, void *addr, char *buf, size_t bufsize)
{
    if (family == AF_INET) {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));

        saddr.sin_family = AF_INET;
        saddr.sin_addr = *(struct in_addr *)addr;

        DWORD len = bufsize;

        if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), NULL, buf, &len))
            return NULL;

        return buf;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 saddr;
        memset(&saddr, 0, sizeof(saddr));

        saddr.sin6_family = AF_INET6;
        saddr.sin6_addr = *(struct in6_addr *)addr;

        DWORD len = bufsize;

        if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), NULL, buf, &len))
            return NULL;

        return buf;
    }

    return NULL;
}

static int inet_pton(sa_family_t family, const char *addrString, void *addrbuf)
{
    if (family == AF_INET) {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(saddr));

        INT len = sizeof(saddr);

        if (WSAStringToAddress((LPTSTR)addrString, AF_INET, NULL, (LPSOCKADDR)&saddr, &len))
            return 0;

        *(struct in_addr *)addrbuf = saddr.sin_addr;

        return 1;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 saddr;
        memset(&saddr, 0, sizeof(saddr));

        INT len = sizeof(saddr);

        if (WSAStringToAddress((LPTSTR)addrString, AF_INET6, NULL, (LPSOCKADDR)&saddr, &len))
            return 0;

        *(struct in6_addr *)addrbuf = saddr.sin6_addr;

        return 1;
    }

    return 0;
}

#endif

/* Check if socket is valid.
 *
 * return 1 if valid
 * return 0 if not valid
 */
int sock_valid(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)

    if (sock == INVALID_SOCKET) {
#else

    if (sock < 0) {
#endif
        return 0;
    }

    return 1;
}

/* Close the socket.
 */
void kill_sock(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    closesocket(sock);
#else
    close(sock);
#endif
}

/* Set socket as nonblocking
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nonblock(sock_t sock)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    u_long mode = 1;
    return (ioctlsocket(sock, FIONBIO, &mode) == 0);
#else
    return (fcntl(sock, F_SETFL, O_NONBLOCK, 1) == 0);
#endif
}

/* Set socket to not emit SIGPIPE
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nosigpipe(sock_t sock)
{
#if defined(__MACH__)
    int set = 1;
    return (setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int)) == 0);
#else
    return 1;
#endif
}

/* Enable SO_REUSEADDR on socket.
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_reuseaddr(sock_t sock)
{
    int set = 1;
    return (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void *)&set, sizeof(set)) == 0);
}

/* Set socket to dual (IPv4 + IPv6 socket)
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_dualstack(sock_t sock)
{
    int ipv6only = 0;
    socklen_t optsize = sizeof(ipv6only);
    int res = getsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0))
        return 1;

    ipv6only = 0;
    return (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&ipv6only, sizeof(ipv6only)) == 0);
}


/*  return current UNIX time in microseconds (us). */
static uint64_t current_time_actual(void)
{
    uint64_t time;
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    /* This probably works fine */
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    time = ft.dwHighDateTime;
    time <<= 32;
    time |= ft.dwLowDateTime;
    time -= 116444736000000000ULL;
    return time / 10;
#else
    struct timeval a;
    gettimeofday(&a, NULL);
    time = 1000000ULL * a.tv_sec + a.tv_usec;
    return time;
#endif
}


#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
static uint64_t last_monotime;
static uint64_t add_monotime;
#endif

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void)
{
    uint64_t time;
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    time = (uint64_t)GetTickCount() + add_monotime;

    if (time < last_monotime) { /* Prevent time from ever decreasing because of 32 bit wrap. */
        uint32_t add = ~0;
        add_monotime += add;
        time += add;
    }

    last_monotime = time;
#else
    struct timespec monotime;
#if defined(__linux__) && defined(CLOCK_MONOTONIC_RAW)
    clock_gettime(CLOCK_MONOTONIC_RAW, &monotime);
#elif defined(__APPLE__)
    clock_serv_t muhclock;
    mach_timespec_t machtime;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &muhclock);
    clock_get_time(muhclock, &machtime);
    mach_port_deallocate(mach_task_self(), muhclock);

    monotime.tv_sec = machtime.tv_sec;
    monotime.tv_nsec = machtime.tv_nsec;
#else
    clock_gettime(CLOCK_MONOTONIC, &monotime);
#endif
    time = 1000ULL * monotime.tv_sec + (monotime.tv_nsec / 1000000ULL);
#endif
    return time;
}

/* In case no logging */
#ifndef LOGGING
#define loglogdata(__message__, __buffer__, __buflen__, __ip_port__, __res__)
#else
#define data_0(__buflen__, __buffer__) __buflen__ > 4 ? ntohl(*(uint32_t *)&__buffer__[1]) : 0
#define data_1(__buflen__, __buffer__) __buflen__ > 7 ? ntohl(*(uint32_t *)&__buffer__[5]) : 0

#define loglogdata(__message__, __buffer__, __buflen__, __ip_port__, __res__) \
    (__ip_port__) .ip; \
    if (__res__ < 0) /* Windows doesn't necessarily know %zu */ \
        LOGGER_TRACE("[%2u] %s %3hu%c %s:%hu (%u: %s) | %04x%04x", \
                 __buffer__[0], __message__, (__buflen__ < 999 ? (uint16_t)__buflen__ : 999), 'E', \
                 ip_ntoa(&((__ip_port__).ip)), ntohs((__ip_port__).port), errno, strerror(errno), data_0(__buflen__, __buffer__), data_1(__buflen__, __buffer__)); \
    else if ((__res__ > 0) && ((size_t)__res__ <= __buflen__)) \
        LOGGER_TRACE("[%2u] %s %3zu%c %s:%hu (%u: %s) | %04x%04x", \
                 __buffer__[0], __message__, (__res__ < 999 ? (size_t)__res__ : 999), ((size_t)__res__ < __buflen__ ? '<' : '='), \
                 ip_ntoa(&((__ip_port__).ip)), ntohs((__ip_port__).port), 0, "OK", data_0(__buflen__, __buffer__), data_1(__buflen__, __buffer__)); \
    else /* empty or overwrite */ \
        LOGGER_TRACE("[%2u] %s %zu%c%zu %s:%hu (%u: %s) | %04x%04x", \
                 __buffer__[0], __message__, (size_t)__res__, (!__res__ ? '!' : '>'), __buflen__, \
                 ip_ntoa(&((__ip_port__).ip)), ntohs((__ip_port__).port), 0, "OK", data_0(__buflen__, __buffer__), data_1(__buflen__, __buffer__));

#endif /* LOGGING */

/* Basic network functions:
 * Function to send packet(data) of length length to ip_port.
 */
int sendpacket(Networking_Core *net, IP_Port ip_port, const uint8_t *data, uint16_t length)
{
    if (net->family == 0) /* Socket not initialized */
        return -1;

    /* socket AF_INET, but target IP NOT: can't send */
    if ((net->family == AF_INET) && (ip_port.ip.family != AF_INET))
        return -1;

    struct sockaddr_storage addr;
    size_t addrsize = 0;

    if (ip_port.ip.family == AF_INET) {
        if (net->family == AF_INET6) {
            /* must convert to IPV4-in-IPV6 address */
            struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

            addrsize = sizeof(struct sockaddr_in6);
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
            struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

            addrsize = sizeof(struct sockaddr_in);
            addr4->sin_family = AF_INET;
            addr4->sin_addr = ip_port.ip.ip4.in_addr;
            addr4->sin_port = ip_port.port;
        }
    } else if (ip_port.ip.family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = ip_port.port;
        addr6->sin6_addr = ip_port.ip.ip6.in6_addr;

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
    } else {
        /* unknown address type*/
        return -1;
    }

    int res = sendto(net->sock, (char *) data, length, 0, (struct sockaddr *)&addr, addrsize);

    loglogdata("O=>", data, length, ip_port, res);

    return res;
}

/* Function to receive data
 *  ip and port of sender is put into ip_port.
 *  Packet data is put into data.
 *  Packet length is put into length.
 */
static int receivepacket(sock_t sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
{
    memset(ip_port, 0, sizeof(IP_Port));
    struct sockaddr_storage addr;
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif
    *length = 0;
    int fail_or_len = recvfrom(sock, (char *) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

    if (fail_or_len < 0) {

        LOGGER_SCOPE( if ((fail_or_len < 0) && (errno != EWOULDBLOCK))
                      LOGGER_ERROR("Unexpected error reading from socket: %u, %s\n", errno, strerror(errno)); );

        return -1; /* Nothing received. */
    }

    *length = (uint32_t)fail_or_len;

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

        if (IPV6_IPV4_IN_V6(ip_port->ip.ip6)) {
            ip_port->ip.family = AF_INET;
            ip_port->ip.ip4.uint32 = ip_port->ip.ip6.uint32[3];
        }
    } else
        return -1;

    loglogdata("=>O", data, MAX_UDP_PACKET_SIZE, *ip_port, *length);

    return 0;
}

void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object)
{
    net->packethandlers[byte].function = cb;
    net->packethandlers[byte].object = object;
}

void networking_poll(Networking_Core *net)
{
    if (net->family == 0) /* Socket not initialized */
        return;

    unix_time_update();

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (receivepacket(net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) continue;

        if (!(net->packethandlers[data[0]].function)) {
            LOGGER_WARNING("[%02u] -- Packet has no handler", data[0]);
            continue;
        }

        net->packethandlers[data[0]].function(net->packethandlers[data[0]].object, ip_port, data, length);
    }
}

#ifndef VANILLA_NACL
/* Used for sodium_init() */
#include <sodium.h>
#endif

uint8_t at_startup_ran = 0;
int networking_at_startup(void)
{
    if (at_startup_ran != 0)
        return 0;

#ifndef VANILLA_NACL

#ifdef USE_RANDOMBYTES_STIR
    randombytes_stir();
#else
    sodium_init();
#endif /*USE_RANDOMBYTES_STIR*/

#endif/*VANILLA_NACL*/

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
        return -1;

#endif
    srand((uint32_t)current_time_actual());
    at_startup_ran = 1;
    return 0;
}

/* TODO: Put this somewhere
static void at_shutdown(void)
{
#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
    WSACleanup();
#endif
}
*/

/* Initialize networking.
 * Added for reverse compatibility with old new_networking calls.
 */
Networking_Core *new_networking(IP ip, uint16_t port)
{
    return new_networking_ex(ip, port, port + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), 0);
}

/* Initialize networking.
 * Bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 *  return Networking_Core object if no problems
 *  return NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.
 */
Networking_Core *new_networking_ex(IP ip, uint16_t port_from, uint16_t port_to, unsigned int *error)
{
    /* If both from and to are 0, use default port range
     * If one is 0 and the other is non-0, use the non-0 value as only port
     * If from > to, swap
     */
    if (port_from == 0 && port_to == 0) {
        port_from = TOX_PORTRANGE_FROM;
        port_to = TOX_PORTRANGE_TO;
    } else if (port_from == 0 && port_to != 0) {
        port_from = port_to;
    } else if (port_from != 0 && port_to == 0) {
        port_to = port_from;
    } else if (port_from > port_to) {
        uint16_t temp = port_from;
        port_from = port_to;
        port_to = temp;
    }

    if (error)
        *error = 2;

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (ip.family != AF_INET && ip.family != AF_INET6) {
#ifdef DEBUG
        fprintf(stderr, "Invalid address family: %u\n", ip.family);
#endif
        return NULL;
    }

    if (networking_at_startup() != 0)
        return NULL;

    Networking_Core *temp = calloc(1, sizeof(Networking_Core));

    if (temp == NULL)
        return NULL;

    temp->family = ip.family;
    temp->port = 0;

    /* Initialize our socket. */
    /* add log message what we're creating */
    temp->sock = socket(temp->family, SOCK_DGRAM, IPPROTO_UDP);

    /* Check for socket error. */
    if (!sock_valid(temp->sock)) {
#ifdef DEBUG
        fprintf(stderr, "Failed to get a socket?! %u, %s\n", errno, strerror(errno));
#endif
        free(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    /* Functions to increase the size of the send and receive UDP buffers.
     */
    int n = 1024 * 1024 * 2;
    setsockopt(temp->sock, SOL_SOCKET, SO_RCVBUF, (char *)&n, sizeof(n));
    setsockopt(temp->sock, SOL_SOCKET, SO_SNDBUF, (char *)&n, sizeof(n));

    /* Enable broadcast on socket */
    int broadcast = 1;
    setsockopt(temp->sock, SOL_SOCKET, SO_BROADCAST, (char *)&broadcast, sizeof(broadcast));

    /* iOS UDP sockets are weird and apparently can SIGPIPE */
    if (!set_socket_nosigpipe(temp->sock)) {
        kill_networking(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    /* Set socket nonblocking. */
    if (!set_socket_nonblock(temp->sock)) {
        kill_networking(temp);

        if (error)
            *error = 1;

        return NULL;
    }

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    uint16_t *portptr = NULL;
    struct sockaddr_storage addr;
    size_t addrsize;

    if (temp->family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = 0;
        addr4->sin_addr = ip.ip4.in_addr;

        portptr = &addr4->sin_port;
    } else if (temp->family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = 0;
        addr6->sin6_addr = ip.ip6.in6_addr;

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;

        portptr = &addr6->sin6_port;
    } else {
        free(temp);
        return NULL;
    }

    if (ip.family == AF_INET6) {
#ifdef LOGGING
        int is_dualstack =
#endif /* LOGGING */
            set_socket_dualstack(temp->sock);
        LOGGER_DEBUG( "Dual-stack socket: %s",
                      is_dualstack ? "enabled" : "Failed to enable, won't be able to receive from/send to IPv4 addresses" );
        /* multicast local nodes */
        struct ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;
#ifdef LOGGING
        int res =
#endif /* LOGGING */
            setsockopt(temp->sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));

        LOGGER_DEBUG(res < 0 ? "Failed to activate local multicast membership. (%u, %s)" :
                     "Local multicast group FF02::1 joined successfully", errno, strerror(errno) );
    }

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
    uint16_t port_to_try = port_from;
    *portptr = htons(port_to_try);
    int tries;

    for (tries = port_from; tries <= port_to; tries++) {
        int res = bind(temp->sock, (struct sockaddr *)&addr, addrsize);

        if (!res) {
            temp->port = *portptr;

            LOGGER_DEBUG("Bound successfully to %s:%u", ip_ntoa(&ip), ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            if (tries > 0)
                errno = 0;

            if (error)
                *error = 0;

            return temp;
        }

        port_to_try++;

        if (port_to_try > port_to)
            port_to_try = port_from;

        *portptr = htons(port_to_try);
    }

    LOGGER_ERROR("Failed to bind socket: %u, %s IP: %s port_from: %u port_to: %u", errno, strerror(errno),
                 ip_ntoa(&ip), port_from, port_to);

    kill_networking(temp);

    if (error)
        *error = 1;

    return NULL;
}

/* Function to cleanup networking stuff. */
void kill_networking(Networking_Core *net)
{
    if (net->family != 0) /* Socket not initialized */
        kill_sock(net->sock);

    free(net);
    return;
}


/* ip_equal
 *  compares two IPAny structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ip_equal(const IP *a, const IP *b)
{
    if (!a || !b)
        return 0;

    /* same family */
    if (a->family == b->family) {
        if (a->family == AF_INET)
            return (a->ip4.in_addr.s_addr == b->ip4.in_addr.s_addr);
        else if (a->family == AF_INET6)
            return a->ip6.uint64[0] == b->ip6.uint64[0] && a->ip6.uint64[1] == b->ip6.uint64[1];
        else
            return 0;
    }

    /* different family: check on the IPv6 one if it is the IPv4 one embedded */
    if ((a->family == AF_INET) && (b->family == AF_INET6)) {
        if (IPV6_IPV4_IN_V6(b->ip6))
            return (a->ip4.in_addr.s_addr == b->ip6.uint32[3]);
    } else if ((a->family == AF_INET6)  && (b->family == AF_INET)) {
        if (IPV6_IPV4_IN_V6(a->ip6))
            return (a->ip6.uint32[3] == b->ip4.in_addr.s_addr);
    }

    return 0;
}

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(const IP_Port *a, const IP_Port *b)
{
    if (!a || !b)
        return 0;

    if (!a->port || (a->port != b->port))
        return 0;

    return ip_equal(&a->ip, &b->ip);
}

/* nulls out ip */
void ip_reset(IP *ip)
{
    if (!ip)
        return;

    memset(ip, 0, sizeof(IP));
}

/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, uint8_t ipv6enabled)
{
    if (!ip)
        return;

    memset(ip, 0, sizeof(IP));
    ip->family = ipv6enabled ? AF_INET6 : AF_INET;
}

/* checks if ip is valid */
int ip_isset(const IP *ip)
{
    if (!ip)
        return 0;

    return (ip->family != 0);
}

/* checks if ip is valid */
int ipport_isset(const IP_Port *ipport)
{
    if (!ipport)
        return 0;

    if (!ipport->port)
        return 0;

    return ip_isset(&ipport->ip);
}

/* copies an ip structure (careful about direction!) */
void ip_copy(IP *target, const IP *source)
{
    if (!source || !target)
        return;

    memcpy(target, source, sizeof(IP));
}

/* copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port *target, const IP_Port *source)
{
    if (!source || !target)
        return;

    memcpy(target, source, sizeof(IP_Port));
}

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 */
/* there would be INET6_ADDRSTRLEN, but it might be too short for the error message */
static char addresstext[96];
const char *ip_ntoa(const IP *ip)
{
    if (ip) {
        if (ip->family == AF_INET) {
            /* returns standard quad-dotted notation */
            struct in_addr *addr = (struct in_addr *)&ip->ip4;

            addresstext[0] = 0;
            inet_ntop(ip->family, addr, addresstext, sizeof(addresstext));
        } else if (ip->family == AF_INET6) {
            /* returns hex-groups enclosed into square brackets */
            struct in6_addr *addr = (struct in6_addr *)&ip->ip6;

            addresstext[0] = '[';
            inet_ntop(ip->family, addr, &addresstext[1], sizeof(addresstext) - 3);
            size_t len = strlen(addresstext);
            addresstext[len] = ']';
            addresstext[len + 1] = 0;
        } else
            snprintf(addresstext, sizeof(addresstext), "(IP invalid, family %u)", ip->family);
    } else
        snprintf(addresstext, sizeof(addresstext), "(IP invalid: NULL)");

    /* brute force protection against lacking termination */
    addresstext[sizeof(addresstext) - 1] = 0;
    return addresstext;
}

/*
 * ip_parse_addr
 *  parses IP structure into an address string
 *
 * input
 *  ip: ip of AF_INET or AF_INET6 families
 *  length: length of the address buffer
 *          Must be at least INET_ADDRSTRLEN for AF_INET
 *          and INET6_ADDRSTRLEN for AF_INET6
 *
 * output
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * returns 1 on success, 0 on failure
 */
int ip_parse_addr(const IP *ip, char *address, size_t length)
{
    if (!address || !ip) {
        return 0;
    }

    if (ip->family == AF_INET) {
        struct in_addr *addr = (struct in_addr *)&ip->ip4;
        return inet_ntop(ip->family, addr, address, length) != NULL;
    } else if (ip->family == AF_INET6) {
        struct in6_addr *addr = (struct in6_addr *)&ip->ip6;
        return inet_ntop(ip->family, addr, address, length) != NULL;
    }

    return 0;
}

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

    struct in_addr addr4;

    if (1 == inet_pton(AF_INET, address, &addr4)) {
        to->family = AF_INET;
        to->ip4.in_addr = addr4;
        return 1;
    }

    struct in6_addr addr6;

    if (1 == inet_pton(AF_INET6, address, &addr6)) {
        to->family = AF_INET6;
        to->ip6.in6_addr = addr6;
        return 1;
    }

    return 0;
}

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

    sa_family_t family = to->family;

    struct addrinfo *server = NULL;
    struct addrinfo *walker = NULL;
    struct addrinfo  hints;
    int              rc;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    if (networking_at_startup() != 0)
        return 0;

    rc = getaddrinfo(address, NULL, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    IP4 ip4;
    memset(&ip4, 0, sizeof(ip4));
    IP6 ip6;
    memset(&ip6, 0, sizeof(ip6));

    for (walker = server; (walker != NULL) && (rc != 3); walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET:
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    to->ip4.in_addr = addr->sin_addr;
                    rc = 3;
                } else if (!(rc & 1)) { /* AF_UNSPEC requested, store away */
                    struct sockaddr_in *addr = (struct sockaddr_in *)walker->ai_addr;
                    ip4.in_addr = addr->sin_addr;
                    rc |= 1;
                }

                break; /* switch */

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
        }
    }

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
}
