/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * Functions for the core networking.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

// For Solaris.
#ifdef __sun
#define __EXTENSIONS__ 1
#endif

// For Linux (and some BSDs).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#undef _WIN32_WINNT
#define _WIN32_WINNT  0x501
#endif

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif

#ifdef OS_WIN32
#ifndef WINVER
// Windows XP
#define WINVER 0x0501
#endif
#endif

#ifdef PLAN9
#include <u.h> // Plan 9 requires this is imported first
// Comment line here to avoid reordering by source code formatters.
#include <libc.h>
#endif

#ifdef OS_WIN32 /* Put win32 includes here */
// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>
// Comment line here to avoid reordering by source code formatters.
#include <windows.h>
#include <ws2tcpip.h>
#endif

#include "network.h"

#ifdef __APPLE__
#include <mach/clock.h>
#include <mach/mach.h>
#endif

#if !defined(OS_WIN32)

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __sun
#include <stropts.h>
#include <sys/filio.h>
#endif

#define TOX_EWOULDBLOCK EWOULDBLOCK

static const char *inet_ntop4(const struct in_addr *addr, char *buf, size_t bufsize)
{
    return inet_ntop(AF_INET, addr, buf, bufsize);
}

static const char *inet_ntop6(const struct in6_addr *addr, char *buf, size_t bufsize)
{
    return inet_ntop(AF_INET6, addr, buf, bufsize);
}

static int inet_pton4(const char *addrString, struct in_addr *addrbuf)
{
    return inet_pton(AF_INET, addrString, addrbuf);
}

static int inet_pton6(const char *addrString, struct in6_addr *addrbuf)
{
    return inet_pton(AF_INET6, addrString, addrbuf);
}

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

#define TOX_EWOULDBLOCK WSAEWOULDBLOCK

static const char *inet_ntop4(const struct in_addr *addr, char *buf, size_t bufsize)
{
    struct sockaddr_in saddr = {0};

    saddr.sin_family = AF_INET;
    saddr.sin_addr = *addr;

    DWORD len = bufsize;

    if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), nullptr, buf, &len)) {
        return nullptr;
    }

    return buf;
}

static const char *inet_ntop6(const struct in6_addr *addr, char *buf, size_t bufsize)
{
    struct sockaddr_in6 saddr = {0};

    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = *addr;

    DWORD len = bufsize;

    if (WSAAddressToString((LPSOCKADDR)&saddr, sizeof(saddr), nullptr, buf, &len)) {
        return nullptr;
    }

    return buf;
}

static int inet_pton4(const char *addrString, struct in_addr *addrbuf)
{
    struct sockaddr_in saddr = {0};

    INT len = sizeof(saddr);

    if (WSAStringToAddress((LPTSTR)addrString, AF_INET, nullptr, (LPSOCKADDR)&saddr, &len)) {
        return 0;
    }

    *addrbuf = saddr.sin_addr;

    return 1;
}

static int inet_pton6(const char *addrString, struct in6_addr *addrbuf)
{
    struct sockaddr_in6 saddr = {0};

    INT len = sizeof(saddr);

    if (WSAStringToAddress((LPTSTR)addrString, AF_INET6, nullptr, (LPSOCKADDR)&saddr, &len)) {
        return 0;
    }

    *addrbuf = saddr.sin6_addr;

    return 1;
}

#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"
#include "mono_time.h"
#include "util.h"

// Disable MSG_NOSIGNAL on systems not supporting it, e.g. Windows, FreeBSD
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif
#endif

#if TOX_INET6_ADDRSTRLEN < INET6_ADDRSTRLEN
#error "TOX_INET6_ADDRSTRLEN should be greater or equal to INET6_ADDRSTRLEN (#INET6_ADDRSTRLEN)"
#endif

#if TOX_INET_ADDRSTRLEN < INET_ADDRSTRLEN
#error "TOX_INET_ADDRSTRLEN should be greater or equal to INET_ADDRSTRLEN (#INET_ADDRSTRLEN)"
#endif

static int make_proto(int proto)
{
    switch (proto) {
        case TOX_PROTO_TCP:
            return IPPROTO_TCP;

        case TOX_PROTO_UDP:
            return IPPROTO_UDP;

        default:
            return proto;
    }
}

static int make_socktype(int type)
{
    switch (type) {
        case TOX_SOCK_STREAM:
            return SOCK_STREAM;

        case TOX_SOCK_DGRAM:
            return SOCK_DGRAM;

        default:
            return type;
    }
}

static int make_family(Family tox_family)
{
    switch (tox_family.value) {
        case TOX_AF_INET:
            return AF_INET;

        case TOX_AF_INET6:
            return AF_INET6;

        case TOX_AF_UNSPEC:
            return AF_UNSPEC;

        default:
            return tox_family.value;
    }
}

static const Family *make_tox_family(int family)
{
    switch (family) {
        case AF_INET:
            return &net_family_ipv4;

        case AF_INET6:
            return &net_family_ipv6;

        case AF_UNSPEC:
            return &net_family_unspec;

        default:
            return nullptr;
    }
}

static void get_ip4(IP4 *result, const struct in_addr *addr)
{
    result->uint32 = addr->s_addr;
}

static void get_ip6(IP6 *result, const struct in6_addr *addr)
{
    assert(sizeof(result->uint8) == sizeof(addr->s6_addr));
    memcpy(result->uint8, addr->s6_addr, sizeof(result->uint8));
}

static void fill_addr4(IP4 ip, struct in_addr *addr)
{
    addr->s_addr = ip.uint32;
}

static void fill_addr6(IP6 ip, struct in6_addr *addr)
{
    assert(sizeof(ip.uint8) == sizeof(addr->s6_addr));
    memcpy(addr->s6_addr, ip.uint8, sizeof(ip.uint8));
}

#if !defined(INADDR_LOOPBACK)
#define INADDR_LOOPBACK 0x7f000001
#endif

const IP4 ip4_broadcast = { INADDR_BROADCAST };
const IP6 ip6_broadcast = {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

IP4 get_ip4_loopback(void)
{
    IP4 loopback;
    loopback.uint32 = htonl(INADDR_LOOPBACK);
    return loopback;
}

IP6 get_ip6_loopback(void)
{
    IP6 loopback;
    get_ip6(&loopback, &in6addr_loopback);
    return loopback;
}

#ifndef OS_WIN32
#define INVALID_SOCKET (-1)
#endif

const Socket net_invalid_socket = { (int)INVALID_SOCKET };

const Family net_family_unspec = {TOX_AF_UNSPEC};
const Family net_family_ipv4 = {TOX_AF_INET};
const Family net_family_ipv6 = {TOX_AF_INET6};
const Family net_family_tcp_family = {TCP_FAMILY};
const Family net_family_tcp_onion = {TCP_ONION_FAMILY};
const Family net_family_tcp_ipv4 = {TCP_INET};
const Family net_family_tcp_ipv6 = {TCP_INET6};
const Family net_family_tox_tcp_ipv4 = {TOX_TCP_INET};
const Family net_family_tox_tcp_ipv6 = {TOX_TCP_INET6};

bool net_family_is_unspec(Family family)
{
    return family.value == net_family_unspec.value;
}

bool net_family_is_ipv4(Family family)
{
    return family.value == net_family_ipv4.value;
}

bool net_family_is_ipv6(Family family)
{
    return family.value == net_family_ipv6.value;
}

bool net_family_is_tcp_family(Family family)
{
    return family.value == net_family_tcp_family.value;
}

bool net_family_is_tcp_onion(Family family)
{
    return family.value == net_family_tcp_onion.value;
}

bool net_family_is_tcp_ipv4(Family family)
{
    return family.value == net_family_tcp_ipv4.value;
}

bool net_family_is_tcp_ipv6(Family family)
{
    return family.value == net_family_tcp_ipv6.value;
}

bool net_family_is_tox_tcp_ipv4(Family family)
{
    return family.value == net_family_tox_tcp_ipv4.value;
}

bool net_family_is_tox_tcp_ipv6(Family family)
{
    return family.value == net_family_tox_tcp_ipv6.value;
}

bool sock_valid(Socket sock)
{
    return sock.socket != net_invalid_socket.socket;
}

/* Close the socket.
 */
void kill_sock(Socket sock)
{
#ifdef OS_WIN32
    closesocket(sock.socket);
#else
    close(sock.socket);
#endif
}

bool set_socket_nonblock(Socket sock)
{
#ifdef OS_WIN32
    u_long mode = 1;
    return ioctlsocket(sock.socket, FIONBIO, &mode) == 0;
#else
    return fcntl(sock.socket, F_SETFL, O_NONBLOCK, 1) == 0;
#endif
}

bool set_socket_nosigpipe(Socket sock)
{
#if defined(__APPLE__)
    int set = 1;
    return setsockopt(sock.socket, SOL_SOCKET, SO_NOSIGPIPE, (const char *)&set, sizeof(int)) == 0;
#else
    return true;
#endif
}

bool set_socket_reuseaddr(Socket sock)
{
    int set = 1;
    return setsockopt(sock.socket, SOL_SOCKET, SO_REUSEADDR, (const char *)&set, sizeof(set)) == 0;
}

bool set_socket_dualstack(Socket sock)
{
    int ipv6only = 0;
    socklen_t optsize = sizeof(ipv6only);
    int res = getsockopt(sock.socket, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0)) {
        return true;
    }

    ipv6only = 0;
    return setsockopt(sock.socket, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&ipv6only, sizeof(ipv6only)) == 0;
}


static uint32_t data_0(uint16_t buflen, const uint8_t *buffer)
{
    uint32_t data = 0;

    if (buflen > 4) {
        net_unpack_u32(buffer + 1, &data);
    }

    return data;
}
static uint32_t data_1(uint16_t buflen, const uint8_t *buffer)
{
    uint32_t data = 0;

    if (buflen > 7) {
        net_unpack_u32(buffer + 5, &data);
    }

    return data;
}

static void loglogdata(const Logger *log, const char *message, const uint8_t *buffer,
                       uint16_t buflen, IP_Port ip_port, int res)
{
    char ip_str[IP_NTOA_LEN];

    if (res < 0) { /* Windows doesn't necessarily know `%zu` */
        int error = net_error();
        const char *strerror = net_new_strerror(error);
        LOGGER_TRACE(log, "[%2u] %s %3u%c %s:%u (%u: %s) | %04x%04x",
                     buffer[0], message, min_u16(buflen, 999), 'E',
                     ip_ntoa(&ip_port.ip, ip_str, sizeof(ip_str)), net_ntohs(ip_port.port), error,
                     strerror, data_0(buflen, buffer), data_1(buflen, buffer));
        net_kill_strerror(strerror);
    } else if ((res > 0) && ((size_t)res <= buflen)) {
        LOGGER_TRACE(log, "[%2u] %s %3u%c %s:%u (%u: %s) | %04x%04x",
                     buffer[0], message, min_u16(res, 999), ((size_t)res < buflen ? '<' : '='),
                     ip_ntoa(&ip_port.ip, ip_str, sizeof(ip_str)), net_ntohs(ip_port.port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer));
    } else { /* empty or overwrite */
        LOGGER_TRACE(log, "[%2u] %s %u%c%u %s:%u (%u: %s) | %04x%04x",
                     buffer[0], message, res, (!res ? '!' : '>'), buflen,
                     ip_ntoa(&ip_port.ip, ip_str, sizeof(ip_str)), net_ntohs(ip_port.port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer));
    }
}

typedef struct Packet_Handler {
    packet_handler_cb *function;
    void *object;
} Packet_Handler;

struct Networking_Core {
    const Logger *log;
    Packet_Handler packethandlers[256];

    Family family;
    uint16_t port;
    /* Our UDP socket. */
    Socket sock;
};

Family net_family(const Networking_Core *net)
{
    return net->family;
}

uint16_t net_port(const Networking_Core *net)
{
    return net->port;
}

/* Basic network functions:
 * Function to send packet(data) of length length to ip_port.
 */
int sendpacket(Networking_Core *net, IP_Port ip_port, const uint8_t *data, uint16_t length)
{
    if (net_family_is_unspec(net->family)) { /* Socket not initialized */
        LOGGER_ERROR(net->log, "attempted to send message of length %u on uninitialised socket", (unsigned)length);
        return -1;
    }

    /* socket TOX_AF_INET, but target IP NOT: can't send */
    if (net_family_is_ipv4(net->family) && !net_family_is_ipv4(ip_port.ip.family)) {
        LOGGER_ERROR(net->log, "attempted to send message with network family %d (probably IPv6) on IPv4 socket",
                     ip_port.ip.family.value);
        return -1;
    }

    if (net_family_is_ipv4(ip_port.ip.family) && net_family_is_ipv6(net->family)) {
        /* must convert to IPV4-in-IPV6 address */
        IP6 ip6;

        /* there should be a macro for this in a standards compliant
         * environment, not found */
        ip6.uint32[0] = 0;
        ip6.uint32[1] = 0;
        ip6.uint32[2] = net_htonl(0xFFFF);
        ip6.uint32[3] = ip_port.ip.ip.v4.uint32;

        ip_port.ip.family = net_family_ipv6;
        ip_port.ip.ip.v6 = ip6;
    }

    struct sockaddr_storage addr;

    size_t addrsize;

    if (net_family_is_ipv4(ip_port.ip.family)) {
        struct sockaddr_in *const addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = ip_port.port;
        fill_addr4(ip_port.ip.ip.v4, &addr4->sin_addr);
    } else if (net_family_is_ipv6(ip_port.ip.family)) {
        struct sockaddr_in6 *const addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = ip_port.port;
        fill_addr6(ip_port.ip.ip.v6, &addr6->sin6_addr);

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
    } else {
        LOGGER_WARNING(net->log, "unknown address type: %d", ip_port.ip.family.value);
        return -1;
    }

    const int res = sendto(net->sock.socket, (const char *)data, length, 0, (struct sockaddr *)&addr, addrsize);

    loglogdata(net->log, "O=>", data, length, ip_port, res);

    return res;
}

/* Function to receive data
 *  ip and port of sender is put into ip_port.
 *  Packet data is put into data.
 *  Packet length is put into length.
 */
static int receivepacket(const Logger *log, Socket sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
{
    memset(ip_port, 0, sizeof(IP_Port));
    struct sockaddr_storage addr;
#ifdef OS_WIN32
    int addrlen = sizeof(addr);
#else
    socklen_t addrlen = sizeof(addr);
#endif
    *length = 0;
    int fail_or_len = recvfrom(sock.socket, (char *) data, MAX_UDP_PACKET_SIZE, 0, (struct sockaddr *)&addr, &addrlen);

    if (fail_or_len < 0) {
        int error = net_error();

        if (fail_or_len < 0 && error != TOX_EWOULDBLOCK) {
            const char *strerror = net_new_strerror(error);
            LOGGER_ERROR(log, "Unexpected error reading from socket: %u, %s", error, strerror);
            net_kill_strerror(strerror);
        }

        return -1; /* Nothing received. */
    }

    *length = (uint32_t)fail_or_len;

    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;

        const Family *const family = make_tox_family(addr_in->sin_family);
        assert(family != nullptr);

        if (family == nullptr) {
            return -1;
        }

        ip_port->ip.family = *family;
        get_ip4(&ip_port->ip.ip.v4, &addr_in->sin_addr);
        ip_port->port = addr_in->sin_port;
    } else if (addr.ss_family == AF_INET6) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        const Family *const family = make_tox_family(addr_in6->sin6_family);
        assert(family != nullptr);

        if (family == nullptr) {
            return -1;
        }

        ip_port->ip.family = *family;
        get_ip6(&ip_port->ip.ip.v6, &addr_in6->sin6_addr);
        ip_port->port = addr_in6->sin6_port;

        if (ipv6_ipv4_in_v6(ip_port->ip.ip.v6)) {
            ip_port->ip.family = net_family_ipv4;
            ip_port->ip.ip.v4.uint32 = ip_port->ip.ip.v6.uint32[3];
        }
    } else {
        return -1;
    }

    loglogdata(log, "=>O", data, MAX_UDP_PACKET_SIZE, *ip_port, *length);

    return 0;
}

void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_cb *cb, void *object)
{
    net->packethandlers[byte].function = cb;
    net->packethandlers[byte].object = object;
}

void networking_poll(Networking_Core *net, void *userdata)
{
    if (net_family_is_unspec(net->family)) {
        /* Socket not initialized */
        return;
    }

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (receivepacket(net->log, net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) {
            continue;
        }

        if (!(net->packethandlers[data[0]].function)) {
            LOGGER_WARNING(net->log, "[%02u] -- Packet has no handler", data[0]);
            continue;
        }

        net->packethandlers[data[0]].function(net->packethandlers[data[0]].object, ip_port, data, length, userdata);
    }
}

#ifndef VANILLA_NACL
/* Used for sodium_init() */
#include <sodium.h>
#endif

//!TOKSTYLE-
// Global mutable state is not allowed in Tokstyle.
static uint8_t at_startup_ran = 0;
//!TOKSTYLE+
int networking_at_startup(void)
{
    if (at_startup_ran != 0) {
        return 0;
    }

#ifndef VANILLA_NACL

#ifdef USE_RANDOMBYTES_STIR
    randombytes_stir();
#else

    if (sodium_init() == -1) {
        return -1;
    }

#endif /*USE_RANDOMBYTES_STIR*/

#endif/*VANILLA_NACL*/

#ifdef OS_WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return -1;
    }

#endif
    at_startup_ran = 1;
    return 0;
}

/* TODO(irungentoo): Put this somewhere */
#if 0
static void at_shutdown(void)
{
#ifdef OS_WIN32
    WSACleanup();
#endif
}
#endif

/* Initialize networking.
 * Added for reverse compatibility with old new_networking calls.
 */
Networking_Core *new_networking(const Logger *log, IP ip, uint16_t port)
{
    return new_networking_ex(log, ip, port, port + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), nullptr);
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
Networking_Core *new_networking_ex(const Logger *log, IP ip, uint16_t port_from, uint16_t port_to, unsigned int *error)
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

    if (error) {
        *error = 2;
    }

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (!net_family_is_ipv4(ip.family) && !net_family_is_ipv6(ip.family)) {
        LOGGER_ERROR(log, "invalid address family: %u", ip.family.value);
        return nullptr;
    }

    if (networking_at_startup() != 0) {
        return nullptr;
    }

    Networking_Core *temp = (Networking_Core *)calloc(1, sizeof(Networking_Core));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->log = log;
    temp->family = ip.family;
    temp->port = 0;

    /* Initialize our socket. */
    /* add log message what we're creating */
    temp->sock = net_socket(temp->family, TOX_SOCK_DGRAM, TOX_PROTO_UDP);

    /* Check for socket error. */
    if (!sock_valid(temp->sock)) {
        int neterror = net_error();
        const char *strerror = net_new_strerror(neterror);
        LOGGER_ERROR(log, "Failed to get a socket?! %d, %s", neterror, strerror);
        net_kill_strerror(strerror);
        free(temp);

        if (error) {
            *error = 1;
        }

        return nullptr;
    }

    /* Functions to increase the size of the send and receive UDP buffers.
     */
    int n = 1024 * 1024 * 2;
    setsockopt(temp->sock.socket, SOL_SOCKET, SO_RCVBUF, (const char *)&n, sizeof(n));
    setsockopt(temp->sock.socket, SOL_SOCKET, SO_SNDBUF, (const char *)&n, sizeof(n));

    /* Enable broadcast on socket */
    int broadcast = 1;
    setsockopt(temp->sock.socket, SOL_SOCKET, SO_BROADCAST, (const char *)&broadcast, sizeof(broadcast));

    /* iOS UDP sockets are weird and apparently can SIGPIPE */
    if (!set_socket_nosigpipe(temp->sock)) {
        kill_networking(temp);

        if (error) {
            *error = 1;
        }

        return nullptr;
    }

    /* Set socket nonblocking. */
    if (!set_socket_nonblock(temp->sock)) {
        kill_networking(temp);

        if (error) {
            *error = 1;
        }

        return nullptr;
    }

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    uint16_t *portptr = nullptr;
    struct sockaddr_storage addr;
    size_t addrsize;

    memset(&addr, 0, sizeof(struct sockaddr_storage));

    if (net_family_is_ipv4(temp->family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = 0;
        fill_addr4(ip.ip.v4, &addr4->sin_addr);

        portptr = &addr4->sin_port;
    } else if (net_family_is_ipv6(temp->family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = 0;
        fill_addr6(ip.ip.v6, &addr6->sin6_addr);

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;

        portptr = &addr6->sin6_port;
    } else {
        free(temp);
        return nullptr;
    }

    if (net_family_is_ipv6(ip.family)) {
        const int is_dualstack = set_socket_dualstack(temp->sock);
        LOGGER_DEBUG(log, "Dual-stack socket: %s",
                     is_dualstack ? "enabled" : "Failed to enable, won't be able to receive from/send to IPv4 addresses");
        /* multicast local nodes */
        struct ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;
        const int res = setsockopt(temp->sock.socket, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, (const char *)&mreq, sizeof(mreq));

        int neterror = net_error();
        const char *strerror = net_new_strerror(neterror);

        if (res < 0) {
            LOGGER_DEBUG(log, "Failed to activate local multicast membership. (%d, %s)", neterror, strerror);
        } else {
            LOGGER_DEBUG(log, "Local multicast group FF02::1 joined successfully. (%d, %s)", neterror, strerror);
        }

        net_kill_strerror(strerror);
    }

    /* A hanging program or a different user might block the standard port.
     * As long as it isn't a parameter coming from the commandline,
     * try a few ports after it, to see if we can find a "free" one.
     *
     * If we go on without binding, the first sendto() automatically binds to
     * a free port chosen by the system (i.e. anything from 1024 to 65535).
     *
     * Returning NULL after bind fails has both advantages and disadvantages:
     * advantage:
     *   we can rely on getting the port in the range 33445..33450, which
     *   enables us to tell joe user to open their firewall to a small range
     *
     * disadvantage:
     *   some clients might not test return of tox_new(), blindly assuming that
     *   it worked ok (which it did previously without a successful bind)
     */
    uint16_t port_to_try = port_from;
    *portptr = net_htons(port_to_try);
    int tries;

    for (tries = port_from; tries <= port_to; ++tries) {
        int res = bind(temp->sock.socket, (struct sockaddr *)&addr, addrsize);

        if (!res) {
            temp->port = *portptr;

            char ip_str[IP_NTOA_LEN];
            LOGGER_DEBUG(log, "Bound successfully to %s:%u", ip_ntoa(&ip, ip_str, sizeof(ip_str)),
                         net_ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            if (tries > 0) {
                errno = 0;
            }

            if (error) {
                *error = 0;
            }

            return temp;
        }

        ++port_to_try;

        if (port_to_try > port_to) {
            port_to_try = port_from;
        }

        *portptr = net_htons(port_to_try);
    }

    char ip_str[IP_NTOA_LEN];
    int neterror = net_error();
    const char *strerror = net_new_strerror(neterror);
    LOGGER_ERROR(log, "Failed to bind socket: %d, %s IP: %s port_from: %u port_to: %u", neterror, strerror,
                 ip_ntoa(&ip, ip_str, sizeof(ip_str)), port_from, port_to);
    net_kill_strerror(strerror);
    kill_networking(temp);

    if (error) {
        *error = 1;
    }

    return nullptr;
}

Networking_Core *new_networking_no_udp(const Logger *log)
{
    if (networking_at_startup() != 0) {
        return nullptr;
    }

    /* this is the easiest way to completely disable UDP without changing too much code. */
    Networking_Core *net = (Networking_Core *)calloc(1, sizeof(Networking_Core));

    if (net == nullptr) {
        return nullptr;
    }

    net->log = log;

    return net;
}

/* Function to cleanup networking stuff. */
void kill_networking(Networking_Core *net)
{
    if (!net) {
        return;
    }

    if (!net_family_is_unspec(net->family)) {
        /* Socket is initialized, so we close it. */
        kill_sock(net->sock);
    }

    free(net);
}


bool ip_equal(const IP *a, const IP *b)
{
    if (!a || !b) {
        return false;
    }

    /* same family */
    if (a->family.value == b->family.value) {
        if (net_family_is_ipv4(a->family) || net_family_is_tcp_ipv4(a->family)) {
            struct in_addr addr_a;
            struct in_addr addr_b;
            fill_addr4(a->ip.v4, &addr_a);
            fill_addr4(b->ip.v4, &addr_b);
            return addr_a.s_addr == addr_b.s_addr;
        }

        if (net_family_is_ipv6(a->family) || net_family_is_tcp_ipv6(a->family)) {
            return a->ip.v6.uint64[0] == b->ip.v6.uint64[0] &&
                   a->ip.v6.uint64[1] == b->ip.v6.uint64[1];
        }

        return false;
    }

    /* different family: check on the IPv6 one if it is the IPv4 one embedded */
    if (net_family_is_ipv4(a->family) && net_family_is_ipv6(b->family)) {
        if (ipv6_ipv4_in_v6(b->ip.v6)) {
            struct in_addr addr_a;
            fill_addr4(a->ip.v4, &addr_a);
            return addr_a.s_addr == b->ip.v6.uint32[3];
        }
    } else if (net_family_is_ipv6(a->family) && net_family_is_ipv4(b->family)) {
        if (ipv6_ipv4_in_v6(a->ip.v6)) {
            struct in_addr addr_b;
            fill_addr4(b->ip.v4, &addr_b);
            return a->ip.v6.uint32[3] == addr_b.s_addr;
        }
    }

    return false;
}

bool ipport_equal(const IP_Port *a, const IP_Port *b)
{
    if (!a || !b) {
        return false;
    }

    if (!a->port || (a->port != b->port)) {
        return false;
    }

    return ip_equal(&a->ip, &b->ip);
}

/* nulls out ip */
void ip_reset(IP *ip)
{
    if (!ip) {
        return;
    }

    memset(ip, 0, sizeof(IP));
}

/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, bool ipv6enabled)
{
    if (!ip) {
        return;
    }

    memset(ip, 0, sizeof(IP));
    ip->family = ipv6enabled ? net_family_ipv6 : net_family_ipv4;
}

/* checks if ip is valid */
bool ip_isset(const IP *ip)
{
    if (!ip) {
        return false;
    }

    return !net_family_is_unspec(ip->family);
}

/* checks if ip is valid */
bool ipport_isset(const IP_Port *ipport)
{
    if (!ipport) {
        return false;
    }

    if (!ipport->port) {
        return false;
    }

    return ip_isset(&ipport->ip);
}

/* copies an ip structure (careful about direction!) */
void ip_copy(IP *target, const IP *source)
{
    if (!source || !target) {
        return;
    }

    *target = *source;
}

/* copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port *target, const IP_Port *source)
{
    if (!source || !target) {
        return;
    }

    *target = *source;
}

/* ip_ntoa
 *   converts ip into a string
 *   ip_str must be of length at least IP_NTOA_LEN
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 *
 *   returns ip_str
 */
const char *ip_ntoa(const IP *ip, char *ip_str, size_t length)
{
    if (length < IP_NTOA_LEN) {
        snprintf(ip_str, length, "Bad buf length");
        return ip_str;
    }

    if (ip) {
        if (net_family_is_ipv4(ip->family)) {
            /* returns standard quad-dotted notation */
            struct in_addr addr;
            fill_addr4(ip->ip.v4, &addr);

            ip_str[0] = 0;
            assert(make_family(ip->family) == AF_INET);
            inet_ntop4(&addr, ip_str, length);
        } else if (net_family_is_ipv6(ip->family)) {
            /* returns hex-groups enclosed into square brackets */
            struct in6_addr addr;
            fill_addr6(ip->ip.v6, &addr);

            ip_str[0] = '[';
            assert(make_family(ip->family) == AF_INET6);
            inet_ntop6(&addr, &ip_str[1], length - 3);
            const size_t len = strlen(ip_str);
            ip_str[len] = ']';
            ip_str[len + 1] = 0;
        } else {
            snprintf(ip_str, length, "(IP invalid, family %u)", ip->family.value);
        }
    } else {
        snprintf(ip_str, length, "(IP invalid: NULL)");
    }

    /* brute force protection against lacking termination */
    ip_str[length - 1] = 0;
    return ip_str;
}

bool ip_parse_addr(const IP *ip, char *address, size_t length)
{
    if (!address || !ip) {
        return false;
    }

    if (net_family_is_ipv4(ip->family)) {
        const struct in_addr *addr = (const struct in_addr *)&ip->ip.v4;
        assert(make_family(ip->family) == AF_INET);
        return inet_ntop4(addr, address, length) != nullptr;
    }

    if (net_family_is_ipv6(ip->family)) {
        const struct in6_addr *addr = (const struct in6_addr *)&ip->ip.v6;
        assert(make_family(ip->family) == AF_INET6);
        return inet_ntop6(addr, address, length) != nullptr;
    }

    return false;
}

bool addr_parse_ip(const char *address, IP *to)
{
    if (!address || !to) {
        return false;
    }

    struct in_addr addr4;

    if (inet_pton4(address, &addr4) == 1) {
        to->family = net_family_ipv4;
        get_ip4(&to->ip.v4, &addr4);
        return true;
    }

    struct in6_addr addr6;

    if (inet_pton6(address, &addr6) == 1) {
        to->family = net_family_ipv6;
        get_ip6(&to->ip.v6, &addr6);
        return true;
    }

    return false;
}

int addr_resolve(const char *address, IP *to, IP *extra)
{
    if (!address || !to) {
        return 0;
    }

    Family tox_family = to->family;
    int family = make_family(tox_family);

    struct addrinfo *server = nullptr;
    struct addrinfo *walker = nullptr;
    struct addrinfo  hints;
    int rc;
    int result = 0;
    int done = 0;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    if (networking_at_startup() != 0) {
        return 0;
    }

    rc = getaddrinfo(address, nullptr, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    IP ip4;
    ip_init(&ip4, 0); // ipv6enabled = 0
    IP ip6;
    ip_init(&ip6, 1); // ipv6enabled = 1

    for (walker = server; (walker != nullptr) && !done; walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET:
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    struct sockaddr_in *addr = (struct sockaddr_in *)(void *)walker->ai_addr;
                    get_ip4(&to->ip.v4, &addr->sin_addr);
                    result = TOX_ADDR_RESOLVE_INET;
                    done = 1;
                } else if (!(result & TOX_ADDR_RESOLVE_INET)) { /* AF_UNSPEC requested, store away */
                    struct sockaddr_in *addr = (struct sockaddr_in *)(void *)walker->ai_addr;
                    get_ip4(&ip4.ip.v4, &addr->sin_addr);
                    result |= TOX_ADDR_RESOLVE_INET;
                }

                break; /* switch */

            case AF_INET6:
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(void *)walker->ai_addr;
                        get_ip6(&to->ip.v6, &addr->sin6_addr);
                        result = TOX_ADDR_RESOLVE_INET6;
                        done = 1;
                    }
                } else if (!(result & TOX_ADDR_RESOLVE_INET6)) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(void *)walker->ai_addr;
                        get_ip6(&ip6.ip.v6, &addr->sin6_addr);
                        result |= TOX_ADDR_RESOLVE_INET6;
                    }
                }

                break; /* switch */
        }
    }

    if (family == AF_UNSPEC) {
        if (result & TOX_ADDR_RESOLVE_INET6) {
            ip_copy(to, &ip6);

            if ((result & TOX_ADDR_RESOLVE_INET) && (extra != nullptr)) {
                ip_copy(extra, &ip4);
            }
        } else if (result & TOX_ADDR_RESOLVE_INET) {
            ip_copy(to, &ip4);
        } else {
            result = 0;
        }
    }

    freeaddrinfo(server);
    return result;
}

bool addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra)
{
    if (!addr_resolve(address, to, extra)) {
        if (!addr_parse_ip(address, to)) {
            return false;
        }
    }

    return true;
}

int net_connect(Socket sock, IP_Port ip_port)
{
    struct sockaddr_storage addr = {0};
    size_t addrsize;

    if (net_family_is_ipv4(ip_port.ip.family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        fill_addr4(ip_port.ip.ip.v4, &addr4->sin_addr);
        addr4->sin_port = ip_port.port;
    } else if (net_family_is_ipv6(ip_port.ip.family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        fill_addr6(ip_port.ip.ip.v6, &addr6->sin6_addr);
        addr6->sin6_port = ip_port.port;
    } else {
        return 0;
    }

    return connect(sock.socket, (struct sockaddr *)&addr, addrsize);
}

int32_t net_getipport(const char *node, IP_Port **res, int tox_type)
{
    struct addrinfo *infos;
    int ret = getaddrinfo(node, nullptr, nullptr, &infos);
    *res = nullptr;

    if (ret != 0) {
        return -1;
    }

    // Used to avoid malloc parameter overflow
    const size_t max_count = min_u64(SIZE_MAX, INT32_MAX) / sizeof(IP_Port);
    int type = make_socktype(tox_type);
    struct addrinfo *cur;
    size_t count = 0;

    for (cur = infos; count < max_count && cur != nullptr; cur = cur->ai_next) {
        if (cur->ai_socktype && type > 0 && cur->ai_socktype != type) {
            continue;
        }

        if (cur->ai_family != AF_INET && cur->ai_family != AF_INET6) {
            continue;
        }

        ++count;
    }

    assert(count <= max_count);

    if (count == 0) {
        freeaddrinfo(infos);
        return 0;
    }

    *res = (IP_Port *)malloc(sizeof(IP_Port) * count);

    if (*res == nullptr) {
        freeaddrinfo(infos);
        return -1;
    }

    IP_Port *ip_port = *res;

    for (cur = infos; cur != nullptr; cur = cur->ai_next) {
        if (cur->ai_socktype && type > 0 && cur->ai_socktype != type) {
            continue;
        }

        if (cur->ai_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)(void *)cur->ai_addr;
            memcpy(&ip_port->ip.ip.v4, &addr->sin_addr, sizeof(IP4));
        } else if (cur->ai_family == AF_INET6) {
            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)(void *)cur->ai_addr;
            memcpy(&ip_port->ip.ip.v6, &addr->sin6_addr, sizeof(IP6));
        } else {
            continue;
        }

        const Family *const family = make_tox_family(cur->ai_family);
        assert(family != nullptr);

        if (family == nullptr) {
            freeaddrinfo(infos);
            return -1;
        }

        ip_port->ip.family = *family;

        ++ip_port;
    }

    freeaddrinfo(infos);

    return count;
}

void net_freeipport(IP_Port *ip_ports)
{
    free(ip_ports);
}

bool bind_to_port(Socket sock, Family family, uint16_t port)
{
    struct sockaddr_storage addr = {0};
    size_t addrsize;

    if (net_family_is_ipv4(family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = net_htons(port);
    } else if (net_family_is_ipv6(family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = net_htons(port);
    } else {
        return false;
    }

    return bind(sock.socket, (struct sockaddr *)&addr, addrsize) == 0;
}

Socket net_socket(Family domain, int type, int protocol)
{
    const int platform_domain = make_family(domain);
    const int platform_type = make_socktype(type);
    const int platform_prot = make_proto(protocol);
    const Socket sock = {(int)socket(platform_domain, platform_type, platform_prot)};
    return sock;
}

int net_send(Socket sock, const void *buf, size_t len)
{
    return send(sock.socket, (const char *)buf, len, MSG_NOSIGNAL);
}

int net_recv(Socket sock, void *buf, size_t len)
{
    return recv(sock.socket, (char *)buf, len, MSG_NOSIGNAL);
}

int net_listen(Socket sock, int backlog)
{
    return listen(sock.socket, backlog);
}

Socket net_accept(Socket sock)
{
    const Socket newsock = {accept(sock.socket, nullptr, nullptr)};
    return newsock;
}

size_t net_socket_data_recv_buffer(Socket sock)
{
#ifdef OS_WIN32
    unsigned long count = 0;
    ioctlsocket(sock.socket, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock.socket, FIONREAD, &count);
#endif

    return count;
}

uint32_t net_htonl(uint32_t hostlong)
{
    return htonl(hostlong);
}

uint16_t net_htons(uint16_t hostshort)
{
    return htons(hostshort);
}

uint32_t net_ntohl(uint32_t hostlong)
{
    return ntohl(hostlong);
}

uint16_t net_ntohs(uint16_t hostshort)
{
    return ntohs(hostshort);
}

size_t net_pack_u16(uint8_t *bytes, uint16_t v)
{
    bytes[0] = (v >> 8) & 0xff;
    bytes[1] = v & 0xff;
    return sizeof(v);
}

size_t net_pack_u32(uint8_t *bytes, uint32_t v)
{
    uint8_t *p = bytes;
    p += net_pack_u16(p, (v >> 16) & 0xffff);
    p += net_pack_u16(p, v & 0xffff);
    return p - bytes;
}

size_t net_pack_u64(uint8_t *bytes, uint64_t v)
{
    uint8_t *p = bytes;
    p += net_pack_u32(p, (v >> 32) & 0xffffffff);
    p += net_pack_u32(p, v & 0xffffffff);
    return p - bytes;
}

size_t net_unpack_u16(const uint8_t *bytes, uint16_t *v)
{
    uint8_t hi = bytes[0];
    uint8_t lo = bytes[1];
    *v = ((uint16_t)hi << 8) | lo;
    return sizeof(*v);
}

size_t net_unpack_u32(const uint8_t *bytes, uint32_t *v)
{
    const uint8_t *p = bytes;
    uint16_t hi;
    uint16_t lo;
    p += net_unpack_u16(p, &hi);
    p += net_unpack_u16(p, &lo);
    *v = ((uint32_t)hi << 16) | lo;
    return p - bytes;
}

size_t net_unpack_u64(const uint8_t *bytes, uint64_t *v)
{
    const uint8_t *p = bytes;
    uint32_t hi;
    uint32_t lo;
    p += net_unpack_u32(p, &hi);
    p += net_unpack_u32(p, &lo);
    *v = ((uint64_t)hi << 32) | lo;
    return p - bytes;
}

bool ipv6_ipv4_in_v6(IP6 a)
{
    return a.uint64[0] == 0 && a.uint32[2] == net_htonl(0xffff);
}

int net_error(void)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

const char *net_new_strerror(int error)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    char *str = nullptr;
    // Windows API is weird. The 5th function arg is of char* type, but we
    // have to pass char** so that it could assign new memory block to our
    // pointer, so we have to cast our char** to char* for the compilation
    // not to fail (otherwise it would fail to find a variant of this function
    // accepting char** as the 5th arg) and Windows inside casts it back
    // to char** to do the assignment. So no, this cast you see here, although
    // it looks weird, is not a mistake.
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   error, 0, (char *)&str, 0, nullptr);
    return str;
#else
    return strerror(error);
#endif
}

void net_kill_strerror(const char *strerror)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    LocalFree((char *)strerror);
#endif
}
