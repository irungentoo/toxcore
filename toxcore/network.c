/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Functions for the core networking.
 */

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

#if defined(OS_WIN32) && !defined(WINVER)
// Windows XP
#define WINVER 0x0501
#endif

#include "network.h"

#ifdef PLAN9
#include <u.h> // Plan 9 requires this is imported first
// Comment line here to avoid reordering by source code formatters.
#include <libc.h>
#endif

#ifdef OS_WIN32 // Put win32 includes here
// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>
// Comment line here to avoid reordering by source code formatters.
#include <windows.h>
#include <ws2tcpip.h>
#endif

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

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef VANILLA_NACL
// Used for sodium_init()
#include <sodium.h>
#endif

#include "ccompat.h"
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

static_assert(sizeof(IP4) == SIZE_IP4, "IP4 size must be 4");

// TODO(iphydf): Stop relying on this. We memcpy this struct (and IP4 above)
// into packets but really should be serialising it properly.
static_assert(sizeof(IP6) == SIZE_IP6, "IP6 size must be 16");

#if !defined(OS_WIN32)

static bool should_ignore_recv_error(int err)
{
    return err == EWOULDBLOCK;
}

static bool should_ignore_connect_error(int err)
{
    return err == EWOULDBLOCK || err == EINPROGRESS;
}

non_null()
static const char *inet_ntop4(const struct in_addr *addr, char *buf, size_t bufsize)
{
    return inet_ntop(AF_INET, addr, buf, bufsize);
}

non_null()
static const char *inet_ntop6(const struct in6_addr *addr, char *buf, size_t bufsize)
{
    return inet_ntop(AF_INET6, addr, buf, bufsize);
}

non_null()
static int inet_pton4(const char *addrString, struct in_addr *addrbuf)
{
    return inet_pton(AF_INET, addrString, addrbuf);
}

non_null()
static int inet_pton6(const char *addrString, struct in6_addr *addrbuf)
{
    return inet_pton(AF_INET6, addrString, addrbuf);
}

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

static bool should_ignore_recv_error(int err)
{
    // We ignore WSAECONNRESET as Windows helpfully* sends that error if a
    // previously sent UDP packet wasn't delivered.
    return err == WSAEWOULDBLOCK || err == WSAECONNRESET;
}

static bool should_ignore_connect_error(int err)
{
    return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS;
}

non_null()
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

non_null()
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

non_null()
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

non_null()
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

static_assert(TOX_INET6_ADDRSTRLEN >= INET6_ADDRSTRLEN,
              "TOX_INET6_ADDRSTRLEN should be greater or equal to INET6_ADDRSTRLEN (#INET6_ADDRSTRLEN)");
static_assert(TOX_INET_ADDRSTRLEN >= INET_ADDRSTRLEN,
              "TOX_INET_ADDRSTRLEN should be greater or equal to INET_ADDRSTRLEN (#INET_ADDRSTRLEN)");

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

static const Family family_unspec = {TOX_AF_UNSPEC};
static const Family family_ipv4 = {TOX_AF_INET};
static const Family family_ipv6 = {TOX_AF_INET6};
static const Family family_tcp_server = {TCP_SERVER_FAMILY};
static const Family family_tcp_client = {TCP_CLIENT_FAMILY};
static const Family family_tcp_ipv4 = {TCP_INET};
static const Family family_tcp_ipv6 = {TCP_INET6};
static const Family family_tox_tcp_ipv4 = {TOX_TCP_INET};
static const Family family_tox_tcp_ipv6 = {TOX_TCP_INET6};

static const Family *make_tox_family(int family)
{
    switch (family) {
        case AF_INET:
            return &family_ipv4;

        case AF_INET6:
            return &family_ipv6;

        case AF_UNSPEC:
            return &family_unspec;

        default:
            return nullptr;
    }
}

non_null()
static void get_ip4(IP4 *result, const struct in_addr *addr)
{
    static_assert(sizeof(result->uint32) == sizeof(addr->s_addr),
                  "Tox and operating system don't agree on size of IPv4 addresses");
    result->uint32 = addr->s_addr;
}

non_null()
static void get_ip6(IP6 *result, const struct in6_addr *addr)
{
    static_assert(sizeof(result->uint8) == sizeof(addr->s6_addr),
                  "Tox and operating system don't agree on size of IPv6 addresses");
    memcpy(result->uint8, addr->s6_addr, sizeof(result->uint8));
}

non_null()
static void fill_addr4(const IP4 *ip, struct in_addr *addr)
{
    addr->s_addr = ip->uint32;
}

non_null()
static void fill_addr6(const IP6 *ip, struct in6_addr *addr)
{
    memcpy(addr->s6_addr, ip->uint8, sizeof(ip->uint8));
}

#if !defined(INADDR_LOOPBACK)
#define INADDR_LOOPBACK 0x7f000001
#endif

static const IP empty_ip = {{0}};
const IP_Port empty_ip_port = {{{0}}};

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
#ifdef ESP_PLATFORM
    loopback = empty_ip_port.ip.ip.v6;
    loopback.uint8[15] = 1;
#else
    get_ip6(&loopback, &in6addr_loopback);
#endif
    return loopback;
}

#ifndef OS_WIN32
#define INVALID_SOCKET (-1)
#endif

const Socket net_invalid_socket = { (int)INVALID_SOCKET };

Family net_family_unspec()
{
    return family_unspec;
}

Family net_family_ipv4()
{
    return family_ipv4;
}

Family net_family_ipv6()
{
    return family_ipv6;
}

Family net_family_tcp_server()
{
    return family_tcp_server;
}

Family net_family_tcp_client()
{
    return family_tcp_client;
}

Family net_family_tcp_ipv4()
{
    return family_tcp_ipv4;
}

Family net_family_tcp_ipv6()
{
    return family_tcp_ipv6;
}

Family net_family_tox_tcp_ipv4()
{
    return family_tox_tcp_ipv4;
}

Family net_family_tox_tcp_ipv6()
{
    return family_tox_tcp_ipv6;
}

bool net_family_is_unspec(Family family)
{
    return family.value == family_unspec.value;
}

bool net_family_is_ipv4(Family family)
{
    return family.value == family_ipv4.value;
}

bool net_family_is_ipv6(Family family)
{
    return family.value == family_ipv6.value;
}

bool net_family_is_tcp_server(Family family)
{
    return family.value == family_tcp_server.value;
}

bool net_family_is_tcp_client(Family family)
{
    return family.value == family_tcp_client.value;
}

bool net_family_is_tcp_ipv4(Family family)
{
    return family.value == family_tcp_ipv4.value;
}

bool net_family_is_tcp_ipv6(Family family)
{
    return family.value == family_tcp_ipv6.value;
}

bool net_family_is_tox_tcp_ipv4(Family family)
{
    return family.value == family_tox_tcp_ipv4.value;
}

bool net_family_is_tox_tcp_ipv6(Family family)
{
    return family.value == family_tox_tcp_ipv6.value;
}

bool sock_valid(Socket sock)
{
    return sock.sock != net_invalid_socket.sock;
}

struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

non_null()
static int sys_close(void *obj, int sock)
{
#if defined(OS_WIN32)
    return closesocket(sock);
#else  // !OS_WIN32
    return close(sock);
#endif
}

non_null()
static int sys_accept(void *obj, int sock)
{
    return accept(sock, nullptr, nullptr);
}

non_null()
static int sys_bind(void *obj, int sock, const Network_Addr *addr)
{
    return bind(sock, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int sys_listen(void *obj, int sock, int backlog)
{
    return listen(sock, backlog);
}

non_null()
static int sys_recvbuf(void *obj, int sock)
{
#ifdef OS_WIN32
    u_long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    return count;
}

non_null()
static int sys_recv(void *obj, int sock, uint8_t *buf, size_t len)
{
    return recv(sock, (char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int sys_send(void *obj, int sock, const uint8_t *buf, size_t len)
{
    return send(sock, (const char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int sys_sendto(void *obj, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
    return sendto(sock, (const char *)buf, len, 0, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int sys_recvfrom(void *obj, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
    socklen_t size = addr->size;
    const int ret = recvfrom(sock, (char *)buf, len, 0, (struct sockaddr *)&addr->addr, &size);
    addr->size = size;
    return ret;
}

non_null()
static int sys_socket(void *obj, int domain, int type, int proto)
{
    return (int)socket(domain, type, proto);
}

non_null()
static int sys_socket_nonblock(void *obj, int sock, bool nonblock)
{
#ifdef OS_WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    return fcntl(sock, F_SETFL, O_NONBLOCK, nonblock ? 1 : 0);
#endif /* OS_WIN32 */
}

non_null()
static int sys_getsockopt(void *obj, int sock, int level, int optname, void *optval, size_t *optlen)
{
    socklen_t len = *optlen;
    const int ret = getsockopt(sock, level, optname, optval, &len);
    *optlen = len;
    return ret;
}

non_null()
static int sys_setsockopt(void *obj, int sock, int level, int optname, const void *optval, size_t optlen)
{
    return setsockopt(sock, level, optname, optval, optlen);
}

static const Network_Funcs system_network_funcs = {
    sys_close,
    sys_accept,
    sys_bind,
    sys_listen,
    sys_recvbuf,
    sys_recv,
    sys_recvfrom,
    sys_send,
    sys_sendto,
    sys_socket,
    sys_socket_nonblock,
    sys_getsockopt,
    sys_setsockopt,
};
static const Network system_network_obj = {&system_network_funcs};

const Network *system_network(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif
#ifdef OS_WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return nullptr;
    }
#endif
    return &system_network_obj;
}

#if 0
/* TODO(iphydf): Call this from functions that use `system_network()`. */
void system_network_deinit(const Network *ns)
{
#ifdef OS_WIN32
    WSACleanup();
#endif
}
#endif

non_null()
static int net_setsockopt(const Network *ns, Socket sock, int level, int optname, const void *optval, size_t optlen)
{
    return ns->funcs->setsockopt(ns->obj, sock.sock, level, optname, optval, optlen);
}

non_null()
static int net_getsockopt(const Network *ns, Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    return ns->funcs->getsockopt(ns->obj, sock.sock, level, optname, optval, optlen);
}

non_null()
static uint32_t data_0(uint16_t buflen, const uint8_t *buffer)
{
    uint32_t data = 0;

    if (buflen > 4) {
        net_unpack_u32(buffer + 1, &data);
    }

    return data;
}
non_null()
static uint32_t data_1(uint16_t buflen, const uint8_t *buffer)
{
    uint32_t data = 0;

    if (buflen > 8) {
        net_unpack_u32(buffer + 5, &data);
    }

    return data;
}

non_null()
static void loglogdata(const Logger *log, const char *message, const uint8_t *buffer,
                       uint16_t buflen, const IP_Port *ip_port, long res)
{
    if (res < 0) { /* Windows doesn't necessarily know `%zu` */
        Ip_Ntoa ip_str;
        const int error = net_error();
        char *strerror = net_new_strerror(error);
        LOGGER_TRACE(log, "[%2u] %s %3u%c %s:%u (%u: %s) | %08x%08x...%02x",
                     buffer[0], message, min_u16(buflen, 999), 'E',
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), error,
                     strerror, data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
        net_kill_strerror(strerror);
    } else if ((res > 0) && ((size_t)res <= buflen)) {
        Ip_Ntoa ip_str;
        LOGGER_TRACE(log, "[%2u] %s %3u%c %s:%u (%u: %s) | %08x%08x...%02x",
                     buffer[0], message, min_u16(res, 999), (size_t)res < buflen ? '<' : '=',
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
    } else { /* empty or overwrite */
        Ip_Ntoa ip_str;
        LOGGER_TRACE(log, "[%2u] %s %lu%c%u %s:%u (%u: %s) | %08x%08x...%02x",
                     buffer[0], message, res, res == 0 ? '!' : '>', buflen,
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
    }
}

int net_send(const Network *ns, const Logger *log,
             Socket sock, const uint8_t *buf, size_t len, const IP_Port *ip_port)
{
    const int res = ns->funcs->send(ns->obj, sock.sock, buf, len);
    loglogdata(log, "T=>", buf, len, ip_port, res);
    return res;
}

non_null()
static int net_sendto(
        const Network *ns,
        Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr, const IP_Port *ip_port)
{
    return ns->funcs->sendto(ns->obj, sock.sock, buf, len, addr);
}

int net_recv(const Network *ns, const Logger *log,
             Socket sock, uint8_t *buf, size_t len, const IP_Port *ip_port)
{
    const int res = ns->funcs->recv(ns->obj, sock.sock, buf, len);
    loglogdata(log, "=>T", buf, len, ip_port, res);
    return res;
}

non_null()
static int net_recvfrom(const Network *ns,
                        Socket sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    return ns->funcs->recvfrom(ns->obj, sock.sock, buf, len, addr);
}

int net_listen(const Network *ns, Socket sock, int backlog)
{
    return ns->funcs->listen(ns->obj, sock.sock, backlog);
}

non_null()
static int net_bind(const Network *ns, Socket sock, const Network_Addr *addr)
{
    return ns->funcs->bind(ns->obj, sock.sock, addr);
}

Socket net_accept(const Network *ns, Socket sock)
{
    const Socket newsock = {ns->funcs->accept(ns->obj, sock.sock)};
    return newsock;
}

/** Close the socket. */
void kill_sock(const Network *ns, Socket sock)
{
    ns->funcs->close(ns->obj, sock.sock);
}

bool set_socket_nonblock(const Network *ns, Socket sock)
{
    return ns->funcs->socket_nonblock(ns->obj, sock.sock, true) == 0;
}

bool set_socket_nosigpipe(const Network *ns, Socket sock)
{
#if defined(__APPLE__)
    int set = 1;
    return net_setsockopt(ns, sock, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(int)) == 0;
#else
    return true;
#endif
}

bool set_socket_reuseaddr(const Network *ns, Socket sock)
{
    int set = 1;
    return net_setsockopt(ns, sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) == 0;
}

bool set_socket_dualstack(const Network *ns, Socket sock)
{
    int ipv6only = 0;
    size_t optsize = sizeof(ipv6only);
    const int res = net_getsockopt(ns, sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0)) {
        return true;
    }

    ipv6only = 0;
    return net_setsockopt(ns, sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) == 0;
}


typedef struct Packet_Handler {
    packet_handler_cb *function;
    void *object;
} Packet_Handler;

struct Networking_Core {
    const Logger *log;
    Packet_Handler packethandlers[256];
    const Network *ns;

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
 */

int send_packet(const Networking_Core *net, const IP_Port *ip_port, Packet packet)
{
    IP_Port ipp_copy = *ip_port;

    if (net_family_is_unspec(ip_port->ip.family)) {
        // TODO(iphydf): Make this an error. Currently this fails sometimes when
        // called from DHT.c:do_ping_and_sendnode_requests.
        return -1;
    }

    if (net_family_is_unspec(net->family)) { /* Socket not initialized */
        // TODO(iphydf): Make this an error. Currently, the onion client calls
        // this via DHT getnodes.
        LOGGER_WARNING(net->log, "attempted to send message of length %u on uninitialised socket", packet.length);
        return -1;
    }

    /* socket TOX_AF_INET, but target IP NOT: can't send */
    if (net_family_is_ipv4(net->family) && !net_family_is_ipv4(ipp_copy.ip.family)) {
        // TODO(iphydf): Make this an error. Occasionally we try to send to an
        // all-zero ip_port.
        LOGGER_WARNING(net->log, "attempted to send message with network family %d (probably IPv6) on IPv4 socket",
                       ipp_copy.ip.family.value);
        return -1;
    }

    if (net_family_is_ipv4(ipp_copy.ip.family) && net_family_is_ipv6(net->family)) {
        /* must convert to IPV4-in-IPV6 address */
        IP6 ip6;

        /* there should be a macro for this in a standards compliant
         * environment, not found */
        ip6.uint32[0] = 0;
        ip6.uint32[1] = 0;
        ip6.uint32[2] = net_htonl(0xFFFF);
        ip6.uint32[3] = ipp_copy.ip.ip.v4.uint32;

        ipp_copy.ip.family = net_family_ipv6();
        ipp_copy.ip.ip.v6 = ip6;
    }

    Network_Addr addr;

    if (net_family_is_ipv4(ipp_copy.ip.family)) {
        struct sockaddr_in *const addr4 = (struct sockaddr_in *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = ipp_copy.port;
        fill_addr4(&ipp_copy.ip.ip.v4, &addr4->sin_addr);
    } else if (net_family_is_ipv6(ipp_copy.ip.family)) {
        struct sockaddr_in6 *const addr6 = (struct sockaddr_in6 *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = ipp_copy.port;
        fill_addr6(&ipp_copy.ip.ip.v6, &addr6->sin6_addr);

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
    } else {
        LOGGER_ERROR(net->log, "unknown address type: %d", ipp_copy.ip.family.value);
        return -1;
    }

    const long res = net_sendto(net->ns, net->sock, packet.data, packet.length, &addr, &ipp_copy);
    loglogdata(net->log, "O=>", packet.data, packet.length, ip_port, res);

    assert(res <= INT_MAX);
    return (int)res;
}

/**
 * Function to send packet(data) of length length to ip_port.
 *
 * @deprecated Use send_packet instead.
 */
int sendpacket(const Networking_Core *net, const IP_Port *ip_port, const uint8_t *data, uint16_t length)
{
    const Packet packet = {data, length};
    return send_packet(net, ip_port, packet);
}

/** @brief Function to receive data
 * ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
non_null()
static int receivepacket(const Network *ns, const Logger *log, Socket sock, IP_Port *ip_port, uint8_t *data, uint32_t *length)
{
    memset(ip_port, 0, sizeof(IP_Port));
    Network_Addr addr = {{0}};
    addr.size = sizeof(addr.addr);
    *length = 0;

    const int fail_or_len = net_recvfrom(ns, sock, data, MAX_UDP_PACKET_SIZE, &addr);

    if (fail_or_len < 0) {
        const int error = net_error();

        if (!should_ignore_recv_error(error)) {
            char *strerror = net_new_strerror(error);
            LOGGER_ERROR(log, "unexpected error reading from socket: %u, %s", error, strerror);
            net_kill_strerror(strerror);
        }

        return -1; /* Nothing received. */
    }

    *length = (uint32_t)fail_or_len;

    if (addr.addr.ss_family == AF_INET) {
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)&addr.addr;

        const Family *const family = make_tox_family(addr_in->sin_family);
        assert(family != nullptr);

        if (family == nullptr) {
            return -1;
        }

        ip_port->ip.family = *family;
        get_ip4(&ip_port->ip.ip.v4, &addr_in->sin_addr);
        ip_port->port = addr_in->sin_port;
    } else if (addr.addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)&addr.addr;
        const Family *const family = make_tox_family(addr_in6->sin6_family);
        assert(family != nullptr);

        if (family == nullptr) {
            return -1;
        }

        ip_port->ip.family = *family;
        get_ip6(&ip_port->ip.ip.v6, &addr_in6->sin6_addr);
        ip_port->port = addr_in6->sin6_port;

        if (ipv6_ipv4_in_v6(&ip_port->ip.ip.v6)) {
            ip_port->ip.family = net_family_ipv4();
            ip_port->ip.ip.v4.uint32 = ip_port->ip.ip.v6.uint32[3];
        }
    } else {
        return -1;
    }

    loglogdata(log, "=>O", data, MAX_UDP_PACKET_SIZE, ip_port, *length);

    return 0;
}

void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_cb *cb, void *object)
{
    net->packethandlers[byte].function = cb;
    net->packethandlers[byte].object = object;
}

void networking_poll(const Networking_Core *net, void *userdata)
{
    if (net_family_is_unspec(net->family)) {
        /* Socket not initialized */
        return;
    }

    IP_Port ip_port;
    uint8_t data[MAX_UDP_PACKET_SIZE];
    uint32_t length;

    while (receivepacket(net->ns, net->log, net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) {
            continue;
        }

        const Packet_Handler *const handler = &net->packethandlers[data[0]];

        if (handler->function == nullptr) {
            // TODO(https://github.com/TokTok/c-toxcore/issues/1115): Make this
            // a warning or error again.
            LOGGER_DEBUG(net->log, "[%02u] -- Packet has no handler", data[0]);
            continue;
        }

        handler->function(handler->object, &ip_port, data, length, userdata);
    }
}

/** @brief Initialize networking.
 * Bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 * @return Networking_Core object if no problems
 * @retval NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.
 */
Networking_Core *new_networking_ex(
        const Logger *log, const Network *ns, const IP *ip,
        uint16_t port_from, uint16_t port_to, unsigned int *error)
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
        const uint16_t temp_port = port_from;
        port_from = port_to;
        port_to = temp_port;
    }

    if (error != nullptr) {
        *error = 2;
    }

    /* maybe check for invalid IPs like 224+.x.y.z? if there is any IP set ever */
    if (!net_family_is_ipv4(ip->family) && !net_family_is_ipv6(ip->family)) {
        LOGGER_ERROR(log, "invalid address family: %u", ip->family.value);
        return nullptr;
    }

    Networking_Core *temp = (Networking_Core *)calloc(1, sizeof(Networking_Core));

    if (temp == nullptr) {
        return nullptr;
    }

    temp->ns = ns;
    temp->log = log;
    temp->family = ip->family;
    temp->port = 0;

    /* Initialize our socket. */
    /* add log message what we're creating */
    temp->sock = net_socket(ns, temp->family, TOX_SOCK_DGRAM, TOX_PROTO_UDP);

    /* Check for socket error. */
    if (!sock_valid(temp->sock)) {
        const int neterror = net_error();
        char *strerror = net_new_strerror(neterror);
        LOGGER_ERROR(log, "failed to get a socket?! %d, %s", neterror, strerror);
        net_kill_strerror(strerror);
        free(temp);

        if (error != nullptr) {
            *error = 1;
        }

        return nullptr;
    }

    /* Functions to increase the size of the send and receive UDP buffers.
     */
    int n = 1024 * 1024 * 2;

    if (net_setsockopt(ns, temp->sock, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) != 0) {
        LOGGER_ERROR(log, "failed to set socket option %d", SO_RCVBUF);
    }

    if (net_setsockopt(ns, temp->sock, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) != 0) {
        LOGGER_ERROR(log, "failed to set socket option %d", SO_SNDBUF);
    }

    /* Enable broadcast on socket */
    int broadcast = 1;

    if (net_setsockopt(ns, temp->sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) != 0) {
        LOGGER_ERROR(log, "failed to set socket option %d", SO_BROADCAST);
    }

    /* iOS UDP sockets are weird and apparently can SIGPIPE */
    if (!set_socket_nosigpipe(ns, temp->sock)) {
        kill_networking(temp);

        if (error != nullptr) {
            *error = 1;
        }

        return nullptr;
    }

    /* Set socket nonblocking. */
    if (!set_socket_nonblock(ns, temp->sock)) {
        kill_networking(temp);

        if (error != nullptr) {
            *error = 1;
        }

        return nullptr;
    }

    /* Bind our socket to port PORT and the given IP address (usually 0.0.0.0 or ::) */
    uint16_t *portptr = nullptr;
    Network_Addr addr;

    memset(&addr.addr, 0, sizeof(struct sockaddr_storage));

    if (net_family_is_ipv4(temp->family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = 0;
        fill_addr4(&ip->ip.v4, &addr4->sin_addr);

        portptr = &addr4->sin_port;
    } else if (net_family_is_ipv6(temp->family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = 0;
        fill_addr6(&ip->ip.v6, &addr6->sin6_addr);

        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;

        portptr = &addr6->sin6_port;
    } else {
        free(temp);
        return nullptr;
    }

    if (net_family_is_ipv6(ip->family)) {
        const bool is_dualstack = set_socket_dualstack(ns, temp->sock);

        if (is_dualstack) {
            LOGGER_TRACE(log, "Dual-stack socket: enabled");
        } else {
            LOGGER_ERROR(log, "Dual-stack socket failed to enable, won't be able to receive from/send to IPv4 addresses");
        }

#ifndef ESP_PLATFORM
        /* multicast local nodes */
        struct ipv6_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        mreq.ipv6mr_multiaddr.s6_addr[ 0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[ 1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;

        const int res = net_setsockopt(ns, temp->sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

        int neterror = net_error();
        char *strerror = net_new_strerror(neterror);

        if (res < 0) {
            LOGGER_INFO(log, "Failed to activate local multicast membership in FF02::1. (%d, %s)", neterror, strerror);
        } else {
            LOGGER_TRACE(log, "Local multicast group joined successfully. (%d, %s)", neterror, strerror);
        }

        net_kill_strerror(strerror);
#endif
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

    for (uint16_t tries = port_from; tries <= port_to; ++tries) {
        const int res = net_bind(ns, temp->sock, &addr);

        if (res == 0) {
            temp->port = *portptr;

            Ip_Ntoa ip_str;
            LOGGER_DEBUG(log, "Bound successfully to %s:%u", net_ip_ntoa(ip, &ip_str),
                         net_ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            if (tries > 0) {
                errno = 0;
            }

            if (error != nullptr) {
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

    Ip_Ntoa ip_str;
    int neterror = net_error();
    char *strerror = net_new_strerror(neterror);
    LOGGER_ERROR(log, "failed to bind socket: %d, %s IP: %s port_from: %u port_to: %u", neterror, strerror,
                 net_ip_ntoa(ip, &ip_str), port_from, port_to);
    net_kill_strerror(strerror);
    kill_networking(temp);

    if (error != nullptr) {
        *error = 1;
    }

    return nullptr;
}

Networking_Core *new_networking_no_udp(const Logger *log, const Network *ns)
{
    /* this is the easiest way to completely disable UDP without changing too much code. */
    Networking_Core *net = (Networking_Core *)calloc(1, sizeof(Networking_Core));

    if (net == nullptr) {
        return nullptr;
    }

    net->ns = ns;
    net->log = log;

    return net;
}

/** Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net)
{
    if (net == nullptr) {
        return;
    }

    if (!net_family_is_unspec(net->family)) {
        /* Socket is initialized, so we close it. */
        kill_sock(net->ns, net->sock);
    }

    free(net);
}


bool ip_equal(const IP *a, const IP *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }

    /* same family */
    if (a->family.value == b->family.value) {
        if (net_family_is_ipv4(a->family) || net_family_is_tcp_ipv4(a->family)) {
            struct in_addr addr_a;
            struct in_addr addr_b;
            fill_addr4(&a->ip.v4, &addr_a);
            fill_addr4(&b->ip.v4, &addr_b);
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
        if (ipv6_ipv4_in_v6(&b->ip.v6)) {
            struct in_addr addr_a;
            fill_addr4(&a->ip.v4, &addr_a);
            return addr_a.s_addr == b->ip.v6.uint32[3];
        }
    } else if (net_family_is_ipv6(a->family) && net_family_is_ipv4(b->family)) {
        if (ipv6_ipv4_in_v6(&a->ip.v6)) {
            struct in_addr addr_b;
            fill_addr4(&b->ip.v4, &addr_b);
            return a->ip.v6.uint32[3] == addr_b.s_addr;
        }
    }

    return false;
}

bool ipport_equal(const IP_Port *a, const IP_Port *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }

    if (a->port == 0 || (a->port != b->port)) {
        return false;
    }

    return ip_equal(&a->ip, &b->ip);
}

/** nulls out ip */
void ip_reset(IP *ip)
{
    if (ip == nullptr) {
        return;
    }

    *ip = empty_ip;
}

/** nulls out ip_port */
void ipport_reset(IP_Port *ipport)
{
    if (ipport == nullptr) {
        return;
    }

    *ipport = empty_ip_port;
}

/** nulls out ip, sets family according to flag */
void ip_init(IP *ip, bool ipv6enabled)
{
    if (ip == nullptr) {
        return;
    }

    *ip = empty_ip;
    ip->family = ipv6enabled ? net_family_ipv6() : net_family_ipv4();
}

/** checks if ip is valid */
bool ip_isset(const IP *ip)
{
    if (ip == nullptr) {
        return false;
    }

    return !net_family_is_unspec(ip->family);
}

/** checks if ip is valid */
bool ipport_isset(const IP_Port *ipport)
{
    if (ipport == nullptr) {
        return false;
    }

    if (ipport->port == 0) {
        return false;
    }

    return ip_isset(&ipport->ip);
}

/** copies an ip structure (careful about direction) */
void ip_copy(IP *target, const IP *source)
{
    if (source == nullptr || target == nullptr) {
        return;
    }

    *target = *source;
}

/** copies an ip_port structure (careful about direction) */
void ipport_copy(IP_Port *target, const IP_Port *source)
{
    if (source == nullptr || target == nullptr) {
        return;
    }

    *target = *source;
}

/** @brief Converts IP into a string.
 *
 * Writes error message into the buffer on error.
 *
 * @param ip_str contains a buffer of the required size.
 *
 * @return Pointer to the buffer inside `ip_str` containing the IP string.
 */
const char *net_ip_ntoa(const IP *ip, Ip_Ntoa *ip_str)
{
    assert(ip_str != nullptr);

    if (ip == nullptr) {
        snprintf(ip_str->buf, sizeof(ip_str->buf), "(IP invalid: NULL)");
        return ip_str->buf;
    }

    if (!ip_parse_addr(ip, ip_str->buf, sizeof(ip_str->buf))) {
        snprintf(ip_str->buf, sizeof(ip_str->buf), "(IP invalid, family %u)", ip->family.value);
        return ip_str->buf;
    }

    /* brute force protection against lacking termination */
    ip_str->buf[sizeof(ip_str->buf) - 1] = '\0';
    return ip_str->buf;
}

bool ip_parse_addr(const IP *ip, char *address, size_t length)
{
    if (address == nullptr || ip == nullptr) {
        return false;
    }

    if (net_family_is_ipv4(ip->family)) {
        struct in_addr addr;
        assert(make_family(ip->family) == AF_INET);
        fill_addr4(&ip->ip.v4, &addr);
        return inet_ntop4(&addr, address, length) != nullptr;
    }

    if (net_family_is_ipv6(ip->family)) {
        struct in6_addr addr;
        assert(make_family(ip->family) == AF_INET6);
        fill_addr6(&ip->ip.v6, &addr);
        return inet_ntop6(&addr, address, length) != nullptr;
    }

    return false;
}

bool addr_parse_ip(const char *address, IP *to)
{
    if (address == nullptr || to == nullptr) {
        return false;
    }

    struct in_addr addr4;

    if (inet_pton4(address, &addr4) == 1) {
        to->family = net_family_ipv4();
        get_ip4(&to->ip.v4, &addr4);
        return true;
    }

    struct in6_addr addr6;

    if (inet_pton6(address, &addr6) == 1) {
        to->family = net_family_ipv6();
        get_ip6(&to->ip.v6, &addr6);
        return true;
    }

    return false;
}

/** addr_resolve return values */
#define TOX_ADDR_RESOLVE_INET  1
#define TOX_ADDR_RESOLVE_INET6 2

/**
 * Uses getaddrinfo to resolve an address into an IP address.
 *
 * Uses the first IPv4/IPv6 addresses returned by getaddrinfo.
 *
 * @param address a hostname (or something parseable to an IP address)
 * @param to to.family MUST be initialized, either set to a specific IP version
 *   (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (0), if both
 *   IP versions are acceptable
 * @param extra can be NULL and is only set in special circumstances, see returns
 *
 * Returns in `*to` a valid IPAny (v4/v6),
 * prefers v6 if `ip.family` was TOX_AF_UNSPEC and both available
 * Returns in `*extra` an IPv4 address, if family was TOX_AF_UNSPEC and `*to` is TOX_AF_INET6
 *
 * @return 0 on failure, `TOX_ADDR_RESOLVE_*` on success.
 */
non_null(1, 2, 3) nullable(4)
static int addr_resolve(const Network *ns, const char *address, IP *to, IP *extra)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return 0;
    }
#endif

    if (address == nullptr || to == nullptr) {
        return 0;
    }

    const Family tox_family = to->family;
    const int family = make_family(tox_family);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.

    struct addrinfo *server = nullptr;

    const int rc = getaddrinfo(address, nullptr, &hints, &server);

    // Lookup failed.
    if (rc != 0) {
        return 0;
    }

    IP ip4;
    ip_init(&ip4, false); // ipv6enabled = false
    IP ip6;
    ip_init(&ip6, true); // ipv6enabled = true

    int result = 0;
    bool done = false;

    for (struct addrinfo *walker = server; walker != nullptr && !done; walker = walker->ai_next) {
        switch (walker->ai_family) {
            case AF_INET: {
                if (walker->ai_family == family) { /* AF_INET requested, done */
                    const struct sockaddr_in *addr = (const struct sockaddr_in *)(const void *)walker->ai_addr;
                    get_ip4(&to->ip.v4, &addr->sin_addr);
                    result = TOX_ADDR_RESOLVE_INET;
                    done = true;
                } else if ((result & TOX_ADDR_RESOLVE_INET) == 0) { /* AF_UNSPEC requested, store away */
                    const struct sockaddr_in *addr = (const struct sockaddr_in *)(const void *)walker->ai_addr;
                    get_ip4(&ip4.ip.v4, &addr->sin_addr);
                    result |= TOX_ADDR_RESOLVE_INET;
                }

                break; /* switch */
            }

            case AF_INET6: {
                if (walker->ai_family == family) { /* AF_INET6 requested, done */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)(void *)walker->ai_addr;
                        get_ip6(&to->ip.v6, &addr->sin6_addr);
                        result = TOX_ADDR_RESOLVE_INET6;
                        done = true;
                    }
                } else if ((result & TOX_ADDR_RESOLVE_INET6) == 0) { /* AF_UNSPEC requested, store away */
                    if (walker->ai_addrlen == sizeof(struct sockaddr_in6)) {
                        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)(void *)walker->ai_addr;
                        get_ip6(&ip6.ip.v6, &addr->sin6_addr);
                        result |= TOX_ADDR_RESOLVE_INET6;
                    }
                }

                break; /* switch */
            }
        }
    }

    if (family == AF_UNSPEC) {
        if ((result & TOX_ADDR_RESOLVE_INET6) != 0) {
            ip_copy(to, &ip6);

            if ((result & TOX_ADDR_RESOLVE_INET) != 0 && (extra != nullptr)) {
                ip_copy(extra, &ip4);
            }
        } else if ((result & TOX_ADDR_RESOLVE_INET) != 0) {
            ip_copy(to, &ip4);
        } else {
            result = 0;
        }
    }

    freeaddrinfo(server);
    return result;
}

bool addr_resolve_or_parse_ip(const Network *ns, const char *address, IP *to, IP *extra)
{
    if (addr_resolve(ns, address, to, extra) == 0) {
        if (!addr_parse_ip(address, to)) {
            return false;
        }
    }

    return true;
}

bool net_connect(const Logger *log, Socket sock, const IP_Port *ip_port)
{
    struct sockaddr_storage addr = {0};
    size_t addrsize;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr;

        addrsize = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        fill_addr4(&ip_port->ip.ip.v4, &addr4->sin_addr);
        addr4->sin_port = ip_port->port;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr;

        addrsize = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        fill_addr6(&ip_port->ip.ip.v6, &addr6->sin6_addr);
        addr6->sin6_port = ip_port->port;
    } else {
        Ip_Ntoa ip_str;
        LOGGER_ERROR(log, "cannot connect to %s:%d which is neither IPv4 nor IPv6",
                     net_ip_ntoa(&ip_port->ip, &ip_str), ip_port->port);
        return false;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return true;
    }
#endif

    Ip_Ntoa ip_str;
    LOGGER_DEBUG(log, "connecting socket %d to %s:%d",
                 (int)sock.sock, net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port));
    errno = 0;

    if (connect(sock.sock, (struct sockaddr *)&addr, addrsize) == -1) {
        const int error = net_error();

        // Non-blocking socket: "Operation in progress" means it's connecting.
        if (!should_ignore_connect_error(error)) {
            char *net_strerror = net_new_strerror(error);
            LOGGER_ERROR(log, "failed to connect to %s:%d: %d (%s)",
                         net_ip_ntoa(&ip_port->ip, &ip_str), ip_port->port, error, net_strerror);
            net_kill_strerror(net_strerror);
            return false;
        }
    }

    return true;
}

int32_t net_getipport(const char *node, IP_Port **res, int tox_type)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        *res = (IP_Port *)calloc(1, sizeof(IP_Port));
        assert(*res != nullptr);
        IP_Port *ip_port = *res;
        ip_port->ip.ip.v4.uint32 = 0x7F000003; // 127.0.0.3
        ip_port->ip.family = *make_tox_family(AF_INET);

        return 1;
    }
#endif

    // Try parsing as IP address first.
    IP_Port parsed = {{{0}}};

    if (addr_parse_ip(node, &parsed.ip)) {
        IP_Port *tmp = (IP_Port *)calloc(1, sizeof(IP_Port));

        if (tmp == nullptr) {
            return -1;
        }

        tmp[0] = parsed;
        *res = tmp;
        return 1;
    }

    // It's not an IP address, so now we try doing a DNS lookup.
    struct addrinfo *infos;
    const int ret = getaddrinfo(node, nullptr, nullptr, &infos);
    *res = nullptr;

    if (ret != 0) {
        return -1;
    }

    // Used to avoid calloc parameter overflow
    const size_t max_count = min_u64(SIZE_MAX, INT32_MAX) / sizeof(IP_Port);
    const int type = make_socktype(tox_type);
    size_t count = 0;

    for (struct addrinfo *cur = infos; count < max_count && cur != nullptr; cur = cur->ai_next) {
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

    *res = (IP_Port *)calloc(count, sizeof(IP_Port));

    if (*res == nullptr) {
        freeaddrinfo(infos);
        return -1;
    }

    IP_Port *ip_port = *res;

    for (struct addrinfo *cur = infos; cur != nullptr; cur = cur->ai_next) {
        if (cur->ai_socktype && type > 0 && cur->ai_socktype != type) {
            continue;
        }

        if (cur->ai_family == AF_INET) {
            const struct sockaddr_in *addr = (const struct sockaddr_in *)(const void *)cur->ai_addr;
            memcpy(&ip_port->ip.ip.v4, &addr->sin_addr, sizeof(IP4));
        } else if (cur->ai_family == AF_INET6) {
            const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)(const void *)cur->ai_addr;
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

bool bind_to_port(const Network *ns, Socket sock, Family family, uint16_t port)
{
    Network_Addr addr = {{0}};

    if (net_family_is_ipv4(family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        addr4->sin_port = net_htons(port);
    } else if (net_family_is_ipv6(family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr.addr;

        addr.size = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = net_htons(port);
    } else {
        return false;
    }

    return net_bind(ns, sock, &addr) == 0;
}

Socket net_socket(const Network *ns, Family domain, int type, int protocol)
{
    const int platform_domain = make_family(domain);
    const int platform_type = make_socktype(type);
    const int platform_prot = make_proto(protocol);
    const Socket sock = {ns->funcs->socket(ns->obj, platform_domain, platform_type, platform_prot)};
    return sock;
}

uint16_t net_socket_data_recv_buffer(const Network *ns, Socket sock)
{
    const int count = ns->funcs->recvbuf(ns->obj, sock.sock);
    return (uint16_t)max_s32(0, min_s32(count, UINT16_MAX));
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
    const uint8_t hi = bytes[0];
    const uint8_t lo = bytes[1];
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

bool ipv6_ipv4_in_v6(const IP6 *a)
{
    return a->uint64[0] == 0 && a->uint32[2] == net_htonl(0xffff);
}

int net_error(void)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    return WSAGetLastError();
#else
    return errno;
#endif
}

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
char *net_new_strerror(int error)
{
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
}
#else
#ifdef _GNU_SOURCE
non_null()
static const char *net_strerror_r(int error, char *tmp, size_t tmp_size)
{
    const char *retstr = strerror_r(error, tmp, tmp_size);

    if (errno != 0) {
        snprintf(tmp, tmp_size, "error %d (strerror_r failed with errno %d)", error, errno);
    }

    return retstr;
}
#else
non_null()
static const char *net_strerror_r(int error, char *tmp, size_t tmp_size)
{
    const int fmt_error = strerror_r(error, tmp, tmp_size);

    if (fmt_error != 0) {
        snprintf(tmp, tmp_size, "error %d (strerror_r failed with error %d, errno %d)", error, fmt_error, errno);
    }

    return tmp;
}
#endif
char *net_new_strerror(int error)
{
    char tmp[256];

    errno = 0;

    const char *retstr = net_strerror_r(error, tmp, sizeof(tmp));
    const size_t retstr_len = strlen(retstr);

    char *str = (char *)malloc(retstr_len + 1);

    if (str == nullptr) {
        return nullptr;
    }

    memcpy(str, retstr, retstr_len + 1);

    return str;
}
#endif

void net_kill_strerror(char *strerror)
{
#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
    LocalFree((char *)strerror);
#else
    free(strerror);
#endif
}
