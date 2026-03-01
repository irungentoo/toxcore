/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif /* __APPLE__ */

// For Solaris.
#ifdef __sun
#define __EXTENSIONS__ 1
#endif /* __sun */

// For Linux (and some BSDs).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif /* _XOPEN_SOURCE */

#include "os_network.h"

#if defined(_WIN32) && defined(_WIN32_WINNT) && defined(_WIN32_WINNT_WINXP) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#undef _WIN32_WINNT
#define _WIN32_WINNT  0x501
#endif /* defined(_WIN32) && defined(_WIN32_WINNT) && defined(_WIN32_WINNT_WINXP) && _WIN32_WINNT >= _WIN32_WINNT_WINXP */

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif /* !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32)) */

#if defined(OS_WIN32) && !defined(WINVER)
// Windows XP
#define WINVER 0x0501
#endif /* defined(OS_WIN32) && !defined(WINVER) */

#ifdef OS_WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#endif /* OS_WIN32 */

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
#endif /* __sun */

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif /* IPV6_V6ONLY */
#endif /* !defined(OS_WIN32) */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"
#include "net.h"

// Disable MSG_NOSIGNAL on systems not supporting it, e.g. Windows, FreeBSD
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif /* !defined(MSG_NOSIGNAL) */

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

static int make_family(int family_value)
{
    switch (family_value) {
        case TOX_AF_INET:
        case TCP_INET:
            return AF_INET;

        case TOX_AF_INET6:
        case TCP_INET6:
            return AF_INET6;

        case TOX_AF_UNSPEC:
            return AF_UNSPEC;

        default:
            return family_value;
    }
}

static void get_ip4(IP4 *_Nonnull result, const struct in_addr *_Nonnull addr)
{
    static_assert(sizeof(result->uint32) == sizeof(addr->s_addr),
                  "Tox and operating system don't agree on size of IPv4 addresses");
    result->uint32 = addr->s_addr;
}

static void get_ip6(IP6 *_Nonnull result, const struct in6_addr *_Nonnull addr)
{
    static_assert(sizeof(result->uint8) == sizeof(addr->s6_addr),
                  "Tox and operating system don't agree on size of IPv6 addresses");
    memcpy(result->uint8, addr->s6_addr, sizeof(result->uint8));
}

static void fill_addr4(const IP4 *_Nonnull ip, struct in_addr *_Nonnull addr)
{
    addr->s_addr = ip->uint32;
}

static void fill_addr6(const IP6 *_Nonnull ip, struct in6_addr *_Nonnull addr)
{
    memcpy(addr->s6_addr, ip->uint8, sizeof(ip->uint8));
}

#ifndef OS_WIN32
#define INVALID_SOCKET (-1)
#endif /* OS_WIN32 */

typedef struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
} Network_Addr;

static void ip_port_to_network_addr(const IP_Port *_Nonnull ip_port, Network_Addr *_Nonnull addr)
{
    addr->size = 0;
    if (net_family_is_ipv4(ip_port->ip.family)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&addr->addr;
        addr->size = sizeof(struct sockaddr_in);
        addr4->sin_family = AF_INET;
        fill_addr4(&ip_port->ip.ip.v4, &addr4->sin_addr);
        addr4->sin_port = ip_port->port;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&addr->addr;
        addr->size = sizeof(struct sockaddr_in6);
        addr6->sin6_family = AF_INET6;
        fill_addr6(&ip_port->ip.ip.v6, &addr6->sin6_addr);
        addr6->sin6_port = ip_port->port;
        addr6->sin6_flowinfo = 0;
        addr6->sin6_scope_id = 0;
    }
}

static bool network_addr_to_ip_port(const Network_Addr *_Nonnull addr, IP_Port *_Nonnull ip_port)
{
    if (addr->addr.ss_family == AF_INET) {
        const struct sockaddr_in *addr_in = (const struct sockaddr_in *)&addr->addr;
        ip_port->ip.family = net_family_ipv4();
        get_ip4(&ip_port->ip.ip.v4, &addr_in->sin_addr);
        ip_port->port = addr_in->sin_port;
        return true;
    } else if (addr->addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr_in6 = (const struct sockaddr_in6 *)&addr->addr;
        ip_port->ip.family = net_family_ipv6();
        get_ip6(&ip_port->ip.ip.v6, &addr_in6->sin6_addr);
        ip_port->port = addr_in6->sin6_port;
        return true;
    }
    return false;
}

#if !defined(OS_WIN32)

static bool should_ignore_recv_error(int err)
{
    return err == EWOULDBLOCK;
}

static bool should_ignore_connect_error(int err)
{
    return err == EWOULDBLOCK || err == EINPROGRESS;
}

static const char *_Nullable inet_ntop4(const struct in_addr *_Nonnull addr, char *_Nonnull buf, size_t bufsize)
{
    return inet_ntop(AF_INET, addr, buf, bufsize);
}

static const char *_Nullable inet_ntop6(const struct in6_addr *_Nonnull addr, char *_Nonnull buf, size_t bufsize)
{
    return inet_ntop(AF_INET6, addr, buf, bufsize);
}

static int inet_pton4(const char *_Nonnull addr_string, struct in_addr *_Nonnull addrbuf)
{
    return inet_pton(AF_INET, addr_string, addrbuf);
}

static int inet_pton6(const char *_Nonnull addr_string, struct in6_addr *_Nonnull addrbuf)
{
    return inet_pton(AF_INET6, addr_string, addrbuf);
}

#else

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

static const char *_Nullable inet_ntop4(const struct in_addr *_Nonnull addr, char *_Nonnull buf, size_t bufsize)
{
    struct sockaddr_in saddr = {0};

    saddr.sin_family = AF_INET;
    saddr.sin_addr = *addr;

    DWORD len = (DWORD)bufsize;

    if (WSAAddressToStringA((LPSOCKADDR)&saddr, sizeof(saddr), nullptr, buf, &len)) {
        return nullptr;
    }

    return buf;
}

static const char *_Nullable inet_ntop6(const struct in6_addr *_Nonnull addr, char *_Nonnull buf, size_t bufsize)
{
    struct sockaddr_in6 saddr = {0};

    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = *addr;

    DWORD len = (DWORD)bufsize;

    if (WSAAddressToStringA((LPSOCKADDR)&saddr, sizeof(saddr), nullptr, buf, &len)) {
        return nullptr;
    }

    return buf;
}

static int inet_pton4(const char *_Nonnull addrString, struct in_addr *_Nonnull addrbuf)
{
    struct sockaddr_in saddr = {0};

    INT len = sizeof(saddr);

    if (WSAStringToAddressA((LPSTR)addrString, AF_INET, nullptr, (LPSOCKADDR)&saddr, &len)) {
        return 0;
    }

    *addrbuf = saddr.sin_addr;

    return 1;
}

static int inet_pton6(const char *_Nonnull addrString, struct in6_addr *_Nonnull addrbuf)
{
    struct sockaddr_in6 saddr = {0};

    INT len = sizeof(saddr);

    if (WSAStringToAddressA((LPSTR)addrString, AF_INET6, nullptr, (LPSOCKADDR)&saddr, &len)) {
        return 0;
    }

    *addrbuf = saddr.sin6_addr;

    return 1;
}

#endif /* !defined(OS_WIN32) */

const char *net_inet_ntop4(const IP4 *addr, char *buf, size_t bufsize)
{
    struct in_addr a;
    fill_addr4(addr, &a);
    return inet_ntop4(&a, buf, bufsize);
}

const char *net_inet_ntop6(const IP6 *addr, char *buf, size_t bufsize)
{
    struct in6_addr a;
    fill_addr6(addr, &a);
    return inet_ntop6(&a, buf, bufsize);
}

int net_inet_pton4(const char *addr_string, IP4 *addrbuf)
{
    struct in_addr a;
    const int ret = inet_pton4(addr_string, &a);
    if (ret == 1) {
        get_ip4(addrbuf, &a);
    }
    return ret;
}

int net_inet_pton6(const char *addr_string, IP6 *addrbuf)
{
    struct in6_addr a;
    const int ret = inet_pton6(addr_string, &a);
    if (ret == 1) {
        get_ip6(addrbuf, &a);
    }
    return ret;
}

bool net_should_ignore_recv_error(int err)
{
    return should_ignore_recv_error(err);
}

bool net_should_ignore_connect_error(int err)
{
    return should_ignore_connect_error(err);
}

static int sys_close(void *_Nullable obj, Socket sock)
{
#if defined(OS_WIN32)
    return closesocket(net_socket_to_native(sock));
#else  // !OS_WIN32
    return close(net_socket_to_native(sock));
#endif /* OS_WIN32 */
}

static Socket sys_accept(void *_Nullable obj, Socket sock)
{
    return net_socket_from_native(accept(net_socket_to_native(sock), nullptr, nullptr));
}

static int sys_bind(void *_Nullable obj, Socket sock, const IP_Port *_Nonnull addr)
{
    Network_Addr naddr;
    ip_port_to_network_addr(addr, &naddr);
    if (naddr.size == 0) {
        return -1;
    }
    return bind(net_socket_to_native(sock), (const struct sockaddr *)&naddr.addr, (socklen_t)naddr.size);
}

static int sys_listen(void *_Nullable obj, Socket sock, int backlog)
{
    return listen(net_socket_to_native(sock), backlog);
}

static int sys_connect(void *_Nullable obj, Socket sock, const IP_Port *_Nonnull addr)
{
    Network_Addr naddr;
    ip_port_to_network_addr(addr, &naddr);
    if (naddr.size == 0) {
        return -1;
    }
    return connect(net_socket_to_native(sock), (const struct sockaddr *)&naddr.addr, (socklen_t)naddr.size);
}

static int sys_recvbuf(void *_Nullable obj, Socket sock)
{
#ifdef OS_WIN32
    u_long count = 0;
    ioctlsocket(net_socket_to_native(sock), FIONREAD, &count);
#else
    int count = 0;
    ioctl(net_socket_to_native(sock), FIONREAD, &count);
#endif /* OS_WIN32 */

    return count;
}

static int sys_recv(void *_Nullable obj, Socket sock, uint8_t *_Nonnull buf, size_t len)
{
    return recv(net_socket_to_native(sock), (char *)buf, len, MSG_NOSIGNAL);
}

static int sys_send(void *_Nullable obj, Socket sock, const uint8_t *_Nonnull buf, size_t len)
{
    return send(net_socket_to_native(sock), (const char *)buf, len, MSG_NOSIGNAL);
}

static int sys_sendto(void *_Nullable obj, Socket sock, const uint8_t *_Nonnull buf, size_t len, const IP_Port *_Nonnull addr)
{
    Network_Addr naddr;
    ip_port_to_network_addr(addr, &naddr);
    if (naddr.size == 0) {
        return -1;
    }
    return sendto(net_socket_to_native(sock), (const char *)buf, len, 0, (const struct sockaddr *)&naddr.addr, (socklen_t)naddr.size);
}

static int sys_recvfrom(void *_Nullable obj, Socket sock, uint8_t *_Nonnull buf, size_t len, IP_Port *_Nonnull addr)
{
    Network_Addr naddr = {{0}};
    socklen_t addrlen = sizeof(naddr.addr);
    const int ret = recvfrom(net_socket_to_native(sock), (char *)buf, len, 0, (struct sockaddr *)&naddr.addr, &addrlen);
    naddr.size = addrlen;
    if (ret >= 0) {
        if (!network_addr_to_ip_port(&naddr, addr)) {
            // Ignore packets from unknown families
            return -1;
        }
    }
    return ret;
}

static Socket sys_socket(void *_Nullable obj, int domain, int type, int proto)
{
    const int platform_domain = make_family(domain);
    const int platform_type = make_socktype(type);
    const int platform_prot = make_proto(proto);
    return net_socket_from_native(socket(platform_domain, platform_type, platform_prot));
}

static int sys_socket_nonblock(void *_Nullable obj, Socket sock, bool nonblock)
{
#ifdef OS_WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(net_socket_to_native(sock), FIONBIO, &mode);
#else
    const int fd = net_socket_to_native(sock);
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    if (nonblock) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
#endif /* OS_WIN32 */
}

static int sys_getsockopt(void *_Nullable obj, Socket sock, int level, int optname, void *_Nonnull optval, size_t *_Nonnull optlen)
{
    socklen_t len = (socklen_t) * optlen;
    const int ret = getsockopt(net_socket_to_native(sock), level, optname, (char *)optval, &len);
    *optlen = len;
    return ret;
}

static int sys_setsockopt(void *_Nullable obj, Socket sock, int level, int optname, const void *_Nonnull optval, size_t optlen)
{
#ifdef EMSCRIPTEN
    return 0;
#else
    return setsockopt(net_socket_to_native(sock), level, optname, (const char *)optval, (socklen_t)optlen);
#endif /* EMSCRIPTEN */
}

static int sys_getaddrinfo(void *_Nullable obj, const Memory *_Nonnull mem, const char *_Nonnull address, int family, int sock_type, IP_Port *_Nullable *_Nonnull addrs)
{
    assert(addrs != nullptr);

    struct addrinfo hints = {0};
    hints.ai_family = make_family(family);
    hints.ai_socktype = make_socktype(sock_type);

    struct addrinfo *infos = nullptr;

    const int rc = getaddrinfo(address, nullptr, &hints, &infos);

    if (rc != 0) {
        return 0;
    }

    const int32_t max_count = INT32_MAX / sizeof(IP_Port);

    int result = 0;
    for (struct addrinfo *walker = infos; walker != nullptr && result < max_count; walker = walker->ai_next) {
        if (walker->ai_family == hints.ai_family || hints.ai_family == AF_UNSPEC) {
            ++result;
        }
    }

    assert(max_count >= result);

    IP_Port *tmp_addrs = (IP_Port *)mem_valloc(mem, result, sizeof(IP_Port));
    if (tmp_addrs == nullptr) {
        freeaddrinfo(infos);
        return 0;
    }

    int i = 0;
    for (struct addrinfo *walker = infos; walker != nullptr; walker = walker->ai_next) {
        if (walker->ai_family == hints.ai_family || hints.ai_family == AF_UNSPEC) {
            Network_Addr naddr;
            naddr.size = walker->ai_addrlen;
            memcpy(&naddr.addr, walker->ai_addr, walker->ai_addrlen);

            if (network_addr_to_ip_port(&naddr, &tmp_addrs[i])) {
                ++i;
            }
        }
    }

    result = i;
    freeaddrinfo(infos);
    *addrs = tmp_addrs;

    return result;
}

static int sys_freeaddrinfo(void *_Nullable obj, const Memory *_Nonnull mem, IP_Port *_Nullable addrs)
{
    if (addrs == nullptr) {
        return 0;
    }

    mem_delete(mem, addrs);

    return 0;
}

static const Network_Funcs os_network_funcs = {
    sys_close,
    sys_accept,
    sys_bind,
    sys_listen,
    sys_connect,
    sys_recvbuf,
    sys_recv,
    sys_recvfrom,
    sys_send,
    sys_sendto,
    sys_socket,
    sys_socket_nonblock,
    sys_getsockopt,
    sys_setsockopt,
    sys_getaddrinfo,
    sys_freeaddrinfo,
};
const Network os_network_obj = {&os_network_funcs, nullptr};

const Network *os_network(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
#ifdef OS_WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return nullptr;
    }
#endif /* OS_WIN32 */
    return &os_network_obj;
}

Socket net_invalid_socket(void)
{
    return net_socket_from_native(INVALID_SOCKET);
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

#if !defined(INADDR_LOOPBACK)
#define INADDR_LOOPBACK 0x7f000001
#endif /* !defined(INADDR_LOOPBACK) */

IP4 net_get_ip4_broadcast(void)
{
    const IP4 ip4_broadcast = {INADDR_BROADCAST};
    return ip4_broadcast;
}

IP6 net_get_ip6_broadcast(void)
{
    const IP6 ip6_broadcast = {
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
    };
    return ip6_broadcast;
}

IP4 net_get_ip4_loopback(void)
{
    IP4 loopback;
    loopback.uint32 = htonl(INADDR_LOOPBACK);
    return loopback;
}

IP6 net_get_ip6_loopback(void)
{
    /* in6addr_loopback isn't available everywhere, so we do it ourselves. */
    IP6 loopback = {{0}};
    loopback.uint8[15] = 1;
    return loopback;
}

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif /* IPV6_JOIN_GROUP */
#endif /* IPV6_ADD_MEMBERSHIP */

bool net_join_multicast(const Network *ns, Socket sock, Family family)
{
#ifndef ESP_PLATFORM
    if (net_family_is_ipv6(family)) {
        /* multicast local nodes */
        struct ipv6_mreq mreq = {{{{0}}}};
        mreq.ipv6mr_multiaddr.s6_addr[0] = 0xFF;
        mreq.ipv6mr_multiaddr.s6_addr[1] = 0x02;
        mreq.ipv6mr_multiaddr.s6_addr[15] = 0x01;
        mreq.ipv6mr_interface = 0;

        return ns_setsockopt(ns, sock, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
    }
#endif /* ESP_PLATFORM */
    return false;
}

bool net_set_socket_nonblock(const Network *ns, Socket sock)
{
    return ns_socket_nonblock(ns, sock, true) == 0;
}

bool net_set_socket_nosigpipe(const Network *ns, Socket sock)
{
#if defined(__APPLE__)
    int set = 1;
    return ns_setsockopt(ns, sock, SOL_SOCKET, SO_NOSIGPIPE, &set, sizeof(int)) == 0;
#else
    return true;
#endif /* __APPLE__ */
}

bool net_set_socket_reuseaddr(const Network *ns, Socket sock)
{
    int set = 1;
#if defined(OS_WIN32)
    return ns_setsockopt(ns, sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, &set, sizeof(set)) == 0;
#else
    return ns_setsockopt(ns, sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) == 0;
#endif /* OS_WIN32 */
}

bool net_set_socket_dualstack(const Network *ns, Socket sock)
{
    int ipv6only = 0;
    size_t optsize = sizeof(ipv6only);
    const int res = ns_getsockopt(ns, sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, &optsize);

    if ((res == 0) && (ipv6only == 0)) {
        return true;
    }

    ipv6only = 0;
    return ns_setsockopt(ns, sock, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6only, sizeof(ipv6only)) == 0;
}

bool net_set_socket_buffer_size(const Network *ns, Socket sock, int size)
{
    bool ok = true;

    if (ns_setsockopt(ns, sock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0) {
        ok = false;
    }

    if (ns_setsockopt(ns, sock, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0) {
        ok = false;
    }

    return ok;
}

bool net_set_socket_broadcast(const Network *ns, Socket sock)
{
    int broadcast = 1;
    return ns_setsockopt(ns, sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == 0;
}

int net_error(void)
{
#ifdef OS_WIN32
    return WSAGetLastError();
#else
    return errno;
#endif /* OS_WIN32 */
}

void net_clear_error(void)
{
#ifdef OS_WIN32
    WSASetLastError(0);
#else
    errno = 0;
#endif /* OS_WIN32 */
}

#ifdef OS_WIN32
char *net_strerror(int error, Net_Strerror *buf)
{
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr,
                   error, 0, buf->data, NET_STRERROR_SIZE, nullptr);
    return buf->data;
}
#else
#if defined(_GNU_SOURCE) && defined(__GLIBC__)
static const char *_Nonnull net_strerror_r(int error, char *_Nonnull tmp, size_t tmp_size)
{
    const char *retstr = strerror_r(error, tmp, tmp_size);

    if (errno != 0) {
        snprintf(tmp, tmp_size, "error %d (strerror_r failed with errno %d)", error, errno);
    }

    return retstr;
}
#else
static const char *_Nonnull net_strerror_r(int error, char *_Nonnull tmp, size_t tmp_size)
{
    const int fmt_error = strerror_r(error, tmp, tmp_size);

    if (fmt_error != 0) {
        snprintf(tmp, tmp_size, "error %d (strerror_r failed with error %d, errno %d)", error, fmt_error, errno);
    }

    return tmp;
}
#endif /* GNU */
char *net_strerror(int error, Net_Strerror *buf)
{
    errno = 0;

    const char *retstr = net_strerror_r(error, buf->data, NET_STRERROR_SIZE);
    const size_t retstr_len = strlen(retstr);
    assert(retstr_len < NET_STRERROR_SIZE);
    buf->size = (uint16_t)retstr_len;

    return buf->data;
}
#endif /* OS_WIN32 */
