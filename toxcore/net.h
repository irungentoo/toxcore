/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_NET_H
#define C_TOXCORE_TOXCORE_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef bitwise int Socket_Value;
typedef struct Socket {
    Socket_Value value;
} Socket;

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

typedef struct Family {
    uint8_t value;
} Family;

typedef union IP4 {
    uint32_t uint32;
    uint16_t uint16[2];
    uint8_t uint8[4];
} IP4;

typedef union IP6 {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
} IP6;

typedef union IP_Union {
    IP4 v4;
    IP6 v6;
} IP_Union;

typedef struct IP {
    Family family;
    IP_Union ip;
} IP;

typedef struct IP_Port {
    IP ip;
    uint16_t port;
} IP_Port;

/** Redefinitions of variables for safe transfer over wire. */
#define TOX_AF_UNSPEC 0
#define TOX_AF_INET 2
#define TOX_AF_INET6 10
#define TOX_TCP_INET 130
#define TOX_TCP_INET6 138

#define TOX_SOCK_STREAM 1
#define TOX_SOCK_DGRAM 2

#define TOX_PROTO_TCP 1
#define TOX_PROTO_UDP 2

/** TCP related */
#define TCP_CLIENT_FAMILY (TOX_AF_INET6 + 1)
#define TCP_INET (TOX_AF_INET6 + 2)
#define TCP_INET6 (TOX_AF_INET6 + 3)
#define TCP_SERVER_FAMILY (TOX_AF_INET6 + 4)

int net_socket_to_native(Socket sock);
Socket net_socket_from_native(int sock);
Socket net_invalid_socket(void);

typedef int net_close_cb(void *_Nullable obj, Socket sock);
typedef Socket net_accept_cb(void *_Nullable obj, Socket sock);
typedef int net_bind_cb(void *_Nullable obj, Socket sock, const IP_Port *_Nonnull addr);
typedef int net_listen_cb(void *_Nullable obj, Socket sock, int backlog);
typedef int net_connect_cb(void *_Nullable obj, Socket sock, const IP_Port *_Nonnull addr);
typedef int net_recvbuf_cb(void *_Nullable obj, Socket sock);
typedef int net_recv_cb(void *_Nullable obj, Socket sock, uint8_t *_Nonnull buf, size_t len);
typedef int net_recvfrom_cb(void *_Nullable obj, Socket sock, uint8_t *_Nonnull buf, size_t len, IP_Port *_Nonnull addr);
typedef int net_send_cb(void *_Nullable obj, Socket sock, const uint8_t *_Nonnull buf, size_t len);
typedef int net_sendto_cb(void *_Nullable obj, Socket sock, const uint8_t *_Nonnull buf, size_t len, const IP_Port *_Nonnull addr);
typedef Socket net_socket_cb(void *_Nullable obj, int domain, int type, int proto);
typedef int net_socket_nonblock_cb(void *_Nullable obj, Socket sock, bool nonblock);
typedef int net_getsockopt_cb(void *_Nullable obj, Socket sock, int level, int optname, void *_Nonnull optval, size_t *_Nonnull optlen);
typedef int net_setsockopt_cb(void *_Nullable obj, Socket sock, int level, int optname, const void *_Nonnull optval, size_t optlen);
typedef int net_getaddrinfo_cb(void *_Nullable obj, const Memory *_Nonnull mem, const char *_Nonnull address, int family, int protocol, IP_Port *_Nullable *_Nonnull addrs);
typedef int net_freeaddrinfo_cb(void *_Nullable obj, const Memory *_Nonnull mem, IP_Port *_Nullable addrs);

typedef struct Network_Funcs {
    net_close_cb *_Nullable close;
    net_accept_cb *_Nullable accept;
    net_bind_cb *_Nullable bind;
    net_listen_cb *_Nullable listen;
    net_connect_cb *_Nullable connect;
    net_recvbuf_cb *_Nullable recvbuf;
    net_recv_cb *_Nullable recv;
    net_recvfrom_cb *_Nullable recvfrom;
    net_send_cb *_Nullable send;
    net_sendto_cb *_Nullable sendto;
    net_socket_cb *_Nullable socket;
    net_socket_nonblock_cb *_Nullable socket_nonblock;
    net_getsockopt_cb *_Nullable getsockopt;
    net_setsockopt_cb *_Nullable setsockopt;
    net_getaddrinfo_cb *_Nullable getaddrinfo;
    net_freeaddrinfo_cb *_Nullable freeaddrinfo;
} Network_Funcs;

typedef struct Network {
    const Network_Funcs *_Nullable funcs;
    void *_Nullable obj;
} Network;

int ns_close(const Network *_Nonnull ns, Socket sock);
Socket ns_accept(const Network *_Nonnull ns, Socket sock);
int ns_bind(const Network *_Nonnull ns, Socket sock, const IP_Port *_Nonnull addr);
int ns_listen(const Network *_Nonnull ns, Socket sock, int backlog);
int ns_connect(const Network *_Nonnull ns, Socket sock, const IP_Port *_Nonnull addr);
int ns_recvbuf(const Network *_Nonnull ns, Socket sock);
int ns_recv(const Network *_Nonnull ns, Socket sock, uint8_t *_Nonnull buf, size_t len);
int ns_recvfrom(const Network *_Nonnull ns, Socket sock, uint8_t *_Nonnull buf, size_t len, IP_Port *_Nonnull addr);
int ns_send(const Network *_Nonnull ns, Socket sock, const uint8_t *_Nonnull buf, size_t len);
int ns_sendto(const Network *_Nonnull ns, Socket sock, const uint8_t *_Nonnull buf, size_t len, const IP_Port *_Nonnull addr);
Socket ns_socket(const Network *_Nonnull ns, int domain, int type, int proto);
int ns_socket_nonblock(const Network *_Nonnull ns, Socket sock, bool nonblock);
int ns_getsockopt(const Network *_Nonnull ns, Socket sock, int level, int optname, void *_Nonnull optval, size_t *_Nonnull optlen);
int ns_setsockopt(const Network *_Nonnull ns, Socket sock, int level, int optname, const void *_Nonnull optval, size_t optlen);
int ns_getaddrinfo(const Network *_Nonnull ns, const Memory *_Nonnull mem, const char *_Nonnull address, int family, int protocol, IP_Port *_Nullable *_Nonnull addrs);
int ns_freeaddrinfo(const Network *_Nonnull ns, const Memory *_Nonnull mem, IP_Port *_Nullable addrs);

bool net_family_is_unspec(Family family);
bool net_family_is_ipv4(Family family);
bool net_family_is_ipv6(Family family);
bool net_family_is_tcp_server(Family family);
bool net_family_is_tcp_client(Family family);
bool net_family_is_tcp_ipv4(Family family);
bool net_family_is_tcp_ipv6(Family family);
bool net_family_is_tox_tcp_ipv4(Family family);
bool net_family_is_tox_tcp_ipv6(Family family);

Family net_family_unspec(void);
Family net_family_ipv4(void);
Family net_family_ipv6(void);
Family net_family_tcp_server(void);
Family net_family_tcp_client(void);
Family net_family_tcp_ipv4(void);
Family net_family_tcp_ipv6(void);
Family net_family_tox_tcp_ipv4(void);
Family net_family_tox_tcp_ipv6(void);

const char *_Nonnull net_family_to_string(Family family);

uint32_t net_htonl(uint32_t hostlong);
uint16_t net_htons(uint16_t hostshort);
uint32_t net_ntohl(uint32_t hostlong);
uint16_t net_ntohs(uint16_t hostshort);

const char *_Nullable net_inet_ntop4(const IP4 *_Nonnull addr, char *_Nonnull buf, size_t bufsize);
const char *_Nullable net_inet_ntop6(const IP6 *_Nonnull addr, char *_Nonnull buf, size_t bufsize);
int net_inet_pton4(const char *_Nonnull addr_string, IP4 *_Nonnull addrbuf);
int net_inet_pton6(const char *_Nonnull addr_string, IP6 *_Nonnull addrbuf);

bool net_should_ignore_recv_error(int err);
bool net_should_ignore_connect_error(int err);

size_t net_pack_bool(uint8_t *_Nonnull bytes, bool v);
size_t net_pack_u16(uint8_t *_Nonnull bytes, uint16_t v);
size_t net_pack_u32(uint8_t *_Nonnull bytes, uint32_t v);
size_t net_pack_u64(uint8_t *_Nonnull bytes, uint64_t v);

size_t net_unpack_bool(const uint8_t *_Nonnull bytes, bool *_Nonnull v);
size_t net_unpack_u16(const uint8_t *_Nonnull bytes, uint16_t *_Nonnull v);
size_t net_unpack_u32(const uint8_t *_Nonnull bytes, uint32_t *_Nonnull v);
size_t net_unpack_u64(const uint8_t *_Nonnull bytes, uint64_t *_Nonnull v);

int net_error(void);
void net_clear_error(void);

#define NET_STRERROR_SIZE 256

/** @brief Contains a null terminated formatted error message.
 *
 * This struct should not contain more than at most the 2 fields.
 */
typedef struct Net_Strerror {
    char     data[NET_STRERROR_SIZE];
    uint16_t size;
} Net_Strerror;

/** @brief Get a text explanation for the error code from `net_error()`.
 *
 * @param error The error code to get a string for.
 * @param buf The struct to store the error message in (usually on stack).
 *
 * @return pointer to a NULL-terminated string describing the error code.
 */
char *_Nonnull net_strerror(int error, Net_Strerror *_Nonnull buf);

IP4 net_get_ip4_loopback(void);
IP4 net_get_ip4_broadcast(void);

IP6 net_get_ip6_loopback(void);
IP6 net_get_ip6_broadcast(void);

bool net_join_multicast(const Network *_Nonnull ns, Socket sock, Family family);

bool net_set_socket_nonblock(const Network *_Nonnull ns, Socket sock);
bool net_set_socket_nosigpipe(const Network *_Nonnull ns, Socket sock);
bool net_set_socket_reuseaddr(const Network *_Nonnull ns, Socket sock);
bool net_set_socket_dualstack(const Network *_Nonnull ns, Socket sock);
bool net_set_socket_buffer_size(const Network *_Nonnull ns, Socket sock, int size);
bool net_set_socket_broadcast(const Network *_Nonnull ns, Socket sock);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_NET_H */
