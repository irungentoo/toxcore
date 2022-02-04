/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Datatypes, functions and includes for the core networking.
 */
#ifndef C_TOXCORE_TOXCORE_NETWORK_H
#define C_TOXCORE_TOXCORE_NETWORK_H

#include <stdbool.h>    // bool
#include <stddef.h>     // size_t
#include <stdint.h>     // uint*_t

#include "logger.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Family {
    uint8_t value;
} Family;

bool net_family_is_unspec(Family family);
bool net_family_is_ipv4(Family family);
bool net_family_is_ipv6(Family family);
bool net_family_is_tcp_family(Family family);
bool net_family_is_tcp_onion(Family family);
bool net_family_is_tcp_ipv4(Family family);
bool net_family_is_tcp_ipv6(Family family);
bool net_family_is_tox_tcp_ipv4(Family family);
bool net_family_is_tox_tcp_ipv6(Family family);

extern const Family net_family_unspec;
extern const Family net_family_ipv4;
extern const Family net_family_ipv6;
extern const Family net_family_tcp_family;
extern const Family net_family_tcp_onion;
extern const Family net_family_tcp_ipv4;
extern const Family net_family_tcp_ipv6;
extern const Family net_family_tox_tcp_ipv4;
extern const Family net_family_tox_tcp_ipv6;

#define MAX_UDP_PACKET_SIZE 2048

typedef enum Net_Packet_Type {
    NET_PACKET_PING_REQUEST         = 0x00, /* Ping request packet ID. */
    NET_PACKET_PING_RESPONSE        = 0x01, /* Ping response packet ID. */
    NET_PACKET_GET_NODES            = 0x02, /* Get nodes request packet ID. */
    NET_PACKET_SEND_NODES_IPV6      = 0x04, /* Send nodes response packet ID for other addresses. */
    NET_PACKET_COOKIE_REQUEST       = 0x18, /* Cookie request packet */
    NET_PACKET_COOKIE_RESPONSE      = 0x19, /* Cookie response packet */
    NET_PACKET_CRYPTO_HS            = 0x1a, /* Crypto handshake packet */
    NET_PACKET_CRYPTO_DATA          = 0x1b, /* Crypto data packet */
    NET_PACKET_CRYPTO               = 0x20, /* Encrypted data packet ID. */
    NET_PACKET_LAN_DISCOVERY        = 0x21, /* LAN discovery packet ID. */

    /* See: `docs/Prevent_Tracking.txt` and `onion.{c,h}` */
    NET_PACKET_ONION_SEND_INITIAL   = 0x80,
    NET_PACKET_ONION_SEND_1         = 0x81,
    NET_PACKET_ONION_SEND_2         = 0x82,

    NET_PACKET_ANNOUNCE_REQUEST     = 0x83,
    NET_PACKET_ANNOUNCE_RESPONSE    = 0x84,
    NET_PACKET_ONION_DATA_REQUEST   = 0x85,
    NET_PACKET_ONION_DATA_RESPONSE  = 0x86,

    NET_PACKET_ONION_RECV_3         = 0x8c,
    NET_PACKET_ONION_RECV_2         = 0x8d,
    NET_PACKET_ONION_RECV_1         = 0x8e,

    BOOTSTRAP_INFO_PACKET_ID        = 0xf0, /* Only used for bootstrap nodes */

    NET_PACKET_MAX                  = 0xff, /* This type must remain within a single uint8. */
} Net_Packet_Type;


#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

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
#define TCP_ONION_FAMILY (TOX_AF_INET6 + 1)
#define TCP_INET (TOX_AF_INET6 + 2)
#define TCP_INET6 (TOX_AF_INET6 + 3)
#define TCP_FAMILY (TOX_AF_INET6 + 4)

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

typedef union IP4 {
    uint32_t uint32;
    uint16_t uint16[2];
    uint8_t uint8[4];
} IP4;

static_assert(sizeof(IP4) == SIZE_IP4, "IP4 size must be 4");

IP4 get_ip4_loopback(void);
extern const IP4 ip4_broadcast;

typedef union IP6 {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
} IP6;

// TODO(iphydf): Stop relying on this. We memcpy this struct (and IP4 above)
// into packets but really should be serialising it properly.
static_assert(sizeof(IP6) == SIZE_IP6, "IP6 size must be 16");

IP6 get_ip6_loopback(void);
extern const IP6 ip6_broadcast;

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

typedef struct Socket {
    int socket;
} Socket;

Socket net_socket(Family domain, int type, int protocol);

/**
 * Check if socket is valid.
 *
 * @return true if valid, false otherwise.
 */
bool sock_valid(Socket sock);

extern const Socket net_invalid_socket;

/**
 * Calls send(sockfd, buf, len, MSG_NOSIGNAL).
 */
int net_send(const Logger *log, Socket sock, const uint8_t *buf, size_t len, const IP_Port *ip_port);
/**
 * Calls recv(sockfd, buf, len, MSG_NOSIGNAL).
 */
int net_recv(const Logger *log, Socket sock, uint8_t *buf, size_t len, const IP_Port *ip_port);
/**
 * Calls listen(sockfd, backlog).
 */
int net_listen(Socket sock, int backlog);
/**
 * Calls accept(sockfd, nullptr, nullptr).
 */
Socket net_accept(Socket sock);

/**
 * return the size of data in the tcp recv buffer.
 * return 0 on failure.
 */
uint16_t net_socket_data_recv_buffer(Socket sock);

/** Convert values between host and network byte order.
 */
uint32_t net_htonl(uint32_t hostlong);
uint16_t net_htons(uint16_t hostshort);
uint32_t net_ntohl(uint32_t hostlong);
uint16_t net_ntohs(uint16_t hostshort);

size_t net_pack_u16(uint8_t *bytes, uint16_t v);
size_t net_pack_u32(uint8_t *bytes, uint32_t v);
size_t net_pack_u64(uint8_t *bytes, uint64_t v);

size_t net_unpack_u16(const uint8_t *bytes, uint16_t *v);
size_t net_unpack_u32(const uint8_t *bytes, uint32_t *v);
size_t net_unpack_u64(const uint8_t *bytes, uint64_t *v);

/** Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
bool ipv6_ipv4_in_v6(const IP6 *a);

#define TOX_ENABLE_IPV6_DEFAULT true

/** addr_resolve return values */
#define TOX_ADDR_RESOLVE_INET  1
#define TOX_ADDR_RESOLVE_INET6 2

#define TOX_INET6_ADDRSTRLEN 66
#define TOX_INET_ADDRSTRLEN 22

/** this would be TOX_INET6_ADDRSTRLEN, but it might be too short for the error message */
#define IP_NTOA_LEN 96 // TODO(irungentoo): magic number. Why not INET6_ADDRSTRLEN ?
/** ip_ntoa
 *   converts ip into a string
 *   ip_str must be of length at least IP_NTOA_LEN
 *
 *   writes error message into the buffer on error
 *
 *   returns ip_str
 */
const char *ip_ntoa(const IP *ip, char *ip_str, size_t length);

/**
 * Parses IP structure into an address string.
 *
 * @param ip IP of TOX_AF_INET or TOX_AF_INET6 families.
 * @param length length of the address buffer.
 *   Must be at least TOX_INET_ADDRSTRLEN for TOX_AF_INET
 *   and TOX_INET6_ADDRSTRLEN for TOX_AF_INET6
 *
 * @param address dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6).
 *
 * @return true on success, false on failure.
 */
bool ip_parse_addr(const IP *ip, char *address, size_t length);

/**
 * Directly parses the input into an IP structure.
 *
 * Tries IPv4 first, then IPv6.
 *
 * @param address dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6).
 * @param to family and the value is set on success.
 *
 * @return true on success, false on failure.
 */
bool addr_parse_ip(const char *address, IP *to);

/**
 * Compares two IPAny structures.
 *
 * Unset means unequal.
 *
 * @return false when not equal or when uninitialized.
 */
bool ip_equal(const IP *a, const IP *b);

/**
 * Compares two IPAny_Port structures.
 *
 * Unset means unequal.
 *
 * @return false when not equal or when uninitialized.
 */
bool ipport_equal(const IP_Port *a, const IP_Port *b);

/** nulls out ip */
void ip_reset(IP *ip);
/** nulls out ip_port */
void ipport_reset(IP_Port *ipport);
/** nulls out ip, sets family according to flag */
void ip_init(IP *ip, bool ipv6enabled);
/** checks if ip is valid */
bool ip_isset(const IP *ip);
/** checks if ip is valid */
bool ipport_isset(const IP_Port *ipport);
/** copies an ip structure (careful about direction!) */
void ip_copy(IP *target, const IP *source);
/** copies an ip_port structure (careful about direction!) */
void ipport_copy(IP_Port *target, const IP_Port *source);

/**
 * Uses getaddrinfo to resolve an address into an IP address.
 *
 * Uses the first IPv4/IPv6 addresses returned by getaddrinfo.
 *
 * @param address a hostname (or something parseable to an IP address)
 * @param to to.family MUST be initialized, either set to a specific IP version
 *     (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 * @param extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in `*to` a valid IPAny (v4/v6),
 *     prefers v6 if `ip.family` was TOX_AF_UNSPEC and both available
 * returns in `*extra` an IPv4 address, if family was TOX_AF_UNSPEC and `*to` is TOX_AF_INET6
 *
 * @return 0 on failure, `TOX_ADDR_RESOLVE_*` on success.
 */
int addr_resolve(const char *address, IP *to, IP *extra);

/**
 * Resolves string into an IP address
 *
 * @param address a hostname (or something parseable to an IP address)
 * @param to to.family MUST be initialized, either set to a specific IP version
 *     (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 * @param extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in `*to` a matching address (IPv6 or IPv4)
 * returns in `*extra`, if not NULL, an IPv4 address, if `to->family` was TOX_AF_UNSPEC
 *
 * @return true on success, false on failure
 */
bool addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra);

/** Function to receive data, ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
typedef int packet_handler_cb(void *object, const IP_Port *ip_port, const uint8_t *data, uint16_t len, void *userdata);

typedef struct Networking_Core Networking_Core;

Family net_family(const Networking_Core *net);
uint16_t net_port(const Networking_Core *net);

/** Run this before creating sockets.
 *
 * return 0 on success
 * return -1 on failure
 */
int networking_at_startup(void);

/** Close the socket.
 */
void kill_sock(Socket sock);

/**
 * Set socket as nonblocking
 *
 * @return true on success, false on failure.
 */
bool set_socket_nonblock(Socket sock);

/**
 * Set socket to not emit SIGPIPE
 *
 * @return true on success, false on failure.
 */
bool set_socket_nosigpipe(Socket sock);

/**
 * Enable SO_REUSEADDR on socket.
 *
 * @return true on success, false on failure.
 */
bool set_socket_reuseaddr(Socket sock);

/**
 * Set socket to dual (IPv4 + IPv6 socket)
 *
 * @return true on success, false on failure.
 */
bool set_socket_dualstack(Socket sock);

/* Basic network functions: */

/**
 * An outgoing network packet.
 *
 * Use `send_packet` to send it to an IP/port endpoint.
 */
typedef struct Packet {
    const uint8_t *data;
    uint16_t length;
} Packet;

/**
 * Function to send a network packet to a given IP/port.
 */
int send_packet(const Networking_Core *net, const IP_Port *ip_port, Packet packet);

/**
 * Function to send packet(data) of length length to ip_port.
 *
 * @deprecated Use send_packet instead.
 */
int sendpacket(const Networking_Core *net, const IP_Port *ip_port, const uint8_t *data, uint16_t length);

/** Function to call when packet beginning with byte is received. */
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_cb *cb, void *object);

/** Call this several times a second. */
void networking_poll(const Networking_Core *net, void *userdata);

/** Connect a socket to the address specified by the ip_port.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int net_connect(const Logger *log, Socket sock, const IP_Port *ip_port);

/** High-level getaddrinfo implementation.
 * Given node, which identifies an Internet host, net_getipport() fills an array
 * with one or more IP_Port structures, each of which contains an Internet
 * address that can be specified by calling net_connect(), the port is ignored.
 *
 * Skip all addresses with socktype != type (use type = -1 to get all addresses)
 * To correctly deallocate array memory use net_freeipport()
 *
 * return number of elements in res array
 * and -1 on error.
 */
int32_t net_getipport(const char *node, IP_Port **res, int tox_type);

/** Deallocates memory allocated by net_getipport
 */
void net_freeipport(IP_Port *ip_ports);

/**
 * @return true on success, false on failure.
 */
bool bind_to_port(Socket sock, Family family, uint16_t port);

/** Get the last networking error code.
 *
 * Similar to Unix's errno, but cross-platform, as not all platforms use errno
 * to indicate networking errors.
 *
 * Note that different platforms may return different codes for the same error,
 * so you likely shouldn't be checking the value returned by this function
 * unless you know what you are doing, you likely just want to use it in
 * combination with net_new_strerror() to print the error.
 *
 * return platform-dependent network error code, if any.
 */
int net_error(void);

/** Get a text explanation for the error code from net_error().
 *
 * return NULL on failure.
 * return pointer to a NULL-terminated string describing the error code on
 * success. The returned string must be freed using net_kill_strerror().
 */
char *net_new_strerror(int error);

/** Frees the string returned by net_new_strerror().
 * It's valid to pass NULL as the argument, the function does nothing in this
 * case.
 */
void net_kill_strerror(char *strerror);

/** Initialize networking.
 * Added for reverse compatibility with old new_networking calls.
 */
Networking_Core *new_networking(const Logger *log, const IP *ip, uint16_t port);
/** Initialize networking.
 * Bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 *  return Networking_Core object if no problems
 *  return NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.
 */
Networking_Core *new_networking_ex(const Logger *log, const IP *ip, uint16_t port_from, uint16_t port_to,
                                   unsigned int *error);
Networking_Core *new_networking_no_udp(const Logger *log);

/** Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
