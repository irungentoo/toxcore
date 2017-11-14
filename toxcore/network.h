/*
 * Datatypes, functions and includes for the core networking.
 */

/*
 * Copyright © 2016-2017 The TokTok team.
 * Copyright © 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NETWORK_H
#define NETWORK_H

#ifdef PLAN9
#include <u.h> // Plan 9 requires this is imported first
// Comment line here to avoid reordering by source code formatters.
#include <libc.h>
#endif

#include "ccompat.h"
#include "logger.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32) /* Put win32 includes here */
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif

// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>

#include <windows.h>
#include <ws2tcpip.h>

#else // UNIX includes

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#endif

typedef short Family;

typedef int Socket;
Socket net_socket(int domain, int type, int protocol);

#define MAX_UDP_PACKET_SIZE 2048

typedef enum NET_PACKET_TYPE {
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

    /* See: docs/Prevent_Tracking.txt and onion.{c,h} */
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
} NET_PACKET_TYPE;


#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

/* Redefinitions of variables for safe transfer over wire. */
#define TOX_AF_UNSPEC 0
#define TOX_AF_INET 2
#define TOX_AF_INET6 10
#define TOX_TCP_INET 130
#define TOX_TCP_INET6 138

#define TOX_SOCK_STREAM 1
#define TOX_SOCK_DGRAM 2

#define TOX_PROTO_TCP 1
#define TOX_PROTO_UDP 2

/* TCP related */
#define TCP_ONION_FAMILY (TOX_AF_INET6 + 1)
#define TCP_INET (TOX_AF_INET6 + 2)
#define TCP_INET6 (TOX_AF_INET6 + 3)
#define TCP_FAMILY (TOX_AF_INET6 + 4)

typedef union {
    uint32_t uint32;
    uint16_t uint16[2];
    uint8_t uint8[4];
}
IP4;

IP4 get_ip4_loopback(void);
extern const IP4 IP4_BROADCAST;

typedef union {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
}
IP6;

IP6 get_ip6_loopback(void);
extern const IP6 IP6_BROADCAST;

typedef struct {
    uint8_t family;
    GNU_EXTENSION union {
        IP4 ip4;
        IP6 ip6;
    };
}
IP;

typedef struct {
    IP ip;
    uint16_t port;
}
IP_Port;

/* Convert values between host and network byte order.
 */
uint32_t net_htonl(uint32_t hostlong);
uint16_t net_htons(uint16_t hostshort);
uint32_t net_ntohl(uint32_t hostlong);
uint16_t net_ntohs(uint16_t hostshort);

/* Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
#define IPV6_IPV4_IN_V6(a) ((a.uint64[0] == 0) && (a.uint32[2] == net_htonl (0xffff)))

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

#define TOX_ENABLE_IPV6_DEFAULT 1

/* addr_resolve return values */
#define TOX_ADDR_RESOLVE_INET  1
#define TOX_ADDR_RESOLVE_INET6 2

#define TOX_INET6_ADDRSTRLEN 66
#define TOX_INET_ADDRSTRLEN 22

/* ip_ntoa
 *   converts ip into a string
 *   ip_str must be of length at least IP_NTOA_LEN
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 *
 *   returns ip_str
 */
/* this would be TOX_INET6_ADDRSTRLEN, but it might be too short for the error message */
#define IP_NTOA_LEN 96 // TODO(irungentoo): magic number. Why not INET6_ADDRSTRLEN ?
const char *ip_ntoa(const IP *ip, char *ip_str, size_t length);

/*
 * ip_parse_addr
 *  parses IP structure into an address string
 *
 * input
 *  ip: ip of TOX_AF_INET or TOX_AF_INET6 families
 *  length: length of the address buffer
 *          Must be at least TOX_INET_ADDRSTRLEN for TOX_AF_INET
 *          and TOX_INET6_ADDRSTRLEN for TOX_AF_INET6
 *
 * output
 *  address: dotted notation (IPv4: quad, IPv6: 16) or colon notation (IPv6)
 *
 * returns 1 on success, 0 on failure
 */
int ip_parse_addr(const IP *ip, char *address, size_t length);

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
int addr_parse_ip(const char *address, IP *to);

/* ip_equal
 *  compares two IPAny structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ip_equal(const IP *a, const IP *b);

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(const IP_Port *a, const IP_Port *b);

/* nulls out ip */
void ip_reset(IP *ip);
/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, uint8_t ipv6enabled);
/* checks if ip is valid */
int ip_isset(const IP *ip);
/* checks if ip is valid */
int ipport_isset(const IP_Port *ipport);
/* copies an ip structure */
void ip_copy(IP *target, const IP *source);
/* copies an ip_port structure */
void ipport_copy(IP_Port *target, const IP_Port *source);

/*
 * addr_resolve():
 *  uses getaddrinfo to resolve an address into an IP address
 *  uses the first IPv4/IPv6 addresses returned by getaddrinfo
 *
 * input
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in *to a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was TOX_AF_UNSPEC and both available
 * returns in *extra an IPv4 address, if family was TOX_AF_UNSPEC and *to is TOX_AF_INET6
 * returns 0 on failure
 */
int addr_resolve(const char *address, IP *to, IP *extra);

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 *  address: a hostname (or something parseable to an IP address)
 *  to: to.family MUST be initialized, either set to a specific IP version
 *     (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 *  returns in *tro a matching address (IPv6 or IPv4)
 *  returns in *extra, if not NULL, an IPv4 address, if to->family was TOX_AF_UNSPEC
 *  returns 1 on success
 *  returns 0 on failure
 */
int addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra);

/* Function to receive data, ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
typedef int (*packet_handler_callback)(void *object, IP_Port ip_port, const uint8_t *data, uint16_t len,
                                       void *userdata);

typedef struct {
    packet_handler_callback function;
    void *object;
} Packet_Handles;

typedef struct {
    Logger *log;
    Packet_Handles packethandlers[256];

    Family family;
    uint16_t port;
    /* Our UDP socket. */
    Socket sock;
} Networking_Core;

/* Run this before creating sockets.
 *
 * return 0 on success
 * return -1 on failure
 */
int networking_at_startup(void);

/* Check if socket is valid.
 *
 * return 1 if valid
 * return 0 if not valid
 */
int sock_valid(Socket sock);

/* Close the socket.
 */
void kill_sock(Socket sock);

/* Set socket as nonblocking
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nonblock(Socket sock);

/* Set socket to not emit SIGPIPE
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nosigpipe(Socket sock);

/* Enable SO_REUSEADDR on socket.
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_reuseaddr(Socket sock);

/* Set socket to dual (IPv4 + IPv6 socket)
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_dualstack(Socket sock);

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void);

/* Basic network functions: */

/* Function to send packet(data) of length length to ip_port. */
int sendpacket(Networking_Core *net, IP_Port ip_port, const uint8_t *data, uint16_t length);

/* Function to call when packet beginning with byte is received. */
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object);

/* Call this several times a second. */
void networking_poll(Networking_Core *net, void *userdata);

/* Connect a socket to the address specified by the ip_port. */
int net_connect(Socket sock, IP_Port ip_port);

/* High-level getaddrinfo implementation.
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

/* Deallocates memory allocated by net_getipport
 */
void net_freeipport(IP_Port *ip_ports);

/* return 1 on success
 * return 0 on failure
 */
int bind_to_port(Socket sock, int family, uint16_t port);

size_t net_sendto_ip4(Socket sock, const char *buf, size_t n, IP_Port ip_port);

/* Initialize networking.
 * bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 * return Networking_Core object if no problems
 * return NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if socket related error, 2 if other.
 */
Networking_Core *new_networking(Logger *log, IP ip, uint16_t port);
Networking_Core *new_networking_ex(Logger *log, IP ip, uint16_t port_from, uint16_t port_to, unsigned int *error);

/* Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);

#endif
