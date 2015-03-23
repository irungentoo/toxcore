/* network.h
 *
 * Datatypes, functions and includes for the core networking.
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

#ifndef NETWORK_H
#define NETWORK_H

#ifdef PLAN9
#include <u.h> //Plan 9 requires this is imported first
#include <libc.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32) /* Put win32 includes here */
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif

typedef unsigned int sock_t;
/* sa_family_t is the sockaddr_in / sockaddr_in6 family field */
typedef short sa_family_t;

#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#else // Linux includes

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netdb.h>
#include <unistd.h>

typedef int sock_t;

#endif

#if defined(__AIX__)
#   define _XOPEN_SOURCE 1
#endif

#if defined(__sun__)
#define __EXTENSIONS__ 1 // SunOS!
#if defined(__SunOS5_6__) || defined(__SunOS5_7__) || defined(__SunOS5_8__) || defined(__SunOS5_9__) || defined(__SunOS5_10__)
//Nothing needed
#else
#define __MAKECONTEXT_V2_SOURCE 1
#endif
#endif

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef  IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif
#endif

#define MAX_UDP_PACKET_SIZE 2048

#define NET_PACKET_PING_REQUEST    0   /* Ping request packet ID. */
#define NET_PACKET_PING_RESPONSE   1   /* Ping response packet ID. */
#define NET_PACKET_GET_NODES       2   /* Get nodes request packet ID. */
#define NET_PACKET_SEND_NODES_IPV6 4   /* Send nodes response packet ID for other addresses. */
#define NET_PACKET_COOKIE_REQUEST  24  /* Cookie request packet */
#define NET_PACKET_COOKIE_RESPONSE 25  /* Cookie response packet */
#define NET_PACKET_CRYPTO_HS       26  /* Crypto handshake packet */
#define NET_PACKET_CRYPTO_DATA     27  /* Crypto data packet */
#define NET_PACKET_CRYPTO          32  /* Encrypted data packet ID. */
#define NET_PACKET_LAN_DISCOVERY   33  /* LAN discovery packet ID. */

/* See:  docs/Prevent_Tracking.txt and onion.{c, h} */
#define NET_PACKET_ONION_SEND_INITIAL 128
#define NET_PACKET_ONION_SEND_1 129
#define NET_PACKET_ONION_SEND_2 130

#define NET_PACKET_ANNOUNCE_REQUEST 131
#define NET_PACKET_ANNOUNCE_RESPONSE 132
#define NET_PACKET_ONION_DATA_REQUEST 133
#define NET_PACKET_ONION_DATA_RESPONSE 134

#define NET_PACKET_ONION_RECV_3 140
#define NET_PACKET_ONION_RECV_2 141
#define NET_PACKET_ONION_RECV_1 142

/* Only used for bootstrap nodes */
#define BOOTSTRAP_INFO_PACKET_ID 240


#define TOX_PORTRANGE_FROM 33445
#define TOX_PORTRANGE_TO   33545
#define TOX_PORT_DEFAULT   TOX_PORTRANGE_FROM

/* TCP related */
#define TCP_ONION_FAMILY (AF_INET6 + 1)
#define TCP_INET (AF_INET6 + 2)
#define TCP_INET6 (AF_INET6 + 3)
#define TCP_FAMILY (AF_INET6 + 4)

typedef union {
    uint8_t uint8[4];
    uint16_t uint16[2];
    uint32_t uint32;
    struct in_addr in_addr;
}
IP4;

typedef union {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
    struct in6_addr in6_addr;
}
IP6;

typedef struct {
    uint8_t family;
    union {
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

/* Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
#define IPV6_IPV4_IN_V6(a) ((a.uint64[0] == 0) && (a.uint32[2] == htonl (0xffff)))

#define SIZE_IP4 4
#define SIZE_IP6 16
#define SIZE_IP (1 + SIZE_IP6)
#define SIZE_PORT 2
#define SIZE_IPPORT (SIZE_IP + SIZE_PORT)

#define TOX_ENABLE_IPV6_DEFAULT 1

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 *
 *   IPv6 addresses are enclosed into square brackets, i.e. "[IPv6]"
 *   writes error message into the buffer on error
 */
const char *ip_ntoa(const IP *ip);

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
 *     (AF_INET/AF_INET6) or to the unspecified AF_UNSPEC (= 0), if both
 *     IP versions are acceptable
 *  extra can be NULL and is only set in special circumstances, see returns
 *
 * returns in *to a valid IPAny (v4/v6),
 *     prefers v6 if ip.family was AF_UNSPEC and both available
 * returns in *extra an IPv4 address, if family was AF_UNSPEC and *to is AF_INET6
 * returns 0 on failure
 */
int addr_resolve(const char *address, IP *to, IP *extra);

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
int addr_resolve_or_parse_ip(const char *address, IP *to, IP *extra);

/* Function to receive data, ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
typedef int (*packet_handler_callback)(void *object, IP_Port ip_port, const uint8_t *data, uint16_t len);

typedef struct {
    packet_handler_callback function;
    void *object;
} Packet_Handles;

typedef struct {
    Packet_Handles packethandlers[256];

    sa_family_t family;
    uint16_t port;
    /* Our UDP socket. */
    sock_t sock;
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
int sock_valid(sock_t sock);

/* Close the socket.
 */
void kill_sock(sock_t sock);

/* Set socket as nonblocking
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nonblock(sock_t sock);

/* Set socket to not emit SIGPIPE
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_nosigpipe(sock_t sock);

/* Set socket to dual (IPv4 + IPv6 socket)
 *
 * return 1 on success
 * return 0 on failure
 */
int set_socket_dualstack(sock_t sock);

/* return current monotonic time in milliseconds (ms). */
uint64_t current_time_monotonic(void);

/* Basic network functions: */

/* Function to send packet(data) of length length to ip_port. */
int sendpacket(Networking_Core *net, IP_Port ip_port, const uint8_t *data, uint16_t length);

/* Function to call when packet beginning with byte is received. */
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object);

/* Call this several times a second. */
void networking_poll(Networking_Core *net);

/* Initialize networking.
 * bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 * return Networking_Core object if no problems
 * return NULL if there are problems.
 *
 * If error is non NULL it is set to 0 if no issues, 1 if bind failed, 2 if other.
 */
Networking_Core *new_networking(IP ip, uint16_t port);
Networking_Core *new_networking_ex(IP ip, uint16_t port_from, uint16_t port_to, unsigned int *error);

/* Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);

#endif
