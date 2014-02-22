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

typedef unsigned int sock_t;
/* sa_family_t is the sockaddr_in / sockaddr_in6 family field */
typedef short sa_family_t;

#ifndef IN6_ARE_ADDR_EQUAL
#ifdef IN6_ADDR_EQUAL
#define IN6_ARE_ADDR_EQUAL(a,b) IN6_ADDR_EQUAL(a,b)
#else
#define IN6_ARE_ADDR_EQUAL(a,b) \
   ((((__const uint32_t *) (a))[0] == ((__const uint32_t *) (b))[0]) \
   && (((__const uint32_t *) (a))[1] == ((__const uint32_t *) (b))[1]) \
   && (((__const uint32_t *) (a))[2] == ((__const uint32_t *) (b))[2]) \
   && (((__const uint32_t *) (a))[3] == ((__const uint32_t *) (b))[3]))
#endif
#endif

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

#ifndef VANILLA_NACL
/* We use libsodium by default. */
#include <sodium.h>
#else
#include <crypto_box.h>
#include <crypto_secretbox.h>
#include <randombytes.h>
#include <crypto_hash_sha256.h>
#define crypto_box_MACBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#endif

#ifndef crypto_secretbox_MACBYTES
#define crypto_secretbox_MACBYTES (crypto_secretbox_ZEROBYTES - crypto_secretbox_BOXZEROBYTES)
#endif

#ifndef IPV6_ADD_MEMBERSHIP
#ifdef  IPV6_JOIN_GROUP
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif
#endif

#define MAX_UDP_PACKET_SIZE 65507

#define NET_PACKET_PING_REQUEST    0   /* Ping request packet ID. */
#define NET_PACKET_PING_RESPONSE   1   /* Ping response packet ID. */
#define NET_PACKET_GET_NODES       2   /* Get nodes request packet ID. */
#define NET_PACKET_SEND_NODES      3   /* Send nodes response packet ID for IPv4 addresses. */
#define NET_PACKET_SEND_NODES_IPV6 4   /* Send nodes response packet ID for other addresses. */
#define NET_PACKET_HANDSHAKE       16  /* Handshake packet ID. */
#define NET_PACKET_SYNC            17  /* SYNC packet ID. */
#define NET_PACKET_DATA            18  /* Data packet ID. */
#define NET_PACKET_CRYPTO          32  /* Encrypted data packet ID. */
#define NET_PACKET_LAN_DISCOVERY   33  /* LAN discovery packet ID. */
#define NET_PACKET_GROUP_CHATS     48  /* Group chats packet ID. */

/* Range of ids that custom user packets can use. */
#define NET_PACKET_CUSTOM_RANGE_START 64
#define NET_PACKET_CUSTOM_RANGE_END 96

#define TOTAL_USERPACKETS (NET_PACKET_CUSTOM_RANGE_END - NET_PACKET_CUSTOM_RANGE_START)

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

typedef union {
    uint8_t uint8[4];
    uint16_t uint16[2];
    uint32_t uint32;
    struct in_addr in_addr;
} IP4;

typedef union {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    struct in6_addr in6_addr;
} IP6;

typedef struct {
    uint8_t family;
    /* Not used for anything right now. */
    uint8_t padding[3];
    union {
        IP4 ip4;
        IP6 ip6;
    };
} IP;

typedef union {
    struct {
        IP4 ip;
        uint16_t port;
        /* Not used for anything right now. */
        uint16_t padding;
    };
    uint8_t uint8[8];
} IP4_Port;

typedef struct IP_Port {
    IP ip;
    uint16_t port;
} IP_Port;

#define TOX_ENABLE_IPV6_DEFAULT 1

/* ip_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 */
const char *ip_ntoa(IP *ip);

/* ip_equal
 *  compares two IPAny structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ip_equal(IP *a, IP *b);

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(IP_Port *a, IP_Port *b);

/* nulls out ip */
void ip_reset(IP *ip);
/* nulls out ip, sets family according to flag */
void ip_init(IP *ip, uint8_t ipv6enabled);
/* checks if ip is valid */
int ip_isset(IP *ip);
/* checks if ip is valid */
int ipport_isset(IP_Port *ipport);
/* copies an ip structure */
void ip_copy(IP *target, IP *source);
/* copies an ip_port structure */
void ipport_copy(IP_Port *target, IP_Port *source);

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
typedef int (*packet_handler_callback)(void *object, IP_Port ip_port, uint8_t *data, uint32_t len);

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
    uint64_t send_fail_eagain;
} Networking_Core;

/*  return current time in milleseconds since the epoch. */
uint64_t current_time(void);

/*  return a random number.
 */
uint32_t random_int(void);
uint64_t random_64b(void);

/* Basic network functions: */

/* Function to send packet(data) of length length to ip_port. */
int sendpacket(Networking_Core *net, IP_Port ip_port, uint8_t *data, uint32_t length);

/* Function to call when packet beginning with byte is received. */
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object);

/* Call this several times a second. */
void networking_poll(Networking_Core *net);

/*
 * functions to avoid excessive polling
 */
int networking_wait_prepare(Networking_Core *net, uint32_t sendqueue_length, uint8_t *data, uint16_t *lenptr);
int networking_wait_execute(uint8_t *data, uint16_t len, uint16_t milliseconds);
void networking_wait_cleanup(Networking_Core *net, uint8_t *data, uint16_t len);

/* Initialize networking.
 * bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 *  return 0 if no problems.
 *  return -1 if there were problems.
 */
Networking_Core *new_networking(IP ip, uint16_t port);

/* Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);

#endif
