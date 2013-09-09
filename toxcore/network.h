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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#ifdef WIN32 /* Put win32 includes here */
#ifndef WINVER
//Windows XP
#define WINVER 0x0501
#endif
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

typedef unsigned int sock_t;

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

#ifndef VANILLA_NACL
/* We use libsodium by default. */
#include <sodium.h>
#else
#include <crypto_box.h>
#define crypto_box_MACBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES)
#endif


#define MAX_UDP_PACKET_SIZE 65507

#define NET_PACKET_PING_REQUEST    0   /* Ping request packet ID. */
#define NET_PACKET_PING_RESPONSE   1   /* Ping response packet ID. */
#define NET_PACKET_GET_NODES       2   /* Get nodes request packet ID. */
#define NET_PACKET_SEND_NODES      3   /* Send nodes response packet ID. */
#define NET_PACKET_HANDSHAKE       16  /* Handshake packet ID. */
#define NET_PACKET_SYNC            17  /* SYNC packet ID. */
#define NET_PACKET_DATA            18  /* Data packet ID. */
#define NET_PACKET_CRYPTO          32  /* Encrypted data packet ID. */
#define NET_PACKET_LAN_DISCOVERY   33  /* LAN discovery packet ID. */


/* Current time, unix format */
#define unix_time() ((uint64_t)time(NULL))


typedef union {
    uint8_t uint8[4];
    uint16_t uint16[2];
    uint32_t uint32;
    struct in_addr in_addr;
} IP4;

typedef struct in6_addr IP6;

typedef struct {
    sa_family_t family;
    union {
        IP4 ip4;
        IP6 ip6;
    };
} IPAny;

/* ipany_ntoa
 *   converts ip into a string
 *   uses a static buffer, so mustn't used multiple times in the same output
 */
const char *ipany_ntoa(IPAny *ip);

typedef union {
    struct {
        IP4 ip;
        uint16_t port;
        /* Not used for anything right now. */
        uint16_t padding;
    };
    uint8_t uint8[8];
} IP_Port;


/* will replace IP_Port as soon as the complete infrastructure is in place
 * removed the unused union and padding also */
typedef struct {
    IPAny ip;
    uint16_t port;
} IPAny_Port;

/* ipport_equal
 *  compares two IPAny_Port structures
 *  unset means unequal
 *
 * returns 0 when not equal or when uninitialized
 */
int ipport_equal(IPAny_Port *a, IPAny_Port *b);

typedef struct {
    int16_t family;
    uint16_t port;
    IP4 ip;
    uint8_t zeroes[8];
#ifdef ENABLE_IPV6
    uint8_t zeroes2[12];
#endif
} ADDR;

/*
 * addr_resolve_or_parse_ip
 *  resolves string into an IP address
 *
 * to->family MUST be set (AF_UNSPEC, AF_INET, AF_INET6)
 * returns 1 on success, 0 on failure
 */
int addr_resolve_or_parse_ip(const char *address, IPAny *to);

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

    /* Our UDP socket. */
    sa_family_t family;
    uint16_t port;
    sock_t sock;
} Networking_Core;

/*  return current time in milleseconds since the epoch. */
uint64_t current_time(void);

/*  return a random number.
 * NOTE: this function should probably not be used where cryptographic randomness is absolutely necessary.
 */
uint32_t random_int(void);

/* Basic network functions: */

/* Function to send packet(data) of length length to ip_port. */
int sendpacket(Networking_Core *net, IP_Port ip_port, uint8_t *data, uint32_t length);

/* Function to call when packet beginning with byte is received. */
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_callback cb, void *object);

/* Call this several times a second. */
void networking_poll(Networking_Core *net);

/* Initialize networking.
 * bind to ip and port.
 * ip must be in network order EX: 127.0.0.1 = (7F000001).
 * port is in host byte order (this means don't worry about it).
 *
 *  return 0 if no problems.
 *  return -1 if there were problems.
 */
Networking_Core *new_networking(IP4 ip, uint16_t port);

/* Function to cleanup networking stuff (doesn't do much right now). */
void kill_networking(Networking_Core *net);

#endif
