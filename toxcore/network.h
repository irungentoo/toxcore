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

/**
 * @brief Wrapper for sockaddr_storage and size.
 */
typedef struct Network_Addr Network_Addr;

typedef int net_close_cb(void *obj, int sock);
typedef int net_accept_cb(void *obj, int sock);
typedef int net_bind_cb(void *obj, int sock, const Network_Addr *addr);
typedef int net_listen_cb(void *obj, int sock, int backlog);
typedef int net_recvbuf_cb(void *obj, int sock);
typedef int net_recv_cb(void *obj, int sock, uint8_t *buf, size_t len);
typedef int net_recvfrom_cb(void *obj, int sock, uint8_t *buf, size_t len, Network_Addr *addr);
typedef int net_send_cb(void *obj, int sock, const uint8_t *buf, size_t len);
typedef int net_sendto_cb(void *obj, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr);
typedef int net_socket_cb(void *obj, int domain, int type, int proto);
typedef int net_socket_nonblock_cb(void *obj, int sock, bool nonblock);
typedef int net_getsockopt_cb(void *obj, int sock, int level, int optname, void *optval, size_t *optlen);
typedef int net_setsockopt_cb(void *obj, int sock, int level, int optname, const void *optval, size_t optlen);
typedef int net_getaddrinfo_cb(void *obj, int family, Network_Addr **addrs);
typedef int net_freeaddrinfo_cb(void *obj, Network_Addr *addrs);

/** @brief Functions wrapping POSIX network functions.
 *
 * Refer to POSIX man pages for documentation of what these functions are
 * expected to do when providing alternative Network implementations.
 */
typedef struct Network_Funcs {
    net_close_cb *close;
    net_accept_cb *accept;
    net_bind_cb *bind;
    net_listen_cb *listen;
    net_recvbuf_cb *recvbuf;
    net_recv_cb *recv;
    net_recvfrom_cb *recvfrom;
    net_send_cb *send;
    net_sendto_cb *sendto;
    net_socket_cb *socket;
    net_socket_nonblock_cb *socket_nonblock;
    net_getsockopt_cb *getsockopt;
    net_setsockopt_cb *setsockopt;
    net_getaddrinfo_cb *getaddrinfo;
    net_freeaddrinfo_cb *freeaddrinfo;
} Network_Funcs;

typedef struct Network {
    const Network_Funcs *funcs;
    void *obj;
} Network;

const Network *system_network(void);

typedef struct Family {
    uint8_t value;
} Family;

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

#define MAX_UDP_PACKET_SIZE 2048

#ifdef USE_TEST_NETWORK
typedef enum Net_Packet_Type {
    NET_PACKET_PING_REQUEST         = 0x05, /* Ping request packet ID. */
    NET_PACKET_PING_RESPONSE        = 0x06, /* Ping response packet ID. */
    NET_PACKET_GET_NODES            = 0x07, /* Get nodes request packet ID. */
    NET_PACKET_SEND_NODES_IPV6      = 0x08, /* Send nodes response packet ID for other addresses. */
    NET_PACKET_COOKIE_REQUEST       = 0x1c, /* Cookie request packet */
    NET_PACKET_COOKIE_RESPONSE      = 0x1d, /* Cookie response packet */
    NET_PACKET_CRYPTO_HS            = 0x1e, /* Crypto handshake packet */
    NET_PACKET_CRYPTO_DATA          = 0x1f, /* Crypto data packet */
    NET_PACKET_CRYPTO               = 0x24, /* Encrypted data packet ID. */
    NET_PACKET_LAN_DISCOVERY        = 0x25, /* LAN discovery packet ID. */

    // TODO(Jfreegman): Uncomment these when we merge the rest of new groupchats
    // NET_PACKET_GC_HANDSHAKE         = 0x62, /* Group chat handshake packet ID */
    // NET_PACKET_GC_LOSSLESS          = 0x63, /* Group chat lossless packet ID */
    // NET_PACKET_GC_LOSSY             = 0x64, /* Group chat lossy packet ID */

    /* See: `docs/Prevent_Tracking.txt` and `onion.{c,h}` */
    NET_PACKET_ONION_SEND_INITIAL   = 0x8f,
    NET_PACKET_ONION_SEND_1         = 0x90,
    NET_PACKET_ONION_SEND_2         = 0x91,

    NET_PACKET_ANNOUNCE_REQUEST     = 0x92,
    NET_PACKET_ANNOUNCE_RESPONSE    = 0x93,
    NET_PACKET_ONION_DATA_REQUEST   = 0x94,
    NET_PACKET_ONION_DATA_RESPONSE  = 0x95,

    NET_PACKET_ANNOUNCE_REQUEST_OLD = 0x96, /* TODO: DEPRECATE */
    NET_PACKET_ANNOUNCE_RESPONSE_OLD = 0x97, /* TODO: DEPRECATE */

    NET_PACKET_ONION_RECV_3         = 0x9b,
    NET_PACKET_ONION_RECV_2         = 0x9c,
    NET_PACKET_ONION_RECV_1         = 0x9d,

    BOOTSTRAP_INFO_PACKET_ID        = 0xf1, /* Only used for bootstrap nodes */

    NET_PACKET_MAX                  = 0xff, /* This type must remain within a single uint8. */
} Net_Packet_Type;
#else
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

    // TODO(Jfreegman): Uncomment these when we merge the rest of new groupchats
    // NET_PACKET_GC_HANDSHAKE         = 0x5a, /* Group chat handshake packet ID */
    // NET_PACKET_GC_LOSSLESS          = 0x5b, /* Group chat lossless packet ID */
    // NET_PACKET_GC_LOSSY             = 0x5c, /* Group chat lossy packet ID */

    /* See: `docs/Prevent_Tracking.txt` and `onion.{c,h}` */
    NET_PACKET_ONION_SEND_INITIAL   = 0x80,
    NET_PACKET_ONION_SEND_1         = 0x81,
    NET_PACKET_ONION_SEND_2         = 0x82,

    NET_PACKET_ANNOUNCE_REQUEST_OLD  = 0x83, /* TODO: DEPRECATE */
    NET_PACKET_ANNOUNCE_RESPONSE_OLD = 0x84, /* TODO: DEPRECATE */

    NET_PACKET_ONION_DATA_REQUEST   = 0x85,
    NET_PACKET_ONION_DATA_RESPONSE  = 0x86,
    NET_PACKET_ANNOUNCE_REQUEST     = 0x87,
    NET_PACKET_ANNOUNCE_RESPONSE    = 0x88,

    NET_PACKET_ONION_RECV_3         = 0x8c,
    NET_PACKET_ONION_RECV_2         = 0x8d,
    NET_PACKET_ONION_RECV_1         = 0x8e,

    NET_PACKET_FORWARD_REQUEST      = 0x90,
    NET_PACKET_FORWARDING           = 0x91,
    NET_PACKET_FORWARD_REPLY        = 0x92,

    NET_PACKET_DATA_SEARCH_REQUEST     = 0x93,
    NET_PACKET_DATA_SEARCH_RESPONSE    = 0x94,
    NET_PACKET_DATA_RETRIEVE_REQUEST   = 0x95,
    NET_PACKET_DATA_RETRIEVE_RESPONSE  = 0x96,
    NET_PACKET_STORE_ANNOUNCE_REQUEST  = 0x97,
    NET_PACKET_STORE_ANNOUNCE_RESPONSE = 0x98,

    BOOTSTRAP_INFO_PACKET_ID        = 0xf0, /* Only used for bootstrap nodes */

    NET_PACKET_MAX                  = 0xff, /* This type must remain within a single uint8. */
} Net_Packet_Type;
#endif // test network


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
#define TCP_CLIENT_FAMILY (TOX_AF_INET6 + 1)
#define TCP_INET (TOX_AF_INET6 + 2)
#define TCP_INET6 (TOX_AF_INET6 + 3)
#define TCP_SERVER_FAMILY (TOX_AF_INET6 + 4)

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

IP4 get_ip4_loopback(void);
extern const IP4 ip4_broadcast;

typedef union IP6 {
    uint8_t uint8[16];
    uint16_t uint16[8];
    uint32_t uint32[4];
    uint64_t uint64[2];
} IP6;

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

extern const IP_Port empty_ip_port;

typedef struct Socket {
    int sock;
} Socket;

non_null()
Socket net_socket(const Network *ns, Family domain, int type, int protocol);

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
non_null()
int net_send(const Network *ns, const Logger *log, Socket sock, const uint8_t *buf, size_t len, const IP_Port *ip_port);
/**
 * Calls recv(sockfd, buf, len, MSG_NOSIGNAL).
 */
non_null()
int net_recv(const Network *ns, const Logger *log, Socket sock, uint8_t *buf, size_t len, const IP_Port *ip_port);
/**
 * Calls listen(sockfd, backlog).
 */
non_null()
int net_listen(const Network *ns, Socket sock, int backlog);
/**
 * Calls accept(sockfd, nullptr, nullptr).
 */
non_null()
Socket net_accept(const Network *ns, Socket sock);

/**
 * return the size of data in the tcp recv buffer.
 * return 0 on failure.
 */
non_null()
uint16_t net_socket_data_recv_buffer(const Network *ns, Socket sock);

/** Convert values between host and network byte order. */
uint32_t net_htonl(uint32_t hostlong);
uint16_t net_htons(uint16_t hostshort);
uint32_t net_ntohl(uint32_t hostlong);
uint16_t net_ntohs(uint16_t hostshort);

non_null()
size_t net_pack_u16(uint8_t *bytes, uint16_t v);
non_null()
size_t net_pack_u32(uint8_t *bytes, uint32_t v);
non_null()
size_t net_pack_u64(uint8_t *bytes, uint64_t v);

non_null()
size_t net_unpack_u16(const uint8_t *bytes, uint16_t *v);
non_null()
size_t net_unpack_u32(const uint8_t *bytes, uint32_t *v);
non_null()
size_t net_unpack_u64(const uint8_t *bytes, uint64_t *v);

/** Does the IP6 struct a contain an IPv4 address in an IPv6 one? */
non_null()
bool ipv6_ipv4_in_v6(const IP6 *a);

#define TOX_ENABLE_IPV6_DEFAULT true

#define TOX_INET6_ADDRSTRLEN 66
#define TOX_INET_ADDRSTRLEN 22

/** this would be TOX_INET6_ADDRSTRLEN, but it might be too short for the error message */
#define IP_NTOA_LEN 96 // TODO(irungentoo): magic number. Why not INET6_ADDRSTRLEN ?

typedef struct Ip_Ntoa {
    char buf[IP_NTOA_LEN];
} Ip_Ntoa;

/** @brief Converts IP into a string.
 *
 * Writes error message into the buffer on error.
 *
 * @param ip_str contains a buffer of the required size.
 *
 * @return Pointer to the buffer inside `ip_str` containing the IP string.
 */
non_null()
const char *net_ip_ntoa(const IP *ip, Ip_Ntoa *ip_str);

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
non_null()
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
non_null()
bool addr_parse_ip(const char *address, IP *to);

/**
 * Compares two IPAny structures.
 *
 * Unset means unequal.
 *
 * @return false when not equal or when uninitialized.
 */
nullable(1, 2)
bool ip_equal(const IP *a, const IP *b);

/**
 * Compares two IPAny_Port structures.
 *
 * Unset means unequal.
 *
 * @return false when not equal or when uninitialized.
 */
nullable(1, 2)
bool ipport_equal(const IP_Port *a, const IP_Port *b);

/** nulls out ip */
non_null()
void ip_reset(IP *ip);
/** nulls out ip_port */
non_null()
void ipport_reset(IP_Port *ipport);
/** nulls out ip, sets family according to flag */
non_null()
void ip_init(IP *ip, bool ipv6enabled);
/** checks if ip is valid */
non_null()
bool ip_isset(const IP *ip);
/** checks if ip is valid */
non_null()
bool ipport_isset(const IP_Port *ipport);
/** copies an ip structure (careful about direction) */
non_null()
void ip_copy(IP *target, const IP *source);
/** copies an ip_port structure (careful about direction) */
non_null()
void ipport_copy(IP_Port *target, const IP_Port *source);

/**
 * Resolves string into an IP address
 *
 * @param address a hostname (or something parseable to an IP address)
 * @param to to.family MUST be initialized, either set to a specific IP version
 *   (TOX_AF_INET/TOX_AF_INET6) or to the unspecified TOX_AF_UNSPEC (0), if both
 *   IP versions are acceptable
 * @param extra can be NULL and is only set in special circumstances, see returns
 *
 * Returns in `*to` a matching address (IPv6 or IPv4)
 * Returns in `*extra`, if not NULL, an IPv4 address, if `to->family` was TOX_AF_UNSPEC
 *
 * @return true on success, false on failure
 */
non_null(1, 2, 3) nullable(4)
bool addr_resolve_or_parse_ip(const Network *ns, const char *address, IP *to, IP *extra);

/** @brief Function to receive data, ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
typedef int packet_handler_cb(void *object, const IP_Port *ip_port, const uint8_t *data, uint16_t len, void *userdata);

typedef struct Networking_Core Networking_Core;

non_null()
Family net_family(const Networking_Core *net);
non_null()
uint16_t net_port(const Networking_Core *net);

/** Close the socket. */
non_null()
void kill_sock(const Network *ns, Socket sock);

/**
 * Set socket as nonblocking
 *
 * @return true on success, false on failure.
 */
non_null()
bool set_socket_nonblock(const Network *ns, Socket sock);

/**
 * Set socket to not emit SIGPIPE
 *
 * @return true on success, false on failure.
 */
non_null()
bool set_socket_nosigpipe(const Network *ns, Socket sock);

/**
 * Enable SO_REUSEADDR on socket.
 *
 * @return true on success, false on failure.
 */
non_null()
bool set_socket_reuseaddr(const Network *ns, Socket sock);

/**
 * Set socket to dual (IPv4 + IPv6 socket)
 *
 * @return true on success, false on failure.
 */
non_null()
bool set_socket_dualstack(const Network *ns, Socket sock);

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
non_null()
int send_packet(const Networking_Core *net, const IP_Port *ip_port, Packet packet);

/**
 * Function to send packet(data) of length length to ip_port.
 *
 * @deprecated Use send_packet instead.
 */
non_null()
int sendpacket(const Networking_Core *net, const IP_Port *ip_port, const uint8_t *data, uint16_t length);

/** Function to call when packet beginning with byte is received. */
non_null(1) nullable(3, 4)
void networking_registerhandler(Networking_Core *net, uint8_t byte, packet_handler_cb *cb, void *object);

/** Call this several times a second. */
non_null(1) nullable(2)
void networking_poll(const Networking_Core *net, void *userdata);

/** @brief Connect a socket to the address specified by the ip_port.
 *
 * Return true on success.
 * Return false on failure.
 */
non_null()
bool net_connect(const Logger *log, Socket sock, const IP_Port *ip_port);

/** @brief High-level getaddrinfo implementation.
 *
 * Given node, which identifies an Internet host, `net_getipport()` fills an array
 * with one or more IP_Port structures, each of which contains an Internet
 * address that can be specified by calling `net_connect()`, the port is ignored.
 *
 * Skip all addresses with socktype != type (use type = -1 to get all addresses)
 * To correctly deallocate array memory use `net_freeipport()`
 *
 * return number of elements in res array
 * and -1 on error.
 */
non_null()
int32_t net_getipport(const char *node, IP_Port **res, int tox_type);

/** Deallocates memory allocated by net_getipport */
nullable(1)
void net_freeipport(IP_Port *ip_ports);

/**
 * @return true on success, false on failure.
 */
non_null()
bool bind_to_port(const Network *ns, Socket sock, Family family, uint16_t port);

/** @brief Get the last networking error code.
 *
 * Similar to Unix's errno, but cross-platform, as not all platforms use errno
 * to indicate networking errors.
 *
 * Note that different platforms may return different codes for the same error,
 * so you likely shouldn't be checking the value returned by this function
 * unless you know what you are doing, you likely just want to use it in
 * combination with `net_new_strerror()` to print the error.
 *
 * return platform-dependent network error code, if any.
 */
int net_error(void);

/** @brief Get a text explanation for the error code from `net_error()`.
 *
 * return NULL on failure.
 * return pointer to a NULL-terminated string describing the error code on
 * success. The returned string must be freed using `net_kill_strerror()`.
 */
char *net_new_strerror(int error);

/** @brief Frees the string returned by `net_new_strerror()`.
 * It's valid to pass NULL as the argument, the function does nothing in this
 * case.
 */
non_null()
void net_kill_strerror(char *strerror);

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
non_null(1, 2, 3) nullable(6)
Networking_Core *new_networking_ex(
        const Logger *log, const Network *ns, const IP *ip,
        uint16_t port_from, uint16_t port_to, unsigned int *error);

non_null()
Networking_Core *new_networking_no_udp(const Logger *log, const Network *ns);

/** Function to cleanup networking stuff (doesn't do much right now). */
nullable(1)
void kill_networking(Networking_Core *net);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif
