/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Functions for the core networking.
 */

#include "network.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attributes.h"
#include "bin_pack.h"
#include "ccompat.h"
#include "logger.h"
#include "mem.h"
#include "net.h"
#include "net_log.h"
#include "net_profile.h"
#include "os_network.h"
#include "util.h"

static_assert(sizeof(IP4) == SIZE_IP4, "IP4 size must be 4");

// TODO(iphydf): Stop relying on this. We memcpy this struct (and IP4 above)
// into packets but really should be serialising it properly.
static_assert(sizeof(IP6) == SIZE_IP6, "IP6 size must be 16");

IP4 get_ip4_broadcast(void)
{
    return net_get_ip4_broadcast();
}

IP6 get_ip6_broadcast(void)
{
    return net_get_ip6_broadcast();
}

IP4 get_ip4_loopback(void)
{
    return net_get_ip4_loopback();
}

IP6 get_ip6_loopback(void)
{
    return net_get_ip6_loopback();
}

bool sock_valid(Socket sock)
{
    const Socket invalid_socket = net_invalid_socket();
    return sock.value != invalid_socket.value;
}

int net_send(const Network *ns, const Logger *log,
             Socket sock, const uint8_t *buf, size_t len, const IP_Port *ip_port, Net_Profile *net_profile)
{
    const int res = ns_send(ns, sock, buf, len);

    if (res > 0) {
        netprof_record_packet(net_profile, buf[0], res, PACKET_DIRECTION_SEND);
    }

    net_log_data(log, "T=>", buf, len, ip_port, res);
    return res;
}

int net_recv(const Network *ns, const Logger *log,
             Socket sock, uint8_t *buf, size_t len, const IP_Port *ip_port)
{
    const int res = ns_recv(ns, sock, buf, len);
    net_log_data(log, "=>T", buf, len, ip_port, res);
    return res;
}

int net_listen(const Network *ns, Socket sock, int backlog)
{
    return ns_listen(ns, sock, backlog);
}

Socket net_accept(const Network *ns, Socket sock)
{
    return ns_accept(ns, sock);
}

/** Close the socket. */
void kill_sock(const Network *ns, Socket sock)
{
    ns_close(ns, sock);
}

bool set_socket_nonblock(const Network *ns, Socket sock)
{
    return net_set_socket_nonblock(ns, sock);
}

bool set_socket_nosigpipe(const Network *ns, Socket sock)
{
    return net_set_socket_nosigpipe(ns, sock);
}

bool set_socket_reuseaddr(const Network *ns, Socket sock)
{
    return net_set_socket_reuseaddr(ns, sock);
}

bool set_socket_dualstack(const Network *ns, Socket sock)
{
    return net_set_socket_dualstack(ns, sock);
}

typedef struct Packet_Handler {
    packet_handler_cb *_Nullable function;
    void *_Nullable object;
} Packet_Handler;

struct Networking_Core {
    const Logger *_Nonnull log;
    const Memory *_Nonnull mem;
    Packet_Handler packethandlers[256];
    const Network *_Nonnull ns;

    Family family;
    uint16_t port;
    /* Our UDP socket. */
    Socket sock;

    Net_Profile *_Nullable udp_net_profile;
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

int net_send_packet(const Networking_Core *net, const IP_Port *ip_port, Net_Packet packet)
{
    IP_Port ipp_copy = *ip_port;

    if (net_family_is_unspec(ip_port->ip.family)) {
        // TODO(iphydf): Make this an error. Currently this fails sometimes when
        // called from DHT.c:do_ping_and_sendnode_requests.
        return -1;
    }

    if (net_family_is_unspec(net->family)) { /* Socket not initialized */
        // TODO(iphydf): Make this an error. Currently, the onion client calls
        // this via DHT nodes requests.
        LOGGER_WARNING(net->log, "attempted to send message of length %u on uninitialised socket", packet.length);
        return -1;
    }

    /* socket TOX_AF_INET, but target IP NOT: can't send */
    if (net_family_is_ipv4(net->family) && !net_family_is_ipv4(ipp_copy.ip.family)) {
        // TODO(iphydf): Make this an error. Occasionally we try to send to an
        // all-zero ip_port.
        Ip_Ntoa ip_str;
        LOGGER_WARNING(net->log, "attempted to send message with network family %d (probably IPv6) on IPv4 socket (%s)",
                       ipp_copy.ip.family.value, net_ip_ntoa(&ipp_copy.ip, &ip_str));
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

    const long res = ns_sendto(net->ns, net->sock, packet.data, packet.length, &ipp_copy);
    net_log_data(net->log, "O=>", packet.data, packet.length, ip_port, res);

    assert(res <= INT_MAX);

    if (res == packet.length && packet.data != nullptr) {
        netprof_record_packet(net->udp_net_profile, packet.data[0], packet.length, PACKET_DIRECTION_SEND);
    }

    return (int)res;
}

/**
 * Function to send packet(data) of length length to ip_port.
 *
 * @deprecated Use net_send_packet instead.
 */
int sendpacket(const Networking_Core *net, const IP_Port *ip_port, const uint8_t *data, uint16_t length)
{
    const Net_Packet packet = {data, length};
    return net_send_packet(net, ip_port, packet);
}

/** @brief Function to receive data
 * ip and port of sender is put into ip_port.
 * Packet data is put into data.
 * Packet length is put into length.
 */
static int receivepacket(const Network *_Nonnull ns, const Logger *_Nonnull log, Socket sock, IP_Port *_Nonnull ip_port, uint8_t *_Nonnull data, uint32_t *_Nonnull length)
{
    memset(ip_port, 0, sizeof(IP_Port));
    *length = 0;

    const int fail_or_len = ns_recvfrom(ns, sock, data, MAX_UDP_PACKET_SIZE, ip_port);

    if (fail_or_len < 0) {
        const int error = net_error();

        if (!net_should_ignore_recv_error(error)) {
            Net_Strerror error_str;
            LOGGER_ERROR(log, "unexpected error reading from socket: %u, %s", (unsigned int)error, net_strerror(error, &error_str));
        }

        return -1; /* Nothing received. */
    }

    *length = (uint32_t)fail_or_len;

    if (net_family_is_ipv6(ip_port->ip.family) && ipv6_ipv4_in_v6(&ip_port->ip.ip.v6)) {
        ip_port->ip.family = net_family_ipv4();
        ip_port->ip.ip.v4.uint32 = ip_port->ip.ip.v6.uint32[3];
    }

    net_log_data(log, "=>O", data, MAX_UDP_PACKET_SIZE, ip_port, *length);

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
    uint8_t data[MAX_UDP_PACKET_SIZE] = {0};
    uint32_t length;

    while (receivepacket(net->ns, net->log, net->sock, &ip_port, data, &length) != -1) {
        if (length < 1) {
            continue;
        }

        netprof_record_packet(net->udp_net_profile, data[0], length, PACKET_DIRECTION_RECV);

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
    const Logger *log, const Memory *mem, const Network *ns, const IP *ip,
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

    Networking_Core *temp = (Networking_Core *)mem_alloc(mem, sizeof(Networking_Core));

    if (temp == nullptr) {
        return nullptr;
    }

    Net_Profile *np = netprof_new(log, mem);

    if (np == nullptr) {
        mem_delete(mem, temp);
        return nullptr;
    }

    temp->udp_net_profile = np;
    temp->ns = ns;
    temp->log = log;
    temp->mem = mem;
    temp->family = ip->family;
    temp->port = 0;

    /* Initialize our socket. */
    /* add log message what we're creating */
    temp->sock = net_socket(ns, temp->family, TOX_SOCK_DGRAM, TOX_PROTO_UDP);

    /* Check for socket error. */
    if (!sock_valid(temp->sock)) {
        const int neterror = net_error();
        Net_Strerror error_str;
        LOGGER_ERROR(log, "failed to get a socket?! %d, %s", neterror, net_strerror(neterror, &error_str));
        netprof_kill(mem, temp->udp_net_profile);
        mem_delete(mem, temp);

        if (error != nullptr) {
            *error = 1;
        }

        return nullptr;
    }

    /* Functions to increase the size of the send and receive UDP buffers.
     */
    if (!net_set_socket_buffer_size(ns, temp->sock, 1024 * 1024 * 2)) {
        LOGGER_WARNING(log, "failed to set socket buffer size");
    }

    /* Enable broadcast on socket */
    if (!net_set_socket_broadcast(ns, temp->sock)) {
        LOGGER_ERROR(log, "failed to set socket broadcast");
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
    IP_Port addr;
    ip_init(&addr.ip, net_family_is_ipv6(temp->family));

    if (net_family_is_ipv4(temp->family) || net_family_is_ipv6(temp->family)) {
        ip_copy(&addr.ip, ip);
        addr.port = 0;
        portptr = &addr.port;
    } else {
        mem_delete(mem, temp);
        return nullptr;
    }

    if (net_family_is_ipv6(ip->family)) {
        const bool is_dualstack = set_socket_dualstack(ns, temp->sock);

        if (is_dualstack) {
            LOGGER_TRACE(log, "Dual-stack socket: enabled");
        } else {
            LOGGER_ERROR(log, "Dual-stack socket failed to enable, won't be able to receive from/send to IPv4 addresses");
        }

        if (!net_join_multicast(ns, temp->sock, ip->family)) {
            const int neterror = net_error();
            Net_Strerror error_str;
            LOGGER_INFO(log, "Failed to activate local multicast membership in FF02::1. (%d, %s)", neterror, net_strerror(neterror, &error_str));
        } else {
            const int neterror = net_error();
            Net_Strerror error_str;
            LOGGER_TRACE(log, "Local multicast group joined successfully. (%d, %s)", neterror, net_strerror(neterror, &error_str));
        }
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
        const int res = ns_bind(ns, temp->sock, &addr);

        if (res == 0) {
            temp->port = *portptr;

            Ip_Ntoa ip_str;
            LOGGER_DEBUG(log, "Bound successfully to %s:%u", net_ip_ntoa(ip, &ip_str),
                         net_ntohs(temp->port));

            /* errno isn't reset on success, only set on failure, the failed
             * binds with parallel clients yield a -EPERM to the outside if
             * errno isn't cleared here */
            if (tries > 0) {
                net_clear_error();
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
    const int neterror = net_error();
    Net_Strerror error_str;
    LOGGER_ERROR(log, "failed to bind socket: %d, %s IP: %s port_from: %u port_to: %u",
                 neterror, net_strerror(neterror, &error_str), net_ip_ntoa(ip, &ip_str), port_from, port_to);
    kill_networking(temp);

    if (error != nullptr) {
        *error = 1;
    }

    return nullptr;
}

Networking_Core *new_networking_no_udp(const Logger *log, const Memory *mem, const Network *ns)
{
    /* this is the easiest way to completely disable UDP without changing too much code. */
    Networking_Core *net = (Networking_Core *)mem_alloc(mem, sizeof(Networking_Core));

    if (net == nullptr) {
        return nullptr;
    }

    net->ns = ns;
    net->log = log;
    net->mem = mem;

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

    netprof_kill(net->mem, net->udp_net_profile);
    mem_delete(net->mem, net);
}

bool ip_equal(const IP *a, const IP *b)
{
    if (a == nullptr || b == nullptr) {
        return false;
    }

    /* same family */
    if (a->family.value == b->family.value) {
        if (net_family_is_ipv4(a->family) || net_family_is_tcp_ipv4(a->family)) {
            return a->ip.v4.uint32 == b->ip.v4.uint32;
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
            return a->ip.v4.uint32 == b->ip.v6.uint32[3];
        }
    } else if (net_family_is_ipv6(a->family) && net_family_is_ipv4(b->family)) {
        if (ipv6_ipv4_in_v6(&a->ip.v6)) {
            return a->ip.v6.uint32[3] == b->ip.v4.uint32;
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

static int ip4_cmp(const IP4 *_Nonnull a, const IP4 *_Nonnull b)
{
    return cmp_uint(a->uint32, b->uint32);
}

static int ip6_cmp(const IP6 *_Nonnull a, const IP6 *_Nonnull b)
{
    const int res = cmp_uint(a->uint64[0], b->uint64[0]);
    if (res != 0) {
        return res;
    }
    return cmp_uint(a->uint64[1], b->uint64[1]);
}

static int ip_cmp(const IP *_Nonnull a, const IP *_Nonnull b)
{
    const int res = cmp_uint(a->family.value, b->family.value);
    if (res != 0) {
        return res;
    }
    switch (a->family.value) {
        case TOX_AF_UNSPEC:
            return 0;
        case TOX_AF_INET:
        case TCP_INET:
        case TOX_TCP_INET:
            return ip4_cmp(&a->ip.v4, &b->ip.v4);
        case TOX_AF_INET6:
        case TCP_INET6:
        case TOX_TCP_INET6:
        case TCP_SERVER_FAMILY:  // these happen to be ipv6 according to TCP_server.c.
        case TCP_CLIENT_FAMILY:
            return ip6_cmp(&a->ip.v6, &b->ip.v6);
    }
    // Invalid, we don't compare any further and consider them equal.
    return 0;
}

int ipport_cmp_handler(const void *a, const void *b, size_t size)
{
    const IP_Port *ipp_a = (const IP_Port *)a;
    const IP_Port *ipp_b = (const IP_Port *)b;
    assert(size == sizeof(IP_Port));

    const int ip_res = ip_cmp(&ipp_a->ip, &ipp_b->ip);
    if (ip_res != 0) {
        return ip_res;
    }

    return cmp_uint(ipp_a->port, ipp_b->port);
}

static const IP empty_ip = {{0}};

/** nulls out ip */
void ip_reset(IP *ip)
{
    if (ip == nullptr) {
        return;
    }

    *ip = empty_ip;
}

static const IP_Port empty_ip_port = {{{0}}};

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

    ip_reset(ip);
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

    // Write to a temporary object first, so that padding bytes are
    // uninitialised and msan can catch mistakes in downstream code.
    IP_Port tmp;
    tmp.ip.family = source->ip.family;
    tmp.ip.ip = source->ip.ip;
    tmp.port = source->port;

    *target = tmp;
}

/** @brief Packs an IP structure.
 *
 * It's the caller's responsibility to make sure `is_ipv4` tells the truth. This
 * function is an implementation detail of @ref bin_pack_ip_port.
 *
 * @param is_ipv4 whether this IP is an IP4 or IP6.
 *
 * @retval true on success.
 */
static bool bin_pack_ip(Bin_Pack *_Nonnull bp, const IP *_Nonnull ip, bool is_ipv4)
{
    if (is_ipv4) {
        return bin_pack_bin_b(bp, ip->ip.v4.uint8, SIZE_IP4);
    } else {
        return bin_pack_bin_b(bp, ip->ip.v6.uint8, SIZE_IP6);
    }
}

/** @brief Packs an IP_Port structure.
 *
 * @retval true on success.
 */
bool bin_pack_ip_port(Bin_Pack *bp, const Logger *logger, const IP_Port *ip_port)
{
    bool is_ipv4;
    uint8_t family;

    if (net_family_is_ipv4(ip_port->ip.family)) {
        // TODO(irungentoo): use functions to convert endianness
        is_ipv4 = true;
        family = TOX_AF_INET;
    } else if (net_family_is_tcp_ipv4(ip_port->ip.family)) {
        is_ipv4 = true;
        family = TOX_TCP_INET;
    } else if (net_family_is_ipv6(ip_port->ip.family)) {
        is_ipv4 = false;
        family = TOX_AF_INET6;
    } else if (net_family_is_tcp_ipv6(ip_port->ip.family)) {
        is_ipv4 = false;
        family = TOX_TCP_INET6;
    } else {
        Ip_Ntoa ip_str;
        // TODO(iphydf): Find out why we're trying to pack invalid IPs, stop
        // doing that, and turn this into an error.
        LOGGER_TRACE(logger, "cannot pack invalid IP: %s", net_ip_ntoa(&ip_port->ip, &ip_str));
        return false;
    }

    return bin_pack_u08_b(bp, family)
           && bin_pack_ip(bp, &ip_port->ip, is_ipv4)
           && bin_pack_u16_b(bp, net_ntohs(ip_port->port));
}

static bool bin_pack_ip_port_handler(const void *_Nonnull obj, const Logger *_Nonnull logger, Bin_Pack *_Nonnull bp)
{
    const IP_Port *ip_port = (const IP_Port *)obj;
    return bin_pack_ip_port(bp, logger, ip_port);
}

int pack_ip_port(const Logger *logger, uint8_t *data, uint16_t length, const IP_Port *ip_port)
{
    const uint32_t size = bin_pack_obj_size(bin_pack_ip_port_handler, ip_port, logger);

    if (size > length) {
        return -1;
    }

    if (!bin_pack_obj(bin_pack_ip_port_handler, ip_port, logger, data, length)) {
        return -1;
    }

    assert(size < INT_MAX);
    return (int)size;
}

int unpack_ip_port(IP_Port *ip_port, const uint8_t *data, uint16_t length, bool tcp_enabled)
{
    if (data == nullptr) {
        return -1;
    }

    bool is_ipv4;
    Family host_family;

    if (data[0] == TOX_AF_INET) {
        is_ipv4 = true;
        host_family = net_family_ipv4();
    } else if (data[0] == TOX_TCP_INET) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = true;
        host_family = net_family_tcp_ipv4();
    } else if (data[0] == TOX_AF_INET6) {
        is_ipv4 = false;
        host_family = net_family_ipv6();
    } else if (data[0] == TOX_TCP_INET6) {
        if (!tcp_enabled) {
            return -1;
        }

        is_ipv4 = false;
        host_family = net_family_tcp_ipv6();
    } else {
        return -1;
    }

    ipport_reset(ip_port);

    if (is_ipv4) {
        const uint32_t size = 1 + SIZE_IP4 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        ip_port->ip.family = host_family;
        memcpy(ip_port->ip.ip.v4.uint8, data + 1, SIZE_IP4);
        memcpy(&ip_port->port, data + 1 + SIZE_IP4, sizeof(uint16_t));
        return size;
    } else {
        const uint32_t size = 1 + SIZE_IP6 + sizeof(uint16_t);

        if (size > length) {
            return -1;
        }

        ip_port->ip.family = host_family;
        memcpy(ip_port->ip.ip.v6.uint8, data + 1, SIZE_IP6);
        memcpy(&ip_port->port, data + 1 + SIZE_IP6, sizeof(uint16_t));
        return size;
    }
}

const char *net_ip_ntoa(const IP *ip, Ip_Ntoa *ip_str)
{
    assert(ip_str != nullptr);

    ip_str->ip_is_valid = false;

    if (ip == nullptr) {
        snprintf(ip_str->buf, sizeof(ip_str->buf), "(IP invalid: NULL)");
        ip_str->length = (uint16_t)strlen(ip_str->buf);
        return ip_str->buf;
    }

    if (!ip_parse_addr(ip, ip_str->buf, sizeof(ip_str->buf))) {
        snprintf(ip_str->buf, sizeof(ip_str->buf), "(IP invalid, family %u)", ip->family.value);
        ip_str->length = (uint16_t)strlen(ip_str->buf);
        return ip_str->buf;
    }

    /* brute force protection against lacking termination */
    ip_str->buf[sizeof(ip_str->buf) - 1] = '\0';
    ip_str->length = (uint16_t)strlen(ip_str->buf);
    ip_str->ip_is_valid = true;

    return ip_str->buf;
}

bool ip_parse_addr(const IP *ip, char *address, size_t length)
{
    if (address == nullptr || ip == nullptr) {
        return false;
    }

    if (net_family_is_ipv4(ip->family) || net_family_is_tcp_ipv4(ip->family)) {
        return net_inet_ntop4(&ip->ip.v4, address, length) != nullptr;
    }

    if (net_family_is_ipv6(ip->family) || net_family_is_tcp_ipv6(ip->family)) {
        return net_inet_ntop6(&ip->ip.v6, address, length) != nullptr;
    }

    return false;
}

bool addr_parse_ip(const char *address, IP *to)
{
    if (address == nullptr || to == nullptr) {
        return false;
    }

    if (net_inet_pton4(address, &to->ip.v4) == 1) {
        to->family = net_family_ipv4();
        return true;
    }

    if (net_inet_pton6(address, &to->ip.v6) == 1) {
        to->family = net_family_ipv6();
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
 * @return false on failure, true on success.
 */
static bool addr_resolve(const Network *_Nonnull ns, const Memory *_Nonnull mem, const char *_Nonnull address, IP *_Nonnull to, IP *_Nullable extra)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return false;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

    if (address == nullptr || to == nullptr) {
        return false;
    }

    const int family = to->family.value;

    IP_Port *addrs = nullptr;
    const int rc = ns_getaddrinfo(ns, mem, address, family, 0, &addrs);

    // Lookup failed / empty.
    if (rc <= 0) {
        return false;
    }

    assert(addrs != nullptr);

    IP ip4;
    ip_init(&ip4, false); // ipv6enabled = false
    IP ip6;
    ip_init(&ip6, true); // ipv6enabled = true

    int result = 0;
    bool done = false;

    for (int i = 0; i < rc && !done; ++i) {
        if (net_family_is_ipv4(addrs[i].ip.family)) {
            if (addrs[i].ip.family.value == to->family.value) { /* AF_INET requested, done */
                ip_copy(to, &addrs[i].ip);
                result = TOX_ADDR_RESOLVE_INET;
                done = true;
            } else if ((result & TOX_ADDR_RESOLVE_INET) == 0) { /* AF_UNSPEC requested, store away */
                ip_copy(&ip4, &addrs[i].ip);
                result |= TOX_ADDR_RESOLVE_INET;
            }
        } else if (net_family_is_ipv6(addrs[i].ip.family)) {
            if (addrs[i].ip.family.value == to->family.value) { /* AF_INET6 requested, done */
                ip_copy(to, &addrs[i].ip);
                result = TOX_ADDR_RESOLVE_INET6;
                done = true;
            } else if ((result & TOX_ADDR_RESOLVE_INET6) == 0) { /* AF_UNSPEC requested, store away */
                ip_copy(&ip6, &addrs[i].ip);
                result |= TOX_ADDR_RESOLVE_INET6;
            }
        }
    }

    if (family == TOX_AF_UNSPEC) {
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

    ns_freeaddrinfo(ns, mem, addrs);
    return result != 0;
}

bool addr_resolve_or_parse_ip(const Network *ns, const Memory *mem, const char *address, IP *to, IP *extra, bool dns_enabled)
{
    if (dns_enabled && addr_resolve(ns, mem, address, to, extra)) {
        return true;
    }

    return addr_parse_ip(address, to);
}

const char *net_err_connect_to_string(Net_Err_Connect err)
{
    switch (err) {
        case NET_ERR_CONNECT_OK:
            return "NET_ERR_CONNECT_OK";
        case NET_ERR_CONNECT_INVALID_FAMILY:
            return "NET_ERR_CONNECT_INVALID_FAMILY";
        case NET_ERR_CONNECT_FAILED:
            return "NET_ERR_CONNECT_FAILED";
    }

    return "<invalid Net_Err_Connect>";
}

bool net_connect(const Network *ns, const Memory *mem, const Logger *log, Socket sock, const IP_Port *ip_port, Net_Err_Connect *err)
{
    if (!(net_family_is_ipv4(ip_port->ip.family) || net_family_is_ipv6(ip_port->ip.family))) {
        Ip_Ntoa ip_str;
        LOGGER_ERROR(log, "cannot connect to %s:%d which is neither IPv4 nor IPv6",
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port));
        *err = NET_ERR_CONNECT_INVALID_FAMILY;
        return false;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        *err = NET_ERR_CONNECT_OK;
        return true;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

    Ip_Ntoa ip_str;
    LOGGER_DEBUG(log, "connecting socket %d to %s:%d",
                 net_socket_to_native(sock), net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port));
    net_clear_error();

    if (ns_connect(ns, sock, ip_port) == -1) {
        const int error = net_error();

        // Non-blocking socket: "Operation in progress" means it's connecting.
        if (!net_should_ignore_connect_error(error)) {
            Net_Strerror error_str;
            LOGGER_WARNING(log, "failed to connect to %s:%d: %d (%s)",
                           net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), error, net_strerror(error, &error_str));
            *err = NET_ERR_CONNECT_FAILED;
            return false;
        }
    }

    *err = NET_ERR_CONNECT_OK;
    return true;
}

int32_t net_getipport(const Network *ns, const Memory *mem, const char *node, IP_Port **res, int tox_type, bool dns_enabled)
{
    assert(node != nullptr);

    // Try parsing as IP address first.
    IP_Port parsed = {{{0}}};
    // Initialise to nullptr. In error paths, at least we initialise the out
    // parameter.
    *res = nullptr;

    if (addr_parse_ip(node, &parsed.ip)) {
        IP_Port *tmp = (IP_Port *)mem_alloc(mem, sizeof(IP_Port));

        if (tmp == nullptr) {
            return -1;
        }

        tmp[0] = parsed;
        *res = tmp;
        return 1;
    }

    if (!dns_enabled) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        IP_Port *ip_port = (IP_Port *)mem_alloc(mem, sizeof(IP_Port));
        if (ip_port == nullptr) {
            abort();
        }
        ip_port->ip.ip.v4.uint32 = net_htonl(0x7F000003); // 127.0.0.3
        ip_port->ip.family = net_family_ipv4();

        *res = ip_port;
        return 1;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

    int type = tox_type;
    // ugly
    if (tox_type == -1) {
        type = 0;
    }

    // It's not an IP address, so now we try doing a DNS lookup.
    IP_Port *addrs = nullptr;
    const int rc = ns_getaddrinfo(ns, mem, node, TOX_AF_UNSPEC, type, &addrs);

    // Lookup failed / empty.
    if (rc <= 0) {
        return -1;
    }

    assert(addrs != nullptr);

    *res = addrs;
    return rc;
}

void net_freeipport(const Memory *mem, IP_Port *ip_ports)
{
    mem_delete(mem, ip_ports);
}

bool bind_to_port(const Network *ns, Socket sock, Family family, uint16_t port)
{
    IP_Port addr;
    ip_init(&addr.ip, net_family_is_ipv6(family));
    addr.ip.family = family;

    if (net_family_is_ipv4(family)) {
        addr.ip.ip.v4.uint32 = 0;
    } else {
        memset(addr.ip.ip.v6.uint8, 0, 16);
    }

    addr.port = net_htons(port);

    return ns_bind(ns, sock, &addr) == 0;
}

Socket net_socket(const Network *ns, Family domain, int type, int protocol)
{
    return ns_socket(ns, domain.value, type, protocol);
}

uint16_t net_socket_data_recv_buffer(const Network *ns, Socket sock)
{
    const int count = ns_recvbuf(ns, sock);
    return (uint16_t)max_s32(0, min_s32(count, UINT16_MAX));
}

bool ipv6_ipv4_in_v6(const IP6 *a)
{
    return a->uint64[0] == 0 && a->uint32[2] == net_htonl(0xffff);
}

const Net_Profile *net_get_net_profile(const Networking_Core *net)
{
    if (net == nullptr) {
        return nullptr;
    }

    return net->udp_net_profile;
}
