/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/*
 * LAN discovery implementation.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "LAN_discovery.h"

#include <string.h>

#include "util.h"

#define MAX_INTERFACES 16


/* TODO: multiple threads might concurrently try to set these, and it isn't clear that this couldn't lead to undesirable
 * behaviour. Consider storing the data in per-instance variables instead. */
//!TOKSTYLE-
// No global mutable state in Tokstyle.
static int     broadcast_count = -1;
static IP_Port broadcast_ip_ports[MAX_INTERFACES];
//!TOKSTYLE+

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)

// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>

#include <windows.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>

static void fetch_broadcast_info(uint16_t port)
{
    IP_ADAPTER_INFO *pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
    unsigned long ulOutBufLen = sizeof(IP_ADAPTER_INFO);

    if (pAdapterInfo == nullptr) {
        return;
    }

    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);

        if (pAdapterInfo == nullptr) {
            return;
        }
    }

    /* We copy these to the static variables `broadcast_*` only at the end of `fetch_broadcast_info()`.
     * The intention is to ensure that even if multiple threads enter `fetch_broadcast_info()` concurrently, only valid
     * interfaces will be set to be broadcast to.
     * */
    int count = 0;
    IP_Port ip_ports[MAX_INTERFACES];

    const int ret = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);

    if (ret == NO_ERROR) {
        IP_ADAPTER_INFO *pAdapter = pAdapterInfo;

        while (pAdapter) {
            IP gateway = {0};
            IP subnet_mask = {0};

            if (addr_parse_ip(pAdapter->IpAddressList.IpMask.String, &subnet_mask)
                    && addr_parse_ip(pAdapter->GatewayList.IpAddress.String, &gateway)) {
                if (net_family_is_ipv4(gateway.family) && net_family_is_ipv4(subnet_mask.family)) {
                    IP_Port *ip_port = &ip_ports[count];
                    ip_port->ip.family = net_family_ipv4;
                    uint32_t gateway_ip = net_ntohl(gateway.ip.v4.uint32);
                    uint32_t subnet_ip = net_ntohl(subnet_mask.ip.v4.uint32);
                    uint32_t broadcast_ip = gateway_ip + ~subnet_ip - 1;
                    ip_port->ip.ip.v4.uint32 = net_htonl(broadcast_ip);
                    ip_port->port = port;
                    ++count;

                    if (count >= MAX_INTERFACES) {
                        break;
                    }
                }
            }

            pAdapter = pAdapter->Next;
        }
    }

    if (pAdapterInfo) {
        free(pAdapterInfo);
    }

    broadcast_count = count;

    for (uint32_t i = 0; i < count; ++i) {
        broadcast_ip_ports[i] = ip_ports[i];
    }
}

#elif defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)

#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/netdevice.h>
#endif

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/if.h>
#endif

static void fetch_broadcast_info(uint16_t port)
{
    /* Not sure how many platforms this will run on,
     * so it's wrapped in `__linux__` for now.
     * Definitely won't work like this on Windows...
     */
    broadcast_count = 0;
    const Socket sock = net_socket(net_family_ipv4, TOX_SOCK_STREAM, 0);

    if (!sock_valid(sock)) {
        return;
    }

    /* Configure ifconf for the ioctl call. */
    struct ifreq i_faces[MAX_INTERFACES];
    memset(i_faces, 0, sizeof(struct ifreq) * MAX_INTERFACES);

    struct ifconf ifc;
    ifc.ifc_buf = (char *)i_faces;
    ifc.ifc_len = sizeof(i_faces);

    if (ioctl(sock.socket, SIOCGIFCONF, &ifc) < 0) {
        kill_sock(sock);
        return;
    }

    /* We copy these to the static variables `broadcast_*` only at the end of `fetch_broadcast_info()`.
     * The intention is to ensure that even if multiple threads enter `fetch_broadcast_info()` concurrently, only valid
     * interfaces will be set to be broadcast to.
     * */
    int count = 0;
    IP_Port ip_ports[MAX_INTERFACES];

    /* `ifc.ifc_len` is set by the `ioctl()` to the actual length used.
     * On usage of the complete array the call should be repeated with
     * a larger array, not done (640kB and 16 interfaces shall be
     * enough, for everybody!)
     */
    int n = ifc.ifc_len / sizeof(struct ifreq);

    for (int i = 0; i < n; ++i) {
        /* there are interfaces with are incapable of broadcast */
        if (ioctl(sock.socket, SIOCGIFBRDADDR, &i_faces[i]) < 0) {
            continue;
        }

        /* moot check: only AF_INET returned (backwards compat.) */
        if (i_faces[i].ifr_broadaddr.sa_family != AF_INET) {
            continue;
        }

        struct sockaddr_in *sock4 = (struct sockaddr_in *)(void *)&i_faces[i].ifr_broadaddr;

        if (count >= MAX_INTERFACES) {
            break;
        }

        IP_Port *ip_port = &ip_ports[count];
        ip_port->ip.family = net_family_ipv4;
        ip_port->ip.ip.v4.uint32 = sock4->sin_addr.s_addr;

        if (ip_port->ip.ip.v4.uint32 == 0) {
            continue;
        }

        ip_port->port = port;
        ++count;
    }

    kill_sock(sock);

    broadcast_count = count;

    for (uint32_t i = 0; i < count; ++i) {
        broadcast_ip_ports[i] = ip_ports[i];
    }
}

#else // TODO(irungentoo): Other platforms?

static void fetch_broadcast_info(uint16_t port)
{
    broadcast_count = 0;
}

#endif
/* Send packet to all IPv4 broadcast addresses
 *
 *  return 1 if sent to at least one broadcast target.
 *  return 0 on failure to find any valid broadcast target.
 */
static uint32_t send_broadcasts(Networking_Core *net, uint16_t port, const uint8_t *data, uint16_t length)
{
    /* fetch only once? on every packet? every X seconds?
     * old: every packet, new: once */
    if (broadcast_count < 0) {
        fetch_broadcast_info(port);
    }

    if (!broadcast_count) {
        return 0;
    }

    for (int i = 0; i < broadcast_count; ++i) {
        sendpacket(net, broadcast_ip_ports[i], data, length);
    }

    return 1;
}

/* Return the broadcast ip. */
static IP broadcast_ip(Family family_socket, Family family_broadcast)
{
    IP ip;
    ip_reset(&ip);

    if (net_family_is_ipv6(family_socket)) {
        if (net_family_is_ipv6(family_broadcast)) {
            ip.family = net_family_ipv6;
            /* `FF02::1` is - according to RFC 4291 - multicast all-nodes link-local */
            /* `FE80::*:` MUST be exact, for that we would need to look over all
             * interfaces and check in which status they are */
            ip.ip.v6.uint8[ 0] = 0xFF;
            ip.ip.v6.uint8[ 1] = 0x02;
            ip.ip.v6.uint8[15] = 0x01;
        } else if (net_family_is_ipv4(family_broadcast)) {
            ip.family = net_family_ipv6;
            ip.ip.v6 = ip6_broadcast;
        }
    } else if (net_family_is_ipv4(family_socket) && net_family_is_ipv4(family_broadcast)) {
        ip.family = net_family_ipv4;
        ip.ip.v4 = ip4_broadcast;
    }

    return ip;
}

static bool ip4_is_local(IP4 ip4)
{
    /* Loopback. */
    return ip4.uint8[0] == 127;
}

/* Is IP a local ip or not. */
bool ip_is_local(IP ip)
{
    if (net_family_is_ipv4(ip.family)) {
        return ip4_is_local(ip.ip.v4);
    }

    /* embedded IPv4-in-IPv6 */
    if (ipv6_ipv4_in_v6(ip.ip.v6)) {
        IP4 ip4;
        ip4.uint32 = ip.ip.v6.uint32[3];
        return ip4_is_local(ip4);
    }

    /* localhost in IPv6 (::1) */
    if (ip.ip.v6.uint64[0] == 0 && ip.ip.v6.uint32[2] == 0 && ip.ip.v6.uint32[3] == net_htonl(1)) {
        return true;
    }

    return false;
}

static bool ip4_is_lan(IP4 ip4)
{
    /* 10.0.0.0 to 10.255.255.255 range. */
    if (ip4.uint8[0] == 10) {
        return true;
    }

    /* 172.16.0.0 to 172.31.255.255 range. */
    if (ip4.uint8[0] == 172 && ip4.uint8[1] >= 16 && ip4.uint8[1] <= 31) {
        return true;
    }

    /* 192.168.0.0 to 192.168.255.255 range. */
    if (ip4.uint8[0] == 192 && ip4.uint8[1] == 168) {
        return true;
    }

    /* 169.254.1.0 to 169.254.254.255 range. */
    if (ip4.uint8[0] == 169 && ip4.uint8[1] == 254 && ip4.uint8[2] != 0
            && ip4.uint8[2] != 255) {
        return true;
    }

    /* RFC 6598: 100.64.0.0 to 100.127.255.255 (100.64.0.0/10)
     * (shared address space to stack another layer of NAT) */
    if ((ip4.uint8[0] == 100) && ((ip4.uint8[1] & 0xC0) == 0x40)) {
        return true;
    }

    return false;
}

bool ip_is_lan(IP ip)
{
    if (ip_is_local(ip)) {
        return true;
    }

    if (net_family_is_ipv4(ip.family)) {
        return ip4_is_lan(ip.ip.v4);
    }

    if (net_family_is_ipv6(ip.family)) {
        /* autogenerated for each interface: `FE80::*` (up to `FEBF::*`)
         * `FF02::1` is - according to RFC 4291 - multicast all-nodes link-local */
        if (((ip.ip.v6.uint8[0] == 0xFF) && (ip.ip.v6.uint8[1] < 3) && (ip.ip.v6.uint8[15] == 1)) ||
                ((ip.ip.v6.uint8[0] == 0xFE) && ((ip.ip.v6.uint8[1] & 0xC0) == 0x80))) {
            return true;
        }

        /* embedded IPv4-in-IPv6 */
        if (ipv6_ipv4_in_v6(ip.ip.v6)) {
            IP4 ip4;
            ip4.uint32 = ip.ip.v6.uint32[3];
            return ip4_is_lan(ip4);
        }
    }

    return false;
}

static int handle_LANdiscovery(void *object, IP_Port source, const uint8_t *packet, uint16_t length, void *userdata)
{
    DHT *dht = (DHT *)object;

    char ip_str[IP_NTOA_LEN] = { 0 };
    ip_ntoa(&source.ip, ip_str, sizeof(ip_str));

    if (!ip_is_lan(source.ip)) {
        return 1;
    }

    if (length != CRYPTO_PUBLIC_KEY_SIZE + 1) {
        return 1;
    }

    dht_bootstrap(dht, source, packet + 1);
    return 0;
}


int lan_discovery_send(uint16_t port, DHT *dht)
{
    uint8_t data[CRYPTO_PUBLIC_KEY_SIZE + 1];
    data[0] = NET_PACKET_LAN_DISCOVERY;
    id_copy(data + 1, dht_get_self_public_key(dht));

    send_broadcasts(dht_get_net(dht), port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE);

    int res = -1;
    IP_Port ip_port;
    ip_port.port = port;

    /* IPv6 multicast */
    if (net_family_is_ipv6(net_family(dht_get_net(dht)))) {
        ip_port.ip = broadcast_ip(net_family_ipv6, net_family_ipv6);

        if (ip_isset(&ip_port.ip)) {
            if (sendpacket(dht_get_net(dht), ip_port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE) > 0) {
                res = 1;
            }
        }
    }

    /* IPv4 broadcast (has to be IPv4-in-IPv6 mapping if socket is IPv6 */
    ip_port.ip = broadcast_ip(net_family(dht_get_net(dht)), net_family_ipv4);

    if (ip_isset(&ip_port.ip)) {
        if (sendpacket(dht_get_net(dht), ip_port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE)) {
            res = 1;
        }
    }

    return res;
}


void lan_discovery_init(DHT *dht)
{
    networking_registerhandler(dht_get_net(dht), NET_PACKET_LAN_DISCOVERY, &handle_LANdiscovery, dht);
}

void lan_discovery_kill(DHT *dht)
{
    networking_registerhandler(dht_get_net(dht), NET_PACKET_LAN_DISCOVERY, nullptr, nullptr);
}
