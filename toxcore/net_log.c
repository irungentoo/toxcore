/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Network traffic logging function.
 */

#include "net_log.h"

#include "attributes.h"
#include "logger.h"
#include "network.h"
#include "util.h"

static uint32_t data_0(uint16_t buflen, const uint8_t *_Nonnull buffer)
{
    uint32_t data = 0;

    if (buflen > 4) {
        net_unpack_u32(buffer + 1, &data);
    }

    return data;
}
static uint32_t data_1(uint16_t buflen, const uint8_t *_Nonnull buffer)
{
    uint32_t data = 0;

    if (buflen > 8) {
        net_unpack_u32(buffer + 5, &data);
    }

    return data;
}

static const char *_Nonnull net_packet_type_name(Net_Packet_Type type)
{
    switch (type) {
        case NET_PACKET_PING_REQUEST:
            return "PING_REQUEST";

        case NET_PACKET_PING_RESPONSE:
            return "PING_RESPONSE";

        case NET_PACKET_NODES_REQUEST:
            return "NODES_REQUEST";

        case NET_PACKET_NODES_RESPONSE:
            return "NODES_RESPONSE";

        case NET_PACKET_COOKIE_REQUEST:
            return "COOKIE_REQUEST";

        case NET_PACKET_COOKIE_RESPONSE:
            return "COOKIE_RESPONSE";

        case NET_PACKET_CRYPTO_HS:
            return "CRYPTO_HS";

        case NET_PACKET_CRYPTO_DATA:
            return "CRYPTO_DATA";

        case NET_PACKET_CRYPTO:
            return "CRYPTO";

        case NET_PACKET_GC_HANDSHAKE:
            return "GC_HANDSHAKE";

        case NET_PACKET_GC_LOSSLESS:
            return "GC_LOSSLESS";

        case NET_PACKET_GC_LOSSY:
            return "GC_LOSSY";

        case NET_PACKET_LAN_DISCOVERY:
            return "LAN_DISCOVERY";

        case NET_PACKET_ONION_SEND_INITIAL:
            return "ONION_SEND_INITIAL";

        case NET_PACKET_ONION_SEND_1:
            return "ONION_SEND_1";

        case NET_PACKET_ONION_SEND_2:
            return "ONION_SEND_2";

        case NET_PACKET_ANNOUNCE_REQUEST_OLD:
            return "ANNOUNCE_REQUEST_OLD";

        case NET_PACKET_ANNOUNCE_RESPONSE_OLD:
            return "ANNOUNCE_RESPONSE_OLD";

        case NET_PACKET_ONION_DATA_REQUEST:
            return "ONION_DATA_REQUEST";

        case NET_PACKET_ONION_DATA_RESPONSE:
            return "ONION_DATA_RESPONSE";

        case NET_PACKET_ANNOUNCE_REQUEST:
            return "ANNOUNCE_REQUEST";

        case NET_PACKET_ANNOUNCE_RESPONSE:
            return "ANNOUNCE_RESPONSE";

        case NET_PACKET_ONION_RECV_3:
            return "ONION_RECV_3";

        case NET_PACKET_ONION_RECV_2:
            return "ONION_RECV_2";

        case NET_PACKET_ONION_RECV_1:
            return "ONION_RECV_1";

        case NET_PACKET_FORWARD_REQUEST:
            return "FORWARD_REQUEST";

        case NET_PACKET_FORWARDING:
            return "FORWARDING";

        case NET_PACKET_FORWARD_REPLY:
            return "FORWARD_REPLY";

        case NET_PACKET_DATA_SEARCH_REQUEST:
            return "DATA_SEARCH_REQUEST";

        case NET_PACKET_DATA_SEARCH_RESPONSE:
            return "DATA_SEARCH_RESPONSE";

        case NET_PACKET_DATA_RETRIEVE_REQUEST:
            return "DATA_RETRIEVE_REQUEST";

        case NET_PACKET_DATA_RETRIEVE_RESPONSE:
            return "DATA_RETRIEVE_RESPONSE";

        case NET_PACKET_STORE_ANNOUNCE_REQUEST:
            return "STORE_ANNOUNCE_REQUEST";

        case NET_PACKET_STORE_ANNOUNCE_RESPONSE:
            return "STORE_ANNOUNCE_RESPONSE";

        case BOOTSTRAP_INFO_PACKET_ID:
            return "BOOTSTRAP_INFO";

        case NET_PACKET_MAX:
            return "MAX";
    }

    return "<unknown>";
}

void net_log_data(const Logger *log, const char *message, const uint8_t *buffer,
                  uint16_t buflen, const IP_Port *ip_port, long res)
{
    if (res < 0) { /* Windows doesn't necessarily know `%zu` */
        Ip_Ntoa ip_str;
        const int error = net_error();
        Net_Strerror error_str;
        LOGGER_TRACE(log, "[%02x = %-21s] %s %3u%c %s:%u (%d: %s) | %08x%08x...%02x",
                     buffer[0], net_packet_type_name((Net_Packet_Type)buffer[0]), message,
                     min_u16(buflen, 999), 'E',
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), error,
                     net_strerror(error, &error_str), data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
    } else if ((res > 0) && ((size_t)res <= buflen)) {
        Ip_Ntoa ip_str;
        LOGGER_TRACE(log, "[%02x = %-21s] %s %3u%c %s:%u (%d: %s) | %08x%08x...%02x",
                     buffer[0], net_packet_type_name((Net_Packet_Type)buffer[0]), message,
                     min_u16(res, 999), (size_t)res < buflen ? '<' : '=',
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
    } else { /* empty or overwrite */
        Ip_Ntoa ip_str;
        LOGGER_TRACE(log, "[%02x = %-21s] %s %ld%c%u %s:%u (%d: %s) | %08x%08x...%02x",
                     buffer[0], net_packet_type_name((Net_Packet_Type)buffer[0]), message,
                     res, res == 0 ? '!' : '>', buflen,
                     net_ip_ntoa(&ip_port->ip, &ip_str), net_ntohs(ip_port->port), 0, "OK",
                     data_0(buflen, buffer), data_1(buflen, buffer), buffer[buflen - 1]);
    }
}
