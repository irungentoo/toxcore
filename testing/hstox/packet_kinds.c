#include "packet_kinds.h"

#include <network.h>

uint8_t const packet_kinds[21] = {
    // = PingRequest       -- 0x00: Ping request
    NET_PACKET_PING_REQUEST,
    // | PingResponse      -- 0x01: Ping response
    NET_PACKET_PING_RESPONSE,
    // | NodesRequest      -- 0x02: Nodes request
    NET_PACKET_GET_NODES,
    // | NodesResponse     -- 0x04: Nodes response
    NET_PACKET_SEND_NODES_IPV6,
    // | CookieRequest     -- 0x18: Cookie request
    NET_PACKET_COOKIE_REQUEST,
    // | CookieResponse    -- 0x19: Cookie response
    NET_PACKET_COOKIE_RESPONSE,
    // | CryptoHandshake   -- 0x1a: Crypto handshake
    NET_PACKET_CRYPTO_HS,
    // | CryptoData        -- 0x1b: Crypto data
    NET_PACKET_CRYPTO_DATA,
    // | Crypto            -- 0x20: Encrypted data
    NET_PACKET_CRYPTO,
    // | LanDiscovery      -- 0x21: LAN discovery
    NET_PACKET_LAN_DISCOVERY,
    // | OnionRequest0     -- 0x80: Initial onion request
    NET_PACKET_ONION_SEND_INITIAL,
    // | OnionRequest1     -- 0x81: First level wrapped onion request
    NET_PACKET_ONION_SEND_1,
    // | OnionRequest2     -- 0x82: Second level wrapped onion request
    NET_PACKET_ONION_SEND_2,
    // | AnnounceRequest   -- 0x83: Announce request
    NET_PACKET_ANNOUNCE_REQUEST,
    // | AnnounceResponse  -- 0x84: Announce response
    NET_PACKET_ANNOUNCE_RESPONSE,
    // | OnionDataRequest  -- 0x85: Onion data request
    NET_PACKET_ONION_DATA_REQUEST,
    // | OnionDataResponse -- 0x86: Onion data response
    NET_PACKET_ONION_DATA_RESPONSE,
    // | OnionResponse3    -- 0x8c: Third level wrapped onion response
    NET_PACKET_ONION_RECV_3,
    // | OnionResponse2    -- 0x8d: Second level wrapped onion response
    NET_PACKET_ONION_RECV_2,
    // | OnionResponse1    -- 0x8e: First level wrapped onion response
    NET_PACKET_ONION_RECV_1,
    // | BootstrapInfo     -- 0xf0: Bootstrap node info request and response
    BOOTSTRAP_INFO_PACKET_ID,
};
