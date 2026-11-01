// clang-format off
#include "group_chats.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "Messenger.h"
#include "crypto_core.h"
#include "group_common.h"
#include "logger.h"
#include "net.h"
#include "network.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox.h"
#include "tox_struct.h"

namespace {

constexpr uint8_t kGhRequest = 0x00;
constexpr uint8_t kHsInviteRequest = 0x00;
// A public chat accepts any join type.
constexpr uint8_t kHjPublic = 0x01;

TEST(GroupHandshakeFlood, DoesNotAddUnboundedPeers)
{
    Tox_Options *opts = tox_options_new(nullptr);
    ASSERT_NE(opts, nullptr);
    tox_options_set_local_discovery_enabled(opts, false);

    Tox_Err_New err;
    Tox *tox = tox_new(opts, &err);
    tox_options_free(opts);
    ASSERT_EQ(err, TOX_ERR_NEW_OK);
    ASSERT_NE(tox, nullptr);

    const uint8_t group_name[] = "flood";
    const uint8_t self_name[] = "host";
    Tox_Err_Group_New gerr;
    const uint32_t group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PUBLIC, group_name,
        sizeof(group_name) - 1, self_name, sizeof(self_name) - 1, &gerr);
    ASSERT_EQ(gerr, TOX_ERR_GROUP_NEW_OK);

    // A public chat announces its key and address to anyone.
    GC_Chat *chat = gc_get_group(tox->m->group_handler, group_number);
    ASSERT_NE(chat, nullptr);

    uint8_t host_pk[ENC_PUBLIC_KEY_SIZE];
    gc_get_self_public_key(chat, host_pk);

    Tox_Err_Get_Port perr;
    const uint16_t udp_port = tox_self_get_udp_port(tox, &perr);
    ASSERT_EQ(perr, TOX_ERR_GET_PORT_OK);

    const uint32_t peers_before = chat->numpeers;

    const Random *rng = os_random();
    const Network *ns = os_network();
    const Memory *mem = os_memory();
    Logger *logger = logger_new(mem);

    const Socket sock = net_socket(ns, net_family_ipv4(), TOX_SOCK_DGRAM, TOX_PROTO_UDP);
    ASSERT_TRUE(sock_valid(sock));

    IP_Port host;
    host.ip.family = net_family_ipv4();
    host.ip.ip.v4 = get_ip4_loopback();
    host.port = net_htons(udp_port);

    Net_Err_Connect cerr;
    ASSERT_TRUE(net_connect(ns, mem, logger, sock, &host, &cerr));

    constexpr int kFloodCount = 256;
    for (int i = 0; i < kFloodCount; ++i) {
        Extended_Public_Key joiner_pk;
        Extended_Secret_Key joiner_sk;
        ASSERT_TRUE(create_extended_keypair(&joiner_pk, &joiner_sk, rng));

        uint8_t session_pk[ENC_PUBLIC_KEY_SIZE];
        uint8_t session_sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(rng, session_pk, session_sk);

        // Without a TCP relay, the UDP source address is enough.
        uint8_t plain[1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1 + 1];
        size_t n = 0;
        plain[n++] = kGhRequest;
        memcpy(plain + n, session_pk, ENC_PUBLIC_KEY_SIZE);
        n += ENC_PUBLIC_KEY_SIZE;
        memcpy(plain + n, joiner_pk.sig, SIG_PUBLIC_KEY_SIZE);
        n += SIG_PUBLIC_KEY_SIZE;
        plain[n++] = kHsInviteRequest;
        plain[n++] = kHjPublic;

        uint8_t nonce[CRYPTO_NONCE_SIZE];
        random_nonce(rng, nonce);

        uint8_t cipher[sizeof(plain) + CRYPTO_MAC_SIZE];
        const int clen
            = encrypt_data(mem, host_pk, joiner_sk.enc, nonce, plain, sizeof(plain), cipher);
        ASSERT_EQ(clen, static_cast<int>(sizeof(cipher)));

        uint8_t packet[1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE
            + sizeof(cipher)];
        size_t p = 0;
        packet[p++] = NET_PACKET_GC_HANDSHAKE;
        memcpy(packet + p, joiner_pk.enc, ENC_PUBLIC_KEY_SIZE);
        p += ENC_PUBLIC_KEY_SIZE;
        memcpy(packet + p, host_pk, ENC_PUBLIC_KEY_SIZE);
        p += ENC_PUBLIC_KEY_SIZE;
        memcpy(packet + p, nonce, CRYPTO_NONCE_SIZE);
        p += CRYPTO_NONCE_SIZE;
        memcpy(packet + p, cipher, sizeof(cipher));
        p += sizeof(cipher);

        ASSERT_EQ(net_send(ns, logger, sock, packet, p, &host, nullptr), static_cast<int>(p));

        if (i % 16 == 15) {
            tox_iterate(tox, nullptr);
        }
    }

    tox_iterate(tox, nullptr);

    const uint32_t added = chat->numpeers - peers_before;
    EXPECT_LT(added, 64u);

    kill_sock(ns, sock);
    logger_kill(logger);

    tox_kill(tox);
}

// Fills a saved peer with a fully-formed UDP address and TCP relay so that it
// survives a pack/unpack round-trip unambiguously.
void fill_saved_peer(GC_SavedPeerInfo *peer)
{
    peer->ip_port.ip.family = net_family_ipv4();
    peer->ip_port.ip.ip.v4.uint8[0] = 0x7f;
    peer->ip_port.ip.ip.v4.uint8[3] = 0x01;
    peer->ip_port.port = 0x1234;

    peer->tcp_relay.ip_port.ip.family = net_family_ipv4();
    peer->tcp_relay.ip_port.ip.ip.v4.uint8[0] = 0x7f;
    peer->tcp_relay.ip_port.ip.ip.v4.uint8[3] = 0x02;
    peer->tcp_relay.ip_port.port = 0x1234;
    std::memset(peer->tcp_relay.public_key, 0xab, sizeof(peer->tcp_relay.public_key));

    std::memset(peer->public_key, 0xcd, sizeof(peer->public_key));
}

// A saved-peers blob loaded from disk can describe more peers than the fixed
// chat->saved_peers[GC_MAX_SAVED_PEERS] array holds. unpack_gc_saved_peers must
// stop at the array bound rather than writing past it.
TEST(UnpackGcSavedPeers, DoesNotOverflowSavedPeersArray)
{
    Logger *log = logger_new(os_memory());

    auto src = std::make_unique<GC_Chat>();
    src->log = log;
    fill_saved_peer(&src->saved_peers[0]);

    // Encode one peer to obtain the wire bytes of a single entry.
    std::array<uint8_t, 256> entry{};
    uint16_t entry_len = 0;
    ASSERT_EQ(pack_gc_saved_peers(src.get(), entry.data(), entry.size(), &entry_len), 1);
    ASSERT_GT(entry_len, 0);

    // Sanity: one entry decodes back to exactly one saved peer.
    auto one = std::make_unique<GC_Chat>();
    one->log = log;
    ASSERT_EQ(unpack_gc_saved_peers(one.get(), entry.data(), entry_len), 1);

    // Build a blob describing far more peers than the array can hold.
    const int peer_count = GC_MAX_SAVED_PEERS + 200;
    std::vector<uint8_t> blob;
    blob.reserve(static_cast<std::size_t>(peer_count) * entry_len);
    for (int i = 0; i < peer_count; ++i) {
        blob.insert(blob.end(), entry.begin(), entry.begin() + entry_len);
    }
    ASSERT_LE(blob.size(), static_cast<std::size_t>(UINT16_MAX));

    auto dst = std::make_unique<GC_Chat>();
    dst->log = log;
    const int unpacked
        = unpack_gc_saved_peers(dst.get(), blob.data(), static_cast<uint16_t>(blob.size()));

    EXPECT_LE(unpacked, GC_MAX_SAVED_PEERS);

    logger_kill(log);
}

}  // namespace
