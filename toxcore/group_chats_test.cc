// clang-format off
#include "group_chats.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "Messenger.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "crypto_core.h"
#include "group_common.h"
#include "logger.h"
#include "net.h"
#include "network.h"
#include "os_memory.h"
#include "tox.h"
#include "tox_private.h"
#include "tox_struct.h"

namespace {

constexpr uint8_t kGhRequest = 0x00;
constexpr uint8_t kHsInviteRequest = 0x00;
constexpr uint8_t kHjPublic = 0x00;

// Handshakes from new peers go straight into the host's UDP socket.
class GroupHandshake : public ::testing::Test {
protected:
    void SetUp() override
    {
        Tox_Options *opts = tox_options_new(nullptr);
        ASSERT_NE(opts, nullptr);
        tox_options_set_local_discovery_enabled(opts, false);

        Tox_Options_Testing testing_opts = {};
        testing_opts.operating_system = &host_->system;
        Tox_Err_New err;
        tox_ = tox_new_testing(opts, &err, &testing_opts, nullptr);
        tox_options_free(opts);
        ASSERT_EQ(err, TOX_ERR_NEW_OK);
        ASSERT_NE(tox_, nullptr);

        const uint8_t group_name[] = "flood";
        const uint8_t self_name[] = "host";
        Tox_Err_Group_New gerr;
        const uint32_t group_number = tox_group_new(tox_, TOX_GROUP_PRIVACY_STATE_PUBLIC,
            group_name, sizeof(group_name) - 1, self_name, sizeof(self_name) - 1, &gerr);
        ASSERT_EQ(gerr, TOX_ERR_GROUP_NEW_OK);

        // A public chat announces its key and address to anyone.
        chat_ = gc_get_group(tox_->m->group_handler, group_number);
        ASSERT_NE(chat_, nullptr);
        gc_get_self_public_key(chat_, host_pk_);

        socket_ = host_->node->get_primary_socket();
        ASSERT_NE(socket_, nullptr);

        sender_.ip.family = net_family_ipv4();
        sender_.ip.ip.v4.uint32 = net_htonl(0x0a000002);
        sender_.port = net_htons(33446);
    }

    void TearDown() override { tox_kill(tox_); }

    void send_request(const Extended_Public_Key &joiner_pk, const Extended_Secret_Key &joiner_sk,
        const uint8_t *sig_pk)
    {
        uint8_t session_pk[ENC_PUBLIC_KEY_SIZE];
        uint8_t session_sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(rng(), session_pk, session_sk);

        // Without a TCP relay, the UDP source address is enough.
        uint8_t plain[1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1 + 1];
        size_t n = 0;
        plain[n++] = kGhRequest;
        memcpy(plain + n, session_pk, ENC_PUBLIC_KEY_SIZE);
        n += ENC_PUBLIC_KEY_SIZE;
        memcpy(plain + n, sig_pk, SIG_PUBLIC_KEY_SIZE);
        n += SIG_PUBLIC_KEY_SIZE;
        plain[n++] = kHsInviteRequest;
        plain[n++] = kHjPublic;

        uint8_t nonce[CRYPTO_NONCE_SIZE];
        random_nonce(rng(), nonce);

        uint8_t cipher[sizeof(plain) + CRYPTO_MAC_SIZE];
        const int clen = encrypt_data(
            &host_->c_memory, host_pk_, joiner_sk.enc, nonce, plain, sizeof(plain), cipher);
        ASSERT_EQ(clen, static_cast<int>(sizeof(cipher)));

        std::vector<uint8_t> packet;
        packet.push_back(NET_PACKET_GC_HANDSHAKE);
        packet.insert(packet.end(), joiner_pk.enc, joiner_pk.enc + ENC_PUBLIC_KEY_SIZE);
        packet.insert(packet.end(), host_pk_, host_pk_ + ENC_PUBLIC_KEY_SIZE);
        packet.insert(packet.end(), nonce, nonce + CRYPTO_NONCE_SIZE);
        packet.insert(packet.end(), cipher, cipher + sizeof(cipher));
        socket_->push_packet(std::move(packet), sender_);
    }

    const Random *rng() const { return &host_->c_random; }

    tox::test::SimulatedEnvironment env_{12345};
    std::unique_ptr<tox::test::ScopedToxSystem> host_ = env_.create_node(0);
    Tox *tox_ = nullptr;
    GC_Chat *chat_ = nullptr;
    uint8_t host_pk_[ENC_PUBLIC_KEY_SIZE];
    tox::test::FakeUdpSocket *socket_ = nullptr;
    IP_Port sender_;
};

TEST_F(GroupHandshake, FloodDoesNotAddUnboundedPeers)
{
    const uint32_t peers_before = chat_->numpeers;

    constexpr int kFloodCount = 256;
    for (int i = 0; i < kFloodCount; ++i) {
        Extended_Public_Key joiner_pk;
        Extended_Secret_Key joiner_sk;
        ASSERT_TRUE(create_extended_keypair(&joiner_pk, &joiner_sk, rng()));
        send_request(joiner_pk, joiner_sk, joiner_pk.sig);

        if (i % 16 == 15) {
            tox_iterate(tox_, nullptr);
        }
    }

    tox_iterate(tox_, nullptr);

    const uint32_t added = chat_->numpeers - peers_before;
    EXPECT_LT(added, 64u);
}

TEST_F(GroupHandshake, KeepsAtMostThePeerLimitOfUnconfirmedPeers)
{
    const uint32_t peers_before = chat_->numpeers;

    for (int i = 0; i < 2 * chat_->shared_state.maxpeers; ++i) {
        uint8_t peer_pk[ENC_PUBLIC_KEY_SIZE];
        random_bytes(rng(), peer_pk, sizeof(peer_pk));
        peer_add(chat_, nullptr, peer_pk);
    }

    EXPECT_EQ(chat_->numpeers - peers_before, chat_->shared_state.maxpeers);
}

TEST_F(GroupHandshake, AddsANewPeer)
{
    const uint32_t peers_before = chat_->numpeers;

    Extended_Public_Key joiner_pk;
    Extended_Secret_Key joiner_sk;
    ASSERT_TRUE(create_extended_keypair(&joiner_pk, &joiner_sk, rng()));
    send_request(joiner_pk, joiner_sk, joiner_pk.sig);

    for (int i = 0; i < 5; ++i) {
        tox_iterate(tox_, nullptr);
    }

    EXPECT_EQ(chat_->numpeers, peers_before + 1);
}

TEST_F(GroupHandshake, DropsANewPeerWithTheWrongSignatureKey)
{
    const uint32_t peers_before = chat_->numpeers;

    Extended_Public_Key joiner_pk;
    Extended_Secret_Key joiner_sk;
    ASSERT_TRUE(create_extended_keypair(&joiner_pk, &joiner_sk, rng()));
    Extended_Public_Key other_pk;
    Extended_Secret_Key other_sk;
    ASSERT_TRUE(create_extended_keypair(&other_pk, &other_sk, rng()));
    send_request(joiner_pk, joiner_sk, other_pk.sig);

    for (int i = 0; i < 5; ++i) {
        tox_iterate(tox_, nullptr);
    }

    EXPECT_EQ(chat_->numpeers, peers_before);
}

class GroupInviteAccepted : public ::testing::Test {
protected:
    void SetUp() override
    {
        Tox_Options *opts = tox_options_new(nullptr);
        ASSERT_NE(opts, nullptr);
        tox_options_set_local_discovery_enabled(opts, false);

        Tox_Options_Testing testing_opts = {};
        testing_opts.operating_system = &host_->system;
        Tox_Err_New err;
        tox_ = tox_new_testing(opts, &err, &testing_opts, nullptr);
        tox_options_free(opts);
        ASSERT_EQ(err, TOX_ERR_NEW_OK);
        ASSERT_NE(tox_, nullptr);

        const Random *rng = &host_->c_random;

        // A new friend that we have no IP address or TCP relays for.
        uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
        uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(rng, friend_pk, friend_sk);
        Tox_Err_Friend_Add ferr;
        friend_number_ = tox_friend_add_norequest(tox_, friend_pk, &ferr);
        ASSERT_EQ(ferr, TOX_ERR_FRIEND_ADD_OK);

        const uint8_t group_name[] = "invite";
        const uint8_t self_name[] = "host";
        Tox_Err_Group_New gerr;
        const uint32_t group_number = tox_group_new(tox_, TOX_GROUP_PRIVACY_STATE_PRIVATE,
            group_name, sizeof(group_name) - 1, self_name, sizeof(self_name) - 1, &gerr);
        ASSERT_EQ(gerr, TOX_ERR_GROUP_NEW_OK);

        chat_ = gc_get_group(tox_->m->group_handler, group_number);
        ASSERT_NE(chat_, nullptr);

        ASSERT_TRUE(tox_group_get_chat_id(tox_, group_number, data_, nullptr));
        random_bytes(rng, data_ + CHAT_ID_SIZE, ENC_PUBLIC_KEY_SIZE);
    }

    void TearDown() override { tox_kill(tox_); }

    bool accept()
    {
        return handle_gc_invite_accepted_packet(
            tox_->m->group_handler, static_cast<int>(friend_number_), data_, sizeof(data_));
    }

    tox::test::SimulatedEnvironment env_{12345};
    std::unique_ptr<tox::test::ScopedToxSystem> host_ = env_.create_node(0);
    Tox *tox_ = nullptr;
    GC_Chat *chat_ = nullptr;
    uint32_t friend_number_ = 0;
    uint8_t data_[GC_JOIN_DATA_LENGTH];
};

TEST_F(GroupInviteAccepted, IgnoresAFriendWeDidNotInvite)
{
    const uint32_t peers_before = chat_->numpeers;
    EXPECT_FALSE(accept());
    EXPECT_EQ(chat_->numpeers, peers_before);
}

TEST_F(GroupInviteAccepted, KeepsTheInvitedPeerUntilItsAddressIsKnown)
{
    // Record the invite the way tox_group_invite_friend does.
    chat_->saved_invites[0] = static_cast<int32_t>(friend_number_);

    const uint32_t peers_before = chat_->numpeers;
    accept();
    ASSERT_EQ(chat_->numpeers, peers_before + 1);

    for (int i = 0; i < 5; ++i) {
        tox_iterate(tox_, nullptr);
    }

    // The peer stays until do_handshakes can get the friend's IP address.
    ASSERT_EQ(chat_->numpeers, peers_before + 1);
    const GC_Connection *gconn = get_gc_connection(chat_, static_cast<int>(peers_before));
    ASSERT_NE(gconn, nullptr);
    EXPECT_FALSE(gconn->pending_delete);
    EXPECT_EQ(gconn->friend_number, static_cast<int>(friend_number_));
}

TEST(GcGroupLoad, LeavesNoGroupWhenTheSavedStateIsCutShort)
{
    Tox_Options *opts = tox_options_new(nullptr);
    ASSERT_NE(opts, nullptr);
    tox_options_set_local_discovery_enabled(opts, false);

    Tox_Err_New err;
    Tox *tox = tox_new(opts, &err);
    tox_options_free(opts);
    ASSERT_EQ(err, TOX_ERR_NEW_OK);
    ASSERT_NE(tox, nullptr);

    const uint8_t group_name[] = "saved";
    const uint8_t self_name[] = "host";
    Tox_Err_Group_New gerr;
    const uint32_t group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, group_name,
        sizeof(group_name) - 1, self_name, sizeof(self_name) - 1, &gerr);
    ASSERT_EQ(gerr, TOX_ERR_GROUP_NEW_OK);

    GC_Session *c = tox->m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);
    ASSERT_NE(chat, nullptr);

    bin_pack_cb *save = [](const void *obj, const Logger *logger, Bin_Pack *bp) {
        gc_group_save(static_cast<const GC_Chat *>(obj), bp);
        return true;
    };
    bin_unpack_cb *load = [](void *obj, Bin_Unpack *bu) {
        return gc_group_load(static_cast<GC_Session *>(obj), bu) >= 0;
    };
    const uint32_t size = bin_pack_obj_size(save, chat, chat->log);
    std::vector<uint8_t> saved(size);
    ASSERT_TRUE(bin_pack_obj(save, chat, chat->log, saved.data(), size));

    const uint32_t groups = gc_count_groups(c);
    // Loading may move `c->chats`, and `chat` with it.
    const Memory *mem = chat->mem;

    // Cut the saved state off halfway, and again in the saved peers, which are
    // loaded last.
    for (const uint32_t length : {size / 2, size - 2}) {
        EXPECT_FALSE(bin_unpack_obj(mem, load, c, saved.data(), length));
        EXPECT_EQ(gc_count_groups(c), groups);
    }

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

// Peers and topic are the same here, so any sync flag we get is GF_STATE.
uint16_t state_sync_flags(const GC_Chat *chat, const GC_Connection *gconn, uint32_t sstate_version,
    uint16_t roles_checksum)
{
    return gc_make_sync_flags(chat, gconn, chat->peers_checksum, 0, sstate_version,
        chat->moderation.sanctions_creds.version, roles_checksum, chat->topic_info.version,
        chat->topic_info.checksum);
}

// A peer that is connected to different peers than us always sends a different
// roles checksum, so asking it for the state again doesn't help.
TEST(GcGetSyncFlags, AsksForTheStateOnceForEachRolesChecksum)
{
    auto chat = std::make_unique<GC_Chat>();
    chat->shared_state.version = 1;
    GC_Connection gconn{};

    EXPECT_NE(state_sync_flags(chat.get(), &gconn, 1, 5), 0);

    // Keep asking until the peer answers. It may have dropped the request.
    gc_state_sync_requested(&gconn, 5);
    EXPECT_NE(state_sync_flags(chat.get(), &gconn, 1, 5), 0);

    gc_state_sync_answered(&gconn);
    EXPECT_EQ(state_sync_flags(chat.get(), &gconn, 1, 5), 0);
    EXPECT_NE(state_sync_flags(chat.get(), &gconn, 1, 6), 0);
    EXPECT_NE(state_sync_flags(chat.get(), &gconn, 2, 5), 0);
}

}  // namespace
