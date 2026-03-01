// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "group_announce.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstddef>

#include "DHT.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "mono_time_test_util.hh"
#include "network.h"

namespace {

using tox::test::FakeClock;
using tox::test::SimulatedEnvironment;

struct Announces : ::testing::Test {
protected:
    SimulatedEnvironment env{12345};
    Memory c_mem_;
    Mono_Time *_Nullable mono_time_ = nullptr;
    GC_Announces_List *_Nullable gca_ = nullptr;
    GC_Announce _ann1;
    GC_Announce _ann2;

    void SetUp() override
    {
        c_mem_ = env.fake_memory().c_memory();
        mono_time_ = mono_time_new(&c_mem_, nullptr, nullptr);
        ASSERT_NE(mono_time_, nullptr);
        setup_fake_clock(mono_time_, env.fake_clock());

        gca_ = new_gca_list(&c_mem_);
        ASSERT_NE(gca_, nullptr);
    }

    ~Announces() override
    {
        kill_gca(gca_);
        mono_time_free(&c_mem_, mono_time_);
    }

    void advance_clock(std::uint64_t increment)
    {
        env.fake_clock().advance(increment);
        mono_time_update(mono_time_);
    }
};

TEST_F(Announces, KillGcaOnNullptrIsNoop)
{
    // All kill functions should be nullable.
    kill_gca(nullptr);
}

TEST_F(Announces, CanBeCreatedAndDeleted)
{
    GC_Public_Announce ann{};
    ann.chat_public_key[0] = 0x88;
    ASSERT_NE(gca_add_announce(&c_mem_, mono_time_, gca_, &ann), nullptr);
#ifndef __clang__
    ASSERT_EQ(gca_add_announce(&c_mem_, mono_time_, gca_, nullptr), nullptr);
    ASSERT_EQ(gca_add_announce(&c_mem_, mono_time_, nullptr, &ann), nullptr);
#endif
}

TEST_F(Announces, AnnouncesCanTimeOut)
{
    advance_clock(100);
    ASSERT_EQ(gca_->root_announces, nullptr);
    GC_Public_Announce ann{};
    ann.chat_public_key[0] = 0xae;
    ASSERT_NE(gca_add_announce(&c_mem_, mono_time_, gca_, &ann), nullptr);
    ASSERT_NE(gca_->root_announces, nullptr);
    ASSERT_EQ(gca_->root_announces->chat_id[0], 0xae);

    // One iteration without having any time passed => announce is still here.
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);

    // 29 seconds later, still there
    advance_clock(29000);
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);

    // One more second and it's gone.
    advance_clock(1000);
    do_gca(mono_time_, gca_);
    ASSERT_EQ(gca_->root_announces, nullptr);
}

TEST_F(Announces, AnnouncesGetAndCleanup)
{
    GC_Public_Announce ann1{};
    GC_Public_Announce ann2{};
    ann1.chat_public_key[0] = 0x91;
    ann1.base_announce.peer_public_key[0] = 0x7f;
    ann2.chat_public_key[0] = 0x92;
    ann2.base_announce.peer_public_key[0] = 0x7c;

    ASSERT_NE(gca_add_announce(&c_mem_, mono_time_, gca_, &ann1), nullptr);
    ASSERT_NE(gca_add_announce(&c_mem_, mono_time_, gca_, &ann2), nullptr);
    ASSERT_NE(gca_add_announce(&c_mem_, mono_time_, gca_, &ann2), nullptr);

    std::uint8_t empty_pk[ENC_PUBLIC_KEY_SIZE] = {0};

    GC_Announce announces;
    ASSERT_EQ(gca_get_announces(gca_, &announces, 1, ann1.chat_public_key, empty_pk), 1);
    ASSERT_EQ(gca_get_announces(gca_, &announces, 1, ann2.chat_public_key, empty_pk), 1);

    cleanup_gca(gca_, ann1.chat_public_key);
    ASSERT_EQ(gca_get_announces(gca_, &announces, 1, ann1.chat_public_key, empty_pk), 0);

    cleanup_gca(gca_, ann2.chat_public_key);
    ASSERT_EQ(gca_get_announces(gca_, &announces, 1, ann2.chat_public_key, empty_pk), 0);
#ifndef __clang__
    ASSERT_EQ(gca_get_announces(gca_, nullptr, 1, ann2.chat_public_key, empty_pk), -1);
#endif
}

struct AnnouncesPack : ::testing::Test {
protected:
    SimulatedEnvironment env{12345};
    Memory c_mem_;
    std::vector<GC_Announce> announces_;
    Logger *logger_ = nullptr;

    void SetUp() override
    {
        c_mem_ = env.fake_memory().c_memory();
        logger_ = logger_new(&c_mem_);
        ASSERT_NE(logger_, nullptr);

        // Add an announce without TCP relay.
        announces_.emplace_back();
        auto &ann1 = announces_.back();

        ann1.peer_public_key[0] = 0xae;
        ann1.ip_port.ip.family = net_family_ipv4();
        ann1.ip_port.ip.ip.v4.uint8[0] = 0x7f;  // 127.0.0.1
        ann1.ip_port.ip.ip.v4.uint8[3] = 0x1;
        ann1.ip_port_is_set = 1;

        // Add an announce with TCP relay.
        announces_.emplace_back();
        auto &ann2 = announces_.back();

        ann2.peer_public_key[0] = 0xaf;  // different key
        ann2.ip_port.ip.family = net_family_ipv4();
        ann2.ip_port.ip.ip.v4.uint8[0] = 0x7f;  // 127.0.0.2
        ann2.ip_port.ip.ip.v4.uint8[3] = 0x2;
        ann2.ip_port_is_set = 1;
        ann2.tcp_relays_count = 1;
        ann2.tcp_relays[0].ip_port.ip.family = net_family_ipv4();
        ann2.tcp_relays[0].ip_port.ip.ip.v4 = get_ip4_broadcast();
        ann2.tcp_relays[0].public_key[0] = 0xea;
    }

    ~AnnouncesPack() override { logger_kill(logger_); }
};

TEST_F(AnnouncesPack, PublicAnnounceCanBePackedAndUnpacked)
{
    GC_Public_Announce ann{};
    ann.chat_public_key[0] = 0x88;
    ann.base_announce = announces_[0];

    std::vector<std::uint8_t> packed(GCA_PUBLIC_ANNOUNCE_MAX_SIZE);
    const int packed_size = gca_pack_public_announce(logger_, packed.data(), packed.size(), &ann);

    EXPECT_GT(packed_size, 0);

    GC_Public_Announce unpacked_ann{};
    EXPECT_EQ(gca_unpack_public_announce(logger_, packed.data(), packed.size(), &unpacked_ann),
        packed_size);
}

TEST_F(AnnouncesPack, UnpackEmptyPublicAnnounce)
{
#ifndef __clang__
    GC_Public_Announce ann{};
    std::vector<std::uint8_t> packed(GCA_PUBLIC_ANNOUNCE_MAX_SIZE);

    EXPECT_EQ(gca_unpack_public_announce(logger_, nullptr, 0, &ann), -1);
    EXPECT_EQ(gca_unpack_public_announce(logger_, packed.data(), packed.size(), nullptr), -1);
#endif
}

TEST_F(AnnouncesPack, PackEmptyPublicAnnounce)
{
#ifndef __clang__
    GC_Public_Announce ann{};
    std::vector<std::uint8_t> packed(GCA_PUBLIC_ANNOUNCE_MAX_SIZE);
    EXPECT_EQ(gca_pack_public_announce(logger_, packed.data(), packed.size(), nullptr), -1);
    EXPECT_EQ(gca_pack_public_announce(logger_, nullptr, 0, &ann), -1);
#endif
}

TEST_F(AnnouncesPack, PublicAnnouncePackNull)
{
    GC_Public_Announce ann{};
    std::vector<std::uint8_t> packed(GCA_PUBLIC_ANNOUNCE_MAX_SIZE);
    EXPECT_EQ(gca_pack_public_announce(logger_, packed.data(), packed.size(), &ann), -1);

    ann.chat_public_key[0] = 0x88;
    ann.base_announce = announces_[0];

    std::vector<std::uint8_t> packedTooSmall(GCA_PUBLIC_ANNOUNCE_MAX_SIZE - 1);
    EXPECT_EQ(
        gca_pack_public_announce(logger_, packedTooSmall.data(), packedTooSmall.size(), &ann), -1);

    ann.base_announce.ip_port_is_set = 0;
    ann.base_announce.tcp_relays_count = 0;

    EXPECT_EQ(gca_pack_public_announce(logger_, packed.data(), packed.size(), &ann), -1);
}

TEST_F(AnnouncesPack, AnnouncesValidationCheck)
{
#ifndef __clang__
    EXPECT_EQ(gca_is_valid_announce(nullptr), false);
#endif

    GC_Announce announce = {0};
    EXPECT_EQ(gca_is_valid_announce(&announce), false);
    EXPECT_EQ(gca_is_valid_announce(&announces_[0]), true);
    EXPECT_EQ(gca_is_valid_announce(&announces_[1]), true);
    announces_[0].ip_port_is_set = 0;
    announces_[0].tcp_relays_count = 0;
    EXPECT_EQ(gca_is_valid_announce(&announces_[0]), false);
}

TEST_F(AnnouncesPack, UnpackIncompleteAnnouncesList)
{
    const std::uint8_t data[] = {0x00, 0x24, 0x3d, 0x00, 0x3d, 0xff, 0xff, 0x5b, 0x04, 0x20, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};

    GC_Announce announce;
    EXPECT_EQ(gca_unpack_announces_list(logger_, data, sizeof(data), &announce, 1), -1);
#ifndef __clang__
    EXPECT_EQ(gca_unpack_announces_list(logger_, data, sizeof(data), nullptr, 1), -1);
    EXPECT_EQ(gca_unpack_announces_list(logger_, nullptr, 0, &announce, 1), -1);
#endif
}

TEST_F(AnnouncesPack, PackedAnnouncesListCanBeUnpacked)
{
    const std::uint16_t size = gca_pack_announces_list_size(announces_.size());
    std::vector<std::uint8_t> packed(size);

    std::size_t processed = 0;

    EXPECT_GT(gca_pack_announces_list(logger_, packed.data(), packed.size(), announces_.data(),
                  announces_.size(), &processed),
        0);
    ASSERT_GE(processed, ENC_PUBLIC_KEY_SIZE + 2);
    ASSERT_LE(processed, size);

    std::vector<GC_Announce> announces_unpacked(announces_.size());
    ASSERT_EQ(gca_unpack_announces_list(logger_, packed.data(), packed.size(),
                  announces_unpacked.data(), announces_unpacked.size()),
        announces_unpacked.size());
}

TEST_F(AnnouncesPack, PackingEmptyAnnounceFails)
{
    GC_Announce announce{};  // all zeroes
    std::vector<std::uint8_t> packed(gca_pack_announces_list_size(1));
    EXPECT_EQ(
        gca_pack_announces_list(logger_, packed.data(), packed.size(), &announce, 1, nullptr), -1);
#ifndef __clang__
    EXPECT_EQ(
        gca_pack_announces_list(logger_, packed.data(), packed.size(), nullptr, 1, nullptr), -1);
    EXPECT_EQ(gca_pack_announces_list(logger_, nullptr, 0, &announce, 1, nullptr), -1);
#endif
}

TEST_F(AnnouncesPack, PackAnnounceNull)
{
#ifndef __clang__
    std::vector<std::uint8_t> data(GCA_ANNOUNCE_MAX_SIZE);
    GC_Announce announce;
    ASSERT_EQ(gca_pack_announce(logger_, nullptr, 0, &announce), -1);
    ASSERT_EQ(gca_pack_announce(logger_, data.data(), data.size(), nullptr), -1);
#endif
}

}  // namespace
