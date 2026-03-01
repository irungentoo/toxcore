// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "group_moderation.h"
// clang-format on

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "DHT.h"
#include "crypto_core.h"
#include "crypto_core_test_util.hh"
#include "logger.h"
#include "util.h"

namespace {

using tox::test::SimulatedEnvironment;
using ModerationHash = std::array<std::uint8_t, MOD_MODERATION_HASH_SIZE>;

TEST(ModList, PackedSizeOfEmptyModListIsZero)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    EXPECT_EQ(mod_list_packed_size(&mods), 0);

    std::uint8_t byte = 1;
    mod_list_pack(&mods, &byte);
    EXPECT_EQ(byte, 1);
}

TEST(ModList, UnpackingZeroSizeArrayIsNoop)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    const std::uint8_t byte = 1;
    EXPECT_EQ(mod_list_unpack(&mods, &byte, 0, 0), 0);
}

TEST(ModList, AddRemoveMultipleMods)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    std::uint8_t sig_pk1[32] = {1};
    std::uint8_t sig_pk2[32] = {2};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk1));
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk2));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk1));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk2));
}

TEST(ModList, PackingAndUnpackingList)
{
    using ModListEntry = std::array<std::uint8_t, MOD_LIST_ENTRY_SIZE>;
    SimulatedEnvironment env{12345};

    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<std::uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    EXPECT_TRUE(mod_list_remove_entry(&mods, ModListEntry{}.data()));

    Moderation mods2{&c_mem};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 1), packed.size());
    EXPECT_TRUE(mod_list_remove_entry(&mods2, ModListEntry{}.data()));
}

TEST(ModList, UnpackingTooManyModsFails)
{
    using ModListEntry = std::array<std::uint8_t, MOD_LIST_ENTRY_SIZE>;
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<std::uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    Moderation mods2{&c_mem};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 2), -1);
    EXPECT_TRUE(mod_list_remove_entry(&mods, ModListEntry{}.data()));
}

TEST(ModList, UnpackingFromEmptyBufferFails)
{
    std::vector<std::uint8_t> packed(1);

    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    EXPECT_EQ(mod_list_unpack(&mods, packed.data(), 0, 1), -1);
}

TEST(ModList, HashOfEmptyModListZeroesOutBuffer)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    auto c_rng = env.fake_random().c_random();

    Moderation mods{&c_mem};

    // Fill with random data, check that it's zeroed.
    ModerationHash hash;
    random_bytes(&c_rng, hash.data(), hash.size());
    EXPECT_TRUE(mod_list_make_hash(&mods, hash.data()));
    EXPECT_EQ(hash, ModerationHash{});
}

TEST(ModList, RemoveIndexFromEmptyModListFails)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    EXPECT_FALSE(mod_list_remove_index(&mods, 0));
    EXPECT_FALSE(mod_list_remove_index(&mods, UINT16_MAX));
}

TEST(ModList, RemoveEntryFromEmptyModListFails)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    std::uint8_t sig_pk[32] = {0};
    EXPECT_FALSE(mod_list_remove_entry(&mods, sig_pk));
}

TEST(ModList, ModListRemoveIndex)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    std::uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_index(&mods, 0));
}

TEST(ModList, CleanupOnEmptyModsIsNoop)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    mod_list_cleanup(&mods);
}

TEST(ModList, EmptyModListCannotVerifyAnySigPk)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    std::uint8_t sig_pk[32] = {1};
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(ModList, ModListAddVerifyRemoveSigPK)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods{&c_mem};
    std::uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_verify_sig_pk(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk));
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(ModList, ModListHashCheck)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mods1{&c_mem};
    std::uint8_t sig_pk1[32] = {1};
    std::array<std::uint8_t, MOD_MODERATION_HASH_SIZE> hash1;

    EXPECT_TRUE(mod_list_add_entry(&mods1, sig_pk1));
    EXPECT_TRUE(mod_list_make_hash(&mods1, hash1.data()));
    EXPECT_TRUE(mod_list_remove_entry(&mods1, sig_pk1));
}

TEST(SanctionsList, PackingIntoUndersizedBufferFails)
{
    Mod_Sanction sanctions[1] = {};
    std::array<std::uint8_t, 1> packed;
    EXPECT_EQ(sanctions_list_pack(packed.data(), packed.size(), sanctions, 1, nullptr), -1);

    std::uint16_t length = sanctions_list_packed_size(1) - 1;
    std::vector<std::uint8_t> packed2(length);
    EXPECT_EQ(sanctions_list_pack(packed2.data(), packed2.size(), sanctions, 1, nullptr), -1);
}

TEST(SanctionsList, PackUnpackSanctionsCreds)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Moderation mod{&c_mem};
    std::array<std::uint8_t, MOD_SANCTIONS_CREDS_SIZE> packed;
    EXPECT_EQ(sanctions_creds_pack(&mod.sanctions_creds, packed.data()), MOD_SANCTIONS_CREDS_SIZE);
    EXPECT_EQ(
        sanctions_creds_unpack(&mod.sanctions_creds, packed.data()), MOD_SANCTIONS_CREDS_SIZE);
}

struct SanctionsListMod : ::testing::Test {
protected:
    SimulatedEnvironment env{12345};
    Memory c_mem_;
    Random c_rng_;

    Extended_Public_Key pk;
    Extended_Secret_Key sk;
    Logger *log = nullptr;
    Moderation mod;

    Mod_Sanction sanctions[2] = {};
    const std::uint8_t sanctioned_pk1[32] = {1};
    const std::uint8_t sanctioned_pk2[32] = {2};

    SanctionsListMod()
        : c_mem_(env.fake_memory().c_memory())
        , c_rng_(env.fake_random().c_random())
        , mod{&c_mem_}
    {
    }

    void SetUp() override
    {
        log = logger_new(&c_mem_);
        ASSERT_TRUE(create_extended_keypair(&pk, &sk, &c_rng_));

        mod.log = log;

        std::memcpy(mod.self_public_sig_key, get_sig_pk(&pk), SIG_PUBLIC_KEY_SIZE);
        std::memcpy(mod.self_secret_sig_key, get_sig_sk(&sk), SIG_SECRET_KEY_SIZE);

        ASSERT_TRUE(mod_list_add_entry(&mod, get_sig_pk(&pk)));

        EXPECT_FALSE(sanctions_list_check_integrity(&mod, &mod.sanctions_creds, &sanctions[0], 0));
        EXPECT_FALSE(sanctions_list_check_integrity(&mod, &mod.sanctions_creds, &sanctions[0], 1));
        EXPECT_FALSE(
            sanctions_list_check_integrity(&mod, &mod.sanctions_creds, &sanctions[0], UINT16_MAX));

        EXPECT_TRUE(sanctions_list_make_entry(&mod, sanctioned_pk1, &sanctions[0], SA_OBSERVER));
        EXPECT_TRUE(sanctions_list_check_integrity(
            &mod, &mod.sanctions_creds, sanctions, mod.num_sanctions));
        EXPECT_TRUE(sanctions_list_make_entry(&mod, sanctioned_pk2, &sanctions[1], SA_OBSERVER));
        EXPECT_TRUE(sanctions_list_check_integrity(
            &mod, &mod.sanctions_creds, sanctions, mod.num_sanctions));
    }

    ~SanctionsListMod() override
    {
        EXPECT_TRUE(sanctions_list_remove_observer(&mod, sanctioned_pk1, nullptr));
        EXPECT_TRUE(sanctions_list_remove_observer(&mod, sanctioned_pk2, nullptr));
        EXPECT_FALSE(sanctions_list_entry_exists(&mod, &sanctions[0]));
        EXPECT_FALSE(sanctions_list_entry_exists(&mod, &sanctions[1]));
        EXPECT_TRUE(mod_list_remove_entry(&mod, get_sig_pk(&pk)));

        logger_kill(log);
    }
};

// TODO(JFreegman): Split this up into smaller subtests
TEST_F(SanctionsListMod, PackUnpackSanction)
{
    std::vector<std::uint8_t> packed(sanctions_list_packed_size(2));

    EXPECT_EQ(
        sanctions_list_pack(packed.data(), packed.size(), sanctions, 2, nullptr), packed.size());

    Mod_Sanction unpacked_sanctions[2] = {};
    std::uint16_t processed_data_len = 0;

    EXPECT_EQ(sanctions_list_unpack(unpacked_sanctions, &mod.sanctions_creds, 2, packed.data(),
                  packed.size(), &processed_data_len),
        2);

    EXPECT_EQ(processed_data_len, packed.size());
    EXPECT_TRUE(sanctions_list_check_integrity(
        &mod, &mod.sanctions_creds, unpacked_sanctions, mod.num_sanctions));
    EXPECT_TRUE(sanctions_list_entry_exists(&mod, &unpacked_sanctions[0]));
    EXPECT_TRUE(sanctions_list_entry_exists(&mod, &unpacked_sanctions[1]));
}

TEST_F(SanctionsListMod, ReplaceSanctionSignatures)
{
    EXPECT_EQ(sanctions_list_replace_sig(&mod, mod.self_public_sig_key), mod.num_sanctions);
    EXPECT_TRUE(
        sanctions_list_check_integrity(&mod, &mod.sanctions_creds, sanctions, mod.num_sanctions));
}

}  // namespace
