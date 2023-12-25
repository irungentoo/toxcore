#include "group_moderation.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

#include "crypto_core.h"
#include "logger.h"
#include "util.h"

namespace {

using ExtPublicKey = std::array<uint8_t, EXT_PUBLIC_KEY_SIZE>;
using ExtSecretKey = std::array<uint8_t, EXT_SECRET_KEY_SIZE>;
using ModerationHash = std::array<uint8_t, MOD_MODERATION_HASH_SIZE>;

TEST(ModList, PackedSizeOfEmptyModListIsZero)
{
    Moderation mods{system_memory()};
    EXPECT_EQ(mod_list_packed_size(&mods), 0);

    uint8_t byte = 1;
    mod_list_pack(&mods, &byte);
    EXPECT_EQ(byte, 1);
}

TEST(ModList, UnpackingZeroSizeArrayIsNoop)
{
    Moderation mods{system_memory()};
    const uint8_t byte = 1;
    EXPECT_EQ(mod_list_unpack(&mods, &byte, 0, 0), 0);
}

TEST(ModList, AddRemoveMultipleMods)
{
    Moderation mods{system_memory()};
    uint8_t sig_pk1[32] = {1};
    uint8_t sig_pk2[32] = {2};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk1));
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk2));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk1));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk2));
}

TEST(ModList, PackingAndUnpackingList)
{
    using ModListEntry = std::array<uint8_t, MOD_LIST_ENTRY_SIZE>;
    Moderation mods{system_memory()};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    EXPECT_TRUE(mod_list_remove_entry(&mods, ModListEntry{}.data()));

    Moderation mods2{system_memory()};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 1), packed.size());
    EXPECT_TRUE(mod_list_remove_entry(&mods2, ModListEntry{}.data()));
}

TEST(ModList, UnpackingTooManyModsFails)
{
    using ModListEntry = std::array<uint8_t, MOD_LIST_ENTRY_SIZE>;
    Moderation mods{system_memory()};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    Moderation mods2{system_memory()};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 2), -1);
    EXPECT_TRUE(mod_list_remove_entry(&mods, ModListEntry{}.data()));
}

TEST(ModList, UnpackingFromEmptyBufferFails)
{
    std::vector<uint8_t> packed(1);

    Moderation mods{system_memory()};
    EXPECT_EQ(mod_list_unpack(&mods, packed.data(), 0, 1), -1);
}

TEST(ModList, HashOfEmptyModListZeroesOutBuffer)
{
    const Random *rng = system_random();
    ASSERT_NE(rng, nullptr);

    Moderation mods{system_memory()};

    // Fill with random data, check that it's zeroed.
    ModerationHash hash;
    random_bytes(rng, hash.data(), hash.size());
    EXPECT_TRUE(mod_list_make_hash(&mods, hash.data()));
    EXPECT_EQ(hash, ModerationHash{});
}

TEST(ModList, RemoveIndexFromEmptyModListFails)
{
    Moderation mods{system_memory()};
    EXPECT_FALSE(mod_list_remove_index(&mods, 0));
    EXPECT_FALSE(mod_list_remove_index(&mods, UINT16_MAX));
}

TEST(ModList, RemoveEntryFromEmptyModListFails)
{
    Moderation mods{system_memory()};
    uint8_t sig_pk[32] = {0};
    EXPECT_FALSE(mod_list_remove_entry(&mods, sig_pk));
}

TEST(ModList, ModListRemoveIndex)
{
    Moderation mods{system_memory()};
    uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_index(&mods, 0));
}

TEST(ModList, CleanupOnEmptyModsIsNoop)
{
    Moderation mods{system_memory()};
    mod_list_cleanup(&mods);
}

TEST(ModList, EmptyModListCannotVerifyAnySigPk)
{
    Moderation mods{system_memory()};
    uint8_t sig_pk[32] = {1};
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(ModList, ModListAddVerifyRemoveSigPK)
{
    Moderation mods{system_memory()};
    uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_verify_sig_pk(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk));
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(ModList, ModListHashCheck)
{
    Moderation mods1{system_memory()};
    uint8_t sig_pk1[32] = {1};
    std::array<uint8_t, MOD_MODERATION_HASH_SIZE> hash1;

    EXPECT_TRUE(mod_list_add_entry(&mods1, sig_pk1));
    EXPECT_TRUE(mod_list_make_hash(&mods1, hash1.data()));
    EXPECT_TRUE(mod_list_remove_entry(&mods1, sig_pk1));
}

TEST(SanctionsList, PackingIntoUndersizedBufferFails)
{
    Mod_Sanction sanctions[1] = {};
    std::array<uint8_t, 1> packed;
    EXPECT_EQ(sanctions_list_pack(packed.data(), packed.size(), sanctions, 1, nullptr), -1);

    uint16_t length = sanctions_list_packed_size(1) - 1;
    std::vector<uint8_t> packed2(length);
    EXPECT_EQ(sanctions_list_pack(packed2.data(), packed2.size(), sanctions, 1, nullptr), -1);
}

TEST(SanctionsList, PackUnpackSanctionsCreds)
{
    Moderation mod{system_memory()};
    std::array<uint8_t, MOD_SANCTIONS_CREDS_SIZE> packed;
    EXPECT_EQ(sanctions_creds_pack(&mod.sanctions_creds, packed.data()), MOD_SANCTIONS_CREDS_SIZE);
    EXPECT_EQ(
        sanctions_creds_unpack(&mod.sanctions_creds, packed.data()), MOD_SANCTIONS_CREDS_SIZE);
}

struct SanctionsListMod : ::testing::Test {
protected:
    ExtPublicKey pk;
    ExtSecretKey sk;
    Logger *log = logger_new();
    Moderation mod{system_memory()};

    Mod_Sanction sanctions[2] = {};
    const uint8_t sanctioned_pk1[32] = {1};
    const uint8_t sanctioned_pk2[32] = {2};

    void SetUp() override
    {
        ASSERT_TRUE(create_extended_keypair(pk.data(), sk.data()));

        mod.log = log;

        memcpy(mod.self_public_sig_key, get_sig_pk(pk.data()), SIG_PUBLIC_KEY_SIZE);
        memcpy(mod.self_secret_sig_key, get_sig_sk(sk.data()), SIG_SECRET_KEY_SIZE);

        ASSERT_TRUE(mod_list_add_entry(&mod, get_sig_pk(pk.data())));

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
        EXPECT_TRUE(mod_list_remove_entry(&mod, get_sig_pk(pk.data())));

        logger_kill(log);
    }
};

// TODO(JFreegman): Split this up into smaller subtests
TEST_F(SanctionsListMod, PackUnpackSanction)
{
    std::vector<uint8_t> packed(sanctions_list_packed_size(2));

    EXPECT_EQ(
        sanctions_list_pack(packed.data(), packed.size(), sanctions, 2, nullptr), packed.size());

    Mod_Sanction unpacked_sanctions[2] = {};
    uint16_t processed_data_len = 0;

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
