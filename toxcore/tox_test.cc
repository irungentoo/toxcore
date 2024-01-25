#include "tox.h"

#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "crypto_core.h"
#include "tox_private.h"

namespace {

static void set_random_name_and_status_message(
    Tox *tox, const Random *rng, uint8_t *name, uint8_t *status_message)
{
    for (uint16_t i = 0; i < tox_max_name_length(); ++i) {
        name[i] = random_u08(rng);
    }

    for (uint16_t i = 0; i < tox_max_status_message_length(); ++i) {
        status_message[i] = random_u08(rng);
    }
}

TEST(Tox, CurrentVersionIsCompatibleWithItself)
{
    EXPECT_TRUE(
        TOX_VERSION_IS_API_COMPATIBLE(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH));
    EXPECT_TRUE(TOX_VERSION_IS_ABI_COMPATIBLE());
    EXPECT_TRUE(
        tox_version_is_compatible(tox_version_major(), tox_version_minor(), tox_version_patch()));
}

TEST(Tox, ConstantsAreNonZero)
{
    EXPECT_GT(tox_public_key_size(), 0);
    EXPECT_GT(tox_secret_key_size(), 0);
    EXPECT_GT(tox_conference_uid_size(), 0);
    EXPECT_GT(tox_conference_id_size(), 0);
    EXPECT_GT(tox_nospam_size(), 0);
    EXPECT_GT(tox_address_size(), 0);
    EXPECT_GT(tox_max_name_length(), 0);
    EXPECT_GT(tox_max_status_message_length(), 0);
    EXPECT_GT(tox_max_friend_request_length(), 0);
    EXPECT_GT(tox_max_message_length(), 0);
    EXPECT_GT(tox_max_custom_packet_size(), 0);
    EXPECT_GT(tox_hash_length(), 0);
    EXPECT_GT(tox_file_id_length(), 0);
    EXPECT_GT(tox_max_filename_length(), 0);
    EXPECT_GT(tox_max_hostname_length(), 0);
    EXPECT_GT(tox_group_max_topic_length(), 0);
    EXPECT_GT(tox_group_max_part_length(), 0);
    EXPECT_GT(tox_group_max_message_length(), 0);
    EXPECT_GT(tox_group_max_custom_lossy_packet_length(), 0);
    EXPECT_GT(tox_group_max_custom_lossless_packet_length(), 0);
    EXPECT_GT(tox_group_max_group_name_length(), 0);
    EXPECT_GT(tox_group_max_password_size(), 0);
    EXPECT_GT(tox_group_chat_id_size(), 0);
    EXPECT_GT(tox_group_peer_public_key_size(), 0);
    EXPECT_GT(tox_dht_node_ip_string_size(), 0);
    EXPECT_GT(tox_dht_node_public_key_size(), 0);
}

TEST(Tox, BootstrapErrorCodes)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    Tox_Err_Bootstrap err;
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> pk;
    tox_bootstrap(tox, "127.0.0.1", 0, pk.data(), &err);
    EXPECT_EQ(err, TOX_ERR_BOOTSTRAP_BAD_PORT);

    tox_bootstrap(tox, nullptr, 33445, pk.data(), &err);
    EXPECT_EQ(err, TOX_ERR_BOOTSTRAP_NULL);

    tox_kill(tox);
}

TEST(Tox, OneTest)
{
    struct Tox_Options *options = tox_options_new(nullptr);
    ASSERT_NE(options, nullptr);

    tox_options_set_log_callback(options,
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            fprintf(stderr, "[%c] %s:%d(%s): %s\n", tox_log_level_to_string(level)[0], file, line,
                func, message);
        });

    // Higher start/end point here to avoid conflict with the LAN discovery test.
    tox_options_set_start_port(options, 33545);
    tox_options_set_end_port(options, 33545 + 2000);

    std::vector<uint8_t> name(tox_max_name_length());
    std::vector<uint8_t> status_message(tox_max_status_message_length());

    std::vector<uint8_t> name2(tox_max_name_length());
    std::vector<uint8_t> status_message2(tox_max_status_message_length());

    Tox *tox1 = tox_new(options, nullptr);
    ASSERT_NE(tox1, nullptr);
    const Random *rng = os_random();
    ASSERT_NE(rng, nullptr);
    set_random_name_and_status_message(tox1, rng, name.data(), status_message.data());
    Tox *tox2 = tox_new(options, nullptr);
    ASSERT_NE(tox2, nullptr);
    set_random_name_and_status_message(tox2, rng, name2.data(), status_message2.data());

    std::array<uint8_t, TOX_ADDRESS_SIZE> address;
    tox_self_get_address(tox1, address.data());
    Tox_Err_Friend_Add error;
    uint32_t ret
        = tox_friend_add(tox1, address.data(), reinterpret_cast<const uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OWN_KEY) << "Adding own address worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    std::vector<uint8_t> message(tox_max_friend_request_length() + 1);
    ret = tox_friend_add(tox1, address.data(), nullptr, 0, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_NULL) << "Sending request with no message worked.";
    EXPECT_EQ(ret, UINT32_MAX);
    ret = tox_friend_add(tox1, address.data(), message.data(), 0, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE) << "Sending request with no message worked.";
    EXPECT_EQ(ret, UINT32_MAX);
    ret = tox_friend_add(tox1, address.data(), message.data(), message.size(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_TOO_LONG) << "tox_max_friend_request_length() is too big.";
    EXPECT_EQ(ret, UINT32_MAX);

    address[0]++;
    ret = tox_friend_add(tox1, address.data(), reinterpret_cast<const uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM) << "Adding address with bad checksum worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    ret = tox_friend_add(
        tox1, address.data(), message.data(), tox_max_friend_request_length(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OK) << "Failed to add friend.";
    EXPECT_EQ(ret, 0);
    ret = tox_friend_add(
        tox1, address.data(), message.data(), tox_max_friend_request_length(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT) << "Adding friend twice worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_set_name(tox1, name.data(), name.size(), nullptr);
    EXPECT_EQ(tox_self_get_name_size(tox1), name.size())
        << "Can't set name of length " << tox_max_name_length();

    tox_self_set_status_message(tox1, status_message.data(), status_message.size(), nullptr);
    EXPECT_EQ(tox_self_get_status_message_size(tox1), status_message.size())
        << "Can't set status message of length " << tox_max_status_message_length();

    tox_self_get_address(tox1, address.data());
    std::vector<uint8_t> data(tox_get_savedata_size(tox1));
    tox_get_savedata(tox1, data.data());

    tox_kill(tox2);
    Tox_Err_New err_n;

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, data.data(), data.size());
    tox2 = tox_new(options, &err_n);
    EXPECT_EQ(err_n, TOX_ERR_NEW_OK) << "Load failed";

    EXPECT_EQ(tox_self_get_name_size(tox2), name.size()) << "Wrong name size.";
    EXPECT_EQ(tox_self_get_status_message_size(tox2), status_message.size())
        << "Wrong status message size";

    std::vector<uint8_t> name_loaded(tox_max_name_length());
    tox_self_get_name(tox2, name_loaded.data());
    EXPECT_EQ(name, name_loaded) << "Wrong name.";

    std::vector<uint8_t> status_message_loaded(tox_max_status_message_length());
    tox_self_get_status_message(tox2, status_message_loaded.data());
    EXPECT_EQ(status_message, status_message_loaded) << "Wrong status message.";

    std::array<uint8_t, TOX_ADDRESS_SIZE> address2;
    tox_self_get_address(tox2, address2.data());
    EXPECT_EQ(address2, address) << "Wrong address.";
    std::vector<uint8_t> new_name(tox_max_name_length());
    tox_self_get_name(tox2, new_name.data());
    EXPECT_EQ(name, new_name) << "Wrong name";

    std::array<uint8_t, TOX_SECRET_KEY_SIZE> sk;
    tox_self_get_secret_key(tox2, sk.data());
    tox_kill(tox2);

    tox_options_default(options);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_SECRET_KEY);
    tox_options_set_savedata_data(options, sk.data(), sk.size());
    tox2 = tox_new(options, &err_n);
    ASSERT_EQ(err_n, TOX_ERR_NEW_OK) << "Load failed";
    tox_self_set_nospam(tox2, tox_self_get_nospam(tox1));
    std::array<uint8_t, TOX_ADDRESS_SIZE> address3;
    tox_self_get_address(tox2, address3.data());
    EXPECT_EQ(address3, address) << "Wrong public key.";
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> pk;
    tox_self_get_public_key(tox2, pk.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> pk_from_addr;
    std::copy(address.begin(), address.begin() + TOX_PUBLIC_KEY_SIZE, pk_from_addr.begin());
    EXPECT_EQ(pk, pk_from_addr) << "Wrong public key.";

    tox_options_free(options);
    tox_kill(tox1);
    tox_kill(tox2);
}

}  // namespace
