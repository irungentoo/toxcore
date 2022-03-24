#include "tox.h"

#include <gtest/gtest.h>

#include <array>

#include "crypto_core.h"

namespace {

static void set_random_name_and_status_message(Tox *tox, uint8_t *name, uint8_t *status_message)
{
    for (uint16_t i = 0; i < TOX_MAX_NAME_LENGTH; ++i) {
        name[i] = random_u08();
    }

    for (uint16_t i = 0; i < TOX_MAX_STATUS_MESSAGE_LENGTH; ++i) {
        status_message[i] = random_u08();
    }
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

    // Higher start/end point here to avoid conflict with the LAN discovery test.
    tox_options_set_start_port(options, 33545);
    tox_options_set_end_port(options, 33545 + 2000);

    std::array<uint8_t, TOX_MAX_NAME_LENGTH> name;
    std::array<uint8_t, TOX_MAX_STATUS_MESSAGE_LENGTH> status_message;

    std::array<uint8_t, TOX_MAX_NAME_LENGTH> name2;
    std::array<uint8_t, TOX_MAX_STATUS_MESSAGE_LENGTH> status_message2;

    Tox *tox1 = tox_new(options, nullptr);
    ASSERT_NE(tox1, nullptr);
    set_random_name_and_status_message(tox1, name.data(), status_message.data());
    Tox *tox2 = tox_new(options, nullptr);
    ASSERT_NE(tox2, nullptr);
    set_random_name_and_status_message(tox2, name2.data(), status_message2.data());

    std::array<uint8_t, TOX_ADDRESS_SIZE> address;
    tox_self_get_address(tox1, address.data());
    Tox_Err_Friend_Add error;
    uint32_t ret
        = tox_friend_add(tox1, address.data(), reinterpret_cast<const uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OWN_KEY) << "Adding own address worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    uint8_t message[TOX_MAX_FRIEND_REQUEST_LENGTH + 1] = {0};
    ret = tox_friend_add(tox1, address.data(), nullptr, 0, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_NULL) << "Sending request with no message worked.";
    EXPECT_EQ(ret, UINT32_MAX);
    ret = tox_friend_add(tox1, address.data(), message, 0, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE) << "Sending request with no message worked.";
    EXPECT_EQ(ret, UINT32_MAX);
    ret = tox_friend_add(tox1, address.data(), message, sizeof(message), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_TOO_LONG) << "TOX_MAX_FRIEND_REQUEST_LENGTH is too big.";
    EXPECT_EQ(ret, UINT32_MAX);

    address[0]++;
    ret = tox_friend_add(tox1, address.data(), reinterpret_cast<const uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM) << "Adding address with bad checksum worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    ret = tox_friend_add(tox1, address.data(), message, TOX_MAX_FRIEND_REQUEST_LENGTH, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OK) << "Failed to add friend.";
    EXPECT_EQ(ret, 0);
    ret = tox_friend_add(tox1, address.data(), message, TOX_MAX_FRIEND_REQUEST_LENGTH, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT) << "Adding friend twice worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_set_name(tox1, name.data(), name.size(), nullptr);
    EXPECT_EQ(tox_self_get_name_size(tox1), name.size()) << "Can't set name of TOX_MAX_NAME_LENGTH";

    tox_self_set_status_message(tox1, status_message.data(), status_message.size(), nullptr);
    EXPECT_EQ(tox_self_get_status_message_size(tox1), status_message.size())
        << "Can't set status message of TOX_MAX_STATUS_MESSAGE_LENGTH";

    tox_self_get_address(tox1, address.data());
    std::vector<uint8_t> data(tox_get_savedata_size(tox1));
    tox_get_savedata(tox1, data.data());

    tox_kill(tox2);
    Tox_Err_New err_n;

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, data.data(), data.size());
    tox2 = tox_new(options, &err_n);
    EXPECT_EQ(err_n, TOX_ERR_NEW_OK) << "Load failed";

    EXPECT_EQ(tox_self_get_name_size(tox2), sizeof name) << "Wrong name size.";
    EXPECT_EQ(tox_self_get_status_message_size(tox2), sizeof status_message)
        << "Wrong status message size";

    std::array<uint8_t, TOX_MAX_NAME_LENGTH> name_loaded{};
    tox_self_get_name(tox2, name_loaded.data());
    EXPECT_EQ(name, name_loaded) << "Wrong name.";

    std::array<uint8_t, TOX_MAX_STATUS_MESSAGE_LENGTH> status_message_loaded{};
    tox_self_get_status_message(tox2, status_message_loaded.data());
    EXPECT_EQ(status_message, status_message_loaded) << "Wrong status message.";

    std::array<uint8_t, TOX_ADDRESS_SIZE> address2{};
    tox_self_get_address(tox2, address2.data());
    EXPECT_EQ(address2, address) << "Wrong address.";
    std::array<uint8_t, TOX_MAX_NAME_LENGTH> new_name{};
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
