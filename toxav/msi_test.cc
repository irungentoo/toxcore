/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "msi.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/logger.h"
#include "../toxcore/os_memory.h"

namespace {

struct MockMsi {
    std::vector<std::vector<std::uint8_t>> sent_packets;
    std::vector<std::uint32_t> sent_to_friends;

    struct CallbackStats {
        int invite = 0;
        int start = 0;
        int end = 0;
        int error = 0;
        int peertimeout = 0;
        int capabilities = 0;
    } stats;

    MSICall *_Nullable last_call = nullptr;
    MSIError last_error = MSI_E_NONE;

    static int send_packet(void *_Nullable user_data, std::uint32_t friend_number,
        const std::uint8_t *_Nonnull data, std::size_t length)
    {
        auto *self = static_cast<MockMsi *>(user_data);
        self->sent_packets.emplace_back(data, data + length);
        self->sent_to_friends.push_back(friend_number);
        return 0;
    }

    static int on_invite(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.invite++;
        self->last_call = call;
        return 0;
    }

    static int on_start(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.start++;
        self->last_call = call;
        return 0;
    }

    static int on_end(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.end++;
        self->last_call = call;
        return 0;
    }

    static int on_error(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.error++;
        self->last_call = call;
        self->last_error = call->error;
        return 0;
    }

    static int on_peertimeout(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.peertimeout++;
        self->last_call = call;
        return 0;
    }

    static int on_capabilities(void *_Nullable object, MSICall *_Nonnull call)
    {
        auto *self = static_cast<MockMsi *>(object);
        self->stats.capabilities++;
        self->last_call = call;
        return 0;
    }
};

class MsiTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        const Memory *_Nonnull mem = os_memory();
        log = logger_new(mem);

        MSICallbacks callbacks = {MockMsi::on_invite, MockMsi::on_start, MockMsi::on_end,
            MockMsi::on_error, MockMsi::on_peertimeout, MockMsi::on_capabilities};

        session = msi_new(log, MockMsi::send_packet, &mock, &callbacks, &mock);
    }

    void TearDown() override
    {
        if (session) {
            msi_kill(log, session);
        }
        logger_kill(log);
    }

    Logger *_Nullable log;
    MSISession *_Nullable session = nullptr;
    MockMsi mock;
};

TEST_F(MsiTest, BasicNewKill)
{
    // setup/teardown handles it
}

TEST_F(MsiTest, Invite)
{
    MSICall *call = nullptr;
    std::uint32_t friend_number = 123;
    std::uint8_t capabilities = MSI_CAP_S_AUDIO | MSI_CAP_R_AUDIO;

    int rc = msi_invite(log, session, &call, friend_number, capabilities);
    ASSERT_EQ(rc, 0);
    ASSERT_NE(call, nullptr);
    EXPECT_EQ(call->friend_number, friend_number);
    EXPECT_EQ(call->self_capabilities, capabilities);
    EXPECT_EQ(call->state, MSI_CALL_REQUESTING);

    ASSERT_EQ(mock.sent_packets.size(), 1u);
    EXPECT_EQ(mock.sent_to_friends[0], friend_number);

    // Verify packet: |ID_REQUEST(1)| |len(1)| |REQU_INIT(0)| |ID_CAPABILITIES(3)| |len(1)| |caps|
    // |0|
    const auto &pkt = mock.sent_packets[0];
    ASSERT_GE(pkt.size(), 7u);
    EXPECT_EQ(pkt[0], 1);  // ID_REQUEST
    EXPECT_EQ(pkt[2], 0);  // REQU_INIT
    EXPECT_EQ(pkt.back(), 0);
}

TEST_F(MsiTest, HandleIncomingInvite)
{
    std::uint32_t friend_number = 456;
    std::uint8_t peer_caps = MSI_CAP_S_VIDEO | MSI_CAP_R_VIDEO;

    // Craft invite packet
    std::uint8_t invite_pkt[] = {
        1, 1, 0,  // ID_REQUEST, len 1, REQU_INIT
        3, 1, peer_caps,  // ID_CAPABILITIES, len 1, caps
        0  // end
    };

    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));

    EXPECT_EQ(mock.stats.invite, 1);
    ASSERT_NE(mock.last_call, nullptr);
    EXPECT_EQ(mock.last_call->friend_number, friend_number);
    EXPECT_EQ(mock.last_call->peer_capabilities, peer_caps);
    EXPECT_EQ(mock.last_call->state, MSI_CALL_REQUESTED);
}

TEST_F(MsiTest, Answer)
{
    // 1. Receive invite first
    std::uint32_t friend_number = 456;
    std::uint8_t peer_caps = MSI_CAP_S_VIDEO | MSI_CAP_R_VIDEO;
    std::uint8_t invite_pkt[] = {1, 1, 0, 3, 1, peer_caps, 0};
    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));
    MSICall *call = mock.last_call;

    // 2. Answer it
    std::uint8_t my_caps = MSI_CAP_S_AUDIO | MSI_CAP_R_AUDIO;
    int rc = msi_answer(log, call, my_caps);
    ASSERT_EQ(rc, 0);
    EXPECT_EQ(call->state, MSI_CALL_ACTIVE);
    EXPECT_EQ(call->self_capabilities, my_caps);

    ASSERT_GE(mock.sent_packets.size(), 1u);
    const auto &pkt = mock.sent_packets.back();
    // REQU_PUSH (1)
    EXPECT_EQ(pkt[0], 1);
    EXPECT_EQ(pkt[2], 1);  // REQU_PUSH
}

TEST_F(MsiTest, Hangup)
{
    MSICall *call = nullptr;
    msi_invite(log, session, &call, 123, 0);
    mock.sent_packets.clear();

    int rc = msi_hangup(log, call);
    ASSERT_EQ(rc, 0);

    ASSERT_EQ(mock.sent_packets.size(), 1u);
    const auto &pkt = mock.sent_packets[0];
    // REQU_POP (2)
    EXPECT_EQ(pkt[2], 2);
}

TEST_F(MsiTest, ChangeCapabilities)
{
    // Setup active call
    std::uint32_t friend_number = 123;
    std::uint8_t invite_pkt[] = {1, 1, 0, 3, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));
    MSICall *call = mock.last_call;
    msi_answer(log, call, 0);
    mock.sent_packets.clear();

    std::uint8_t new_caps = MSI_CAP_S_VIDEO;
    int rc = msi_change_capabilities(log, call, new_caps);
    ASSERT_EQ(rc, 0);
    EXPECT_EQ(call->self_capabilities, new_caps);

    ASSERT_EQ(mock.sent_packets.size(), 1u);
    EXPECT_EQ(mock.sent_packets[0][2], 1);  // REQU_PUSH
    EXPECT_EQ(mock.sent_packets[0][5], new_caps);
}

TEST_F(MsiTest, PeerTimeout)
{
    MSICall *call = nullptr;
    std::uint32_t friend_number = 123;
    msi_invite(log, session, &call, friend_number, 0);

    msi_call_timeout(session, log, friend_number);

    EXPECT_EQ(mock.stats.peertimeout, 1);
}

TEST_F(MsiTest, RemoteHangup)
{
    std::uint32_t friend_number = 123;
    MSICall *call = nullptr;
    msi_invite(log, session, &call, friend_number, 0);

    // Craft pop packet
    std::uint8_t pop_pkt[] = {1, 1, 2, 0};  // REQU_POP
    msi_handle_packet(session, log, friend_number, pop_pkt, sizeof(pop_pkt));

    EXPECT_EQ(mock.stats.end, 1);
}

TEST_F(MsiTest, RemoteError)
{
    std::uint32_t friend_number = 123;
    MSICall *call = nullptr;
    msi_invite(log, session, &call, friend_number, 0);

    // Craft error packet (ID_ERROR = 2)
    std::uint8_t error_pkt[] = {1, 1, 2, 2, 1, 1, 0};  // REQU_POP + MSI_E_INVALID_MESSAGE
    msi_handle_packet(session, log, friend_number, error_pkt, sizeof(error_pkt));

    EXPECT_EQ(mock.stats.error, 1);
    ASSERT_NE(mock.last_call, nullptr);
    EXPECT_EQ(mock.last_error, MSI_E_INVALID_MESSAGE);
}

TEST_F(MsiTest, MultipleConcurrentCalls)
{
    MSICall *call1 = nullptr;
    MSICall *call2 = nullptr;

    msi_invite(log, session, &call1, 1, 0);
    msi_invite(log, session, &call2, 2, 0);

    EXPECT_NE(call1, call2);
    EXPECT_EQ(call1->friend_number, 1u);
    EXPECT_EQ(call2->friend_number, 2u);

    // End call 1
    msi_hangup(log, call1);

    // Call 2 should still be there
    std::uint8_t pop_pkt[] = {1, 1, 2, 0};
    msi_handle_packet(session, log, 2, pop_pkt, sizeof(pop_pkt));
    EXPECT_EQ(mock.stats.end, 1);
}

TEST_F(MsiTest, RemoteAnswer)
{
    MSICall *call = nullptr;
    msi_invite(log, session, &call, 123, 0);

    std::uint8_t peer_caps = MSI_CAP_S_AUDIO;
    std::uint8_t push_pkt[] = {1, 1, 1, 3, 1, peer_caps, 0};  // REQU_PUSH + capabilities
    msi_handle_packet(session, log, 123, push_pkt, sizeof(push_pkt));

    EXPECT_EQ(mock.stats.start, 1);
    EXPECT_EQ(call->state, MSI_CALL_ACTIVE);
    EXPECT_EQ(call->peer_capabilities, peer_caps);
}

TEST_F(MsiTest, RemoteCapabilitiesChange)
{
    std::uint32_t friend_number = 123;
    std::uint8_t invite_pkt[] = {1, 1, 0, 3, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));
    MSICall *call = mock.last_call;
    msi_answer(log, call, 0);

    std::uint8_t new_caps = MSI_CAP_S_VIDEO;
    std::uint8_t push_pkt[] = {1, 1, 1, 3, 1, new_caps, 0};  // REQU_PUSH + new capabilities
    msi_handle_packet(session, log, friend_number, push_pkt, sizeof(push_pkt));

    EXPECT_EQ(mock.stats.capabilities, 1);
    EXPECT_EQ(call->peer_capabilities, new_caps);
}

TEST_F(MsiTest, FriendRecall)
{
    std::uint32_t friend_number = 123;
    std::uint8_t invite_pkt[] = {1, 1, 0, 3, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));
    MSICall *call = mock.last_call;
    msi_answer(log, call, 0);
    mock.sent_packets.clear();

    // Friend sends invite again while we are active
    msi_handle_packet(session, log, friend_number, invite_pkt, sizeof(invite_pkt));

    // We should have sent a REQU_PUSH back
    ASSERT_GE(mock.sent_packets.size(), 1u);
    EXPECT_EQ(mock.sent_packets.back()[2], 1);  // REQU_PUSH
}

TEST_F(MsiTest, GapInFriendNumbers)
{
    MSICall *call1 = nullptr;
    MSICall *call3 = nullptr;
    MSICall *call2 = nullptr;

    msi_invite(log, session, &call1, 1, 0);
    msi_invite(log, session, &call3, 3, 0);
    msi_invite(log, session, &call2, 2, 0);  // This fills a hole

    EXPECT_EQ(call2->prev, call1);
    EXPECT_EQ(call2->next, call3);
    EXPECT_EQ(call1->next, call2);
    EXPECT_EQ(call3->prev, call2);
}

TEST_F(MsiTest, InvalidPackets)
{
    std::uint32_t friend_number = 123;

    // Empty packet
    std::uint8_t empty = 0;
    msi_handle_packet(session, log, friend_number, &empty, 0);

    // Missing end byte
    std::uint8_t no_end[] = {1, 1, 0};
    msi_handle_packet(session, log, friend_number, no_end, sizeof(no_end));

    // Invalid ID
    std::uint8_t invalid_id[] = {99, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, invalid_id, sizeof(invalid_id));

    // Invalid size (too large)
    std::uint8_t invalid_size[] = {1, 10, 0, 0};
    msi_handle_packet(session, log, friend_number, invalid_size, sizeof(invalid_size));

    // Invalid size (mismatch)
    std::uint8_t size_mismatch[] = {1, 2, 0, 0};
    msi_handle_packet(session, log, friend_number, size_mismatch, sizeof(size_mismatch));

    // Missing request field
    std::uint8_t no_request[] = {3, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, no_request, sizeof(no_request));
}

TEST_F(MsiTest, CallbackFailure)
{
    struct FailMock {
        static int fail_cb(void *, MSICall *) { return -1; }
    };

    // Create a new session with a failing callback
    MSICallbacks callbacks = {FailMock::fail_cb, MockMsi::on_start, MockMsi::on_end,
        MockMsi::on_error, MockMsi::on_peertimeout, MockMsi::on_capabilities};

    MSISession *fail_session = msi_new(log, MockMsi::send_packet, &mock, &callbacks, &mock);

    std::uint8_t invite_pkt[] = {1, 1, 0, 3, 1, 0, 0};
    msi_handle_packet(fail_session, log, 123, invite_pkt, sizeof(invite_pkt));

    // Should have sent an error back
    ASSERT_GE(mock.sent_packets.size(), 1u);
    // REQU_POP (2) + ID_ERROR (2)
    EXPECT_EQ(mock.sent_packets.back()[2], 2);
    EXPECT_EQ(mock.sent_packets.back()[3], 2);

    msi_kill(log, fail_session);
}

TEST_F(MsiTest, InvalidStates)
{
    MSICall *call = nullptr;
    msi_invite(log, session, &call, 123, 0);

    // Cannot answer a REQUESTING call
    EXPECT_EQ(msi_answer(log, call, 0), -1);

    // Cannot change capabilities of a REQUESTING call
    EXPECT_EQ(msi_change_capabilities(log, call, 0), -1);

    // Cannot invite a friend we are already in call with
    MSICall *call2 = nullptr;
    EXPECT_EQ(msi_invite(log, session, &call2, 123, 0), -1);
}

TEST_F(MsiTest, StrayPackets)
{
    std::uint32_t friend_number = 123;

    // PUSH for non-existent call
    std::uint8_t push_pkt[] = {1, 1, 1, 3, 1, 0, 0};
    msi_handle_packet(session, log, friend_number, push_pkt, sizeof(push_pkt));

    // POP for non-existent call
    std::uint8_t pop_pkt[] = {1, 1, 2, 0};
    msi_handle_packet(session, log, friend_number, pop_pkt, sizeof(pop_pkt));

    // Error sent back for stray PUSH
    ASSERT_GE(mock.sent_packets.size(), 1u);
}

TEST_F(MsiTest, KillMultipleCalls)
{
    MSICall *call1 = nullptr;
    MSICall *call2 = nullptr;

    msi_invite(log, session, &call1, 1, 0);
    msi_invite(log, session, &call2, 2, 0);

    mock.sent_packets.clear();

    // msi_kill is called in TearDown, but we can call it here to verify
    msi_kill(log, session);

    // Should have sent POP for both calls
    EXPECT_EQ(mock.sent_packets.size(), 2u);

    // Set session to NULL so TearDown doesn't double-kill it (though msi_kill handles it)
    session = nullptr;
}

}  // namespace
