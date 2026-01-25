/** @file
 * @brief Generates a valid input for e2e_fuzz_test.
 *
 * This bootstraps 2 toxes tox1 and tox2, adds tox1 as tox2's friend, waits for
 * the friend request, then tox1 adds tox2 in response, waits for the friend to
 * come online, sends a 2-message exchange, and waits for the read receipt.
 *
 * All random inputs and network traffic is recorded and dumped to files at the
 * end. This can then be fed to e2e_fuzz_test for replay (only of tox1) and
 * further code path exploration using fuzzer mutations.
 *
 * We write 2 files: an init file that contains all the inputs needed to reach
 * the "friend online" state, and a smaller file containing things to mutate
 * once the tox instance is in that state. This allows for more specific
 * exploration of code paths starting from "friend is online". DHT and onion
 * packet parsing is explored more in bootstrap_fuzz_test.
 *
 * Usage:
 *
 *   bazel build //c-toxcore/testing/fuzzing:protodump && \
 *     bazel-bin/c-toxcore/testing/fuzzing/protodump
 */
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <vector>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "../support/public/simulated_environment.hh"

namespace {

using tox::test::FakeClock;
using tox::test::Packet;
using tox::test::ScopedToxSystem;
using tox::test::SimulatedEnvironment;

constexpr uint32_t MESSAGE_COUNT = 5;

class Recorder {
public:
    std::vector<uint8_t> data;

    void push(bool val) { data.push_back(val); }
    void push(uint8_t val) { data.push_back(val); }
    void push(const uint8_t *bytes, std::size_t size)
    {
        data.insert(data.end(), bytes, bytes + size);
    }

    // Format: 2 bytes length (big-endian), then data.
    void push_packet(const uint8_t *bytes, std::size_t size)
    {
        assert(size <= 65535);
        push(static_cast<uint8_t>(size >> 8));
        push(static_cast<uint8_t>(size & 0xFF));
        push(bytes, size);
    }
};

struct State {
    Tox *tox;
    uint32_t done;
};

void setup_callbacks(Tox_Dispatch *dispatch)
{
    tox_events_callback_conference_connected(
        dispatch, [](const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_connected(
        dispatch, [](const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_invite(
        dispatch, [](const Tox_Event_Conference_Invite *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_message(
        dispatch, [](const Tox_Event_Conference_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_list_changed(
        dispatch, [](const Tox_Event_Conference_Peer_List_Changed *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_name(
        dispatch, [](const Tox_Event_Conference_Peer_Name *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_title(dispatch,
        [](const Tox_Event_Conference_Title *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_file_chunk_request(
        dispatch, [](const Tox_Event_File_Chunk_Request *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv(dispatch,
        [](const Tox_Event_File_Recv *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_file_recv_chunk(dispatch,
        [](const Tox_Event_File_Recv_Chunk *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_file_recv_control(
        dispatch, [](const Tox_Event_File_Recv_Control *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_connection_status(
        dispatch, [](const Tox_Event_Friend_Connection_Status *event, void *user_data) {
            State *state = static_cast<State *>(user_data);
            const uint32_t friend_number
                = tox_event_friend_connection_status_get_friend_number(event);
            assert(friend_number == 0);
            const uint8_t message = 'A';
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(
                state->tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &message, 1, &err);
            assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
        });
    tox_events_callback_friend_lossless_packet(
        dispatch, [](const Tox_Event_Friend_Lossless_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossy_packet(
        dispatch, [](const Tox_Event_Friend_Lossy_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_message(
        dispatch, [](const Tox_Event_Friend_Message *event, void *user_data) {
            State *state = static_cast<State *>(user_data);
            const uint32_t friend_number = tox_event_friend_message_get_friend_number(event);
            assert(friend_number == 0);
            const uint32_t message_length = tox_event_friend_message_get_message_length(event);
            assert(message_length == 1);
            const uint8_t *message = tox_event_friend_message_get_message(event);
            const uint8_t reply = message[0] + 1;
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(
                state->tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &reply, 1, &err);
            assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
        });
    tox_events_callback_friend_name(
        dispatch, [](const Tox_Event_Friend_Name *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_name_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            State *state = static_cast<State *>(user_data);
            const uint32_t friend_number = tox_event_friend_read_receipt_get_friend_number(event);
            assert(friend_number == 0);
            const uint32_t message_id = tox_event_friend_read_receipt_get_message_id(event);
            state->done = std::max(state->done, message_id);
        });
    tox_events_callback_friend_request(
        dispatch, [](const Tox_Event_Friend_Request *event, void *user_data) {
            State *state = static_cast<State *>(user_data);
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(
                state->tox, tox_event_friend_request_get_public_key(event), &err);
            assert(err == TOX_ERR_FRIEND_ADD_OK || err == TOX_ERR_FRIEND_ADD_OWN_KEY
                || err == TOX_ERR_FRIEND_ADD_ALREADY_SENT
                || err == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
        });
    tox_events_callback_friend_status(
        dispatch, [](const Tox_Event_Friend_Status *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_status_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_status_message(
        dispatch, [](const Tox_Event_Friend_Status_Message *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_status_message_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_typing(
        dispatch, [](const Tox_Event_Friend_Typing *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_typing_get_friend_number(event);
            assert(friend_number == 0);
            assert(!tox_event_friend_typing_get_typing(event));
        });
    tox_events_callback_self_connection_status(
        dispatch, [](const Tox_Event_Self_Connection_Status *event, void *user_data) {});
}

void dump(std::vector<uint8_t> recording, const char *filename)
{
    std::printf("%zu bytes: %s\n", recording.size(), filename);
    std::ofstream(filename, std::ios::binary)
        .write(reinterpret_cast<const char *>(recording.data()), recording.size());
}

void RecordBootstrap(const char *init, const char *bootstrap)
{
    SimulatedEnvironment env1{12345};
    SimulatedEnvironment env2{12346};

    // Set deterministic seeds.
    std::minstd_rand rng1(4);
    env1.fake_random().set_entropy_source([&](uint8_t *out, std::size_t count) {
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (std::size_t i = 0; i < count; ++i)
            out[i] = static_cast<uint8_t>(dist(rng1));
    });

    std::minstd_rand rng2(5);
    env2.fake_random().set_entropy_source([&](uint8_t *out, std::size_t count) {
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (std::size_t i = 0; i < count; ++i)
            out[i] = static_cast<uint8_t>(dist(rng2));
    });

    Recorder recorder1;
    Recorder recorder2;

    env1.fake_memory().set_observer([&](bool success) { recorder1.push(success); });

    env1.fake_random().set_observer(
        [&](const uint8_t *data, std::size_t count) { recorder1.push(data, count); });

    auto node1 = env1.create_node(33445);
    auto node2 = env2.create_node(33446);

    // Record received packets.
    node1->endpoint->set_recv_observer([&](const std::vector<uint8_t> &data, const IP_Port &from) {
        recorder1.push_packet(data.data(), data.size());
    });

    // Bridge the two simulated networks.
    env1.simulation().net().add_observer(
        [&](const Packet &p) { env2.simulation().net().send_packet(p); });

    env2.simulation().net().add_observer(
        [&](const Packet &p) { env1.simulation().net().send_packet(p); });

    Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_local_discovery_enabled(opts, false);

    Tox_Options_Testing opts_test1;
    opts_test1.operating_system = &node1->system;

    Tox_Err_New error_new;
    Tox_Err_New_Testing error_new_testing;

    Tox *tox1 = tox_new_testing(opts, &error_new, &opts_test1, &error_new_testing);
    assert(tox1 != nullptr);

    Tox_Options_Testing opts_test2;
    opts_test2.operating_system = &node2->system;

    Tox *tox2 = tox_new_testing(opts, &error_new, &opts_test2, &error_new_testing);
    assert(tox2 != nullptr);

    tox_options_free(opts);

    std::array<uint8_t, TOX_ADDRESS_SIZE> address1;
    tox_self_get_address(tox1, address1.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> dht_key1;
    tox_self_get_dht_id(tox1, dht_key1.data());

    // Bootstrap tox2 to tox1.
    const bool udp_success = tox_bootstrap(tox2, "127.0.0.1", 33445, dht_key1.data(), nullptr);
    assert(udp_success);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    setup_callbacks(dispatch);

    State state1 = {tox1, 0};
    State state2 = {tox2, 0};

    const auto iterate = [&](uint8_t clock_increment) {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events;

        std::unique_ptr<Tox_Iterate_Options, void (*)(Tox_Iterate_Options *)> iterate_opts(
            tox_iterate_options_new(nullptr), tox_iterate_options_free);
        tox_iterate_options_set_fail_hard(iterate_opts.get(), true);

        events = tox_events_iterate(tox1, iterate_opts.get(), &error_iterate);
        tox_dispatch_invoke(dispatch, events, &state1);
        tox_events_free(events);

        events = tox_events_iterate(tox2, iterate_opts.get(), &error_iterate);
        tox_dispatch_invoke(dispatch, events, &state2);
        tox_events_free(events);
        // Record the clock increment.
        env1.fake_clock().advance(clock_increment);
        recorder1.push(clock_increment);

        env2.fake_clock().advance(clock_increment);

        env1.simulation().net().process_events(env1.fake_clock().current_time_ms());
        env2.simulation().net().process_events(env2.fake_clock().current_time_ms());
    };

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE
        || tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        iterate(200);
    }

    std::printf("toxes are online\n");

    const uint8_t msg = 'A';
    const uint32_t friend_number = tox_friend_add(tox2, address1.data(), &msg, 1, nullptr);
    assert(friend_number == 0);

    while (tox_friend_get_connection_status(tox2, friend_number, nullptr) == TOX_CONNECTION_NONE
        || tox_friend_get_connection_status(tox1, 0, nullptr) == TOX_CONNECTION_NONE) {
        iterate(200);
    }

    std::printf("tox clients connected\n");

    dump(recorder1.data, init);

    // Clear the recorder.
    recorder1.data.clear();

    while (state1.done < MESSAGE_COUNT && state2.done < MESSAGE_COUNT) {
        iterate(20);
    }

    std::printf("test complete\n");

    tox_dispatch_free(dispatch);
    tox_kill(tox2);
    tox_kill(tox1);

    dump(recorder1.data, bootstrap);
}

}

int main(int argc, char *argv[])
{
    const char *init = "tools/toktok-fuzzer/init/e2e_fuzz_test.dat";
    const char *bootstrap = "tools/toktok-fuzzer/corpus/e2e_fuzz_test/bootstrap.dat";
    if (argc == 3) {
        init = argv[1];
        bootstrap = argv[2];
    }
    RecordBootstrap(init, bootstrap);
}
