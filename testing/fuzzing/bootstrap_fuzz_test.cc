#include <cassert>
#include <cstddef>
#include <cstdio>
#include <functional>
#include <memory>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "../support/public/fuzz_data.hh"
#include "../support/public/fuzz_helpers.hh"
#include "../support/public/simulated_environment.hh"

namespace {

using tox::test::configure_fuzz_memory_source;
using tox::test::configure_fuzz_packet_source;
using tox::test::FakeClock;
using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T *)>;

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
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossless_packet(
        dispatch, [](const Tox_Event_Friend_Lossless_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossy_packet(
        dispatch, [](const Tox_Event_Friend_Lossy_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_message(dispatch,
        [](const Tox_Event_Friend_Message *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_friend_name(dispatch,
        [](const Tox_Event_Friend_Name *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_friend_read_receipt(
        dispatch, [](const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_request(
        dispatch, [](const Tox_Event_Friend_Request *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
            if (!(err == TOX_ERR_FRIEND_ADD_OK || err == TOX_ERR_FRIEND_ADD_OWN_KEY
                    || err == TOX_ERR_FRIEND_ADD_ALREADY_SENT
                    || err == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM
                    || err == TOX_ERR_FRIEND_ADD_MALLOC)) {
                printf("unexpected error: %s\n", tox_err_friend_add_to_string(err));
            }
        });
    tox_events_callback_friend_status(dispatch,
        [](const Tox_Event_Friend_Status *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_friend_status_message(
        dispatch, [](const Tox_Event_Friend_Status_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_typing(dispatch,
        [](const Tox_Event_Friend_Typing *event, void *user_data) { assert(event == nullptr); });
    tox_events_callback_self_connection_status(
        dispatch, [](const Tox_Event_Self_Connection_Status *event, void *user_data) {
            assert(event == nullptr);
        });
}

void TestBootstrap(Fuzz_Data &input)
{
    SimulatedEnvironment env{12345};
    env.fake_clock().advance(1000000000);  // Match legacy behavior
    auto node = env.create_node(33445);
    configure_fuzz_memory_source(env.fake_memory(), input);
    configure_fuzz_packet_source(*node->endpoint, input);

    // Create a second null system for tox_events_equal check
    SimulatedEnvironment null_env{12346};
    auto null_node = null_env.create_node(0);  // Port 0 (unbound/irrelevant)

    Ptr<Tox_Options> opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);

    tox_options_set_log_callback(opts.get(),
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            // Log to stdout.
            if (Fuzz_Data::FUZZ_DEBUG) {
                // Approximate level name mapping
                char level_char = '?';
                switch (level) {
                case TOX_LOG_LEVEL_TRACE:
                    level_char = 'T';
                    break;
                case TOX_LOG_LEVEL_DEBUG:
                    level_char = 'D';
                    break;
                case TOX_LOG_LEVEL_INFO:
                    level_char = 'I';
                    break;
                case TOX_LOG_LEVEL_WARNING:
                    level_char = 'W';
                    break;
                case TOX_LOG_LEVEL_ERROR:
                    level_char = 'E';
                    break;
                }
                std::printf("[tox1] %c %s:%u(%s): %s\n", level_char, file, line, func, message);
            }
        });

    CONSUME1_OR_RETURN(const uint8_t, proxy_type, input);
    if (proxy_type == 0) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_NONE);
    } else if (proxy_type == 1) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_SOCKS5);
        tox_options_set_proxy_host(opts.get(), "127.0.0.1");
        tox_options_set_proxy_port(opts.get(), 8080);
    } else if (proxy_type == 2) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_HTTP);
        tox_options_set_proxy_host(opts.get(), "127.0.0.1");
        tox_options_set_proxy_port(opts.get(), 8080);
    }

    CONSUME1_OR_RETURN(const uint8_t, tcp_relay_enabled, input);
    if (tcp_relay_enabled >= (UINT8_MAX / 2)) {
        tox_options_set_tcp_port(opts.get(), 33445);
    }

    Tox_Options_Testing tox_options_testing;
    tox_options_testing.operating_system = &node->system;

    Tox_Err_New error_new;
    Tox_Err_New_Testing error_new_testing;
    Tox *tox = tox_new_testing(opts.get(), &error_new, &tox_options_testing, &error_new_testing);

    if (tox == nullptr) {
        // It might fail, because some I/O happens in tox_new, and the fuzzer
        // might do things that make that I/O fail.
        return;
    }

    assert(error_new == TOX_ERR_NEW_OK);
    assert(error_new_testing == TOX_ERR_NEW_TESTING_OK);

    uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

    // These may fail, but that's ok. We ignore their return values.
    tox_bootstrap(tox, "127.0.0.2", 33446, pub_key, nullptr);
    tox_add_tcp_relay(tox, "127.0.0.2", 33446, pub_key, nullptr);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    Ptr<Tox_Iterate_Options> iterate_opts(
        tox_iterate_options_new(nullptr), tox_iterate_options_free);
    tox_iterate_options_set_fail_hard(iterate_opts.get(), true);

    std::size_t input_size = input.size();
    while (!input.empty()) {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events = tox_events_iterate(tox, iterate_opts.get(), &error_iterate);
        assert(tox_events_equal(&null_node->system, events, events));
        tox_dispatch_invoke(dispatch, events, tox);
        tox_events_free(events);

        env.advance_time(200);

        // If no input was consumed, stop.
        if (input_size == input.size()) {
            break;
        }

        input_size = input.size();
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, std::size_t size)
{
    Fuzz_Data input{data, size};
    TestBootstrap(input);
    return 0;  // Non-zero return values are reserved for future use.
}
