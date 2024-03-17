#include <cassert>
#include <cstdio>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "fuzz_support.hh"
#include "fuzz_tox.hh"

namespace {

constexpr bool PROTODUMP_DEBUG = Fuzz_Data::DEBUG;

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
            Tox *tox = static_cast<Tox *>(user_data);
            // OK: friend came online.
            const uint32_t friend_number
                = tox_event_friend_connection_status_get_friend_number(event);
            assert(friend_number == 0);
            const uint8_t message = 'A';
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &message, 1, &err);
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
            Tox *tox = static_cast<Tox *>(user_data);
            const uint32_t friend_number = tox_event_friend_message_get_friend_number(event);
            assert(friend_number == 0);
            const uint32_t message_length = tox_event_friend_message_get_message_length(event);
            assert(message_length == 1);
            const uint8_t *message = tox_event_friend_message_get_message(event);
            const uint8_t reply = message[0] + 1;
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &reply, 1, &err);
            assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
        });
    tox_events_callback_friend_name(
        dispatch, [](const Tox_Event_Friend_Name *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_name_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_read_receipt_get_friend_number(event);
            assert(friend_number == 0);
            const uint32_t message_id = tox_event_friend_read_receipt_get_message_id(event);
            uint32_t *done = static_cast<uint32_t *>(user_data);
            *done = std::max(*done, message_id);
        });
    tox_events_callback_friend_request(
        dispatch, [](const Tox_Event_Friend_Request *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
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
        dispatch, [](const Tox_Event_Self_Connection_Status *event, void *user_data) {
            // OK: we got connected.
        });
}

void TestEndToEnd(Fuzz_Data &input)
{
    /**
     * Whether to abort the program if a friend connection can be established.
     *
     * This is useful to make the fuzzer produce minimal startup data so the
     * interesting part of the fuzzer (the part that comes after the friend
     * connection is established) can run sooner and thus more frequently.
     */
    const bool PROTODUMP_REDUCE = getenv("PROTODUMP_REDUCE") != nullptr;

    Fuzz_System sys(input);

    Ptr<Tox_Options> opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);
    tox_options_set_local_discovery_enabled(opts.get(), false);

    Tox_Options_Testing tox_options_testing;
    tox_options_testing.operating_system = sys.sys.get();

    tox_options_set_log_callback(opts.get(),
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            // Log to stdout.
            if (PROTODUMP_DEBUG) {
                std::printf("[tox1] %c %s:%d(%s): %s\n", tox_log_level_name(level), file, line,
                    func, message);
            }
        });

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

    tox_events_init(tox);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    while (!input.empty()) {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events = tox_events_iterate(tox, true, &error_iterate);
        tox_events_equal(tox_get_system(tox), events, events);  // TODO(iphydf): assert?
        tox_dispatch_invoke(dispatch, events, tox);
        tox_events_free(events);
        const uint8_t clock_increment = random_u08(sys.rng.get());
        if (PROTODUMP_DEBUG) {
            printf("clock increment: %d\n", clock_increment);
        }
        sys.clock += std::max(System::MIN_ITERATION_INTERVAL, clock_increment);
    }

    if (PROTODUMP_REDUCE) {
        assert(tox_friend_get_connection_status(tox, 0, nullptr) != 2);
    } else {
        printf("friend: %d\n", tox_friend_get_connection_status(tox, 0, nullptr));
        printf("self: %d\n", tox_self_get_connection_status(tox));
        assert(tox_friend_get_connection_status(tox, 0, nullptr) == 2);
        assert(input.empty());
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Fuzz_Data input{data, size};
    TestEndToEnd(input);
    return 0;  // Non-zero return values are reserved for future use.
}
