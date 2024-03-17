#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <fstream>
#include <vector>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "fuzz_support.hh"
#include "fuzz_tox.hh"

namespace {

void setup_callbacks(Tox_Dispatch *dispatch)
{
    tox_events_callback_conference_connected(
        dispatch, [](const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_connected(
        dispatch, [](const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event != nullptr);
        });
    tox_events_callback_conference_invite(
        dispatch, [](const Tox_Event_Conference_Invite *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            const uint32_t friend_number = tox_event_conference_invite_get_friend_number(event);
            const uint8_t *cookie = tox_event_conference_invite_get_cookie(event);
            const uint32_t cookie_length = tox_event_conference_invite_get_cookie_length(event);
            tox_conference_join(tox, friend_number, cookie, cookie_length, nullptr);
        });
    tox_events_callback_conference_message(
        dispatch, [](const Tox_Event_Conference_Message *event, void *user_data) {
            assert(event != nullptr);
        });
    tox_events_callback_conference_peer_list_changed(
        dispatch, [](const Tox_Event_Conference_Peer_List_Changed *event, void *user_data) {
            assert(event != nullptr);
        });
    tox_events_callback_conference_peer_name(
        dispatch, [](const Tox_Event_Conference_Peer_Name *event, void *user_data) {
            assert(event != nullptr);
        });
    tox_events_callback_conference_title(dispatch,
        [](const Tox_Event_Conference_Title *event, void *user_data) { assert(event != nullptr); });
    tox_events_callback_file_chunk_request(
        dispatch, [](const Tox_Event_File_Chunk_Request *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv(dispatch, [](const Tox_Event_File_Recv *event, void *user_data) {
        Tox *tox = static_cast<Tox *>(user_data);
        const uint32_t friend_number = tox_event_file_recv_get_friend_number(event);
        const uint32_t file_number = tox_event_file_recv_get_file_number(event);
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, nullptr);
    });
    tox_events_callback_file_recv_chunk(dispatch,
        [](const Tox_Event_File_Recv_Chunk *event, void *user_data) { assert(event != nullptr); });
    tox_events_callback_file_recv_control(
        dispatch, [](const Tox_Event_File_Recv_Control *event, void *user_data) {
            assert(event != nullptr);
        });
    tox_events_callback_friend_connection_status(
        dispatch, [](const Tox_Event_Friend_Connection_Status *event, void *user_data) {
            // OK: friend came online.
            const uint32_t friend_number
                = tox_event_friend_connection_status_get_friend_number(event);
            assert(friend_number != UINT32_MAX);
        });
    tox_events_callback_friend_lossless_packet(
        dispatch, [](const Tox_Event_Friend_Lossless_Packet *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            const uint32_t friend_number
                = tox_event_friend_lossless_packet_get_friend_number(event);
            const uint32_t data_length = tox_event_friend_lossless_packet_get_data_length(event);
            const uint8_t *data = tox_event_friend_lossless_packet_get_data(event);
            tox_friend_send_lossless_packet(tox, friend_number, data, data_length, nullptr);
        });
    tox_events_callback_friend_lossy_packet(
        dispatch, [](const Tox_Event_Friend_Lossy_Packet *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            const uint32_t friend_number = tox_event_friend_lossy_packet_get_friend_number(event);
            const uint32_t data_length = tox_event_friend_lossy_packet_get_data_length(event);
            const uint8_t *data = tox_event_friend_lossy_packet_get_data(event);
            tox_friend_send_lossy_packet(tox, friend_number, data, data_length, nullptr);
        });
    tox_events_callback_friend_message(
        dispatch, [](const Tox_Event_Friend_Message *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            const uint32_t friend_number = tox_event_friend_message_get_friend_number(event);
            const Tox_Message_Type type = tox_event_friend_message_get_type(event);
            const uint32_t message_length = tox_event_friend_message_get_message_length(event);
            const uint8_t *message = tox_event_friend_message_get_message(event);
            tox_friend_send_message(tox, friend_number, type, message, message_length, nullptr);
        });
    tox_events_callback_friend_name(
        dispatch, [](const Tox_Event_Friend_Name *event, void *user_data) {
            // OK: friend name received.
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            // OK: message has been received.
        });
    tox_events_callback_friend_request(
        dispatch, [](const Tox_Event_Friend_Request *event, void *user_data) {
            Tox *tox = static_cast<Tox *>(user_data);
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
        });
    tox_events_callback_friend_status(
        dispatch, [](const Tox_Event_Friend_Status *event, void *user_data) {
            // OK: friend status received.
        });
    tox_events_callback_friend_status_message(
        dispatch, [](const Tox_Event_Friend_Status_Message *event, void *user_data) {
            // OK: friend status message received.
        });
    tox_events_callback_friend_typing(
        dispatch, [](const Tox_Event_Friend_Typing *event, void *user_data) {
            // OK: friend may be typing.
        });
    tox_events_callback_self_connection_status(
        dispatch, [](const Tox_Event_Self_Connection_Status *event, void *user_data) {
            // OK: we got connected.
        });
}

void TestEndToEnd(Fuzz_Data &input)
{
    Fuzz_System sys(input);
    // Used for places where we want all allocations to succeed.
    Null_System null_sys;

    Ptr<Tox_Options> opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);
    tox_options_set_local_discovery_enabled(opts.get(), false);

    tox_options_set_log_callback(opts.get(),
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            // Log to stdout.
            if (Fuzz_Data::DEBUG) {
                std::printf("[tox1] %c %s:%d(%s): %s\n", tox_log_level_name(level), file, line,
                    func, message);
            }
        });

    Tox_Options_Testing tox_options_testing;
    tox_options_testing.operating_system = sys.sys.get();

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
        assert(tox_events_equal(null_sys.sys.get(), events, events));
        tox_dispatch_invoke(dispatch, events, tox);
        tox_events_free(events);
        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        sys.clock += std::max(System::MIN_ITERATION_INTERVAL, random_u08(sys.rng.get()));
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox);
}

const std::vector<uint8_t> startup_data = [] {
    constexpr char startup_file[] = "tools/toktok-fuzzer/init/e2e_fuzz_test.dat";

    struct stat statbuf;
    const int res = stat(startup_file, &statbuf);
    assert(res == 0);
    const int fd = open(startup_file, O_RDONLY);
    assert(fd > 0);

    std::vector<uint8_t> data(statbuf.st_size);

    const ssize_t read_count = read(fd, data.data(), data.size());
    assert(read_count > 0 && read_count == statbuf.st_size);
    return data;
}();

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<uint8_t> full_data(startup_data.size() + size);
    std::copy(startup_data.begin(), startup_data.end(), full_data.begin());
    std::copy(data, data + size, full_data.begin() + startup_data.size());

    Fuzz_Data input{full_data.data(), full_data.size()};
    TestEndToEnd(input);
    return 0;  // Non-zero return values are reserved for future use.
}
