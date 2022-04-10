#include <cassert>
#include <cstring>
#include <memory>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "../../toxcore/tox_struct.h"
#include "../../toxcore/util.h"
#include "fuzz_support.h"

namespace {

void setup_callbacks(Tox_Dispatch *dispatch)
{
    tox_events_callback_conference_connected(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_connected(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_invite(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Invite *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_message(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_list_changed(dispatch,
        [](Tox *tox, const Tox_Event_Conference_Peer_List_Changed *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_name(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Peer_Name *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_title(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Title *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_chunk_request(
        dispatch, [](Tox *tox, const Tox_Event_File_Chunk_Request *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv_chunk(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv_Chunk *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv_control(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv_Control *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_connection_status(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Connection_Status *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossless_packet(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Lossless_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossy_packet(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Lossy_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_name(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Name *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_request(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Request *event, void *user_data) {
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
            assert(err == TOX_ERR_FRIEND_ADD_OK || err == TOX_ERR_FRIEND_ADD_OWN_KEY
                || err == TOX_ERR_FRIEND_ADD_ALREADY_SENT
                || err == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
        });
    tox_events_callback_friend_status(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_status_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_typing(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_self_connection_status(
        dispatch, [](Tox *tox, const Tox_Event_Self_Connection_Status *event, void *user_data) {
            assert(event == nullptr);
        });
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Fuzz_Data input{data, size};

    Fuzz_System sys(input);
    assert(sys.rng != nullptr);

    Tox_Options *opts = tox_options_new(nullptr);
    assert(opts != nullptr);
    tox_options_set_operating_system(opts, sys.sys.get());

    Tox_Err_New error_new;
    Tox *tox = tox_new(opts, &error_new);
    tox_options_free(opts);

    if (tox == nullptr) {
        // It might fail, because some I/O happens in tox_new, and the fuzzer
        // might do things that make that I/O fail.
        return 0;
    }

    assert(error_new == TOX_ERR_NEW_OK);

    uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

    const bool success = tox_bootstrap(tox, "127.0.0.1", 12345, pub_key, nullptr);
    assert(success);

    tox_events_init(tox);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    while (input.size > 0) {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events = tox_events_iterate(tox, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox, nullptr);
        tox_events_free(events);
        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        sys.clock += 200;
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox);
    return 0;  // Non-zero return values are reserved for future use.
}
