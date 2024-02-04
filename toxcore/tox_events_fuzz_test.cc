#include "tox_events.h"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>

#include "../testing/fuzzing/fuzz_support.hh"
#include "tox_dispatch.h"

namespace {

void TestUnpack(Fuzz_Data data)
{
    // 2 bytes: size of the events data
    CONSUME_OR_RETURN(const uint8_t *events_size_bytes, data, sizeof(uint16_t));
    uint16_t events_size;
    std::memcpy(&events_size, events_size_bytes, sizeof(uint16_t));

    // events_size bytes: events data (max 64K)
    CONSUME_OR_RETURN(const uint8_t *events_data, data, events_size);

    if (data.empty()) {
        // If there's no more input, no malloc failure paths can possibly be
        // tested, so we ignore this input.
        return;
    }

    // rest of the fuzz data is input for malloc
    Fuzz_System sys{data};

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);

    auto ignore = [](auto *event, void *user_data) {};
    tox_events_callback_conference_connected(dispatch, ignore);
    tox_events_callback_conference_invite(dispatch, ignore);
    tox_events_callback_conference_message(dispatch, ignore);
    tox_events_callback_conference_peer_list_changed(dispatch, ignore);
    tox_events_callback_conference_peer_name(dispatch, ignore);
    tox_events_callback_conference_title(dispatch, ignore);
    tox_events_callback_file_chunk_request(dispatch, ignore);
    tox_events_callback_file_recv(dispatch, ignore);
    tox_events_callback_file_recv_chunk(dispatch, ignore);
    tox_events_callback_file_recv_control(dispatch, ignore);
    tox_events_callback_friend_connection_status(dispatch, ignore);
    tox_events_callback_friend_lossless_packet(dispatch, ignore);
    tox_events_callback_friend_lossy_packet(dispatch, ignore);
    tox_events_callback_friend_message(dispatch, ignore);
    tox_events_callback_friend_name(dispatch, ignore);
    tox_events_callback_friend_read_receipt(dispatch, ignore);
    tox_events_callback_friend_request(dispatch, ignore);
    tox_events_callback_friend_status(dispatch, ignore);
    tox_events_callback_friend_status_message(dispatch, ignore);
    tox_events_callback_friend_typing(dispatch, ignore);
    tox_events_callback_self_connection_status(dispatch, ignore);
    tox_events_callback_group_peer_name(dispatch, ignore);
    tox_events_callback_group_peer_status(dispatch, ignore);
    tox_events_callback_group_topic(dispatch, ignore);
    tox_events_callback_group_privacy_state(dispatch, ignore);
    tox_events_callback_group_voice_state(dispatch, ignore);
    tox_events_callback_group_topic_lock(dispatch, ignore);
    tox_events_callback_group_peer_limit(dispatch, ignore);
    tox_events_callback_group_password(dispatch, ignore);
    tox_events_callback_group_message(dispatch, ignore);
    tox_events_callback_group_private_message(dispatch, ignore);
    tox_events_callback_group_custom_packet(dispatch, ignore);
    tox_events_callback_group_custom_private_packet(dispatch, ignore);
    tox_events_callback_group_invite(dispatch, ignore);
    tox_events_callback_group_peer_join(dispatch, ignore);
    tox_events_callback_group_peer_exit(dispatch, ignore);
    tox_events_callback_group_self_join(dispatch, ignore);
    tox_events_callback_group_join_fail(dispatch, ignore);
    tox_events_callback_group_moderation(dispatch, ignore);

    Tox_Events *events = tox_events_load(sys.sys.get(), events_data, events_size);
    if (events) {
        std::vector<uint8_t> packed(tox_events_bytes_size(events));
        tox_events_get_bytes(events, packed.data());

        tox_dispatch_invoke(dispatch, events, nullptr);
    }
    tox_events_free(events);
    tox_dispatch_free(dispatch);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TestUnpack(Fuzz_Data(data, size));
    return 0;
}
