// clang-format off
#include "group_connection.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

#include "group_chats.h"
#include "group_common.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "os_memory.h"
#include "os_random.h"

namespace {

// The send array keeps one slot free to tell a full array from an empty one,
// also when its oldest entry is in the first slot.
TEST(GroupConnection, SendArrayIsFullWhenOldestEntryIsInFirstSlot)
{
    const Memory *mem = os_memory();
    Logger *log = logger_new(mem);
    ASSERT_NE(log, nullptr);
    Mono_Time *mono_time = mono_time_new(mem, nullptr, nullptr);
    ASSERT_NE(mono_time, nullptr);

    auto chat = std::make_unique<GC_Chat>();
    chat->log = log;
    chat->mem = mem;
    chat->rng = os_random();
    chat->mono_time = mono_time;

    GC_Connection gconn{};
    gconn.send_array = static_cast<GC_Message_Array_Entry *>(
        mem_valloc(mem, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
    gconn.recv_array = static_cast<GC_Message_Array_Entry *>(
        mem_valloc(mem, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
    ASSERT_NE(gconn.send_array, nullptr);
    ASSERT_NE(gconn.recv_array, nullptr);
    gcc_set_send_message_id(&gconn, 0);

    const std::uint8_t data[1] = {0};
    for (int i = 0; i < GCC_BUFFER_SIZE - 1; ++i) {
        ASSERT_EQ(
            gcc_send_lossless_packet(chat.get(), &gconn, data, sizeof(data), GP_BROADCAST), 0);
    }
    EXPECT_EQ(gcc_send_lossless_packet(chat.get(), &gconn, data, sizeof(data), GP_BROADCAST), -1);

    gcc_peer_cleanup(mem, &gconn);
    mono_time_free(mem, mono_time);
    logger_kill(log);
}

}  // namespace
