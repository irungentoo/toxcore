#include "group_jitter_buffer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <vector>

#include "../toxcore/attributes.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/os_memory.h"

namespace {

std::uint64_t fixed_time_cb(void *_Nullable user_data)
{
    return *static_cast<std::uint64_t *>(user_data);
}

Group_Audio_Packet *_Nullable new_packet(std::uint16_t sequnum)
{
    auto *pk = static_cast<Group_Audio_Packet *>(std::calloc(1, sizeof(Group_Audio_Packet)));
    if (pk == nullptr) {
        return nullptr;
    }
    pk->sequnum = sequnum;
    pk->data = static_cast<std::uint8_t *>(std::calloc(1, 1));
    if (pk->data == nullptr) {
        std::free(pk);
        return nullptr;
    }
    return pk;
}

TEST(GroupJitterBuffer, DeliversPacketsInOrderAcrossSequenceWrap)
{
    const Memory *mem = os_memory();
    std::uint64_t now = 1000000;
    Mono_Time *mono_time = mono_time_new(mem, fixed_time_cb, &now);
    ASSERT_NE(mono_time, nullptr);
    mono_time_update(mono_time);
    Group_JitterBuffer *q = group_jbuf_new(6);
    ASSERT_NE(q, nullptr);

    // Packet 65535 is lost, so the buffer waits for it while the sequence
    // number wraps around.
    std::vector<std::uint16_t> sent = {65530, 65531, 65532, 65533, 65534};
    for (std::uint16_t sequnum = 0; sequnum < 10; ++sequnum) {
        sent.push_back(sequnum);
    }

    std::vector<std::uint16_t> received;
    for (const std::uint16_t sequnum : sent) {
        Group_Audio_Packet *pk = new_packet(sequnum);
        ASSERT_NE(pk, nullptr);
        if (group_jbuf_write(q, mono_time, pk) == -1) {
            group_audio_packet_free(pk);
        }

        int success = 0;
        do {
            Group_Audio_Packet *out = group_jbuf_read(q, &success);
            if (out != nullptr) {
                received.push_back(out->sequnum);
                group_audio_packet_free(out);
            }
        } while (success != 0);
    }

    EXPECT_EQ(received, sent);

    group_jbuf_kill(q);
    mono_time_free(mem, mono_time);
}

}  // namespace
