#include "TCP_common.h"

#include <gtest/gtest.h>

#include <cstddef>

#include "logger.h"
#include "os_memory.h"
#include "os_random.h"

namespace {

TEST(TCP_common, PriorityQueueOrderingAndIntegrity)
{
    constexpr Network_Funcs mock_funcs = {
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        // Mock net_send to simulate a full buffer (returns 0)
        // This forces packets into the priority queue.
        [](void *obj, Socket sock, const uint8_t *buf, std::size_t len) {
            (void)obj;
            (void)sock;
            (void)buf;
            (void)len;
            return 0;
        },
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
    };

    TCP_Connection con;
    memset(&con, 0, sizeof(con));
    con.mem = os_memory();
    con.rng = os_random();
    Network ns = {&mock_funcs, nullptr};
    con.ns = &ns;

    Logger *logger = logger_new(con.mem);
    ASSERT_NE(logger, nullptr);

    // Minimal initialization to make write_packet_tcp_secure_connection happy
    // It calls encrypt_data_symmetric which needs shared_key and sent_nonce
    memset(con.shared_key, 0x42, sizeof(con.shared_key));
    memset(con.sent_nonce, 0x12, sizeof(con.sent_nonce));

    uint8_t data1[] = "packet1";
    uint8_t data2[] = "packet2";
    uint8_t data3[] = "packet3";

    // First packet: will fail net_send (mocked to 0) and go to add_priority
    // Queue: [packet1]
    int ret1 = write_packet_tcp_secure_connection(logger, &con, data1, sizeof(data1), true);
    ASSERT_EQ(ret1, 1);
    ASSERT_NE(con.priority_queue_start, nullptr);
    ASSERT_EQ(con.priority_queue_start, con.priority_queue_end);

    // Second packet: will go to add_priority
    // Queue: [packet1] -> [packet2]
    int ret2 = write_packet_tcp_secure_connection(logger, &con, data2, sizeof(data2), true);
    ASSERT_EQ(ret2, 1);
    ASSERT_NE(con.priority_queue_start->next, nullptr);
    ASSERT_EQ(con.priority_queue_start->next, con.priority_queue_end);

    // Third packet: will go to add_priority
    // WITH BUG: Queue becomes [packet1] -> [packet3], packet2 is LOST
    // WITHOUT BUG: Queue: [packet1] -> [packet2] -> [packet3]
    int ret3 = write_packet_tcp_secure_connection(logger, &con, data3, sizeof(data3), true);
    ASSERT_EQ(ret3, 1);

    // Verify integrity
    TCP_Priority_List *p = con.priority_queue_start;
    int count = 0;
    while (p) {
        count++;
        p = p->next;
    }

    // This is where it will fail if the change in
    // https://github.com/TokTok/c-toxcore/pull/2387 is applied.
    // The count will be 2 instead of 3.
    EXPECT_EQ(count, 3)
        << "Priority queue lost packets! (likely due to incorrect tail pointer usage)";

    // Clean up
    wipe_priority_list(con.mem, con.priority_queue_start);
    logger_kill(logger);
}

}
