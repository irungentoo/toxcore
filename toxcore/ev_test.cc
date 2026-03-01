/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "ev.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <vector>

#include "ev_test_util.hh"
#include "logger.h"
#include "net.h"
#include "os_event.h"
#include "os_memory.h"
#include "os_network.h"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace {

class EvTest : public ::testing::Test {
    static void logger_cb_stderr(void *context, Logger_Level level, const char *file, uint32_t line,
        const char *func, const char *message, void *userdata)
    {
        fprintf(stderr, "[%d] %s:%u: %s: %s\n", level, file, line, func, message);
    }

protected:
    void SetUp() override
    {
        ASSERT_NE(os_network(), nullptr);  // WSAStartup
        mem = os_memory();
        log = logger_new(mem);
        logger_callback_log(log, logger_cb_stderr, nullptr, nullptr);
        ev = os_event_new(mem, log);
        ASSERT_NE(ev, nullptr);
    }

    void TearDown() override
    {
        ev_kill(ev);
        logger_kill(log);
    }

    const Memory *mem;
    Logger *log;
    Ev *ev;
    int tag1;
    int tag2;
    int tag3;
    int tag4;
};

TEST_F(EvTest, Lifecycle)
{
    // Already covered by SetUp/TearDown
}

TEST_F(EvTest, AddDel)
{
    Socket s1{}, s2{};
    ASSERT_EQ(create_pair(&s1, &s2), 0);

    EXPECT_TRUE(ev_add(ev, s1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, s2, EV_WRITE, &tag2));

    // Adding same socket again should fail
    EXPECT_FALSE(ev_add(ev, s1, EV_READ, &tag3));

    EXPECT_TRUE(ev_del(ev, s1));
    EXPECT_TRUE(ev_del(ev, s2));

    // Deleting non-existent socket should fail
    EXPECT_FALSE(ev_del(ev, s1));

    close_pair(s1, s2);
}

TEST_F(EvTest, RunPipe)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag4));

    Ev_Result results[1];
    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, results, 1, 0), 0);

    // Write something to the pipe/socket
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    // Should now be readable
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    EXPECT_EQ(results[0].events, EV_READ);
    EXPECT_EQ(results[0].data, &tag4);

    close_pair(rs, ws);
}

TEST_F(EvTest, WriteEvent)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    // Register write end for EV_WRITE
    EXPECT_TRUE(ev_add(ev, ws, EV_WRITE, &tag1));

    Ev_Result results[1];
    // Should be immediately writable
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(ws));
    EXPECT_EQ(results[0].events, EV_WRITE);
    EXPECT_EQ(results[0].data, &tag1);

    close_pair(rs, ws);
}

TEST_F(EvTest, Mod)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag1));
    EXPECT_TRUE(ev_mod(ev, rs, EV_READ, &tag2));

    // Write something to the pipe/socket to make it readable
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    EXPECT_EQ(results[0].events, EV_READ);
    EXPECT_EQ(results[0].data, &tag2);

    close_pair(rs, ws);
}

TEST_F(EvTest, MultipleEvents)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    EXPECT_TRUE(ev_add(ev, rs1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, rs2, EV_READ, &tag2));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    Ev_Result results[2];
    int32_t n = ev_run(ev, results, 2, 100);
    EXPECT_EQ(n, 2);

    bool found1 = false;
    bool found2 = false;
    for (int i = 0; i < 2; ++i) {
        if (results[i].data == &tag1)
            found1 = true;
        if (results[i].data == &tag2)
            found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);

    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, MaxResults)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    EXPECT_TRUE(ev_add(ev, rs1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, rs2, EV_READ, &tag2));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);

    // The second event should still be there for the next run
    n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);

    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, EmptyLoop)
{
    Ev_Result results[1];
    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, results, 1, 10), 0);
}

TEST_F(EvTest, ZeroMaxResults)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);
    EXPECT_TRUE(ev_add(ev, rs, EV_READ, nullptr));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 0, 100);
    EXPECT_LE(n, 0);

    close_pair(rs, ws);
}

TEST_F(EvTest, ErrorEvent)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag1));

    // Close the write end to potentially trigger something on the read end
    close_socket(ws);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    // On Linux, closing the write end of a pipe makes the read end readable (EOF).
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));

    close_socket(rs);
}

TEST_F(EvTest, ReallocPointers)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    // Add first socket. This will be at index 0.
    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag1));

    // Add enough sockets to force realloc of regs array.
    // Initial capacity is 0, then 8.
    // We need > 8 sockets. Let's add 20 more.
    std::vector<Socket> extra_sockets_r;
    std::vector<Socket> extra_sockets_w;

    for (int i = 0; i < 20; ++i) {
        Socket r{}, w{};
        ASSERT_EQ(create_pair(&r, &w), 0);
        extra_sockets_r.push_back(r);
        extra_sockets_w.push_back(w);
        EXPECT_TRUE(ev_add(ev, r, EV_READ, nullptr));
    }

    // Now write to the first socket to trigger event.
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);

    // Check if we got the correct data back
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    EXPECT_EQ(results[0].data, &tag1);

    // Cleanup
    close_pair(rs, ws);
    for (std::size_t i = 0; i < extra_sockets_r.size(); ++i) {
        close_pair(extra_sockets_r[i], extra_sockets_w[i]);
    }
}

#ifdef EV_USE_EPOLL
TEST(EvManualTest, ExhaustFds)
{
    ASSERT_NE(os_network(), nullptr);
    const Memory *mem = os_memory();
    Logger *log = logger_new(mem);

    // Consume all file descriptors
    std::vector<int> fds;
    while (true) {
        int fd = dup(0);
        if (fd < 0) {
            break;
        }
        fds.push_back(fd);
    }

    // New event loop creation should fail gracefully
    Ev *ev = os_event_new(mem, log);
    EXPECT_EQ(ev, nullptr);

    // Release one FD and try again (epoll_create needs 1 FD)
    if (!fds.empty()) {
        close(fds.back());
        fds.pop_back();

        ev = os_event_new(mem, log);
        EXPECT_NE(ev, nullptr);
        ev_kill(ev);
    }

    // Cleanup
    for (int fd : fds) {
        close(fd);
    }
    logger_kill(log);
}
#endif  // EV_USE_EPOLL

}  // namespace
