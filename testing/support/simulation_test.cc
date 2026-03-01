#include "public/simulation.hh"

#include <gtest/gtest.h>

namespace tox::test {

TEST(LogFilterTest, Operators)
{
    LogMetadata md1{TOX_LOG_LEVEL_INFO, "file1.c", 10, "func1", "message1", 1};
    LogMetadata md2{TOX_LOG_LEVEL_DEBUG, "file2.c", 20, "func2", "message2", 2};

    auto f1 = log_filter::file("file1");
    auto f2 = log_filter::level(TOX_LOG_LEVEL_INFO);

    EXPECT_TRUE(f1(md1));
    EXPECT_FALSE(f1(md2));

    EXPECT_TRUE(f2(md1));
    EXPECT_FALSE(f2(md2));

    auto f_and = f1 && f2;
    EXPECT_TRUE(f_and(md1));
    EXPECT_FALSE(f_and(md2));

    auto f_or = f1 || log_filter::file("file2");
    EXPECT_TRUE(f_or(md1));
    EXPECT_TRUE(f_or(md2));

    auto f_not = !f1;
    EXPECT_FALSE(f_not(md1));
    EXPECT_TRUE(f_not(md2));
}

TEST(LogFilterTest, LevelComparison)
{
    LogMetadata md_trace{TOX_LOG_LEVEL_TRACE, "file.c", 1, "func", "msg", 1};
    LogMetadata md_debug{TOX_LOG_LEVEL_DEBUG, "file.c", 1, "func", "msg", 1};
    LogMetadata md_info{TOX_LOG_LEVEL_INFO, "file.c", 1, "func", "msg", 1};
    LogMetadata md_warn{TOX_LOG_LEVEL_WARNING, "file.c", 1, "func", "msg", 1};
    LogMetadata md_error{TOX_LOG_LEVEL_ERROR, "file.c", 1, "func", "msg", 1};

    // level() > DEBUG
    auto f_gt = log_filter::level() > TOX_LOG_LEVEL_DEBUG;
    EXPECT_FALSE(f_gt(md_trace));
    EXPECT_FALSE(f_gt(md_debug));
    EXPECT_TRUE(f_gt(md_info));
    EXPECT_TRUE(f_gt(md_error));

    // level() < INFO
    auto f_lt = log_filter::level() < TOX_LOG_LEVEL_INFO;
    EXPECT_TRUE(f_lt(md_trace));
    EXPECT_TRUE(f_lt(md_debug));
    EXPECT_FALSE(f_lt(md_info));
    EXPECT_FALSE(f_lt(md_error));

    // level() == WARNING
    auto f_eq = log_filter::level() == TOX_LOG_LEVEL_WARNING;
    EXPECT_FALSE(f_eq(md_info));
    EXPECT_TRUE(f_eq(md_warn));
    EXPECT_FALSE(f_eq(md_error));
}

TEST(LogFilterTest, SimulationIntegration)
{
    Simulation sim{0};
    sim.net().set_verbose(true);

    sim.set_log_filter(log_filter::level(TOX_LOG_LEVEL_ERROR) && log_filter::node(1));

    auto node = sim.create_node();
    auto tox = node->create_tox();

    SUCCEED();
}

}  // namespace tox::test
