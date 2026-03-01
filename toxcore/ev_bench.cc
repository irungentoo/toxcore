/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include <benchmark/benchmark.h>

#include <cstddef>
#include <cstdlib>
#include <vector>

#include "ev_test_util.hh"
#include "logger.h"
#include "net.h"
#include "os_event.h"
#include "os_memory.h"
#include "os_network.h"

namespace {

class EvBenchFixture : public benchmark::Fixture {
public:
    void SetUp(const ::benchmark::State &state) override
    {
        if (os_network() == nullptr) {
            setup_error = "os_network failed";
            return;
        }
        mem = os_memory();
        log = logger_new(mem);
        // We don't want log output during benchmark
        ev = os_event_new(mem, log);
    }

    void TearDown(const ::benchmark::State &state) override
    {
        for (std::size_t i = 0; i < sockets_r.size(); ++i) {
            close_pair(sockets_r[i], sockets_w[i]);
        }
        sockets_r.clear();
        sockets_w.clear();
        ev_kill(ev);
        logger_kill(log);
    }

    const Memory *mem = nullptr;
    Logger *log = nullptr;
    Ev *ev = nullptr;
    std::vector<Socket> sockets_r;
    std::vector<Socket> sockets_w;
    int tag = 1;
    std::string setup_error;
};

// Specialized SetUp to handle socket creation based on range
class EvBenchSocketsFixture : public EvBenchFixture {
public:
    void SetUp(const ::benchmark::State &state) override
    {
        EvBenchFixture::SetUp(state);
        if (!setup_error.empty()) {
            return;
        }
        const int num_sockets = state.range(0);

        for (int i = 0; i < num_sockets; ++i) {
            Socket r{}, w{};
            if (create_pair(&r, &w) != 0) {
                setup_error = "Failed to create socket pair";
                return;
            }
            sockets_r.push_back(r);
            sockets_w.push_back(w);
            if (!ev_add(ev, r, EV_READ, &tag)) {
                setup_error = "Failed to add socket to event loop";
                return;
            }
        }
    }
};

BENCHMARK_DEFINE_F(EvBenchSocketsFixture, EventLoopRun)(benchmark::State &state)
{
    if (!setup_error.empty()) {
        state.SkipWithError(setup_error.c_str());
        return;
    }
    // Sockets are already created in SetUp.

    Ev_Result results[1];
    char buf = 'x';

    // We trigger the last socket
    if (write_socket(sockets_w.back(), &buf, 1) != 1) {
        state.SkipWithError("Failed to write to socket");
        return;
    }

    for (auto _ : state) {
        int32_t n = ev_run(ev, results, 1, 100);
        if (n != 1) {
            state.SkipWithError("ev_run did not return event");
            break;
        }
    }
}

BENCHMARK_REGISTER_F(EvBenchSocketsFixture, EventLoopRun)->Range(8, 1024);

BENCHMARK_DEFINE_F(EvBenchSocketsFixture, EventLoopMultipleActive)(benchmark::State &state)
{
    if (!setup_error.empty()) {
        state.SkipWithError(setup_error.c_str());
        return;
    }

    const int num_sockets = state.range(0);
    const int num_active = state.range(1);

    if (num_active > num_sockets) {
        state.SkipWithError("Active sockets cannot exceed total sockets");
        return;
    }

    char buf = 'x';
    // Trigger 'num_active' sockets
    for (int i = 0; i < num_active; ++i) {
        if (write_socket(sockets_w[i], &buf, 1) != 1) {
            state.SkipWithError("Failed to write socket");
            return;
        }
    }

    std::vector<Ev_Result> results(num_active);

    for (auto _ : state) {
        int32_t n = ev_run(ev, results.data(), num_active, 100);
        if (n != num_active) {
            state.SkipWithError("ev_run did not return expected number of events");
            break;
        }
    }
}

// Fix N=1024, vary M
BENCHMARK_REGISTER_F(EvBenchSocketsFixture, EventLoopMultipleActive)
    ->Args({1024, 1})
    ->Args({1024, 10})
    ->Args({1024, 100})
    ->Args({1024, 1024});

}  // namespace

BENCHMARK_MAIN();
