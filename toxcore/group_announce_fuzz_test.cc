#include "group_announce.h"

#include <cassert>
#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/simulated_environment.hh"
#include "attributes.h"

namespace {

using tox::test::FakeClock;
using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

void TestUnpackAnnouncesList(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const std::uint8_t, max_count, input);
    // Always allocate at least something to avoid passing nullptr to functions below.
    std::vector<GC_Announce> announces(max_count + 1);

    // TODO(iphydf): How do we know the packed size?
    CONSUME1_OR_RETURN(const std::uint16_t, packed_size, input);

    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Logger *logger = logger_new(&c_mem);
    if (gca_unpack_announces_list(logger, input.data(), input.size(), announces.data(), max_count)
        != -1) {
        // Always allocate at least something to avoid passing nullptr to functions below.
        std::vector<std::uint8_t> packed(packed_size + 1);
        std::size_t processed;
        gca_pack_announces_list(
            logger, packed.data(), packed_size, announces.data(), max_count, &processed);
    }
    logger_kill(logger);
}

void TestUnpackPublicAnnounce(Fuzz_Data &input)
{
    GC_Public_Announce public_announce;

    // TODO(iphydf): How do we know the packed size?
    CONSUME1_OR_RETURN(const std::uint16_t, packed_size, input);

    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    Logger *logger = logger_new(&c_mem);
    if (gca_unpack_public_announce(logger, input.data(), input.size(), &public_announce) != -1) {
        // Always allocate at least something to avoid passing nullptr to functions below.
        std::vector<std::uint8_t> packed(packed_size + 1);
        gca_pack_public_announce(logger, packed.data(), packed_size, &public_announce);
    }
    logger_kill(logger);
}

void TestDoGca(Fuzz_Data &input)
{
    SimulatedEnvironment env{12345};
    auto c_mem = env.fake_memory().c_memory();
    std::unique_ptr<Logger, void (*)(Logger *)> logger(logger_new(&c_mem), logger_kill);

    std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time(
        mono_time_new(
            &c_mem,
            [](void *_Nullable user_data) -> std::uint64_t {
                return static_cast<FakeClock *>(user_data)->current_time_ms();
            },
            &env.fake_clock()),
        [c_mem](Mono_Time *ptr) { mono_time_free(&c_mem, ptr); });
    assert(mono_time != nullptr);

    std::unique_ptr<GC_Announces_List, std::function<void(GC_Announces_List *)>> gca(
        new_gca_list(&c_mem), [](GC_Announces_List *ptr) { kill_gca(ptr); });
    assert(gca != nullptr);

    while (!input.empty()) {
        CONSUME1_OR_RETURN(const std::uint8_t, choice, input);
        switch (choice) {
        case 0: {
            // Add an announce.
            CONSUME1_OR_RETURN(const std::uint16_t, length, input);
            CONSUME_OR_RETURN(const std::uint8_t *data, input, length);
            GC_Public_Announce public_announce;
            if (gca_unpack_public_announce(logger.get(), data, length, &public_announce) != -1) {
                gca_add_announce(&c_mem, mono_time.get(), gca.get(), &public_announce);
            }
            break;
        }
        case 1: {
            // Advance the time by a number of tox_iteration_intervals.
            CONSUME1_OR_RETURN(const std::uint8_t, iterations, input);
            env.fake_clock().advance(iterations * 20);
            // Do an iteration.
            do_gca(mono_time.get(), gca.get());
            break;
        }
        case 2: {
            // Get announces.
            CONSUME1_OR_RETURN(const std::uint8_t, max_nodes, input);
            // Always allocate at least something to avoid passing nullptr to functions below.
            std::vector<GC_Announce> gc_announces(max_nodes + 1);
            CONSUME_OR_RETURN(const std::uint8_t *chat_id, input, CHAT_ID_SIZE);
            CONSUME_OR_RETURN(const std::uint8_t *except_public_key, input, ENC_PUBLIC_KEY_SIZE);
            gca_get_announces(
                gca.get(), gc_announces.data(), max_nodes, chat_id, except_public_key);
            break;
        }
        case 3: {
            // Remove a chat.
            CONSUME_OR_RETURN(const std::uint8_t *chat_id, input, CHAT_ID_SIZE);
            cleanup_gca(gca.get(), chat_id);
            break;
        }
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    tox::test::fuzz_select_target<TestUnpackAnnouncesList, TestUnpackPublicAnnounce, TestDoGca>(
        data, size);
    return 0;
}
