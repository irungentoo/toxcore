#include "group_announce.h"

#include <cassert>
#include <functional>
#include <memory>
#include <vector>

#include "../testing/fuzzing/fuzz_support.hh"
#include "mem_test_util.hh"

namespace {

void TestUnpackAnnouncesList(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const uint8_t, max_count, input);
    // Always allocate at least something to avoid passing nullptr to functions below.
    std::vector<GC_Announce> announces(max_count + 1);

    // TODO(iphydf): How do we know the packed size?
    CONSUME1_OR_RETURN(const uint16_t, packed_size, input);

    Logger *logger = logger_new();
    if (gca_unpack_announces_list(logger, input.data(), input.size(), announces.data(), max_count)
        != -1) {
        // Always allocate at least something to avoid passing nullptr to functions below.
        std::vector<uint8_t> packed(packed_size + 1);
        size_t processed;
        gca_pack_announces_list(
            logger, packed.data(), packed_size, announces.data(), max_count, &processed);
    }
    logger_kill(logger);
}

void TestUnpackPublicAnnounce(Fuzz_Data &input)
{
    GC_Public_Announce public_announce;

    // TODO(iphydf): How do we know the packed size?
    CONSUME1_OR_RETURN(const uint16_t, packed_size, input);

    Logger *logger = logger_new();
    if (gca_unpack_public_announce(logger, input.data(), input.size(), &public_announce) != -1) {
        // Always allocate at least something to avoid passing nullptr to functions below.
        std::vector<uint8_t> packed(packed_size + 1);
        gca_pack_public_announce(logger, packed.data(), packed_size, &public_announce);
    }
    logger_kill(logger);
}

void TestDoGca(Fuzz_Data &input)
{
    Test_Memory mem;
    std::unique_ptr<Logger, void (*)(Logger *)> logger(logger_new(), logger_kill);

    uint64_t clock = 1;
    std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time(
        mono_time_new(
            mem, [](void *user_data) { return *static_cast<uint64_t *>(user_data); }, &clock),
        [mem](Mono_Time *ptr) { mono_time_free(mem, ptr); });
    assert(mono_time != nullptr);
    std::unique_ptr<GC_Announces_List, void (*)(GC_Announces_List *)> gca(new_gca_list(), kill_gca);
    assert(gca != nullptr);

    while (!input.empty()) {
        CONSUME1_OR_RETURN(const uint8_t, choice, input);
        switch (choice) {
        case 0: {
            // Add an announce.
            CONSUME1_OR_RETURN(const uint16_t, length, input);
            CONSUME_OR_RETURN(const uint8_t *data, input, length);
            GC_Public_Announce public_announce;
            if (gca_unpack_public_announce(logger.get(), data, length, &public_announce) != -1) {
                gca_add_announce(mono_time.get(), gca.get(), &public_announce);
            }
            break;
        }
        case 1: {
            // Advance the time by a number of tox_iteration_intervals.
            CONSUME1_OR_RETURN(const uint8_t, iterations, input);
            clock += iterations * 20;
            // Do an iteration.
            do_gca(mono_time.get(), gca.get());
            break;
        }
        case 2: {
            // Get announces.
            CONSUME1_OR_RETURN(const uint8_t, max_nodes, input);
            // Always allocate at least something to avoid passing nullptr to functions below.
            std::vector<GC_Announce> gc_announces(max_nodes + 1);
            CONSUME_OR_RETURN(const uint8_t *chat_id, input, CHAT_ID_SIZE);
            CONSUME_OR_RETURN(const uint8_t *except_public_key, input, ENC_PUBLIC_KEY_SIZE);
            gca_get_announces(
                gca.get(), gc_announces.data(), max_nodes, chat_id, except_public_key);
            break;
        }
        case 3: {
            // Remove a chat.
            CONSUME_OR_RETURN(const uint8_t *chat_id, input, CHAT_ID_SIZE);
            cleanup_gca(gca.get(), chat_id);
            break;
        }
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target<TestUnpackAnnouncesList, TestUnpackPublicAnnounce, TestDoGca>(data, size);
    return 0;
}
