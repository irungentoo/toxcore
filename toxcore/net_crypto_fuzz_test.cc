#include "net_crypto.h"

#include <cassert>
#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>

#include "../testing/support/public/fuzz_data.hh"
#include "../testing/support/public/fuzz_helpers.hh"
#include "../testing/support/public/simulated_environment.hh"
#include "DHT.h"
#include "TCP_client.h"
#include "attributes.h"
#include "net_profile.h"
#include "network.h"

namespace {

using tox::test::configure_fuzz_memory_source;
using tox::test::FakeClock;
using tox::test::Fuzz_Data;
using tox::test::SimulatedEnvironment;

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T *)>;

std::optional<std::tuple<IP_Port, std::uint8_t>> prepare(Fuzz_Data &input)
{
    IP_Port ipp;
    ip_init(&ipp.ip, true);
    ipp.port = net_htons(33445);

    CONSUME_OR_RETURN_VAL(const std::uint8_t *iterations_packed, input, 1, std::nullopt);
    std::uint8_t iterations = *iterations_packed;

    return {{ipp, iterations}};
}

static constexpr Net_Crypto_DHT_Funcs dht_funcs = {
    [](void *_Nonnull dht, const std::uint8_t *_Nonnull public_key) {
        return dht_get_shared_key_sent(static_cast<DHT *>(dht), public_key);
    },
    [](const void *_Nonnull dht) { return dht_get_self_public_key(static_cast<const DHT *>(dht)); },
    [](const void *_Nonnull dht) { return dht_get_self_secret_key(static_cast<const DHT *>(dht)); },
};

void TestNetCrypto(Fuzz_Data &input)
{
    const auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    const auto [ipp, iterations] = prep.value();

    SimulatedEnvironment env{12345};
    env.fake_clock().advance(1000000000);  // Start clock high to match legacy behavior
    auto node = env.create_node(ipp.port);
    configure_fuzz_memory_source(env.fake_memory(), input);

    const Ptr<Logger> logger(logger_new(&node->c_memory), logger_kill);
    if (logger == nullptr) {
        return;
    }

    const Ptr<Networking_Core> net(
        new_networking_ex(logger.get(), &node->c_memory, &node->c_network, &ipp.ip, ipp.port,
            ipp.port + 100, nullptr),
        kill_networking);
    if (net == nullptr) {
        return;
    }

    const std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time(
        mono_time_new(
            &node->c_memory,
            [](void *_Nullable user_data) {
                return static_cast<FakeClock *>(user_data)->current_time_ms();
            },
            &env.fake_clock()),
        [&node](Mono_Time *ptr) { mono_time_free(&node->c_memory, ptr); });

    if (mono_time == nullptr) {
        return;
    }

    const Ptr<DHT> dht(new_dht(logger.get(), &node->c_memory, &node->c_random, &node->c_network,
                           mono_time.get(), net.get(), false, false),
        kill_dht);
    if (dht == nullptr) {
        return;
    }

    Net_Profile *tcp_np = netprof_new(logger.get(), &node->c_memory);

    if (tcp_np == nullptr) {
        return;
    }

    const TCP_Proxy_Info proxy_info = {0};

    const Ptr<Net_Crypto> net_crypto(
        new_net_crypto(logger.get(), &node->c_memory, &node->c_random, &node->c_network,
            mono_time.get(), net.get(), dht.get(), &dht_funcs, &proxy_info, tcp_np),
        kill_net_crypto);
    if (net_crypto == nullptr) {
        netprof_kill(&node->c_memory, tcp_np);
        return;
    }

    for (std::uint8_t i = 0; i < iterations; ++i) {
        networking_poll(net.get(), nullptr);
        do_dht(dht.get());
        do_net_crypto(net_crypto.get(), nullptr);

        env.advance_time(200);
    }

    netprof_kill(&node->c_memory, tcp_np);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    tox::test::fuzz_select_target<TestNetCrypto>(data, size);
    return 0;
}
