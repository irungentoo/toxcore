#include "DHT_test_util.hh"

#include <cassert>
#include <cstring>
#include <iomanip>
#include <ostream>

#include "../testing/support/public/simulated_environment.hh"
#include "DHT.h"
#include "crypto_core.h"
#include "crypto_core_test_util.hh"
#include "network.h"
#include "network_test_util.hh"

using tox::test::FakeClock;

// --- Mock DHT Implementation ---

MockDHT::MockDHT(const Random *_Nonnull rng)
{
    crypto_new_keypair(rng, self_public_key, self_secret_key);
}

const std::uint8_t *_Nullable MockDHT::get_shared_key(const std::uint8_t *_Nonnull pk)
{
    std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE> pk_arr;
    std::copy(pk, pk + CRYPTO_PUBLIC_KEY_SIZE, pk_arr.begin());
    auto it = shared_keys.find(pk_arr);
    if (it != shared_keys.end()) {
        return it->second.data();
    }

    ++computation_count;

    // Compute new shared key
    std::array<std::uint8_t, CRYPTO_SHARED_KEY_SIZE> sk;
    encrypt_precompute(pk, self_secret_key, sk.data());
    shared_keys[pk_arr] = sk;
    return shared_keys[pk_arr].data();
}

const Net_Crypto_DHT_Funcs MockDHT::funcs = {
    [](void *_Nonnull obj, const std::uint8_t *_Nonnull public_key) {
        return static_cast<MockDHT *>(obj)->get_shared_key(public_key);
    },
    [](const void *_Nonnull obj) { return static_cast<const MockDHT *>(obj)->self_public_key; },
    [](const void *_Nonnull obj) { return static_cast<const MockDHT *>(obj)->self_secret_key; },
};

// --- WrappedMockDHT Implementation ---

WrappedMockDHT::WrappedMockDHT(tox::test::SimulatedEnvironment &env, std::uint16_t port)
    : node_(env.create_node(0))
    , logger_(logger_new(&node_->c_memory), [](Logger *l) { logger_kill(l); })
    , mono_time_(mono_time_new(
                     &node_->c_memory,
                     [](void *_Nullable ud) -> std::uint64_t {
                         return static_cast<tox::test::FakeClock *>(ud)->current_time_ms();
                     },
                     &env.fake_clock()),
          [mem = &node_->c_memory](Mono_Time *t) { mono_time_free(mem, t); })
    , networking_(nullptr, [](Networking_Core *n) { kill_networking(n); })
    , dht_(&node_->c_random)
{
    // Setup Networking
    IP ip;
    ip_init(&ip, false);
    unsigned int error = 0;
    networking_.reset(new_networking_ex(
        logger_.get(), &node_->c_memory, &node_->c_network, &ip, port, port + 1, &error));
    assert(error == 0);

    node_->endpoint = node_->node->get_primary_socket();
    assert(node_->endpoint != nullptr);
    assert(node_->endpoint->local_port() == port);
}

WrappedMockDHT::~WrappedMockDHT() = default;

IP_Port WrappedMockDHT::get_ip_port() const
{
    IP_Port ip_port;
    ip_port.ip = node_->node->ip;
    ip_port.port = net_htons(node_->endpoint->local_port());
    return ip_port;
}

void WrappedMockDHT::poll()
{
    mono_time_update(mono_time_.get());
    networking_poll(networking_.get(), nullptr);
}

const Net_Crypto_DHT_Funcs WrappedMockDHT::funcs = MockDHT::funcs;

// --- WrappedDHT Implementation ---

WrappedDHT::WrappedDHT(tox::test::SimulatedEnvironment &env, std::uint16_t port)
    : node_(env.create_node(0))
    , logger_(logger_new(&node_->c_memory), [](Logger *l) { logger_kill(l); })
    , mono_time_(mono_time_new(
                     &node_->c_memory,
                     [](void *_Nullable ud) -> std::uint64_t {
                         return static_cast<FakeClock *>(ud)->current_time_ms();
                     },
                     &env.fake_clock()),
          [mem = &node_->c_memory](Mono_Time *t) { mono_time_free(mem, t); })
    , networking_(nullptr, [](Networking_Core *n) { kill_networking(n); })
    , dht_(nullptr, [](DHT *d) { kill_dht(d); })
{
    // Setup Networking
    IP ip;
    ip_init(&ip, false);
    unsigned int error = 0;
    networking_.reset(new_networking_ex(
        logger_.get(), &node_->c_memory, &node_->c_network, &ip, port, port + 1, &error));
    assert(error == 0);

    node_->endpoint = node_->node->get_primary_socket();
    assert(node_->endpoint != nullptr);
    assert(node_->endpoint->local_port() == port);

    // Setup DHT
    dht_.reset(new_dht(logger_.get(), &node_->c_memory, &node_->c_random, &node_->c_network,
        mono_time_.get(), networking_.get(), true, true));
}

WrappedDHT::~WrappedDHT() = default;

const std::uint8_t *WrappedDHT::dht_public_key() const
{
    return dht_get_self_public_key(dht_.get());
}

const std::uint8_t *WrappedDHT::dht_secret_key() const
{
    return dht_get_self_secret_key(dht_.get());
}

IP_Port WrappedDHT::get_ip_port() const
{
    IP_Port ip_port;
    ip_port.ip = node_->node->ip;
    ip_port.port = net_htons(node_->endpoint->local_port());
    return ip_port;
}

void WrappedDHT::poll()
{
    mono_time_update(mono_time_.get());
    networking_poll(networking_.get(), nullptr);
    do_dht(dht_.get());
}

const Net_Crypto_DHT_Funcs WrappedDHT::funcs = {
    [](void *_Nonnull obj, const std::uint8_t *_Nonnull public_key) {
        return dht_get_shared_key_sent(static_cast<DHT *>(obj), public_key);
    },
    [](const void *_Nonnull obj) { return dht_get_self_public_key(static_cast<const DHT *>(obj)); },
    [](const void *_Nonnull obj) { return dht_get_self_secret_key(static_cast<const DHT *>(obj)); },
};

// --- Test Util Functions ---

Node_format random_node_format(const Random *_Nonnull rng)
{
    Node_format node;
    auto const pk = random_pk(rng);
    std::copy(pk.begin(), pk.end(), node.public_key);
    node.ip_port = random_ip_port(rng);
    return node;
}

bool operator==(Node_format const &a, Node_format const &b)
{
    return std::memcmp(a.public_key, b.public_key, sizeof(a.public_key)) == 0
        && a.ip_port == b.ip_port;
}

std::ostream &operator<<(std::ostream &out, Node_format const &v)
{
    return out << "\n    Node_format{\n"
               << "      public_key = " << PublicKey(v.public_key) << ",\n"
               << "      ip_port = " << v.ip_port << " }";
}
