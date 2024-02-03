/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#include "fuzz_support.hh"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <memory>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/network.h"
#include "../../toxcore/tox_private.h"
#include "func_conversion.hh"

// TODO(iphydf): Put this somewhere shared.
struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

System::System(std::unique_ptr<Tox_System> in_sys, std::unique_ptr<Memory> in_mem,
    std::unique_ptr<Network> in_ns, std::unique_ptr<Random> in_rng)
    : sys(std::move(in_sys))
    , mem(std::move(in_mem))
    , ns(std::move(in_ns))
    , rng(std::move(in_rng))
{
}
System::System(System &&) = default;

System::~System() { }

static int recv_common(Fuzz_Data &input, uint8_t *buf, size_t buf_len)
{
    if (input.size() < 2) {
        errno = ENOMEM;
        return -1;
    }

    CONSUME_OR_ABORT(const uint8_t *fuzz_len_bytes, input, 2);
    const std::size_t fuzz_len = (fuzz_len_bytes[0] << 8) | fuzz_len_bytes[1];

    if (fuzz_len == 0xffff) {
        errno = EWOULDBLOCK;
        if (Fuzz_Data::DEBUG) {
            std::printf("recvfrom: no data for tox1\n");
        }
        return -1;
    }

    if (Fuzz_Data::DEBUG) {
        std::printf(
            "recvfrom: %zu (%02x, %02x) for tox1\n", fuzz_len, input.data()[-2], input.data()[-1]);
    }
    const size_t res = std::min(buf_len, std::min(fuzz_len, input.size()));

    CONSUME_OR_ABORT(const uint8_t *data, input, res);
    std::copy(data, data + res, buf);

    return res;
}

static void *report_alloc(const char *name, const char *func, std::size_t size, void *ptr)
{
    if (Fuzz_Data::DEBUG) {
        printf("%s: %s(%zu): %s\n", name, func, size, ptr == nullptr ? "false" : "true");
    }
    return ptr;
}

template <typename F, F Func, typename... Args>
static void *alloc_common(const char *func, std::size_t size, Fuzz_Data &data, Args... args)
{
    CONSUME1_OR_RETURN_VAL(
        const bool, want_alloc, data, report_alloc("tox1", func, size, Func(args...)));
    if (!want_alloc) {
        return nullptr;
    }
    return report_alloc("tox1", func, size, Func(args...));
}

static constexpr Memory_Funcs fuzz_memory_funcs = {
    /* .malloc = */
    ![](Fuzz_System *self, uint32_t size) {
        return alloc_common<decltype(std::malloc), std::malloc>("malloc", size, self->data, size);
    },
    /* .calloc = */
    ![](Fuzz_System *self, uint32_t nmemb, uint32_t size) {
        return alloc_common<decltype(std::calloc), std::calloc>(
            "calloc", nmemb * size, self->data, nmemb, size);
    },
    /* .realloc = */
    ![](Fuzz_System *self, void *ptr, uint32_t size) {
        return alloc_common<decltype(std::realloc), std::realloc>(
            "realloc", size, self->data, ptr, size);
    },
    /* .free = */
    ![](Fuzz_System *self, void *ptr) { std::free(ptr); },
};

static constexpr Network_Funcs fuzz_network_funcs = {
    /* .close = */ ![](Fuzz_System *self, Socket sock) { return 0; },
    /* .accept = */ ![](Fuzz_System *self, Socket sock) { return Socket{1337}; },
    /* .bind = */ ![](Fuzz_System *self, Socket sock, const Network_Addr *addr) { return 0; },
    /* .listen = */ ![](Fuzz_System *self, Socket sock, int backlog) { return 0; },
    /* .recvbuf = */
    ![](Fuzz_System *self, Socket sock) {
        assert(sock.value == 42 || sock.value == 1337);
        const size_t count = random_u16(self->rng.get());
        return static_cast<int>(std::min(count, self->data.size()));
    },
    /* .recv = */
    ![](Fuzz_System *self, Socket sock, uint8_t *buf, size_t len) {
        assert(sock.value == 42 || sock.value == 1337);
        // Receive data from the fuzzer.
        return recv_common(self->data, buf, len);
    },
    /* .recvfrom = */
    ![](Fuzz_System *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        assert(sock.value == 42 || sock.value == 1337);

        addr->addr = sockaddr_storage{};
        // Dummy Addr
        addr->addr.ss_family = AF_INET;

        // We want an AF_INET address with dummy values
        sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
        addr_in->sin_port = htons(33446);
        addr_in->sin_addr.s_addr = htonl(0x7f000002);  // 127.0.0.2
        addr->size = sizeof(struct sockaddr);

        return recv_common(self->data, buf, len);
    },
    /* .send = */
    ![](Fuzz_System *self, Socket sock, const uint8_t *buf, size_t len) {
        assert(sock.value == 42 || sock.value == 1337);
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Fuzz_System *self, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        assert(sock.value == 42 || sock.value == 1337);
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .socket = */ ![](Fuzz_System *self, int domain, int type, int proto) { return Socket{42}; },
    /* .socket_nonblock = */ ![](Fuzz_System *self, Socket sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Fuzz_System *self, Socket sock, int level, int optname, void *optval, size_t *optlen) {
        std::memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Fuzz_System *self, Socket sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static constexpr Random_Funcs fuzz_random_funcs = {
    /* .random_bytes = */
    ![](Fuzz_System *self, uint8_t *bytes, size_t length) {
        // Amount of data is limited
        const size_t bytes_read = std::min(length, self->data.size());
        // Initialize everything to make MSAN and others happy
        std::memset(bytes, 0, length);
        CONSUME_OR_ABORT(const uint8_t *data, self->data, bytes_read);
        std::copy(data, data + bytes_read, bytes);
        if (Fuzz_Data::DEBUG) {
            if (length == 1) {
                std::printf("rng: %d (0x%02x)\n", bytes[0], bytes[0]);
            } else {
                std::printf("rng: %02x..%02x[%zu]\n", bytes[0], bytes[length - 1], length);
            }
        }
    },
    /* .random_uniform = */
    ![](Fuzz_System *self, uint32_t upper_bound) {
        uint32_t randnum = 0;
        if (upper_bound > 0) {
            self->rng->funcs->random_bytes(
                self, reinterpret_cast<uint8_t *>(&randnum), sizeof(randnum));
            randnum %= upper_bound;
        }
        return randnum;
    },
};

Fuzz_System::Fuzz_System(Fuzz_Data &input)
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Memory>(Memory{&fuzz_memory_funcs, this}),
        std::make_unique<Network>(Network{&fuzz_network_funcs, this}),
        std::make_unique<Random>(Random{&fuzz_random_funcs, this}),
    }
    , data(input)
{
    sys->mono_time_callback = [](void *self) { return static_cast<Fuzz_System *>(self)->clock; };
    sys->mono_time_user_data = this;
    sys->mem = mem.get();
    sys->ns = ns.get();
    sys->rng = rng.get();
}

static constexpr Memory_Funcs null_memory_funcs = {
    /* .malloc = */
    ![](Null_System *self, uint32_t size) { return std::malloc(size); },
    /* .calloc = */
    ![](Null_System *self, uint32_t nmemb, uint32_t size) { return std::calloc(nmemb, size); },
    /* .realloc = */
    ![](Null_System *self, void *ptr, uint32_t size) { return std::realloc(ptr, size); },
    /* .free = */
    ![](Null_System *self, void *ptr) { std::free(ptr); },
};

static constexpr Network_Funcs null_network_funcs = {
    /* .close = */ ![](Null_System *self, Socket sock) { return 0; },
    /* .accept = */ ![](Null_System *self, Socket sock) { return Socket{1337}; },
    /* .bind = */ ![](Null_System *self, Socket sock, const Network_Addr *addr) { return 0; },
    /* .listen = */ ![](Null_System *self, Socket sock, int backlog) { return 0; },
    /* .recvbuf = */ ![](Null_System *self, Socket sock) { return 0; },
    /* .recv = */
    ![](Null_System *self, Socket sock, uint8_t *buf, size_t len) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .recvfrom = */
    ![](Null_System *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .send = */
    ![](Null_System *self, Socket sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Null_System *self, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .socket = */ ![](Null_System *self, int domain, int type, int proto) { return Socket{42}; },
    /* .socket_nonblock = */ ![](Null_System *self, Socket sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Null_System *self, Socket sock, int level, int optname, void *optval, size_t *optlen) {
        std::memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Null_System *self, Socket sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static uint64_t simple_rng(uint64_t &seed)
{
    // https://nuclear.llnl.gov/CNP/rng/rngman/node4.html
    seed = 2862933555777941757LL * seed + 3037000493LL;
    return seed;
}

static constexpr Random_Funcs null_random_funcs = {
    /* .random_bytes = */
    ![](Null_System *self, uint8_t *bytes, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = simple_rng(self->seed) & 0xff;
        }
    },
    /* .random_uniform = */
    ![](Null_System *self, uint32_t upper_bound) {
        return static_cast<uint32_t>(simple_rng(self->seed)) % upper_bound;
    },
};

Null_System::Null_System()
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Memory>(Memory{&null_memory_funcs, this}),
        std::make_unique<Network>(Network{&null_network_funcs, this}),
        std::make_unique<Random>(Random{&null_random_funcs, this}),
    }
{
    sys->mono_time_callback = [](void *self) { return static_cast<Null_System *>(self)->clock; };
    sys->mono_time_user_data = this;
    sys->mem = mem.get();
    sys->ns = ns.get();
    sys->rng = rng.get();
}

static uint16_t get_port(const Network_Addr *addr)
{
    if (addr->addr.ss_family == AF_INET6) {
        return reinterpret_cast<const sockaddr_in6 *>(&addr->addr)->sin6_port;
    } else {
        assert(addr->addr.ss_family == AF_INET);
        return reinterpret_cast<const sockaddr_in *>(&addr->addr)->sin_port;
    }
}

static constexpr Memory_Funcs record_memory_funcs = {
    /* .malloc = */
    ![](Record_System *self, uint32_t size) {
        self->push(true);
        return report_alloc(self->name_, "malloc", size, std::malloc(size));
    },
    /* .calloc = */
    ![](Record_System *self, uint32_t nmemb, uint32_t size) {
        self->push(true);
        return report_alloc(self->name_, "calloc", nmemb * size, std::calloc(nmemb, size));
    },
    /* .realloc = */
    ![](Record_System *self, void *ptr, uint32_t size) {
        self->push(true);
        return report_alloc(self->name_, "realloc", size, std::realloc(ptr, size));
    },
    /* .free = */
    ![](Record_System *self, void *ptr) { std::free(ptr); },
};

static constexpr Network_Funcs record_network_funcs = {
    /* .close = */ ![](Record_System *self, Socket sock) { return 0; },
    /* .accept = */ ![](Record_System *self, Socket sock) { return Socket{2}; },
    /* .bind = */
    ![](Record_System *self, Socket sock, const Network_Addr *addr) {
        const uint16_t port = get_port(addr);
        if (self->global_.bound.find(port) != self->global_.bound.end()) {
            errno = EADDRINUSE;
            return -1;
        }
        self->global_.bound.emplace(port, self);
        self->port = port;
        return 0;
    },
    /* .listen = */ ![](Record_System *self, Socket sock, int backlog) { return 0; },
    /* .recvbuf = */ ![](Record_System *self, Socket sock) { return 0; },
    /* .recv = */
    ![](Record_System *self, Socket sock, uint8_t *buf, size_t len) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .recvfrom = */
    ![](Record_System *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        assert(sock.value == 42);
        if (self->recvq.empty()) {
            self->push("\xff\xff");
            errno = EWOULDBLOCK;
            if (Fuzz_Data::DEBUG) {
                std::printf("%s: recvfrom: no data\n", self->name_);
            }
            return -1;
        }
        const auto [from, packet] = std::move(self->recvq.front());
        self->recvq.pop_front();
        const size_t recvlen = std::min(len, packet.size());
        std::copy(packet.begin(), packet.end(), buf);

        addr->addr = sockaddr_storage{};
        // Dummy Addr
        addr->addr.ss_family = AF_INET;

        // We want an AF_INET address with dummy values
        sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
        addr_in->sin_port = from;
        addr_in->sin_addr.s_addr = htonl(0x7f000002);  // 127.0.0.2
        addr->size = sizeof(struct sockaddr);

        assert(recvlen > 0 && recvlen <= INT_MAX);
        self->push(uint8_t(recvlen >> 8));
        self->push(uint8_t(recvlen & 0xff));
        if (Fuzz_Data::DEBUG) {
            std::printf("%s: recvfrom: %zu (%02x, %02x)\n", self->name_, recvlen,
                self->recording().end()[-2], self->recording().end()[-1]);
        }
        self->push(buf, recvlen);
        return static_cast<int>(recvlen);
    },
    /* .send = */
    ![](Record_System *self, Socket sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Record_System *self, Socket sock, const uint8_t *buf, size_t len,
         const Network_Addr *addr) {
        assert(sock.value == 42);
        auto backend = self->global_.bound.find(get_port(addr));
        assert(backend != self->global_.bound.end());
        backend->second->receive(self->port, buf, len);
        return static_cast<int>(len);
    },
    /* .socket = */
    ![](Record_System *self, int domain, int type, int proto) { return Socket{42}; },
    /* .socket_nonblock = */ ![](Record_System *self, Socket sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Record_System *self, Socket sock, int level, int optname, void *optval, size_t *optlen) {
        std::memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Record_System *self, Socket sock, int level, int optname, const void *optval,
         size_t optlen) { return 0; },
};

static constexpr Random_Funcs record_random_funcs = {
    /* .random_bytes = */
    ![](Record_System *self, uint8_t *bytes, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = simple_rng(self->seed_) & 0xff;
            self->push(bytes[i]);
        }
        if (Fuzz_Data::DEBUG) {
            std::printf(
                "%s: rng: %02x..%02x[%zu]\n", self->name_, bytes[0], bytes[length - 1], length);
        }
    },
    /* .random_uniform = */
    fuzz_random_funcs.random_uniform,
};

Record_System::Record_System(Global &global, uint64_t seed, const char *name)
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Memory>(Memory{&record_memory_funcs, this}),
        std::make_unique<Network>(Network{&record_network_funcs, this}),
        std::make_unique<Random>(Random{&record_random_funcs, this}),
    }
    , global_(global)
    , seed_(seed)
    , name_(name)
{
    sys->mono_time_callback = [](void *self) { return static_cast<Record_System *>(self)->clock; };
    sys->mono_time_user_data = this;
    sys->mem = mem.get();
    sys->ns = ns.get();
    sys->rng = rng.get();
}

void Record_System::receive(uint16_t send_port, const uint8_t *buf, size_t len)
{
    assert(port != 0);
    recvq.emplace_back(send_port, std::vector<uint8_t>{buf, buf + len});
}
