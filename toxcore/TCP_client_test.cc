// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "TCP_client.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "TCP_common.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"
#include "test_util.hh"
#include "util.h"

namespace {

using namespace tox::test;

class TCPClientTest : public ::testing::Test {
protected:
    SimulatedEnvironment env{12345};

    Mono_Time *_Nonnull create_mono_time(const Memory *_Nonnull mem)
    {
        Mono_Time *_Nonnull mt = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
        mono_time_set_current_time_callback(
            mt,
            [](void *_Nullable user_data) -> std::uint64_t {
                auto *clock = static_cast<FakeClock *>(user_data);
                return clock->current_time_ms();
            },
            &env.fake_clock());
        return mt;
    }

    static void log_cb(void *_Nullable context, Logger_Level level, const char *_Nonnull file,
        std::uint32_t line, const char *_Nonnull func, const char *_Nonnull message,
        void *_Nullable userdata)
    {
        if (level > LOGGER_LEVEL_TRACE) {
            fprintf(stderr, "[%d] %s:%u %s: %s\n", level, file, line, func, message);
        }
    }

    static void net_profile_deleter(Net_Profile *_Nullable p, const Memory *_Nonnull mem)
    {
        netprof_kill(mem, p);
    }
};

TEST_F(TCPClientTest, ConnectsToRelay)
{
    auto server_node = env.create_node(33445);
    auto client_node = env.create_node(0);  // Ephemeral port

    Logger *server_log = logger_new(&server_node->c_memory);
    logger_callback_log(server_log, &TCPClientTest::log_cb, nullptr, nullptr);
    Logger *client_log = logger_new(&client_node->c_memory);
    logger_callback_log(client_log, &TCPClientTest::log_cb, nullptr, nullptr);

    Mono_Time *client_time = create_mono_time(&client_node->c_memory);

    // 1. Setup Server Socket
    Socket server_sock
        = net_socket(&server_node->c_network, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    ASSERT_TRUE(sock_valid(server_sock));
    ASSERT_TRUE(set_socket_nonblock(&server_node->c_network, server_sock));
    ASSERT_TRUE(bind_to_port(&server_node->c_network, server_sock, net_family_ipv4(), 33445));
    ASSERT_EQ(0, net_listen(&server_node->c_network, server_sock, 5));

    // Server Keys
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&server_node->c_random, server_pk, server_sk);

    // Client Keys
    std::uint8_t client_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t client_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&client_node->c_random, client_pk, client_sk);

    Net_Profile *client_profile = netprof_new(client_log, &client_node->c_memory);

    // 2. Client connects to Server
    IP_Port server_ip_port;
    server_ip_port.ip = server_node->node->ip;
    server_ip_port.port = net_htons(33445);

    TCP_Client_Connection *client_conn = new_tcp_connection(client_log, &client_node->c_memory,
        client_time, &client_node->c_random, &client_node->c_network, &server_ip_port, server_pk,
        client_pk, client_sk, nullptr, client_profile);
    ASSERT_NE(client_conn, nullptr);

    // 3. Simulation Loop
    bool connected = false;
    Socket accepted_sock = net_invalid_socket();
    std::uint64_t start_time = env.clock().current_time_ms();

    while (env.clock().current_time_ms() - start_time < 5000) {
        env.advance_time(10);
        do_tcp_connection(client_log, client_time, client_conn, nullptr);

        // Server accepts connection
        if (!sock_valid(accepted_sock)) {
            accepted_sock = net_accept(&server_node->c_network, server_sock);
            if (sock_valid(accepted_sock)) {
                fprintf(stderr, "Server accepted connection! Socket: %d\n", accepted_sock.value);
                set_socket_nonblock(&server_node->c_network, accepted_sock);
            }
        }

        // Server handles handshake
        if (sock_valid(accepted_sock)) {
            std::uint8_t buf[TCP_CLIENT_HANDSHAKE_SIZE];
            IP_Port remote = {{{0}}};
            int len = net_recv(
                &server_node->c_network, server_log, accepted_sock, buf, sizeof(buf), &remote);

            if (len > 0) {
                fprintf(stderr, "Server received %d bytes\n", len);
            }

            if (len == TCP_CLIENT_HANDSHAKE_SIZE) {
                // Verify client PK
                EXPECT_EQ(0, std::memcmp(buf, client_pk, CRYPTO_PUBLIC_KEY_SIZE));

                // Decrypt
                std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
                encrypt_precompute(client_pk, server_sk, shared_key);

                std::uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
                const std::uint8_t *nonce_ptr = buf + CRYPTO_PUBLIC_KEY_SIZE;
                const std::uint8_t *ciphertext_ptr
                    = buf + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE;

                int res = decrypt_data_symmetric(&server_node->c_memory, shared_key, nonce_ptr,
                    ciphertext_ptr,
                    TCP_CLIENT_HANDSHAKE_SIZE - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE),
                    plain);

                if (res != TCP_HANDSHAKE_PLAIN_SIZE) {
                    fprintf(stderr, "Decryption failed: res=%d\n", res);
                }

                if (res == TCP_HANDSHAKE_PLAIN_SIZE) {
                    // Generate Response
                    // [Nonce (24)] [Encrypted (PK(32)+Nonce(24)+MAC(16))]

                    std::uint8_t resp_nonce[CRYPTO_NONCE_SIZE];
                    random_nonce(&server_node->c_random, resp_nonce);

                    std::uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
                    std::uint8_t temp_sk[CRYPTO_SECRET_KEY_SIZE];
                    crypto_new_keypair(&server_node->c_random, temp_pk, temp_sk);

                    std::uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
                    std::memcpy(resp_plain, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
                    random_nonce(&server_node->c_random, resp_plain + CRYPTO_PUBLIC_KEY_SIZE);

                    std::uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
                    std::memcpy(response, resp_nonce, CRYPTO_NONCE_SIZE);

                    encrypt_data_symmetric(&server_node->c_memory, shared_key,
                        resp_nonce,  // nonce
                        resp_plain,  // plain
                        TCP_HANDSHAKE_PLAIN_SIZE,  // plain len
                        response + CRYPTO_NONCE_SIZE  // dest
                    );

                    net_send(&server_node->c_network, server_log, accepted_sock, response,
                        sizeof(response), &remote, nullptr);
                }
            }
        }

        if (tcp_con_status(client_conn) == TCP_CLIENT_CONFIRMED) {
            connected = true;
            break;
        }
    }

    EXPECT_TRUE(connected);

    // Cleanup
    kill_tcp_connection(client_conn);
    net_profile_deleter(client_profile, &client_node->c_memory);
    kill_sock(&server_node->c_network, server_sock);
    if (sock_valid(accepted_sock))
        kill_sock(&server_node->c_network, accepted_sock);

    logger_kill(client_log);
    logger_kill(server_log);
    mono_time_free(&client_node->c_memory, client_time);
}

TEST_F(TCPClientTest, SendDataIntegerOverflow)
{
    auto server_node = env.create_node(33446);
    auto client_node = env.create_node(0);

    Logger *server_log = logger_new(&server_node->c_memory);
    logger_callback_log(server_log, &TCPClientTest::log_cb, nullptr, nullptr);
    Logger *client_log = logger_new(&client_node->c_memory);
    logger_callback_log(client_log, &TCPClientTest::log_cb, nullptr, nullptr);

    Mono_Time *client_time = create_mono_time(&client_node->c_memory);

    Socket server_sock
        = net_socket(&server_node->c_network, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    ASSERT_TRUE(sock_valid(server_sock));
    ASSERT_TRUE(set_socket_nonblock(&server_node->c_network, server_sock));
    ASSERT_TRUE(bind_to_port(&server_node->c_network, server_sock, net_family_ipv4(), 33446));
    ASSERT_EQ(0, net_listen(&server_node->c_network, server_sock, 5));

    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&server_node->c_random, server_pk, server_sk);

    std::uint8_t client_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t client_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(&client_node->c_random, client_pk, client_sk);

    Net_Profile *client_profile = netprof_new(client_log, &client_node->c_memory);

    IP_Port server_ip_port;
    server_ip_port.ip = server_node->node->ip;
    server_ip_port.port = net_htons(33446);

    TCP_Client_Connection *client_conn = new_tcp_connection(client_log, &client_node->c_memory,
        client_time, &client_node->c_random, &client_node->c_network, &server_ip_port, server_pk,
        client_pk, client_sk, nullptr, client_profile);
    ASSERT_NE(client_conn, nullptr);

    bool connected = false;
    Socket accepted_sock = net_invalid_socket();
    std::uint64_t start_time = env.clock().current_time_ms();
    std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    std::uint8_t sent_nonce[CRYPTO_NONCE_SIZE] = {0};
    std::uint8_t recv_nonce[CRYPTO_NONCE_SIZE] = {0};

    // Helper to send encrypted packet from server to client
    auto server_send_packet = [&](const std::uint8_t *data, std::uint16_t length) {
        std::uint16_t packet_size = sizeof(std::uint16_t) + length + CRYPTO_MAC_SIZE;
        std::vector<std::uint8_t> packet(packet_size);
        std::uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
        std::memcpy(packet.data(), &c_length, sizeof(std::uint16_t));

        encrypt_data_symmetric(&server_node->c_memory, shared_key, sent_nonce, data, length,
            packet.data() + sizeof(std::uint16_t));
        increment_nonce(sent_nonce);

        IP_Port remote = {{{0}}};
        net_send(&server_node->c_network, server_log, accepted_sock, packet.data(), packet_size,
            &remote, nullptr);
    };

    while (env.clock().current_time_ms() - start_time < 5000) {
        env.advance_time(10);
        do_tcp_connection(client_log, client_time, client_conn, nullptr);

        if (!sock_valid(accepted_sock)) {
            accepted_sock = net_accept(&server_node->c_network, server_sock);
            if (sock_valid(accepted_sock)) {
                set_socket_nonblock(&server_node->c_network, accepted_sock);
            }
        }

        if (sock_valid(accepted_sock) && !connected) {
            std::uint8_t buf[TCP_CLIENT_HANDSHAKE_SIZE];
            IP_Port remote = {{{0}}};
            int len = net_recv(
                &server_node->c_network, server_log, accepted_sock, buf, sizeof(buf), &remote);

            if (len == TCP_CLIENT_HANDSHAKE_SIZE) {
                encrypt_precompute(client_pk, server_sk, shared_key);
                std::uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
                if (decrypt_data_symmetric(&server_node->c_memory, shared_key,
                        buf + CRYPTO_PUBLIC_KEY_SIZE,
                        buf + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                        TCP_CLIENT_HANDSHAKE_SIZE - (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE),
                        plain)
                    == TCP_HANDSHAKE_PLAIN_SIZE) {
                    std::memcpy(recv_nonce, plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

                    std::uint8_t resp_nonce[CRYPTO_NONCE_SIZE];
                    random_nonce(&server_node->c_random, resp_nonce);
                    std::memcpy(sent_nonce, resp_nonce, CRYPTO_NONCE_SIZE);

                    std::uint8_t temp_pk[CRYPTO_PUBLIC_KEY_SIZE];
                    std::uint8_t temp_sk[CRYPTO_SECRET_KEY_SIZE];
                    crypto_new_keypair(&server_node->c_random, temp_pk, temp_sk);

                    std::uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
                    std::memcpy(resp_plain, temp_pk, CRYPTO_PUBLIC_KEY_SIZE);
                    random_nonce(&server_node->c_random, resp_plain + CRYPTO_PUBLIC_KEY_SIZE);

                    // FIX: Save the nonce that client will use for receiving
                    std::memcpy(sent_nonce, resp_plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

                    std::uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
                    std::memcpy(response, resp_nonce, CRYPTO_NONCE_SIZE);
                    encrypt_data_symmetric(&server_node->c_memory, shared_key, resp_nonce,
                        resp_plain, TCP_HANDSHAKE_PLAIN_SIZE, response + CRYPTO_NONCE_SIZE);
                    net_send(&server_node->c_network, server_log, accepted_sock, response,
                        sizeof(response), &remote, nullptr);

                    // FIX: Update shared key using Client's Ephemeral PK and Server's Ephemeral SK
                    encrypt_precompute(plain, temp_sk, shared_key);
                }
            }
        }

        if (tcp_con_status(client_conn) == TCP_CLIENT_CONFIRMED) {
            connected = true;
            break;
        }
    }
    ASSERT_TRUE(connected);

    // Establish sub-connection 0
    std::uint8_t con_id = 0;
    std::uint8_t other_pk[CRYPTO_PUBLIC_KEY_SIZE] = {0};  // Dummy PK
    // 1. Send Routing Response to set status=1
    {
        std::uint8_t packet[1 + 1 + CRYPTO_PUBLIC_KEY_SIZE];
        packet[0] = TCP_PACKET_ROUTING_RESPONSE;
        packet[1] = con_id + NUM_RESERVED_PORTS;
        std::memcpy(packet + 2, other_pk, CRYPTO_PUBLIC_KEY_SIZE);
        server_send_packet(packet, sizeof(packet));
    }

    // Pump loop to process packet
    for (int i = 0; i < 10; ++i) {
        env.advance_time(10);
        do_tcp_connection(client_log, client_time, client_conn, nullptr);
    }

    // 2. Send Connection Notification to set status=2
    {
        std::uint8_t packet[1 + 1];
        packet[0] = TCP_PACKET_CONNECTION_NOTIFICATION;
        packet[1] = con_id + NUM_RESERVED_PORTS;
        server_send_packet(packet, sizeof(packet));
    }

    // Pump loop to process packet
    for (int i = 0; i < 10; ++i) {
        env.advance_time(10);
        do_tcp_connection(client_log, client_time, client_conn, nullptr);
    }

    // Now call send_data with 65535 bytes
    std::vector<std::uint8_t> large_data(65535);
    // This should trigger integer overflow: 1 + 65535 = 0. VLA(0). packet[0] write -> Crash/UB
    send_data(client_log, client_conn, con_id, large_data.data(), 65535);

    // Cleanup
    kill_tcp_connection(client_conn);
    net_profile_deleter(client_profile, &client_node->c_memory);
    kill_sock(&server_node->c_network, server_sock);
    if (sock_valid(accepted_sock))
        kill_sock(&server_node->c_network, accepted_sock);
    logger_kill(client_log);
    logger_kill(server_log);
    mono_time_free(&client_node->c_memory, client_time);
}

}  // namespace
