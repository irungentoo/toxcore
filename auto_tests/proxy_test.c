/* Tests that we can send messages to friends.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "auto_test_support.h"

static void *proxy_routine(void *arg)
{
    const char *proxy_bin = (const char *)arg;
    ck_assert(proxy_bin != nullptr);
    printf("starting http/sock5 proxy: %s\n", proxy_bin);
    ck_assert(system(proxy_bin) == 0);
    return nullptr;
}

static bool try_bootstrap(Tox *tox1, Tox *tox2, Tox *tox3, Tox *tox4)
{
    for (uint32_t i = 0; i < 400; ++i) {
        if (tox_self_get_connection_status(tox1) != TOX_CONNECTION_NONE &&
                tox_self_get_connection_status(tox2) != TOX_CONNECTION_NONE &&
                tox_self_get_connection_status(tox3) != TOX_CONNECTION_NONE &&
                tox_self_get_connection_status(tox4) != TOX_CONNECTION_NONE) {
            printf("%d %d %d %d\n",
                   tox_self_get_connection_status(tox1),
                   tox_self_get_connection_status(tox2),
                   tox_self_get_connection_status(tox3),
                   tox_self_get_connection_status(tox4));
            return true;
        }

        tox_iterate(tox1, nullptr);
        tox_iterate(tox2, nullptr);
        tox_iterate(tox3, nullptr);
        tox_iterate(tox4, nullptr);

        if (i % 10 == 0) {
            printf("%d %d %d %d\n",
                   tox_self_get_connection_status(tox1),
                   tox_self_get_connection_status(tox2),
                   tox_self_get_connection_status(tox3),
                   tox_self_get_connection_status(tox4));
        }

        c_sleep(tox_iteration_interval(tox1));
    }

    return false;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc >= 3) {
        char *proxy_bin = argv[2];
        pthread_t proxy_thread;
        pthread_create(&proxy_thread, nullptr, proxy_routine, proxy_bin);
        c_sleep(100);
    }

    const uint16_t tcp_port = 8082;
    uint32_t index[] = { 1, 2, 3, 4 };

    struct Tox_Options *tox_options = tox_options_new(nullptr);
    ck_assert(tox_options != nullptr);

    // tox1 is a TCP server and has UDP enabled.
    tox_options_set_udp_enabled(tox_options, true);
    tox_options_set_tcp_port(tox_options, tcp_port);

    Tox *tox1 = tox_new_log(tox_options, nullptr, &index[0]);
    ck_assert(tox1 != nullptr);

    // Get tox1's DHT key and port.
    uint8_t dht_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_pk);
    uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);
    ck_assert(dht_port != 0);

    // tox2 is a regular DHT node bootstrapping against tox1.
    tox_options_set_udp_enabled(tox_options, true);
    tox_options_set_tcp_port(tox_options, 0);

    Tox *tox2 = tox_new_log(tox_options, nullptr, &index[1]);
    ck_assert(tox2 != nullptr);

    // tox2 bootstraps against tox1 with UDP.
    ck_assert(tox_bootstrap(tox2, "127.0.0.1", dht_port, dht_pk, nullptr));

    // tox3 has UDP disabled and connects to tox1 via an HTTP proxy
    tox_options_set_udp_enabled(tox_options, false);
    tox_options_set_proxy_host(tox_options, "127.0.0.1");
    tox_options_set_proxy_port(tox_options, 8080);
    tox_options_set_proxy_type(tox_options, TOX_PROXY_TYPE_HTTP);

    Tox *tox3 = tox_new_log(tox_options, nullptr, &index[2]);
    ck_assert(tox3 != nullptr);

    // tox4 has UDP disabled and connects to tox1 via a SOCKS5 proxy
    tox_options_set_udp_enabled(tox_options, false);
    tox_options_set_proxy_host(tox_options, "127.0.0.1");
    tox_options_set_proxy_port(tox_options, 8081);
    tox_options_set_proxy_type(tox_options, TOX_PROXY_TYPE_SOCKS5);

    Tox *tox4 = tox_new_log(tox_options, nullptr, &index[3]);
    ck_assert(tox4 != nullptr);

    // tox3 and tox4 bootstrap against tox1 and add it as a TCP relay
    ck_assert(tox_bootstrap(tox3, "127.0.0.1", dht_port, dht_pk, nullptr));
    ck_assert(tox_add_tcp_relay(tox3, "127.0.0.1", tcp_port, dht_pk, nullptr));

    ck_assert(tox_bootstrap(tox4, "127.0.0.1", dht_port, dht_pk, nullptr));
    ck_assert(tox_add_tcp_relay(tox4, "127.0.0.1", tcp_port, dht_pk, nullptr));

    int ret = 1;
    if (try_bootstrap(tox1, tox2, tox3, tox4)) {
        ret = 0;
    }

    tox_options_free(tox_options);
    tox_kill(tox4);
    tox_kill(tox3);
    tox_kill(tox2);
    tox_kill(tox1);

    return ret;
}
