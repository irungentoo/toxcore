filegroup(
    name = "public",
    srcs = ["tox.h"],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ccompat",
    hdrs = [
        "ccompat.h",
    ],
    visibility = ["//visibility:public"],
)

cc_library(
    name = "crypto_core",
    srcs = [
        "crypto_core.c",
        "crypto_core_mem.c",
    ],
    hdrs = [
        "crypto_core.h",
    ],
    visibility = ["//c-toxcore:__subpackages__"],
    deps = [
        ":ccompat",
        "@libsodium",
    ],
)

cc_library(
    name = "toxcore",
    srcs = [
        "DHT.c",
        "DHT.h",
        "LAN_discovery.c",
        "LAN_discovery.h",
        "Messenger.c",
        "Messenger.h",
        "TCP_client.c",
        "TCP_client.h",
        "TCP_connection.c",
        "TCP_connection.h",
        "TCP_server.c",
        "TCP_server.h",
        "friend_connection.c",
        "friend_connection.h",
        "friend_requests.c",
        "friend_requests.h",
        "group.c",
        "group.h",
        "list.c",
        "list.h",
        "logger.c",
        "logger.h",
        "net_crypto.c",
        "net_crypto.h",
        "network.c",
        "network.h",
        "onion.c",
        "onion.h",
        "onion_announce.c",
        "onion_announce.h",
        "onion_client.c",
        "onion_client.h",
        "ping.c",
        "ping.h",
        "ping_array.c",
        "ping_array.h",
        "tox.c",
        "tox.h",
        "tox_api.c",
        "util.c",
        "util.h",
    ],
    copts = [
        "-std=c99",
        "-Wno-parentheses",
    ],
    linkopts = ["-lpthread"],
    visibility = ["//visibility:public"],
    deps = [
        ":ccompat",
        ":crypto_core",
        "//c-toxcore/toxencryptsave",
    ],
)

cc_library(
    name = "monolith",
    hdrs = glob([
        "*.c",
        "*.h",
    ]),
    visibility = ["//c-toxcore/other:__pkg__"],
)
