load("//tools:no_undefined.bzl", "cc_library")

filegroup(
    name = "public_headers",
    srcs = ["tox.h"],
    visibility = ["//c-toxcore:__pkg__"],
)

cc_library(
    name = "ccompat",
    hdrs = ["ccompat.h"],
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
    visibility = ["//c-toxcore/toxencryptsave:__pkg__"],
    deps = [
        ":ccompat",
        "@libsodium",
    ],
)

cc_library(
    name = "list",
    srcs = ["list.c"],
    hdrs = ["list.h"],
)

cc_library(
    name = "logger",
    srcs = ["logger.c"],
    hdrs = ["logger.h"],
)

cc_library(
    name = "network",
    srcs = [
        "network.c",
        "util.c",
    ],
    hdrs = [
        "network.h",
        "util.h",
    ],
    linkopts = ["-lpthread"],
    visibility = [
        "//c-toxcore/other:__pkg__",
        "//c-toxcore/toxav:__pkg__",
    ],
    deps = [
        ":ccompat",
        ":crypto_core",
        ":logger",
    ],
)

cc_library(
    name = "ping_array",
    srcs = ["ping_array.c"],
    hdrs = ["ping_array.h"],
    deps = [":network"],
)

cc_library(
    name = "DHT",
    srcs = [
        "DHT.c",
        "LAN_discovery.c",
        "ping.c",
    ],
    hdrs = [
        "DHT.h",
        "LAN_discovery.h",
        "ping.h",
    ],
    copts = [
        "-Wno-parentheses",
    ],
    visibility = ["//c-toxcore/other/bootstrap_daemon:__pkg__"],
    deps = [
        ":crypto_core",
        ":logger",
        ":ping_array",
    ],
)

cc_library(
    name = "onion",
    srcs = ["onion.c"],
    hdrs = ["onion.h"],
    deps = [":DHT"],
)

cc_library(
    name = "TCP_connection",
    srcs = [
        "TCP_client.c",
        "TCP_connection.c",
        "TCP_server.c",
    ],
    hdrs = [
        "TCP_client.h",
        "TCP_connection.h",
        "TCP_server.h",
    ],
    deps = [
        ":crypto_core",
        ":list",
        ":onion",
    ],
)

cc_library(
    name = "net_crypto",
    srcs = ["net_crypto.c"],
    hdrs = ["net_crypto.h"],
    deps = [
        ":DHT",
        ":TCP_connection",
    ],
)

cc_library(
    name = "onion_announce",
    srcs = ["onion_announce.c"],
    hdrs = ["onion_announce.h"],
    deps = [":onion"],
)

cc_library(
    name = "onion_client",
    srcs = ["onion_client.c"],
    hdrs = ["onion_client.h"],
    deps = [
        ":net_crypto",
        ":onion_announce",
    ],
)

cc_library(
    name = "friend_connection",
    srcs = ["friend_connection.c"],
    hdrs = ["friend_connection.h"],
    deps = [
        ":DHT",
        ":net_crypto",
        ":onion_client",
    ],
)

cc_library(
    name = "friend_requests",
    srcs = ["friend_requests.c"],
    hdrs = ["friend_requests.h"],
    deps = [":friend_connection"],
)

cc_library(
    name = "Messenger",
    srcs = ["Messenger.c"],
    hdrs = ["Messenger.h"],
    visibility = ["//c-toxcore/toxav:__pkg__"],
    deps = [":friend_requests"],
)

cc_library(
    name = "group",
    srcs = ["group.c"],
    hdrs = ["group.h"],
    visibility = ["//c-toxcore/toxav:__pkg__"],
    deps = [":Messenger"],
)

cc_library(
    name = "toxcore",
    srcs = [
        "tox.c",
        "tox.h",
        "tox_api.c",
    ],
    copts = [
        "-Wno-parentheses",
    ],
    visibility = ["//c-toxcore:__subpackages__"],
    deps = [
        ":group",
        "//c-toxcore/toxencryptsave:defines",
    ],
)

cc_library(
    name = "monolith",
    hdrs = glob([
        "*.c",
        "*.h",
    ]),
    copts = [
        "-Wno-parentheses",
    ],
    linkopts = ["-lpthread"],
    visibility = ["//c-toxcore/other:__pkg__"],
    deps = [
        "//c-toxcore/toxencryptsave:defines",
        "@libsodium",
    ],
)
